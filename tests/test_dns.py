import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import client
import config as config_module
import dns_backend


class DnsmasqTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.online = root / 'servers'
        self.offline = root / 'offline'
        self.offline.write_text('server=9.9.9.9\nserver=/example.org/8.8.8.8\n')
        self.online.symlink_to(self.offline)
        route = patch.object(dns_backend, 'routed_to_tunnel', return_value=True)
        self.route = route.start()
        self.addCleanup(route.stop)
        for name, value in [('ACTIVE', self.online), ('OFFLINE', self.offline)]:
            mock = patch.object(dns_backend, name, value)
            mock.start()
            self.addCleanup(mock.stop)

    @patch('dns_backend.reload_dnsmasq')
    def test_switch_and_restore(self, reload):
        dns_backend.activate(['10.11.8.2', '10.11.8.3', '10.11.8.2', 'invalid'], 'tun-test')
        self.assertEqual(self.online.read_text(), 'server=10.11.8.2\nserver=10.11.8.3\n')
        self.assertFalse(self.online.is_symlink())
        dns_backend.restore()
        self.assertEqual(os.readlink(self.online), str(self.offline))
        self.assertEqual(reload.call_count, 2)

    @patch('dns_backend.reload_dnsmasq')
    def test_no_valid_servers_leaves_dns_untouched(self, reload):
        dns_backend.activate(['0.0.0.0', '127.0.0.1', '1.2.3.4\nserver=9.9.9.9'], 'tun-test')
        self.assertEqual(os.readlink(self.online), str(self.offline))
        reload.assert_not_called()

    @patch('dns_backend.reload_dnsmasq')
    def test_reload_failure_restores_file(self, reload):
        reload.side_effect = [subprocess.CalledProcessError(1, 'systemctl'), None]
        with self.assertRaises(subprocess.CalledProcessError):
            dns_backend.activate(['10.11.8.2'], 'tun-test')
        self.assertEqual(os.readlink(self.online), str(self.offline))
        self.assertEqual(reload.call_count, 2)

    @patch('dns_backend.reload_dnsmasq')
    def test_retry_restore_after_failed_reload(self, reload):
        reload.side_effect = [None, subprocess.CalledProcessError(1, 'systemctl'), None]
        dns_backend.activate(['10.11.8.2'], 'tun-test')
        with self.assertRaises(subprocess.CalledProcessError):
            dns_backend.restore()
        self.assertTrue(self.online.is_symlink())
        dns_backend.restore()
        self.assertEqual(reload.call_count, 3)

    @patch('dns_backend.reload_dnsmasq')
    def test_dns_outside_tunnel_is_not_selected(self, reload):
        self.route.return_value = False
        self.assertFalse(dns_backend.activate(['10.11.8.2'], 'tun-test'))
        reload.assert_not_called()

    @patch('dns_backend.reload_dnsmasq')
    def test_no_integration_configured(self, reload):
        self.online.unlink()
        with self.assertRaises(OSError):
            dns_backend.activate(['10.11.8.2'], 'tun-test')
        dns_backend.restore()
        reload.assert_not_called()

    def backend_process(self, operation, invocation='', expected=0):
        # Separate interpreter, real filesystem, no host DNS reload or route lookup.
        script = '''
import os, sys
from pathlib import Path
import dns_backend as db
db.ACTIVE, db.OFFLINE = map(Path, sys.argv[1:3])
db.routed_to_tunnel = lambda *args: True
def reload():
    with db.ACTIVE.with_name('reloads').open('a') as stream:
        stream.write('offline\\n' if db.ACTIVE.is_symlink() else 'online\\n')
db.reload_dnsmasq = reload
''' + operation
        result = subprocess.run([sys.executable, '-c', script, str(self.online), str(self.offline)],
                                env={**os.environ, 'INVOCATION_ID': invocation},
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, expected, result.stderr)

    def test_main_exception_does_not_restore_another_process_dns(self):
        self.backend_process("db.activate(['10.11.8.2'], 'tun-test')")
        config = dict(dns_backend='dnsmasq', gateways=[('vpn.invalid', 443)], username='test', password='test')
        with patch('client.load_config', return_value=config), \
             patch('client.os.geteuid', return_value=0), patch('client.signal.signal'), \
             patch('client.run_vpn', side_effect=RuntimeError('session failed')), \
             patch('dns_backend.reload_dnsmasq') as reload:
            with self.assertRaisesRegex(RuntimeError, 'session failed'):
                client.main()
        self.assertFalse(self.online.is_symlink())
        reload.assert_not_called()

    def test_stop_post_recovers_only_matching_invocation_after_process_death(self):
        owner, other = '1' * 32, '2' * 32
        stop = 'db.restore_for_invocation()'
        activate = "db.activate(['10.11.8.2'], 'tun-test')"
        self.backend_process(stop, owner)  # Exited before any activation.
        log = self.online.with_name('reloads')
        self.assertFalse(log.exists())
        self.backend_process(activate + '\nos._exit(42)', owner, expected=42)
        self.backend_process(stop, other)
        self.backend_process(stop)
        self.assertFalse(self.online.is_symlink())
        self.assertEqual(log.read_text(), 'online\n')
        self.backend_process(stop, owner)
        self.assertEqual(self.online.readlink(), self.offline)
        self.backend_process(stop, owner)  # Idempotent after successful cleanup.
        self.backend_process(activate)  # A subsequent manual instance.
        self.backend_process(stop, owner)
        self.assertFalse(self.online.is_symlink())
        self.assertEqual(log.read_text(), 'online\noffline\nonline\n')

    def test_stop_post_does_not_reload_if_process_died_before_replacing_file(self):
        owner = '1' * 32
        self.backend_process("db.replace_active = lambda *args: os._exit(42)\n"
                             "db.activate(['10.11.8.2'], 'tun-test')", owner, expected=42)
        self.backend_process('db.restore_for_invocation()', owner)
        self.assertFalse(self.online.with_name('reloads').exists())
        self.assertEqual(self.online.readlink(), self.offline)
        self.backend_process("db.activate(['10.11.8.2'], 'tun-test')")  # Claim was released.

    def test_stop_post_retries_reload_after_crash_during_rollback(self):
        owner = '1' * 32
        self.backend_process("db.activate(['10.11.8.2'], 'tun-test')\n"
                             "db.reload_dnsmasq = lambda: os._exit(42)\n"
                             "db.restore()", owner, expected=42)
        self.assertEqual(self.online.readlink(), self.offline)
        # A manual instance must not claim the offline symlink while rollback is pending.
        self.backend_process("try:\n    db.activate(['10.11.8.3'], 'tun-test')\n"
                             "except OSError:\n    sys.exit(42)", expected=42)
        self.backend_process('db.restore_for_invocation()', owner)
        self.assertEqual(self.online.with_name('reloads').read_text(), 'online\noffline\n')

    def test_foreign_claim_stops_without_forwarding_or_retry(self):
        self.backend_process("db.activate(['10.11.8.2'], 'tun-test')", '1' * 32)
        self.check_ownership_conflict()

    def test_stale_claim_after_failed_restore_stops_even_without_usable_dns(self):
        self.backend_process("db.activate(['10.11.8.2'], 'tun-test')\n"
                             "db.reload_dnsmasq = lambda: os._exit(42)\n"
                             "db.restore()", '1' * 32, expected=42)
        self.assertEqual(self.online.readlink(), self.offline)
        self.route.return_value = False
        self.check_ownership_conflict()

    def test_unmarked_online_file_stops_new_session_without_adopting_it(self):
        self.online.unlink()
        self.online.write_text('server=10.11.8.2\n')  # v1.1.11 online state
        self.backend_process('db.restore_for_invocation()', '1' * 32)
        self.assertFalse(self.online.is_symlink())
        self.assertFalse(self.online.with_name('reloads').exists())
        self.check_ownership_conflict()

    def check_ownership_conflict(self):
        marker = self.online.with_name('servers.owner')

        def snapshot(path):
            if path.is_symlink():
                return path.lstat().st_ino, path.readlink()
            if path.exists():
                return path.stat().st_ino, path.read_bytes()

        before = snapshot(self.online), snapshot(marker)
        config = dict(tun_name='tun-test', dns_backend='dnsmasq', gateways=[])
        gateway = dict(ip='192.0.2.1', host='vpn.invalid', port=443, latency=1)
        vip = dict(vip_ip='198.51.100.9', mask='255.255.255.224', routes=[], dns=['198.51.100.17'])
        stop = Mock(wraps=threading.Event())
        stop.wait.return_value = True
        ready = Mock()
        run_session = client._run_session
        with patch.object(client, 'select_gateway', return_value=[gateway, {**gateway, 'ip': '192.0.2.2'}]) as select, \
             patch.object(client, 'authenticate', return_value=2) as auth, \
             patch.object(client, 'open_gateway_tls', return_value=Mock()), \
             patch.object(client, 'negotiate', return_value=vip), \
             patch.object(client, 'create_tun', return_value=(42, 'tun-test')), \
             patch.object(client.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='[]')), \
             patch.object(client.os, 'close') as close, \
             patch.object(client, '_run_session', side_effect=lambda c, ctx, s, gw, _: run_session(c, ctx, s, gw, ready)), \
             patch.object(client, '_forward', side_effect=lambda *_: stop.set()) as forward, \
             patch.object(client, 'restore_dns') as restore, \
             patch.object(dns_backend, 'reload_dnsmasq') as reload, \
             self.assertLogs('openunivpn') as logs:
            self.assertEqual(client.run_vpn(config, stop), 78)
        self.assertIn('所有权冲突', '\n'.join(logs.output))
        select.assert_called_once()
        auth.assert_called_once()
        close.assert_called_once_with(42)
        ready.assert_not_called()
        forward.assert_not_called()
        stop.wait.assert_not_called()
        restore.assert_not_called()
        reload.assert_not_called()
        self.assertEqual((snapshot(self.online), snapshot(marker)), before)

    def test_dnsmasq_restores_before_tun_close_on_disconnect_and_reconnect(self):
        actions = []

        def ip_run(args, **kwargs):
            if args[:4] == ['ip', 'route', 'add', '203.0.113.0/24']:
                actions.append('DNS route added')
            return subprocess.CompletedProcess(args, 0, stdout='[]')

        def reload():
            actions.append('offline' if self.online.is_symlink() else 'online')

        real_close = os.close

        def close(fd):
            if fd in (42, 43):
                actions.append(fd)
            else:
                real_close(fd)

        config = dict(tun_name='tun-test', dns_backend='dnsmasq', extra_routes=['203.0.113.0/24'])
        gateway = dict(ip='192.0.2.1', host='vpn.invalid', port=443, latency=1)
        vip = dict(vip_ip='198.51.100.9', mask='255.255.255.224', routes=[], dns=['203.0.113.53'])
        transient = client.SessionFailure('转发', '断开', retryable=True)
        with patch.object(client, 'authenticate', return_value=2), \
             patch.object(client, 'open_gateway_tls', return_value=Mock()), \
             patch.object(client, 'negotiate', return_value=vip), \
             patch.object(client, 'create_tun', side_effect=[(42, 'tun-test'), (43, 'tun-test')]), \
             patch.object(client.subprocess, 'run', side_effect=ip_run), \
             patch.object(client.os, 'close', side_effect=close), \
             patch.object(dns_backend, 'reload_dnsmasq', side_effect=reload), \
             patch.object(client, '_forward', side_effect=[transient, None]):
            def connect():
                client._run_session(config, None, threading.Event(), gateway, lambda: actions.append('ready'))

            with self.assertRaises(client.SessionFailure) as raised:
                connect()
            self.assertIs(raised.exception, transient)
            self.assertEqual(self.online.readlink(), self.offline)
            connect()
            self.assertEqual(self.online.readlink(), self.offline)

        self.assertEqual(actions, ['DNS route added', 'online', 'ready', 'offline', 42,
                                   'DNS route added', 'online', 'ready', 'offline', 43])


class GatewayTrustTest(unittest.TestCase):
    @patch('dns_backend.subprocess.run')
    def test_broadcast_route_does_not_qualify_as_tunnel_route(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, '[{"type":"broadcast","dev":"tun-test"}]')
        self.assertFalse(dns_backend.routed_to_tunnel('10.11.8.255', 'tun-test'))

    def test_resolvconf_ignores_unused_static_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.conf'
            path.write_text('[dns]\nbackend=resolvconf\nservers=not-an-ip\n')
            self.assertEqual(config_module._parse_config(path)['dns_servers'], [])

    def test_unverified_gateway_uses_only_configured_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / 'config.conf'
            config_file.write_text('[dns]\nbackend=dnsmasq\nservers=10.11.8.2,10.11.8.3\n'
                                   '[gateway]\ntls_verify=false\n')
            config = config_module._parse_config(config_file)
        ctx = client.gateway_tls_context(config)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertEqual(client.select_session_dns(config, ['192.0.2.1']),
                         ['10.11.8.2', '10.11.8.3'])

    def test_unverified_gateway_requires_configured_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_file = Path(tmp) / 'config.conf'
            config_file.write_text('[dns]\nbackend=dnsmasq\n[gateway]\ntls_verify=false\n')
            with self.assertRaisesRegex(ValueError, 'servers'):
                config_module._parse_config(config_file)

    def test_exclusive_backend_verifies_tls_peer(self):
        ctx = client.gateway_tls_context({'dns_backend': 'dnsmasq'})
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_default_backend_verifies_tls_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.conf'
            path.write_text('')
            config = config_module._parse_config(path)
        self.assertEqual(config['dns_backend'], 'resolvconf')
        for opts in (config, {'dns_backend': 'resolvconf'}, {}):
            with self.subTest(opts=opts):
                ctx = client.gateway_tls_context(opts)
                self.assertTrue(ctx.check_hostname)
                self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_unverified_resolvconf_without_static_dns_ignores_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.conf'
            path.write_text('[gateway]\ntls_verify=false\n')
            config = config_module._parse_config(path)
        self.assertEqual(client.gateway_tls_context(config).verify_mode, ssl.CERT_NONE)
        self.assertEqual(client.select_session_dns(config, ['192.0.2.1']), [])

    def test_unverified_resolvconf_uses_only_static_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.conf'
            path.write_text('[gateway]\ntls_verify=false\n[dns]\nservers=192.0.2.2\n')
            config = config_module._parse_config(path)
        self.assertEqual(client.select_session_dns(config, ['192.0.2.1']), ['192.0.2.2'])

    @patch('client.subprocess.run')
    @patch('client._resolvconf_available', return_value=True)
    @patch('dns_backend.routed_to_tunnel', side_effect=lambda ip, tun: str(ip) == '192.0.2.2')
    def test_resolvconf_only_registers_dns_routed_via_tunnel(self, route, available, run):
        run.return_value = subprocess.CompletedProcess([], 0)
        client.setup_dns(['192.0.2.1'], 'resolvconf', 'tun-test')
        run.assert_not_called()
        client.setup_dns(['192.0.2.1', '192.0.2.2'], 'resolvconf', 'tun-test')
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs['input'], 'nameserver 192.0.2.2\n')

    @patch('dns_backend.restore')
    @patch('client.run_vpn', side_effect=RuntimeError('session failed'))
    @patch('client.signal.signal')
    @patch('client.os.geteuid', return_value=0)
    @patch('client.load_config', return_value={
        'dns_backend': 'dnsmasq', 'gateways': [('vpn.example', 443)],
        'username': 'test', 'password': 'test',
    })
    def test_standalone_exception_survives_dns_restore_failure(self, load, geteuid, signal, run, restore):
        restore.side_effect = OSError('restore failed')
        with self.assertLogs('openunivpn', level='ERROR'), self.assertRaisesRegex(RuntimeError, 'session failed'):
            client.main()
        restore.assert_called_once_with()
