"""Offline gateway recovery: all network and host I/O is replaced at its boundary."""
from contextlib import ExitStack
from pathlib import Path
import errno
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import client
import config


CONFIG = dict(gateways=[('one.invalid', 443)], tun_name='test0',
              username='test-user', password='test-pass')
REAL_CLOSE = os.close


class RetryTests(unittest.TestCase):
    def test_long_outage_reprobes_until_recovery(self):
        stop = Mock(wraps=threading.Event())
        delays = []
        def wait(delay):
            delays.append(delay)
            return False
        stop.wait.side_effect = wait
        gateway = dict(host='one.invalid', ip='192.0.2.1', port=443, latency=1)
        # Stay offline beyond the unit's 300-second window before recovering.
        with patch('client.probe_gateway', side_effect=[None] * 10 + [gateway]) as probe, \
             patch('random.uniform', return_value=1), \
             patch('client._run_session', side_effect=lambda *_: stop.set()) as connect, \
             self.assertLogs('openunivpn', level='INFO'):
            self.assertEqual(client.run_vpn(CONFIG, stop), 0)
        self.assertEqual(probe.call_count, 11)
        connect.assert_called_once()
        self.assertEqual(delays, [3, 6, 12, 24, 48, 60, 60, 60, 60, 60])
        self.assertGreater(sum(delays), 300)

    def test_stop_interrupts_backoff_without_reprobe(self):
        stop = Mock(wraps=threading.Event())
        def wait(_):
            stop.set()
            return True
        stop.wait.side_effect = wait
        with patch('client.probe_gateway', return_value=None) as probe, self.assertLogs('openunivpn'):
            self.assertEqual(client.run_vpn(CONFIG, stop), 0)
        probe.assert_called_once()
        stop.wait.assert_called_once()

    @patch('client.socket.getaddrinfo', return_value=[(None, None, None, None, ('192.0.2.1', 0))])
    @patch('client.socket.create_connection', side_effect=OSError(errno.EMFILE, 'local limit'))
    def test_local_probe_error_is_not_an_outage(self, connect, resolve):
        stop = Mock(wraps=threading.Event())
        stop.wait.return_value = True
        with self.assertLogs('openunivpn'):
            self.assertEqual(client.run_vpn(CONFIG, stop), 78)
        stop.wait.assert_not_called()

    @patch('client.fcntl.ioctl', side_effect=OSError(errno.EBUSY, 'busy'))
    @patch('client.os.open', return_value=42)
    @patch('client.os.close')
    def test_tun_ioctl_failure_does_not_leak_fd(self, close, open_fd, ioctl):
        with self.assertRaises(OSError):
            client.create_tun('test0')
        close.assert_called_once_with(42)


class SessionTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.config = dict(CONFIG, gateways=[('slow.invalid', 443), ('fast.invalid', 443)])
        self.stop = Mock(wraps=threading.Event())
        self.stop.wait.return_value = False
        self.gateway = {
            'slow.invalid': dict(host='slow.invalid', ip='192.0.2.2', port=443, latency=9),
            'fast.invalid': dict(host='fast.invalid', ip='192.0.2.1', port=443, latency=1),
        }
        stack.enter_context(patch('client.probe_gateway', side_effect=lambda host, *_: self.gateway[host]))
        self.connect = stack.enter_context(patch('client.socket.create_connection'))
        self.udp = stack.enter_context(patch('client.socket.socket')).return_value
        self.tls = stack.enter_context(patch('client.gateway_tls_context'))
        self.wrap = self.tls.return_value.wrap_socket
        self.tun = stack.enter_context(patch('client.create_tun', return_value=(42, 'test0')))
        self.cmd = stack.enter_context(patch('client.subprocess.run', side_effect=lambda args, **_:
                                             subprocess.CompletedProcess(args, 0)))
        self.close_fd = stack.enter_context(patch('client.os.close'))
        stack.enter_context(patch('client._resolvconf_available', return_value=True))
        self.dns_route = stack.enter_context(patch('dns_backend.routed_to_tunnel', return_value=True))
        self.restore_dns = stack.enter_context(patch('client.restore_dns', wraps=client.restore_dns))
        self.forward = stack.enter_context(patch('client._forward',
                                                  side_effect=lambda *_: self.stop.set()))
        self.logs = stack.enter_context(self.assertLogs('openunivpn', level='INFO'))

    def run_vpn(self):
        return client.run_vpn(self.config, self.stop)

    def run_with_netcfg(self, **vip):
        self.ready = Mock()
        gateway = self.gateway['fast.invalid']
        with patch('client.authenticate', return_value=2), \
             patch('client.negotiate', return_value=dict(vip_ip='192.0.2.3', routes=[], dns=[]) | vip):
            client._run_session(self.config, self.tls.return_value, self.stop, gateway, self.ready)
        return self.ready

    def test_ip_failure_never_starts_forwarding(self):
        for failed in ('link', 'addr', 'route'):
            with self.subTest(failed=failed):
                self.close_fd.reset_mock()
                self.cmd.side_effect = lambda args, **_: subprocess.CompletedProcess(
                    args, 2 if failed in args else 0, stdout='[]', stderr='failed')
                with patch('client.authenticate', return_value=2) as auth, \
                     patch('client.negotiate', return_value=dict(vip_ip='192.0.2.3', routes=[], dns=[])):
                    self.assertEqual(self.run_vpn(), 78)
                auth.assert_called_once()
                self.forward.assert_not_called()
                self.close_fd.assert_called_once_with(42)

    def test_existing_route_only_accepted_when_equivalent(self):
        def run(args, **kwargs):
            if args[:3] == ['ip', 'route', 'add'] and args[3] == '10.11.0.0/16':
                return subprocess.CompletedProcess(args, 2, stderr='File exists')
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps([existing]))

        self.cmd.side_effect = run
        existing = dict(dst='10.11.0.0/16', dev='other0', scope='link')
        with self.assertRaises(client.SessionFailure):
            self.run_with_netcfg()
        self.forward.assert_not_called()
        existing['dev'] = 'test0'
        self.run_with_netcfg(routes=[('10.11.0.0', '255.255.0.0')]).assert_called_once()
        self.forward.assert_called_once()

    def run_dns_session(self):
        with patch('client.authenticate', return_value=2) as auth, \
             patch('client.negotiate', return_value=dict(vip_ip='192.0.2.3', routes=[], dns=['192.0.2.53'])), \
             patch('client.select_gateway', return_value=list(self.gateway.values())) as select:
            result = self.run_vpn()
        select.assert_called_once()
        auth.assert_called_once()
        self.stop.wait.assert_not_called()
        return result

    def test_resolvconf_restore_failure_blocks_retry(self):
        self.check_resolvconf_restore_failure(add_status=0)

    def test_resolvconf_partial_registration_restore_failure_blocks_retry(self):
        self.check_resolvconf_restore_failure(add_status=1)

    def check_resolvconf_restore_failure(self, add_status):
        actions = []
        def run(args, **kwargs):
            if args[0] == 'resolvconf':
                actions.append(args[1])
                return subprocess.CompletedProcess(args, add_status if args[1] == '-a' else 1,
                                                   stderr='failed')
            return subprocess.CompletedProcess(args, 0)
        self.cmd.side_effect = run
        self.close_fd.side_effect = lambda *_: actions.append('close TUN')
        self.forward.side_effect = client.SessionFailure('TLS', 'transient', retryable=True)
        self.stop.wait.return_value = True
        self.assertEqual(self.run_dns_session(), 78)
        self.assertEqual(actions, ['-a', '-d', 'close TUN'])
        self.assertIn('恢复', '\n'.join(self.logs.output))
        if add_status:
            self.forward.assert_not_called()

    def test_dnsmasq_restore_failure_preserves_terminal_kickout(self):
        self.check_dnsmasq_restore_failure(partial=False, retryable=False)

    def test_dnsmasq_restore_failure_blocks_retry(self):
        self.check_dnsmasq_restore_failure(partial=False, retryable=True)

    def test_dnsmasq_partial_activation_restore_failure_blocks_retry(self):
        self.check_dnsmasq_restore_failure(partial=True, retryable=True)

    def check_dnsmasq_restore_failure(self, *, partial, retryable):
        self.config['dns_backend'] = 'dnsmasq'
        actions = []
        def reload():
            actions.append('offline reload' if active.is_symlink() else 'online reload')
            if active.is_symlink() or partial:
                raise subprocess.CalledProcessError(1, 'reload')
        self.close_fd.side_effect = lambda fd: actions.append('close TUN') if fd == 42 else REAL_CLOSE(fd)
        self.forward.side_effect = client.SessionFailure('TLS', 'transient' if retryable else 'KICKOUT',
                                                         retryable=retryable)
        self.stop.wait.return_value = True
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / 'active'
            offline = Path(directory) / 'offline'
            offline.write_text('server=192.0.2.1\n')
            active.symlink_to(offline)
            with patch.multiple(client.dns_backend, ACTIVE=active, OFFLINE=offline, reload_dnsmasq=reload):
                self.assertEqual(self.run_dns_session(), 78)
                self.assertEqual(active.readlink(), offline)
        self.assertEqual(actions, ['online reload', 'offline reload', 'close TUN'])
        logs = '\n'.join(self.logs.output)
        self.assertIn('恢复', logs)
        if partial:
            self.forward.assert_not_called()
            self.assertIn('切换', logs)
        elif not retryable:
            self.assertIn('KICKOUT', logs)

    def test_no_dns_registration_does_not_try_to_restore(self):
        self.dns_route.return_value = False
        self.run_with_netcfg(dns=['192.0.2.53']).assert_called_once()
        self.restore_dns.assert_not_called()

    def test_transient_auth_connect_failure_uses_next_ranked_gateway(self):
        raw = Mock()
        auth, cn = Mock(), Mock()
        auth.recv.side_effect = [b'\xf0\xf0', b'\xf0\xf0\x00\x00\x00\x02']
        acl = client.cnem_frame(client.CMD_ACL)
        netcfg = bytes(160) + socket.inet_aton('192.0.2.53')
        cn.recv.side_effect = [acl[:7], acl[7:], client.cnem_frame(client.CMD_REQVIP, netcfg),
                               socket.timeout(), socket.timeout()]
        self.connect.side_effect = [OSError(errno.ENETUNREACH, 'offline'), raw, raw]
        self.wrap.side_effect = [auth, cn]
        self.assertEqual(self.run_vpn(), 0)
        self.assertEqual([call.args[0] for call in self.connect.call_args_list],
                         [('192.0.2.1', 443), ('192.0.2.2', 443), ('192.0.2.2', 443)])
        self.assertEqual(self.wrap.call_args.kwargs['server_hostname'], 'slow.invalid')
        auth.close.assert_called_once()
        cn.close.assert_called_once()
        self.udp.close.assert_called_once()
        self.close_fd.assert_called_once_with(42)
        self.restore_dns.assert_called_once()
        self.forward.assert_called_once()

    def test_bytewise_acl_and_reqvip_complete_within_deadlines(self):
        auth, cn = Mock(), Mock()
        self.wrap.side_effect = [auth, cn]
        auth.recv.return_value = b'\xf0' * 4 + client.be32(2)
        # ACL responses use a little-endian payload size.
        acl = client.cnem_frame(client.CMD_ACL)[:14] + b'\x14\x00' + bytes(20)
        reply = client.cnem_frame(client.CMD_REQVIP, bytes(30))
        cn.recv.side_effect = [bytes([byte]) for byte in acl + reply] + [socket.timeout()] * 2
        self.stop.wait.return_value = True
        self.stop.wait.side_effect = [False, False, True]
        self.assertEqual(self.run_vpn(), 0)
        self.forward.assert_called_once()

    def test_auth_drip_feed_cannot_extend_response_deadline(self):
        now = 0
        self.config['gateways'] = [('fast.invalid', 443)]
        self.stop.wait.return_value = True
        auth = self.wrap.return_value
        def recv(_):
            nonlocal now
            now += 3
            return b'\xf0'
        auth.recv.side_effect = recv
        with patch('client.time.monotonic', side_effect=lambda: now):
            self.assertEqual(self.run_vpn(), 0)
        self.stop.wait.assert_called_once()  # Backoff, not terminal.
        self.assertEqual(auth.recv.call_count, 2)
        self.assertEqual([call.args[0] for call in auth.settimeout.call_args_list], [5, 2])

    def test_required_handshake_drip_feed_times_out_as_transient(self):
        now = 0
        self.config['gateways'] = [('fast.invalid', 443)]
        self.stop.wait.return_value = True
        sock = Mock()
        acl = iter(bytes([byte]) for byte in client.cnem_frame(client.CMD_ACL))
        def recv(_):
            nonlocal now
            now += 7
            return next(acl)
        sock.recv.side_effect = recv
        self.wrap.return_value = sock
        with patch('client.time.monotonic', side_effect=lambda: now), patch('client.authenticate', return_value=2):
            self.assertEqual(self.run_vpn(), 0)
        self.stop.wait.assert_called_once()
        self.assertEqual(sock.recv.call_count, 5)
        self.assertEqual(sock.settimeout.call_args.args, (2,))

    def test_required_handshake_complete_unexpected_frame_is_terminal(self):
        sock = self.wrap.return_value
        sock.recv.return_value = client.cnem_frame(client.CMD_KEEPALIVE)
        with patch('client.authenticate', return_value=2) as auth:
            self.assertEqual(self.run_vpn(), 78)
        auth.assert_called_once()
        self.stop.wait.assert_not_called()
        sock.recv.assert_called_once()

    def test_reqvip_ignored_frames_do_not_extend_deadline(self):
        now = 0
        self.config['gateways'] = [('fast.invalid', 443)]
        self.stop.wait.return_value = True
        sock = self.wrap.return_value
        frames = iter([client.cnem_frame(client.CMD_ACL)] + [client.KEEPALIVE_FRAME] * 5)
        def recv(_):
            nonlocal now
            now += 4
            return next(frames)
        sock.recv.side_effect = recv
        with patch('client.time.monotonic', side_effect=lambda: now), patch('client.authenticate', return_value=2):
            self.assertEqual(self.run_vpn(), 0)
        self.stop.wait.assert_called_once()
        self.assertEqual(sock.recv.call_count, 5)
        self.assertEqual(sock.settimeout.call_args.args, (3,))

    def test_required_handshake_bounds_unparseable_buffer(self):
        sock = self.wrap.return_value
        # Unknown command with ambiguous length and no following frame boundary.
        header = client.cnem_frame(0x9999)[:14] + b'\xff\xfe'
        sock.recv.side_effect = [header.ljust(65536, b'\0'), bytes(31)]
        with patch('client.authenticate', return_value=2) as auth:
            self.assertEqual(self.run_vpn(), 78)
        auth.assert_called_once()
        self.stop.wait.assert_not_called()
        self.assertEqual([call.args[0] for call in sock.recv.call_args_list], [65536, 31])
        self.assertIn('缓冲上限', '\n'.join(self.logs.output))

    def test_ready_session_resets_backoff_after_outage(self):
        self.config['gateways'] = [('fast.invalid', 443)]
        auth, cn = Mock(), Mock()
        self.wrap.side_effect = [auth, cn]
        auth.recv.return_value = b'\xf0' * 4 + b'\x00\x00\x00\x02'
        cn.recv.side_effect = [client.cnem_frame(client.CMD_ACL),
                               client.cnem_frame(client.CMD_REQVIP, bytes(30)),
                               socket.timeout(), socket.timeout()]
        self.forward.side_effect = client.SessionFailure('转发', '关闭', retryable=True)
        self.stop.wait.side_effect = [False, False, False, False, True]
        with patch('client.probe_gateway', side_effect=[None, None, self.gateway['fast.invalid']]), \
             patch('random.uniform', return_value=1):
            self.assertEqual(self.run_vpn(), 0)
        self.assertEqual([c.args[0] for c in self.stop.wait.call_args_list], [3, 6, 1, 2, 3])

    def test_explicit_auth_rejection_stops_without_leaking_response(self):
        auth = self.wrap.return_value
        auth.recv.return_value = b'\xf0' * 4 + b'\xff\xff\xff\xfbNOT-FOR-LOGS'
        self.assertEqual(self.run_vpn(), 78)
        self.connect.assert_called_once()
        auth.close.assert_called_once()
        self.stop.wait.assert_not_called()
        self.assertIn('认证拒绝', '\n'.join(self.logs.output))
        self.assertNotIn('NOT-FOR-LOGS', '\n'.join(self.logs.output))

    def test_default_cert_failure_stops_and_closes_raw_socket(self):
        self.wrap.side_effect = ssl.SSLCertVerificationError('untrusted')
        self.assertEqual(self.run_vpn(), 78)
        self.tls.assert_called_once_with(self.config)
        self.connect.assert_called_once()
        self.connect.return_value.close.assert_called_once()
        self.stop.wait.assert_not_called()
        self.assertIn('证书校验', '\n'.join(self.logs.output))

    def test_certificate_failure_survives_raw_close_epipe(self):
        self.wrap.side_effect = ssl.SSLCertVerificationError('untrusted')
        self.connect.return_value.close.side_effect = BrokenPipeError(errno.EPIPE, 'closed')
        self.stop.wait.return_value = True
        self.assertEqual(self.run_vpn(), 78)
        self.connect.assert_called_once()
        self.connect.return_value.close.assert_called_once()
        self.stop.wait.assert_not_called()
        self.assertIn('证书校验', '\n'.join(self.logs.output))

    def test_invalid_ca_config_stops_even_when_network_is_down(self):
        self.tls.side_effect = FileNotFoundError('missing CA file')
        self.stop.wait.return_value = True
        with patch('client.probe_gateway', return_value=None) as probe:
            self.assertEqual(self.run_vpn(), 78)
        probe.assert_not_called()
        self.stop.wait.assert_not_called()

    def test_unknown_auth_response_stops_but_is_not_reported_as_rejection(self):
        self.wrap.return_value.recv.return_value = b'HTTP/1.1 502 NOT-FOR-LOGS'
        self.assertEqual(self.run_vpn(), 78)
        self.connect.assert_called_once()
        self.stop.wait.assert_not_called()
        logs = '\n'.join(self.logs.output)
        self.assertIn('协议', logs)
        self.assertNotIn('认证拒绝', logs)
        self.assertNotIn('NOT-FOR-LOGS', logs)

    def test_kickout_in_reqvip_closes_session_and_stops_without_reauth(self):
        auth, cn = Mock(), Mock()
        self.wrap.side_effect = [auth, cn]
        auth.recv.return_value = b'\xf0' * 4 + b'\x00\x00\x00\x02'
        cn.recv.side_effect = [client.cnem_frame(client.CMD_ACL),
                               client.cnem_frame(client.CMD_KEEPALIVE) + client.cnem_frame(8)]
        self.assertEqual(self.run_vpn(), 78)
        self.assertEqual(self.connect.call_count, 2)
        cn.close.assert_called_once()
        self.udp.close.assert_called_once()
        self.tun.assert_not_called()
        self.restore_dns.assert_not_called()
        self.stop.wait.assert_not_called()
        self.assertIn('KICKOUT', '\n'.join(self.logs.output))


    def test_coalesced_ack_data_and_kickout_stop_without_reauth(self):
        auth, cn = Mock(), Mock()
        self.wrap.side_effect = [auth, cn, OSError(errno.EPERM, 'unexpected retry')]
        auth.recv.return_value = b'\xf0' * 4 + client.be32(2)
        packet = b'\x45\x00\x00\x14' + bytes(16)
        ack = client.cnem_frame(client.CMD_DATA_CONNECT, client.be32(4))
        cn.recv.side_effect = [client.cnem_frame(client.CMD_ACL),
                               client.cnem_frame(client.CMD_REQVIP, bytes(30)),
                               socket.timeout(),
                               ack + client.cnem_frame(client.CMD_DATA, packet)
                               + client.cnem_frame(client.CMD_KICKOUT)]
        cn.sendall.side_effect = [None] * 4 + [BrokenPipeError(errno.EPIPE, 'closed')]
        self.assertEqual(self.run_vpn(), 78)
        self.assertEqual(self.connect.call_count, 2)
        self.tun.assert_not_called()
        self.assertIn('KICKOUT', '\n'.join(self.logs.output))

    def test_optional_ack_does_not_consume_early_data(self):
        auth, cn = Mock(), Mock()
        self.wrap.side_effect = [auth, cn]
        auth.recv.return_value = b'\xf0' * 4 + client.be32(2)
        packet = b'\x45\x00\x00\x24' + client.cnem_frame(client.CMD_KICKOUT) + bytes(16)
        cn.recv.side_effect = [client.cnem_frame(client.CMD_ACL),
                               client.cnem_frame(client.CMD_REQVIP, bytes(30)),
                               client.cnem_frame(client.CMD_DATA, packet), socket.timeout()]
        self.assertEqual(self.run_vpn(), 0)
        stream = self.forward.call_args.args[1]
        self.assertEqual(stream.pop('test'), (client.CMD_DATA, packet))


class UnitTests(unittest.TestCase):
    def test_sigterm_during_stop_wait_does_not_deadlock(self):
        # Run in a child so a regression cannot deadlock the test runner.
        script = '''
import signal
from unittest.mock import patch
import client

def interrupt(*args):
    signal.raise_signal(signal.SIGTERM)

def run(config, stop):
    # Event.wait enters Condition.wait with its lock held. For a lock-free
    # wait, inject the same real signal at the sleep boundary instead.
    with patch('threading.Condition.wait', side_effect=interrupt), \\
         patch('client.time.sleep', side_effect=interrupt):
        assert stop.wait(60)
        assert stop.is_set()
    return 0

with patch('client.os.geteuid', return_value=0), \\
     patch('client.load_config', return_value=dict(gateways=[('one.invalid', 443)],
                                                  username='test', password='test')), \\
     patch('client.run_vpn', side_effect=run):
    assert client.main() == 0
'''
        result = subprocess.run([sys.executable, '-c', script], capture_output=True,
                                text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unit_does_not_restart_terminal_exit(self):
        unit = Path(client.__file__).with_name('openunivpn.service').read_text()
        self.assertIn('RestartPreventExitStatus=78', unit.splitlines())

    @patch('client.os.geteuid', return_value=0)
    @patch('client.signal.signal')
    @patch('client.run_vpn')
    def test_invalid_gateway_config_stops_before_probing(self, run, signal, uid):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.conf'
            for gateway in (':443', 'vpn.invalid:65536', 'vpn.invalid:abc', 'vpn.invalid:1:2'):
                with self.subTest(gateway=gateway):
                    path.write_text('[auth]\nusername=test\npassword=test\n[gateway]\nlist=' + gateway)
                    with patch('client.load_config', side_effect=lambda: config._parse_config(path)):
                        self.assertEqual(client.main(), 78)
        run.assert_not_called()
