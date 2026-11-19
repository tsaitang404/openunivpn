import os
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dns_backend
import client


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


class GatewayTrustTest(unittest.TestCase):
    def test_exclusive_backend_verifies_tls_peer(self):
        ctx = client.gateway_tls_context({'dns_backend': 'dnsmasq'})
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    @patch('client.restore_dns')
    @patch('client.run_vpn', side_effect=RuntimeError('session failed'))
    @patch('client.signal.signal')
    @patch('client.os.geteuid', return_value=0)
    @patch('client.load_config', return_value={
        'dns_backend': 'dnsmasq', 'gateways': [('vpn.example', 443)],
        'username': 'test', 'password': 'test',
    })
    def test_standalone_exception_restores_dns(self, load, geteuid, signal, run, restore):
        with self.assertRaises(RuntimeError):
            client.main()
        restore.assert_called_once_with('dnsmasq')
