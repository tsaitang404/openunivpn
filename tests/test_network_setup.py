"""Offline TUN lifecycle tests; no real sockets, TUN or ip commands."""
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

import client
import config


class NetworkSetupTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.vip: dict = dict(vip_ip='198.51.100.9', mask='255.255.255.224', routes=[], dns=[])
        self.config: dict = dict(tun_name='test0')
        self.gateway = dict(ip='192.0.2.1', host='vpn.invalid', port=443, latency=1)
        self.actions = []
        self.tun = stack.enter_context(patch.object(client, 'create_tun', return_value=(42, 'test0')))
        stack.enter_context(patch.object(client.os, 'close', side_effect=lambda fd: self.actions.append(('close', fd))))
        stack.enter_context(patch.object(client, 'authenticate', return_value=2))
        stack.enter_context(patch.object(client, 'open_gateway_tls', return_value=Mock()))
        stack.enter_context(patch.object(client, 'negotiate', return_value=self.vip))
        self.cmd = stack.enter_context(patch.object(client.subprocess, 'run', side_effect=self.run_cmd))
        self.forward = stack.enter_context(patch.object(client, '_forward'))
        self.dns = stack.enter_context(patch.object(client, 'setup_dns'))
        self.ready = Mock()

    def run_cmd(self, args, **kwargs):
        self.actions.append(tuple(args))
        return subprocess.CompletedProcess(args, 0, stdout='[]')

    def connect(self):
        client._run_session(self.config, None, threading.Event(), self.gateway, self.ready)

    def writes(self, operation):
        return [args for args in self.actions if args[:3] == ('ip', *operation)]

    def test_uses_negotiated_non_24_mask(self):
        self.connect()
        self.assertIn('198.51.100.9/27', self.writes(('addr', 'add'))[0])

    def test_invalid_negotiated_mask_never_opens_tun(self):
        for mask in ('255.0.255.0', '0.0.0.31', '0.0.0.0', '27', None):
            with self.subTest(mask=mask):
                self.vip['mask'] = mask
                with self.assertRaises(client.SessionFailure):
                    self.connect()
                self.tun.assert_not_called()
                self.dns.assert_not_called()
                self.ready.assert_not_called()

    def test_no_unsolicited_site_routes(self):
        self.connect()
        self.assertTrue(all('198.51.100.0/27' in args for args in self.writes(('route', 'add'))))

    def test_explicit_extra_route_is_added_once(self):
        self.config['extra_routes'] = ['203.0.113.0/24', '203.0.113.0/24', '203.0.114.0/24']
        self.vip['routes'] = [('203.0.113.0', '255.255.255.0')]
        self.connect()
        routes = self.writes(('route', 'add'))
        self.assertEqual(sum('203.0.113.0/24' in args for args in routes), 1)
        self.assertEqual(sum('203.0.114.0/24' in args for args in routes), 1)

    def test_rejects_entire_plan_before_creating_tun(self):
        for overrides, extras in (
            ({'routes': [('203.0.113.9', '255.255.255.0'), ('192.0.2.0', '255.255.255.0')]}, []),
            ({'routes': [('0.0.0.0', '0.0.0.0')]}, []),
            ({'routes': [('203.0.113.0', '0.0.0.255')]}, []),
            ({'vip_ip': '192.0.2.9'}, []),
            ({}, ['192.0.2.1/32']),
        ):
            with self.subTest(overrides=overrides, extras=extras):
                with patch.dict(self.vip, overrides):
                    self.config['extra_routes'] = extras
                    with self.assertRaises(client.SessionFailure):
                        self.connect()
                self.tun.assert_not_called()
                self.assertEqual(self.actions, [])

    def test_route_parsing_preserves_declared_default_for_policy_rejection(self):
        payload = bytearray(client.NETCFG_RT_START + client.NETCFG_RT_STRIDE)
        payload[:8] = socket.inet_aton(self.vip['vip_ip']) + socket.inet_aton(self.vip['mask'])
        payload[client.NETCFG_RT_COUNT_OFF:client.NETCFG_RT_START] = b'\0\1'
        parsed = client.parse_netcfg(payload)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed['routes'], [('0.0.0.0', '0.0.0.0')])

    def test_truncated_route_list_does_not_become_partial_plan(self):
        payload = bytearray(client.NETCFG_RT_START + 8)
        payload[client.NETCFG_RT_COUNT_OFF:client.NETCFG_RT_START] = b'\0\2'
        self.assertIsNone(client.parse_netcfg(payload))

    def test_last_route_must_include_its_opaque_four_bytes(self):
        payload = bytearray(client.NETCFG_RT_START)
        payload[:8] = socket.inet_aton(self.vip['vip_ip']) + socket.inet_aton(self.vip['mask'])
        payload[client.NETCFG_RT_COUNT_OFF:client.NETCFG_RT_START] = b'\0\2'
        payload.extend(bytes.fromhex('cb007100 ffffff00 01020304 c6336409 ffffffff aabbccdd'))
        for missing in range(1, 5):
            with self.subTest(missing=missing):
                self.assertIsNone(client.parse_netcfg(payload[:-missing]))
        parsed = client.parse_netcfg(payload)
        assert parsed is not None
        self.assertEqual(parsed['routes'],
                         [('203.0.113.0', '255.255.255.0'), ('198.51.100.9', '255.255.255.255')])

    def test_existing_prefix_collision_is_rejected_before_any_write(self):
        def run(args, **kwargs):
            if 'exact' in args and args[-1] == conflict:
                self.actions.append(tuple(args))
                route = dict(dst=conflict, dev='foreign0', metric=100)
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps([route]))
            return self.run_cmd(args, **kwargs)

        self.cmd.side_effect = run
        self.config['extra_routes'] = ['203.0.113.0/24']
        for conflict in ('198.51.100.9/32', '198.51.100.0/27', '203.0.113.0/24',
                         '198.51.100.31/32', '198.51.100.0/32'):
            with self.subTest(prefix=conflict):
                with self.assertRaises(client.SessionFailure):
                    self.connect()
                self.tun.assert_not_called()
                self.dns.assert_not_called()
                self.ready.assert_not_called()
                self.assertTrue(all('show' in args for args in self.actions))

    def test_point_to_point_prefix_does_not_reserve_other_endpoint_as_broadcast(self):
        self.vip['mask'] = '255.255.255.254'
        self.connect()
        self.assertFalse(any('exact' in args and args[-1] == '198.51.100.8/32'
                             for args in self.actions))
        self.config['extra_routes'] = ['198.51.100.8/32']
        self.connect()
        self.assertIn('198.51.100.8/32', self.writes(('route', 'add'))[-1])

    def test_explicit_route_conflicting_with_implicit_broadcast_is_rejected_before_tun(self):
        for routes, extras in (([('198.51.100.31', '255.255.255.255')], []),
                              ([], ['198.51.100.31/32']), ([], ['198.51.100.0/32'])):
            with self.subTest(routes=routes, extras=extras):
                self.vip['routes'] = routes
                self.config['extra_routes'] = extras
                with self.assertRaisesRegex(client.SessionFailure, '广播'):
                    self.connect()
                self.tun.assert_not_called()
                self.dns.assert_not_called()
                self.ready.assert_not_called()
                self.forward.assert_not_called()
                self.assertEqual(self.actions, [])

    def test_late_route_error_closes_only_owned_tun_without_touching_dns(self):
        def run(args, **kwargs):
            result = self.run_cmd(args, **kwargs)
            if args[:4] == ['ip', 'route', 'add', '203.0.113.0/24']:
                result.returncode = 2
            if 'exact' in args and args[-1] == '203.0.113.0/24' and self.writes(('route', 'add')):
                result.stdout = '[{"dst":"203.0.113.0/24","dev":"test0","scope":"link"}]'
            return result

        self.cmd.side_effect = run
        self.config['extra_routes'] = ['203.0.113.0/24']
        with self.assertRaises(client.SessionFailure):
            self.connect()
        self.assertEqual([args[3] for args in self.writes(('route', 'add'))],
                         ['198.51.100.0/27', '203.0.113.0/24'])
        self.assertTrue(self.writes(('addr', 'add')))
        self.assertEqual(self.actions[-1], ('close', 42))
        self.assertFalse(any(set(args) & {'replace', 'del', 'flush'} for args in self.actions))
        self.dns.assert_not_called()
        self.ready.assert_not_called()
        self.forward.assert_not_called()


class TunOwnershipTests(unittest.TestCase):
    @patch('client.os.close')
    @patch('client.os.open', return_value=42)
    def test_existing_tun_requires_kernel_exclusive_create(self, open_fd, close_fd):
        def ioctl(fd, request, ifreq):
            # Model a persistent TUN which would allow attachment without TUN_EXCL.
            flags = int.from_bytes(ifreq[16:18], byteorder=sys.byteorder)
            if flags & 0x8000:
                raise OSError('already exists')

        with patch('client.fcntl.ioctl', side_effect=ioctl), self.assertRaises(OSError):
            client.create_tun('test0')
        close_fd.assert_called_once_with(42)

    @patch('client.fcntl.ioctl')
    @patch('client.os.open', return_value=42)
    def test_tun_name_never_uses_kernel_template_or_truncation(self, open_fd, ioctl):
        for name in ('', 'test%d', 'sixteen_chars_ok', 'test/0', '测试接口'):
            with self.subTest(name=name), self.assertRaises(client.SessionFailure):
                client.create_tun(name)
        open_fd.assert_not_called()
        ioctl.assert_not_called()

    def test_unit_does_not_delete_tun_by_name(self):
        contents = Path(client.__file__).with_name('openunivpn.service').read_text()
        self.assertNotIn('ip link del', contents)
        self.assertIn('ExecStopPost=-/usr/bin/python3 /opt/openunivpn/dns_backend.py', contents)


class RouteConfigTests(unittest.TestCase):
    def parse(self, extra_routes=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.conf'
            path.write_text('' if extra_routes is None else f'[tun]\nextra_routes = {extra_routes}\n')
            return config._parse_config(path)

    def test_extra_routes_default_to_empty(self):
        self.assertEqual(self.parse()['extra_routes'], [])

    def test_extra_routes_accept_explicit_ipv4_cidrs(self):
        self.assertEqual(self.parse('198.51.100.0/24, 203.0.113.9/32')['extra_routes'],
                         ['198.51.100.0/24', '203.0.113.9/32'])

    def test_extra_routes_reject_invalid_or_default_routes(self):
        for route in ('0.0.0.0/0', '::/1', '203.0.113.4', '203.0.113.4/24', '203.0.113.0/0.0.0.255'):
            with self.subTest(route=route), self.assertRaisesRegex(ValueError, 'extra_routes'):
                self.parse(route)

    def test_gateway_list_uses_host_and_optional_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.conf'
            path.write_text('[gateway]\nlist = vpn.example.com, backup.example.com:8443\n')
            parsed = config._parse_config(path)
        self.assertEqual(parsed['gateways'], [('vpn.example.com', 443), ('backup.example.com', 8443)])

    def test_gateway_list_rejects_non_numeric_port(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.conf'
            path.write_text('[gateway]\nlist = vpn.example.com:1.2.3.4\n')
            with self.assertRaisesRegex(ValueError, 'numeric port'):
                config._parse_config(path)

    def test_mac_address_is_normalized_or_derived(self):
        self.assertEqual(config.parse_mac_address('aa:bb:cc:dd:ee:ff'), 'AA-BB-CC-DD-EE-FF')
        with patch.object(config.uuid, 'getnode', return_value=0x010203040506):
            self.assertEqual(config.parse_mac_address(''), '01-02-03-04-05-06')

    def test_mac_address_rejects_invalid_value(self):
        with self.assertRaisesRegex(ValueError, 'mac_address'):
            config.parse_mac_address('not-a-mac')
