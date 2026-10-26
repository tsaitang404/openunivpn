"""Exercise the actual receiver loop without opening TLS or a privileged TUN."""
import ast
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock

from client import cnem_frame
import client


class ReceiverTests(unittest.TestCase):
    def receiver(self, sock):
        tree = ast.parse(Path(client.__file__).read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == 'tls_to_tun')
        env = dict(vars(client), sock=sock, running=True, RECV_TIMEOUT=5,
                   reconnect=[False], tun_fd=42, print=Mock(), os=Mock())
        exec(compile(ast.Module(body=[fn], type_ignores=[]), '<receiver>', 'exec'), env)
        return env

    def test_idle_and_unanswered_traffic_do_not_reconnect(self):
        sock = Mock()
        env = self.receiver(sock)
        count = 0

        def recv(_):
            nonlocal count
            count += 1
            if count == 20:
                env['running'] = False
            if count % 2:
                raise socket.timeout()
            return cnem_frame(5)

        sock.recv.side_effect = recv
        env['tls_to_tun']()
        self.assertFalse(env['reconnect'][0])
        env['os'].write.assert_not_called()

    def test_transport_close_error_and_kickout_reconnect(self):
        for result in (b'', OSError('closed'), cnem_frame(8)):
            sock = Mock()
            sock.recv.side_effect = [result]
            env = self.receiver(sock)
            env['tls_to_tun']()
            self.assertTrue(env['reconnect'][0])
