"""Exercise the actual forwarding workers without opening TLS or a privileged TUN."""
import socket
import threading
import unittest
from unittest.mock import Mock, patch

import client


class ReceiverTests(unittest.TestCase):
    def forward(self, sock, stop):
        # No data from the TUN; the receiver determines the session outcome.
        with patch('client.select.select', return_value=([], [], [])), \
             patch('client.os.write') as write:
            try:
                client._forward(sock, client.CnemStream(sock), 42, 1, stop)
            finally:
                write.assert_not_called()
                sock.shutdown.assert_called_once_with(socket.SHUT_RDWR)

    def test_idle_and_unanswered_traffic_do_not_reconnect(self):
        sock = Mock()
        stop = threading.Event()
        events = iter([socket.timeout(), client.cnem_frame(5)] * 10)

        def recv(_):
            result = next(events, None)
            if result is None:
                stop.set()
                return b''
            if isinstance(result, Exception):
                raise result
            return result

        sock.recv.side_effect = recv
        self.forward(sock, stop)
        self.assertEqual(sock.recv.call_count, 21)

    def test_established_transport_eof_or_reset_is_retryable(self):
        for result in (b'', ConnectionResetError(104, 'reset')):
            with self.subTest(result=result):
                sock = Mock()
                sock.recv.side_effect = [result]
                with self.assertRaises(client.SessionFailure) as failure:
                    self.forward(sock, threading.Event())
                self.assertTrue(failure.exception.retryable)

    def test_established_kickout_is_terminal(self):
        sock = Mock()
        kickout = client.cnem_frame(client.CMD_KICKOUT)
        sock.recv.side_effect = [kickout[:13], kickout[13:]]
        with self.assertRaisesRegex(client.SessionFailure, 'KICKOUT') as failure:
            self.forward(sock, threading.Event())
        self.assertFalse(failure.exception.retryable)

    def test_established_malformed_frame_is_terminal(self):
        sock = Mock()
        sock.recv.side_effect = [b'bad!' + bytes(12)]
        with self.assertRaisesRegex(client.SessionFailure, 'CNEM') as failure:
            self.forward(sock, threading.Event())
        self.assertFalse(failure.exception.retryable)
