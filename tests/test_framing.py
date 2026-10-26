import struct
import unittest

from client import (CMD_ACL, CMD_DATA, CMD_DATA_CONNECT, CMD_REQVIP,
                    MAGIC_B, cnem_frame, parse_cnem)


def packet(size, version):
    p = bytearray(size)
    p[0] = 0x45 if version == 4 else 0x60
    offset = 2 if version == 4 else 4
    p[offset:offset + 2] = struct.pack('>H', size if version == 4 else size - 40)
    return bytes(p)


def frame(payload, endian, cmd=CMD_DATA):
    f = cnem_frame(cmd, payload)
    return f[:14] + struct.pack(endian + 'H', len(payload)) + payload


class FramingTests(unittest.TestCase):
    def test_every_split_and_coalescing(self):
        tail = cnem_frame(5)
        for version in (4, 6):
            for size in (64, 256, 1024, 1500):
                for endian in ('<', '>'):
                    payload = packet(size, version)
                    f = frame(payload, endian)
                    for split in range(len(f)):
                        with self.subTest(version=version, size=size, endian=endian, split=split):
                            self.assertEqual(parse_cnem(f[:split]), (None, None, f[:split]))
                            self.assertEqual(parse_cnem(f[:split] + f[split:] + tail),
                                             (CMD_DATA, payload, tail))

    def test_boundaries(self):
        for version, size in ((4, 20), (6, 40), (4, 65535), (6, 65535)):
            for endian in ('<', '>'):
                p = packet(size, version)
                self.assertEqual(parse_cnem(frame(p, endian)), (CMD_DATA, p, b''))

    def test_invalid(self):
        cases = [cnem_frame(CMD_DATA, b'\x70' + bytes(39)),
                 frame(b'\x44\x00\x00\x14' + bytes(16), '>'),
                 frame(b'\x46\x00\x00\x14' + bytes(16), '>'),
                 frame(packet(64, 4), '>')[:14] + b'\x00\x20' + packet(64, 4),
                 b'xxxx' + frame(packet(64, 4), '>')[4:]]
        for f in cases:
            with self.assertRaises(ValueError):
                parse_cnem(f)

    def test_control_fragmentation(self):
        for cmd, endian, size in ((CMD_ACL, '<', 20), (CMD_REQVIP, '>', 956),
                                  (CMD_DATA_CONNECT, '<', 4), (CMD_DATA_CONNECT, '>', 4)):
            p = bytes(size)
            f = frame(p, endian, cmd)
            for split in range(len(f)):
                self.assertEqual(parse_cnem(f[:split]), (None, None, f[:split]))
            self.assertEqual(parse_cnem(f), (cmd, p, b''))

    def test_unknown_control_does_not_guess_from_recv_size(self):
        p = bytes(1024)
        for endian in ('<', '>'):
            f = frame(p, endian, 0x77)
            for split in (20, 64, len(f)):
                self.assertEqual(parse_cnem(f[:split]), (None, None, f[:split]))
            tail = cnem_frame(5)
            self.assertEqual(parse_cnem(f + tail), (0x77, p, tail))


if __name__ == '__main__':
    unittest.main()
