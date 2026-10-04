import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from common import dos_text
from mz import parse


def executable(image=b"\x90\xcb", relocs=()):
    header = bytearray(32 + len(relocs) * 4)
    header.extend(bytes((-len(header)) % 16))
    size = len(header) + len(image)
    struct.pack_into("<14H", header, 0, 0x5a4d, size % 512, (size + 511) // 512,
                     len(relocs), len(header) // 16, 0, 0xffff, 0, 0, 0, 0, 0, 28, 0)
    for i, pair in enumerate(relocs):
        struct.pack_into("<HH", header, 28 + i * 4, *pair)
    return bytes(header) + image


class PrimitiveTests(unittest.TestCase):
    def test_mz_tail_not_image(self):
        data = executable() + b"tail"
        result = parse(data)
        self.assertEqual(result["trailing_size"], 4)
        self.assertEqual(result["image"]["size"], 2)

    def test_mz_relocation_order(self):
        result = parse(executable(bytes(8), [(4, 0), (0, 0), (4, 0)]))
        self.assertEqual([r["linear"] for r in result["relocations"]], [4, 0, 4])

    def test_malformed_mz_refused(self):
        for data in [b"MZ", executable()[:-1], executable(b"x", [(0, 0)])]:
            with self.assertRaises(ValueError):
                parse(data)

    def test_dos_text(self):
        self.assertEqual(dos_text("a\nb\r\nc\r"), b"a\r\nb\r\nc\r\n")

    def test_explicit_overlay_coordinate_scope(self):
        data = bytearray(executable(bytes(4), [(0, 0)]))
        struct.pack_into("<HH", data, 28, 2, 0xc17)
        with self.assertRaises(ValueError):
            parse(bytes(data))
        result = parse(bytes(data), relocation_scope="shared-root")
        self.assertEqual(result["relocations"][0]["linear"], 0xc172)
        self.assertIsNone(result["relocations"][0]["word"])


if __name__ == "__main__":
    unittest.main()
