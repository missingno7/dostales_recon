import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from resources import parse, pack
from compare import bytes_diff, sequence_diff


class ResourceTests(unittest.TestCase):
    def test_real_index_reconstruction(self):
        members = [struct.pack("<IH", n, k) + bytes(10) + bytes(range(n)) for n, k in [(2, 1), (3, 4)]]
        original = pack(members)
        report, parsed = parse(original)
        self.assertEqual(parsed, members)
        self.assertEqual(pack(parsed), original)
        self.assertEqual(report["entries"][1]["start"], 28)
        self.assertNotEqual(pack([members[0], members[1] + b"x"]), original)

    def test_bad_offsets_payloads(self):
        valid = pack([struct.pack("<I", 0) + bytes(12)])
        for bad in [b"", b"\0\0", valid[:-1], b"\1\0\5\0\0\0" + valid[6:]]:
            with self.assertRaises(ValueError):
                parse(bad)

    def test_diff_refuses_size_and_order(self):
        self.assertFalse(bytes_diff(b"ab", b"abc")["exact"])
        self.assertEqual(bytes_diff(b"ab", b"ac")["first_difference"], 1)
        self.assertFalse(sequence_diff([1, 2], [2, 1])["exact"])
