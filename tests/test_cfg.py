"""Focused control-flow regression checks for the conservative DOS decoder."""
import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from cfg import run


class RecursiveCfgTests(unittest.TestCase):
    def test_ordinary_fallthrough_wraps_ip(self):
        image = bytearray(0x10000)
        image[0] = 0xC3
        image[0xFFFF] = 0x90
        report = run(bytes(image), [("entry", 0xFFFF, "test")], [])
        self.assertEqual({0, 0xFFFF}, {i["offset"] for i in report["instructions"]})

    def test_instruction_fetch_does_not_decode_past_cs_window(self):
        image = bytearray(0x10002)
        image[0xFFFF:] = bytes.fromhex("b83412")
        report = run(bytes(image), [("entry", 0xFFFF, "test")], [])
        self.assertEqual([], report["instructions"])
        self.assertEqual("invalid_or_truncated_instruction", report["functions"][0]["stops"][0]["reason"])

    def test_near_call_uses_cs_logical_ip_and_keeps_fallthrough(self):
        image = bytearray(0x100)
        base = 0x20
        image[base:base + 3] = bytes.fromhex("e80100")  # call IP+4
        image[base + 3] = 0xC3  # caller return
        image[base + 4] = 0xC3  # callee return
        report = run(bytes(image), [("entry", base, "test")], [], base)
        entry = report["functions"][0]
        self.assertIn({"from": base, "to": base + 4, "kind": "near_direct"}, entry["calls"])
        self.assertIn({"kind": "fallthrough", "from": base, "to": base + 3}, entry["edges"])
        self.assertEqual({base, base + 3, base + 4},
                         {i["offset"] for i in report["instructions"]})

    def test_near_relative_flow_wraps_ip_within_64k_segment(self):
        image = bytearray(0x10000)
        image[0:1] = b"\xC3"
        image[0xFFFD:0x10000] = bytes.fromhex("e80000")  # next IP wraps to 0
        report = run(bytes(image), [("entry", 0xFFFD, "test")], [])
        entry = report["functions"][0]
        self.assertIn({"from": 0xFFFD, "to": 0, "kind": "near_direct"}, entry["calls"])
        self.assertIn({"kind": "fallthrough", "from": 0xFFFD, "to": 0}, entry["edges"])

    def test_same_cs_far_call_is_mapped_but_other_segment_stays_unresolved(self):
        image = bytearray(0x120)
        base = 0x20
        image[base:base + 5] = bytes.fromhex("9a18000200")  # far call 0002:0018
        image[base + 5:base + 10] = bytes.fromhex("9a08002222")  # far call 2222:0008
        image[base + 10] = 0xC3
        image[base + 0x18] = 0xCB
        report = run(bytes(image), [("entry", base, "test")], [], base)
        entry = report["functions"][0]
        self.assertIn({"from": base, "to": base + 0x18, "kind": "far_direct_same_cs",
                       "pointer": {"segment": 2, "offset": 0x18}}, entry["calls"])
        self.assertIn({"kind": "fallthrough", "from": base, "to": base + 5}, entry["edges"])
        unresolved = next(c for c in entry["calls"] if c["from"] == base + 5)
        self.assertEqual("far_direct", unresolved["kind"])
        self.assertEqual({"segment": 0x2222, "offset": 8}, unresolved["pointer"])

    def test_indirect_jump_stops_and_tail_remains_unknown(self):
        image = bytes.fromhex("ffe0") + bytes([0x90]) * 14
        report = run(image, [("entry", 0, "test")], [])
        self.assertEqual(["indirect_jump"], [s["reason"] for s in report["functions"][0]["stops"]])
        self.assertEqual([2, 16], report["categories"]["unknown"][0])
        self.assertEqual([{"function": "entry", "at": 0, "kind": "jump",
                           "mnemonic": "jmp", "operands": "ax"}],
                         report["diagnostics"]["indirect_transfers"])

    def test_confirmed_data_range_is_not_decoded(self):
        report = run(bytes.fromhex("90c3"), [("entry", 0, "test")], [[0, 2]])
        self.assertEqual([], report["instructions"])
        self.assertEqual([[0, 2]], report["categories"]["explicit_data"])


if __name__ == "__main__":
    unittest.main()
