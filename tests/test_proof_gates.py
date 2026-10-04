import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from compare import object_diff
from match import compare_segment, image_for
from status import accounting


class ProofGateTests(unittest.TestCase):
    def test_overlay_relocations_are_compared_at_module_offsets(self):
        from overlays import arena_base
        mz = {"image_start": 0, "image_end": 14, "relocations": [{"linear": arena_base() + 5}]}
        result = (bytes(14), b"", [], {"overlays": [{"id": "overlay-01", "mz": mz}]})
        image, sites = image_for("overlay-01", result)
        self.assertEqual(len(image), 14)
        self.assertEqual(sites, [5])
        mz["relocations"][0]["linear"] = arena_base() + 13
        with self.assertRaises(ValueError):
            image_for("overlay-01", result)

    def test_no_trimmed_candidate_can_pass(self):
        segment = {"name": "_TEXT", "class": "CODE", "length": 3,
                   "data_hex": "9090c3", "initialized_ranges": [[0, 3]]}
        obj = {"segments": [segment], "fixups": [], "externals": [], "publics": [], "communals": []}
        report = compare_segment(obj, b"\x90\x90", 0, 2, "_TEXT", [])
        self.assertEqual(report["proof_level"], "MISMATCH")
        self.assertEqual(report["bytes"]["size_displacement"], 1)

    def test_code_equality_never_awards_bindings(self):
        obj = {"segments": [{"name": "_TEXT", "class": "CODE", "length": 1,
                              "data_hex": "c3", "initialized_ranges": [[0, 1]]}],
               "fixups": [{"offset": 0}], "externals": ["unbound"], "publics": [], "communals": []}
        report = compare_segment(obj, b"\xc3", 0, 1, "_TEXT", [0])
        self.assertEqual(report["proof_level"], "CODE_BYTES_EXACT")
        self.assertFalse(report["OBJECT_CONTRIBUTION_EXACT"])
        self.assertEqual(report["obligations"]["expected_relocation_sites"], [0])

    def test_unsupported_omf_metadata_cannot_pass_equality(self):
        obj = {"strict_comparison_supported": False}
        self.assertFalse(object_diff(obj, obj)["strict_comparison_supported"]["exact"])

    def test_ownership_gap_overlap_or_unknown_kind_rejected(self):
        result = (b"", bytes(4), [], {"overlays": []})
        row = {"id": "a", "unit": "root", "kind": "UNRESOLVED", "start": 0, "end": 4}
        manifest = {"units": [{"id": "root", "size": 4}], "owners": [row], "bss": {}}
        self.assertEqual(accounting(manifest, result)["unresolved_bytes"], 4)
        for change in ("gap", "overlap", "kind"):
            edited = copy.deepcopy(manifest)
            if change == "gap": edited["owners"][0]["start"] = 1
            if change == "overlap": edited["owners"].append({**row, "id": "b"})
            if change == "kind": edited["owners"][0]["kind"] = "C_EXACT"
            with self.assertRaises(ValueError):
                accounting(edited, result)
