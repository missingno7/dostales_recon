from pathlib import Path
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from exepack import analyze, scan_overlays, unpack


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "DUCKTALE.EXE"


class ExepackTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = SOURCE.read_bytes()

    def test_depacked_image_and_relocations(self):
        image, relocations, report = unpack(self.data)
        self.assertEqual(len(image), 87664)
        self.assertEqual(report["root_image"]["sha256"],
                         "47e622175ccf124edab2ed1b5ccb725045d5e54b5766428f8309303fcdf5564d")
        self.assertEqual(len(relocations), 659)
        self.assertEqual(report["exepack"]["relocation_group_counts"],
                         [612, 47] + [0] * 14)
        self.assertEqual(report["stream"]["source_prefix_size"], 49520)
        self.assertEqual(report["stream"]["source_prefix_size"],
                         report["stream"]["destination_prefix_size"])
        self.assertEqual(report["stream"]["ff_padding_bytes"], 9)
        self.assertEqual(report["root_entry"]["image_linear"], 0x87A3)
        self.assertEqual(report["root_stack"], {"sp": 0x0800, "ss": 0x1B89})

    def test_overlay_extents_and_shared_root_fixups(self):
        report = analyze(self.data)
        overlays = report["overlays"]
        self.assertEqual(len(overlays), 10)
        self.assertEqual([o["file_start"] for o in overlays],
                         [61952, 62976, 72704, 76800, 95744,
                          108544, 120832, 129536, 155648, 159232])
        self.assertEqual([o["header"]["overlay_number"] for o in overlays],
                         list(range(1, 11)))
        self.assertTrue(all(r["linear"] + 2 <= report["root_image"]["size"]
                            for o in overlays for r in o["relocations"]))
        self.assertEqual(overlays[0]["relocations"][0]["segment"], 0x0C17)
        self.assertGreater(len({r["segment"] for o in overlays
                                for r in o["relocations"]}), 1)
        self.assertEqual(overlays[-1]["file_end"], len(self.data))

    def test_bad_exepack_signature_is_rejected(self):
        damaged = bytearray(self.data)
        damaged[60158] ^= 1
        with self.assertRaisesRegex(ValueError, "signature"):
            unpack(bytes(damaged))

    def test_bad_overlay_gap_is_rejected(self):
        damaged = bytearray(self.data)
        damaged[61787] = 1
        with self.assertRaisesRegex(ValueError, "gap"):
            scan_overlays(bytes(damaged))


if __name__ == "__main__":
    unittest.main()
