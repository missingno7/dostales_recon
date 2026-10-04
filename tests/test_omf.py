import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from omf import OMFError, read_object, records, split_library, split_library_report


def rec(kind, body=b""):
    size = len(body) + 1
    head = bytes((kind, size & 255, size >> 8))
    checksum = (-sum(head + body)) & 255
    return head + body + bytes((checksum,))


def s(value):
    b = value.encode("ascii")
    return bytes((len(b),)) + b


class OMFTests(unittest.TestCase):
    def valid_object(self, module="TEST"):
        # LNAMES: 1 CODE, 2 TEXT, 3 DGROUP.
        return b"".join((
            rec(0x80, s(module)),
            rec(0x96, s("CODE") + s("TEXT") + s("DGROUP")),
            rec(0x98, bytes((0x68, 16, 0, 1, 2, 0))),
            rec(0x9A, bytes((3, 0xff, 1))),
            rec(0x8C, s("EXT") + bytes((0,))),
            rec(0x90, bytes((1, 1)) + s("ENTRY") + bytes((2, 0, 0))),
            rec(0xB0, s("COMMON") + bytes((0, 0x62, 0x81, 0x34, 0x12))),
            rec(0xB0, s("FARCOM") + bytes((0, 0x61, 3, 4))),
            rec(0xA0, bytes((1, 0, 0)) + b"\x90\x00\x00\x00"),
            # 16-bit offset fixup at LEDATA + 1: frame=segment 1,
            # target=external 1, explicit displacement 0x1234.
            rec(0x9C, bytes((0x84, 1, 2, 1, 1, 0x34, 0x12))),
            # Two repetitions of the literal 'ab' at offset 8.
            rec(0xA2, bytes((1, 8, 0, 2, 0, 0, 0, 2)) + b"ab"),
            rec(0x8A, b"\0"),
        ))

    def test_globals_communal_fixup_and_initialized_spans(self):
        parsed = read_object(self.valid_object())
        self.assertEqual(parsed["name"], "TEST")
        self.assertEqual(parsed["segments"][0]["length"], 16)
        self.assertTrue(parsed["segments"][0]["use16"])
        self.assertEqual(parsed["segments"][0]["overlay_name"], "")
        self.assertEqual(parsed["segments"][0]["initialized_ranges"], [[0, 4], [8, 12]])
        self.assertEqual(parsed["segments"][0]["data_hex"], (b"\x90\0\0\0" + b"\0"*4 + b"abab" + b"\0"*4).hex())
        self.assertEqual(parsed["groups"], [{"name": "DGROUP", "segments": [1]}])
        self.assertEqual(parsed["externals"][0]["name"], "EXT")
        self.assertEqual(parsed["publics"][0]["name"], "ENTRY")
        self.assertEqual(parsed["fixups"][0], {
            "segment": 1, "offset": 1, "location_type": 1,
            "segment_relative": False,
            "frame": {"method": "segment", "datum": 1},
            "target": {"method": "external", "datum": 1},
            "displacement": 0x1234,
        })
        self.assertEqual(parsed["communals"][0]["length"], 0x1234)
        self.assertEqual(parsed["communals"][1], {
            "name": "FARCOM", "type_index": 0, "kind": "far",
            "count": 3, "element_length": 4,
        })

    def test_absolute_segment_definition_fields(self):
        data = self.valid_object()
        original = rec(0x98, bytes((0x68, 16, 0, 1, 2, 0)))
        absolute = rec(0x98, bytes((0x08, 0x34, 0x12, 5, 16, 0, 1, 2, 0)))
        parsed = read_object(data.replace(original, absolute))
        segment = parsed["segments"][0]
        self.assertEqual(segment["absolute_frame"], 0x1234)
        self.assertEqual(segment["absolute_offset"], 5)

    def test_communal_index_space_and_numeric_widths(self):
        obj = self.valid_object()
        end = rec(0x8A, b"\0")
        extra = rec(0xB0, s("WIDE") + bytes((0, 0x62, 0x84, 3, 2, 1)))
        extra += rec(0xB0, s("DWORD") + bytes((0, 0x62, 0x88, 4, 3, 2, 1)))
        extra += rec(0xB0, s("SMALL") + bytes((0, 0x62, 0x80)))
        parsed = read_object(obj[:-len(end)] + extra + end)
        self.assertEqual([x["length"] for x in parsed["communals"][-3:]], [0x010203, 0x01020304, 128])
        self.assertEqual([x["name"] for x in parsed["externals"]], ["EXT", "COMMON", "FARCOM", "WIDE", "DWORD", "SMALL"])

    def test_fixup_width_and_use32_refused(self):
        obj = self.valid_object()
        old = rec(0x9C, bytes((0x84, 1, 2, 1, 1, 0x34, 0x12)))
        bad = rec(0x9C, bytes((0x8c, 1, 2, 1, 1, 0, 0)))
        with self.assertRaisesRegex(OMFError, "location"):
            read_object(obj.replace(old, bad))
        old = rec(0x98, bytes((0x68, 16, 0, 1, 2, 0)))
        with self.assertRaisesRegex(OMFError, "USE32"):
            read_object(obj.replace(old, rec(0x98, bytes((0x69, 16, 0, 1, 2, 0)))))

    def test_checksum_truncation_and_unsupported_record_rejected(self):
        data = self.valid_object()
        bad = bytearray(data); bad[5] ^= 1
        with self.assertRaisesRegex(OMFError, "checksum"):
            read_object(bytes(bad))
        with self.assertRaisesRegex(OMFError, "truncated"):
            read_object(data[:-1])
        unsupported = rec(0x99, b"\0")
        end = rec(0x8A, b"\0")
        with self.assertRaisesRegex(OMFError, "unsupported record"):
            read_object(data[:-len(end)] + unsupported + end)

    def test_zero_checksum_can_be_computed_or_omitted(self):
        zero = rec(0x80, b"\x7e")  # 0x80 + length 2 + 0x7e == 256
        self.assertEqual(zero[-1], 0)
        self.assertEqual(records(zero)[0]["checksum_state"], "computed")
        omitted = bytearray(rec(0x80, b"\0")); omitted[-1] = 0
        self.assertNotEqual(sum(omitted) & 255, 0)
        self.assertEqual(records(bytes(omitted))[0]["checksum_state"], "omitted_zero")
        # A malformed nonzero checksum is never treated as omitted.
        bad = bytearray(rec(0x80, b"\0")); bad[-1] = 1
        with self.assertRaisesRegex(OMFError, "checksum"):
            records(bytes(bad))

    def test_fixup_threads_persist_and_lidata_fixups_are_rejected(self):
        base = self.valid_object()
        # Define F0=SEGDEF 1 and T2=EXTDEF 1 before data, then use them later.
        threads = rec(0x9C, bytes((0x40, 1, 0x08, 1)))
        direct_fixup = rec(0x9C, bytes((0x84, 1, 2, 1, 1, 0x34, 0x12)))
        threaded_fixup = rec(0x9C, bytes((0x84, 1, 0x88, 0, 0)))
        led = rec(0xA0, bytes((1, 0, 0)) + b"\x90\0\0\0")
        end = rec(0x8A, b"\0")
        base = base.replace(direct_fixup, threaded_fixup).replace(led, threads + led)
        parsed = read_object(base)
        self.assertEqual(len(parsed["fixups"]), 1)

        # Construct an object whose location fixup follows LIDATA.
        no_fixup = self.valid_object()
        old_fixup = rec(0x9C, bytes((0x84, 1, 2, 1, 1, 0x34, 0x12)))
        altered = no_fixup.replace(old_fixup, b"")
        lidata = rec(0xA2, bytes((1, 12, 0, 1, 0, 0, 0, 1)) + b"x")
        fix = rec(0x9C, bytes((0x84, 0, 2, 1, 1, 0, 0)))
        end = rec(0x8A, b"\0")
        altered = altered[:-len(end)] + lidata + fix + end
        with self.assertRaisesRegex(OMFError, "after LIDATA"):
            read_object(altered)

    def test_comments_and_page_aligned_library(self):
        module = self.valid_object()
        # Known Microsoft comment retained exactly; unknown class is inspection-only.
        comment = rec(0x88, bytes((0, 0x9f)) + b"MLIBCE")
        end = rec(0x8A, b"\0")
        module_with_comment = module[:-len(end)] + comment + end
        self.assertEqual(read_object(module_with_comment)["comments"][0]["data_hex"], b"MLIBCE".hex())
        unknown = rec(0x88, bytes((0, 0x77)) + b"raw")
        sample = module[:-len(end)] + unknown + end
        with self.assertRaisesRegex(OMFError, "COMENT class"):
            read_object(sample)
        self.assertFalse(read_object(sample, strict=False)["strict_comparison_supported"])

        page = 512
        dict_start = 1536
        hdr_body = dict_start.to_bytes(4, "little") + (1).to_bytes(2, "little") + b"\0"
        header = b"\xf0" + (page-3).to_bytes(2, "little") + hdr_body + b"\0"*(page-3-len(hdr_body))
        marker = b"\xf1" + (dict_start-1024-3).to_bytes(2, "little") + b"\0"*(dict_start-1024-3)
        library = header + module + b"\0"*(page-len(module)) + marker + b"\0"*(page-3-len(marker)+3) + b"\0"*page
        self.assertEqual(split_library(library), [module])

    def test_inspection_split_reports_bad_nonzero_without_changing_member(self):
        module = self.valid_object()
        end = rec(0x8A, b"\0")
        broken_comment = bytearray(rec(0x88, bytes((0, 0xA2, 0))))
        broken_comment[-1] = (broken_comment[-1] + 1) & 255
        damaged = module[:-len(end)] + bytes(broken_comment) + end
        with self.assertRaisesRegex(OMFError, "bad checksum"):
            read_object(damaged)
        page, dict_start = 512, 1536
        hdr_body = dict_start.to_bytes(4, "little") + (1).to_bytes(2, "little") + b"\0"
        header = b"\xF0" + (page-3).to_bytes(2, "little") + hdr_body + b"\0"*(page-3-len(hdr_body))
        marker = b"\xF1" + (dict_start-1024-3).to_bytes(2, "little") + b"\0"*(dict_start-1024-3)
        library = header + damaged + b"\0"*(page-len(damaged)) + marker + b"\0"*page
        with self.assertRaisesRegex(OMFError, "bad checksum"):
            split_library(library)
        self.assertEqual(split_library(library, strict=False), [damaged])
        report = split_library_report(library)
        self.assertEqual(report["members"], [damaged])
        self.assertEqual(report["integrity_anomalies"], [{
            "module_index": 1, "record_offset": 512 + len(module) - len(end),
            "module_offset": len(module) - len(end), "record_type": 0x88,
            "record_name": "COMENT", "checksum_state": "bad_nonzero",
            "stored_checksum": broken_comment[-1], "checksum_sum": 1,
            "expected_checksum": (broken_comment[-1] - 1) & 255,
        }])

    def test_split_concatenated_modules(self):
        a, b = self.valid_object(), self.valid_object("DEMO")
        members = split_library(a + b)
        self.assertEqual(members, [a, b])
        self.assertEqual([read_object(x)["name"] for x in members], ["TEST", "DEMO"])


if __name__ == "__main__":
    unittest.main()
