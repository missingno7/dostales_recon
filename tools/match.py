"""Compare a complete OMF segment against one locked image region.

Byte equality is diagnostic when data, fixups or bindings remain unresolved.
This command never promotes sources or rewrites an expected region.
"""
import argparse
from pathlib import Path
from common import ROOT, build_path, identity, require, write_json
from compare import bytes_diff
from oracle import verify


def image_for(unit, result):
    if unit == "root":
        return result[1], [a + b * 16 for a, b in result[2]]
    from mz import load_image
    overlays = [o for o in result[3]["overlays"] if o["id"] == unit]
    require(len(overlays) == 1, "Unknown oracle unit")
    mz = overlays[0]["mz"]
    from overlays import arena_base
    image = load_image(result[0], mz)
    sites = [r["linear"] - arena_base() for r in mz["relocations"]]
    require(all(0 <= r and r + 2 <= len(image) for r in sites), "Overlay relocation outside loaded contribution")
    return image, sites


def compare_segment(obj, image, start, end, name, relocations):
    rows = [s for s in obj["segments"] if s["name"] == name]
    require(len(rows) == 1, "Unknown/ambiguous OMF segment")
    segment = rows[0]
    require(0 <= start < end <= len(image), "Target extent outside oracle image")
    actual = bytes.fromhex(segment["data_hex"])
    declared = segment["length"]
    complete = segment["initialized_ranges"] == [[0, declared]] and len(actual) == declared
    byte_report = bytes_diff(image[start:end], actual)
    obligations = {"complete_declared_extent": complete,
                   "extent_size_equal": declared == end - start,
                   "fixups": obj["fixups"], "externals": obj["externals"],
                   "publics": obj["publics"], "communals": obj["communals"],
                   "other_segments": [s for s in obj["segments"] if s is not segment and s["length"]],
                   "expected_relocation_sites": [r for r in relocations if start - 1 <= r < end]}
    exact = byte_report["exact"] and complete and declared == end - start
    instruction_difference = None
    if not exact and segment["class"] == "CODE":
        from context import disassemble
        first = byte_report["first_difference"] or 0
        expected_rows = disassemble(image[start:end], start)
        actual_rows = disassemble(actual, start)
        near = lambda rows: [r for r in rows if r["offset"] + len(bytes.fromhex(r["bytes"])) > start + max(0, first - 8)][:6]
        instruction_difference = {"expected": near(expected_rows), "actual": near(actual_rows),
                                  "scope": "diagnostic decode; unlinked OMF operands can still carry fixups"}
    return {"proof_level": "CODE_BYTES_EXACT" if exact else "MISMATCH",
            "OBJECT_CONTRIBUTION_EXACT": False, "ancestry": "unproven",
            "reason": "Linked bindings, declarations and native data need independent proof even if code bytes agree",
            "bytes": byte_report, "instructions": instruction_difference, "obligations": obligations}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("object")
    p.add_argument("unit")
    p.add_argument("start", type=lambda x: int(x, 0))
    p.add_argument("end", type=lambda x: int(x, 0))
    p.add_argument("--segment", default="_TEXT")
    p.add_argument("--report", default="build/match.json")
    args = p.parse_args()
    from omf import read_object
    obj = read_object(Path(args.object).read_bytes())
    image, relocations = image_for(args.unit, verify(write=False))
    report = compare_segment(obj, image, args.start, args.end, args.segment, relocations)
    report.update({"object": identity(Path(args.object).read_bytes()), "unit": args.unit,
                   "start": args.start, "end": args.end, "segment": args.segment})
    write_json(build_path(args.report), report)
    print(report["proof_level"], report["bytes"], report["reason"])
    raise SystemExit(0 if report["proof_level"] == "CODE_BYTES_EXACT" else 1)
