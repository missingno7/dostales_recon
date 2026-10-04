"""Exact comparisons: independent layers, useful first differences, no patching."""
import argparse
from pathlib import Path
from common import identity, read_json, write_json
from mz import parse, load_image


def bytes_diff(expected, actual):
    offsets = [i for i in range(min(len(expected), len(actual))) if expected[i] != actual[i]]
    if len(expected) != len(actual):
        offsets.append(min(len(expected), len(actual)))
    first = min(offsets) if offsets else None
    return {"exact": expected == actual, "expected": identity(expected), "actual": identity(actual),
            "first_difference": first, "size_displacement": len(actual) - len(expected),
            "differing_bytes": sum(a != b for a, b in zip(expected, actual)) + abs(len(expected) - len(actual)),
            "expected_context": expected[max(0, first - 8):first + 16].hex() if first is not None else None,
            "actual_context": actual[max(0, first - 8):first + 16].hex() if first is not None else None}


def sequence_diff(expected, actual):
    index = next((i for i, (a, b) in enumerate(zip(expected, actual)) if a != b), None)
    if index is None and len(expected) != len(actual):
        index = min(len(expected), len(actual))
    return {"exact": expected == actual, "expected_count": len(expected), "actual_count": len(actual),
            "first_difference": index, "expected_item": expected[index] if index is not None and index < len(expected) else None,
            "actual_item": actual[index] if index is not None and index < len(actual) else None}


def mz_diff(expected, actual, relocation_scope="module"):
    em, am = parse(expected, relocation_scope=relocation_scope), parse(actual, relocation_scope=relocation_scope)
    pairs = lambda r: [(x["offset"], x["segment"]) for x in r["relocations"]]
    return {"UNPACKED_IMAGE_EXACT": bytes_diff(load_image(expected, em), load_image(actual, am)),
            "RELOCATIONS_EXACT": sequence_diff(pairs(em), pairs(am)),
            "MZ_HEADER_EXACT": sequence_diff(list(em["header"].items()), list(am["header"].items())),
            "APPENDED_BYTES_EXACT": bytes_diff(expected[em["image_end"]:], actual[am["image_end"]:]),
            "FILE_EXACT": bytes_diff(expected, actual)}


def object_diff(expected, actual):
    # Includes complete declared extent, native data, bindings and ordered fixups.
    # THEADR paths and record checksums are recorded, not linker identity fields.
    fields = ("segments", "groups", "externals", "publics", "fixups", "communals", "comments", "modend", "strict_comparison_supported")
    return {key: {"exact": (expected.get(key) == actual.get(key) and
                            (key != "strict_comparison_supported" or expected.get(key) is True)),
                  "expected": expected.get(key), "actual": actual.get(key)} for key in fields}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("expected")
    p.add_argument("actual")
    p.add_argument("--mz", action="store_true")
    p.add_argument("--omf", action="store_true")
    p.add_argument("--shared-relocations", action="store_true", help="Overlay MZ records use shared-root coordinates")
    p.add_argument("--report", default="build/comparison.json")
    args = p.parse_args()
    if args.omf:
        from omf import read_object
        report = object_diff(read_object(Path(args.expected).read_bytes()), read_object(Path(args.actual).read_bytes()))
    else:
        a, b = Path(args.expected).read_bytes(), Path(args.actual).read_bytes()
        report = mz_diff(a, b, "shared-root" if args.shared_relocations else "module") if args.mz else bytes_diff(a, b)
    from common import build_path
    write_json(build_path(args.report), report)
    print(report)
    raise SystemExit(0 if (report.get("exact") if "exact" in report else all(x["exact"] for x in report.values())) else 1)
