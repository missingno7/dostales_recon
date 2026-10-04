"""Strict OMF inspection, or library framing with explicit integrity anomalies."""
import argparse
from pathlib import Path
from common import ROOT, build_path, identity, write_json
from omf import read_object, split_library_report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path")
    p.add_argument("--library", action="store_true")
    p.add_argument("--inspection", action="store_true")
    p.add_argument("--out", default="build/omf.json")
    args = p.parse_args()
    data = Path(args.path).read_bytes()
    if args.library:
        framing = split_library_report(data, strict=not args.inspection)
        report = {"file": identity(data), "integrity_anomalies": framing["integrity_anomalies"], "members": []}
        for m in framing["members"]:
            try:
                obj = read_object(m, strict=not args.inspection)
                report["members"].append({"identity": identity(m), "object": obj})
            except ValueError as exc:
                report["members"].append({"identity": identity(m), "unsupported": str(exc)})
    else:
        report = read_object(data, strict=not args.inspection)
    write_json(build_path(args.out), report)
    print("OMF report", args.out, "inspection" if args.inspection else "strict")
