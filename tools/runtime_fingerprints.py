"""Fixup-masked CRT searches are attribution diagnostics, never acceptance."""
from pathlib import Path
from common import ROOT, identity, write_json
from historical import verify_profile
from omf import read_object, split_library_report
from oracle import verify

WIDTHS = {0: 1, 1: 2, 2: 2, 3: 4, 4: 1, 5: 2}
MARKERS = (b"MS Run-Time Library", b"Overlay not found", b"Overlay Manager stack overflow")


def positions(image, data, mask):
    runs, at = [], 0
    while at < len(mask):
        if not mask[at]:
            at += 1
            continue
        end = at + 1
        while end < len(mask) and mask[end]:
            end += 1
        runs.append((at, end))
        at = end
    if not runs:
        return []
    start, end = max(runs, key=lambda pair: pair[1] - pair[0])
    if end - start < 8:
        return []
    needle, cursor, hits = data[start:end], 0, []
    while True:
        hit = image.find(needle, cursor)
        if hit < 0:
            return hits
        cursor, base = hit + 1, hit - start
        if 0 <= base and base + len(data) <= len(image) and all(not m or image[base + i] == data[i] for i, m in enumerate(mask)):
            hits.append(base)


def run():
    image = verify(write=False)[1]
    report = {"root_image": identity(image), "proof_level": "DIAGNOSTIC_ONLY", "libraries": []}
    for name in ("msc500-medium", "msc510-medium", "msc600-medium"):
        _, profile = verify_profile(name)
        path = Path(profile["runtime_library"])
        data = path.read_bytes()
        framed = split_library_report(data, strict=False)
        library = {"profile": name, "library": identity(data), "path": str(path),
                   "member_count": len(framed["members"]), "integrity_anomalies": framed["integrity_anomalies"],
                   "hits": [], "markers": [], "unsupported": []}
        for member in framed["members"]:
            try:
                obj = read_object(member, strict=False)
            except ValueError as exc:
                library["unsupported"].append({"member": identity(member), "reason": str(exc)})
                continue
            if any(marker in member for marker in MARKERS):
                library["markers"].append({"module": obj["name"], "member": identity(member),
                                           "texts": [m.decode("ascii") for m in MARKERS if m in member]})
            for seg in obj["segments"]:
                if seg["class"] != "CODE" or not seg["length"] or seg["initialized_ranges"] != [[0, seg["length"]]]:
                    continue
                code = bytes.fromhex(seg["data_hex"])
                mask = bytearray([1]) * len(code)
                for fixup in obj["fixups"]:
                    if fixup["segment"] == seg["index"]:
                        off, width = fixup["offset"], WIDTHS[fixup["location_type"]]
                        mask[off:off + width] = bytes(width)
                hits = positions(image, code, mask)
                if hits:
                    library["hits"].append({"module": obj["name"], "member": identity(member),
                                            "segment": seg["name"], "size": len(code), "offsets": hits,
                                            "compared_bytes": sum(mask), "masked_bytes": len(code) - sum(mask),
                                            "strict_object_supported": obj["strict_comparison_supported"],
                                            "publics": obj["publics"]})
        library["code_segment_hit_count"] = len(library["hits"])
        report["libraries"].append(library)
    write_json(ROOT / "build/runtime-fingerprints.json", report)
    return report


if __name__ == "__main__":
    print([(r["profile"], r["code_segment_hit_count"], len(r["unsupported"])) for r in run()["libraries"]])
