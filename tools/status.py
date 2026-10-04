"""Authoritative current reconstruction accounting, derived from checked inputs."""
from collections import Counter
from common import ROOT, identity, read_json, require, write_json
from oracle import verify
from runtime import validate as validate_runtime


def accounting(manifest, result):
    sizes = {"root": len(result[1]), **{o["id"]: o["mz"]["image"]["size"] for o in result[3]["overlays"]}}
    declared = {u["id"]: u["size"] for u in manifest["units"]}
    require(sizes == declared and len(manifest["units"]) == len(sizes), "Manifest unit map differs from oracle")
    known_kinds = {"UNRESOLVED", "PINNED_RUNTIME"}
    totals = Counter()
    ids = set()
    for row in manifest["owners"]:
        require(row["id"] not in ids, "Duplicate ownership ID")
        ids.add(row["id"])
        require(row["unit"] in sizes and row["kind"] in known_kinds, "Unsupported/unverified ownership kind")
        require(0 <= row["start"] < row["end"] <= sizes[row["unit"]], "Owner extent outside unit")
        totals[row["kind"]] += row["end"] - row["start"]
    for unit, size in sizes.items():
        cursor = 0
        for row in sorted((r for r in manifest["owners"] if r["unit"] == unit), key=lambda r: r["start"]):
            require(row["start"] == cursor, f"Ownership gap/overlap in {unit} at {cursor}")
            cursor = row["end"]
        require(cursor == size, f"Unaccounted tail in {unit}")
    return {"initialized_image_bytes": sum(sizes.values()), "unresolved_bytes": totals["UNRESOLVED"],
            "pinned_runtime_bytes": totals["PINNED_RUNTIME"], "accepted_C_bytes": 0, "accepted_ASM_bytes": 0,
            "accepted_data_bytes": 0, "BSS": manifest["bss"], "units": sizes}


def generate(result=None, cfg=None):
    result = result or verify(write=False)
    manifest = read_json(ROOT / "layout/manifest.json")
    counts = accounting(manifest, result)
    runtime = validate_runtime(manifest["owners"], result)
    if cfg is None:
        from context import root_cfg
        cfg = root_cfg(result)
    require(cfg["image_identity"] == identity(result[1]), "CFG belongs to another image")
    containers = result[3]["resources"]
    report = {"schema": 1, "scope": "Forensic bootstrap; no full reconstructed game build yet",
              "oracle_lock": identity((ROOT / "layout/oracle.lock.json").read_bytes()),
              "assets": {"files": len(result[3]["inputs"]), "bytes": sum(x["size"] for x in result[3]["inputs"].values())},
              "ownership": counts, "runtime": runtime,
              "root_relocations": len(result[2]),
              "overlay_relocations": sum(len(o["mz"]["relocations"]) for o in result[3]["overlays"]),
              "resources": {"containers": len(containers), "raw_entries": sum(r["count"] for r in containers.values()),
                            "payload_decoders_proven": 0},
              "classification": {"root_provisional_code_bytes": sum(b - a for a, b in cfg["categories"]["code"]),
                                 "root_unvisited_bytes": sum(b - a for a, b in cfg["categories"]["unknown"]),
                                 "function_seeds": len(cfg["functions"]), "confirmed_data_bytes": 0,
                                 "note": "Provisional CFG and ownership are separate, overlapping measurements"},
              "full_game_acceptance": {name: "NOT_ATTEMPTED" for name in ("HYBRID_EXACT", "C_EXACT", "ASM_EXACT", "UNPACKED_IMAGE_EXACT", "RELOCATIONS_EXACT", "OVERLAYS_EXACT", "PACKED_EXE_EXACT")},
              "next_tasks": ["Bind the Microsoft overlay manager's native storage and linker-generated segment/vector maps",
                             "Resolve complete CRT native data/BSS and segment/group/extern fixups",
                             "Investigate game C translation units with MSC 5.10 size/time optimization variants",
                             "Identify IT resource prefix consumers and validate a payload decoder against the original code",
                             "Build an independent historical LINK layout before source-image/packing acceptance"]}
    write_json(ROOT / "build/status.json", report)
    return report


if __name__ == "__main__":
    report = generate()
    print(report["scope"], report["ownership"], report["classification"])
