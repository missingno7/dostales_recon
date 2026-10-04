"""Validate complete hash-pinned, relocation-free CRT contributions."""
from pathlib import Path
from common import ROOT, identity, read_json, require, write_json
from historical import verify_profile
from omf import read_object, split_library
from oracle import verify


def signature(obj):
    import copy
    result = copy.deepcopy(obj)
    for segment in result["segments"]:
        segment["native_data"] = identity(bytes.fromhex(segment.pop("data_hex")))
    return result


def validate(owners=None, result=None):
    result = result or verify(write=False)
    owners = owners if owners is not None else read_json(ROOT / "layout/manifest.json")["owners"]
    reports = []
    for row in owners:
        if row["kind"] != "PINNED_RUNTIME":
            continue
        lock, profile = verify_profile(row["profile"])
        library = Path(row["library"])
        require(any(f["path"] == library.as_posix() and f["sha256"] == row["library_sha256"] for f in profile["files"]), "Library not profile-pinned")
        data = library.read_bytes()
        require(identity(data)["sha256"] == row["library_sha256"], "Library changed")
        # Inspection framing permits the documented unrelated startup checksum
        # anomaly. The chosen member is independently parsed strictly below.
        modules = [m for m in split_library(data, strict=False) if identity(m)["sha256"] == row["member_sha256"]]
        require(len(modules) == 1, "Runtime member missing/ambiguous")
        obj = read_object(modules[0], strict=True)
        require(signature(obj) == row["object"], "Runtime declarations/fixups/native initialized spans changed")
        require(not obj["fixups"] and not obj["externals"] and not obj["communals"], "Runtime member requires a binding proof")
        code = [s for s in obj["segments"] if s["name"] == row["segment"]]
        require(len(code) == 1, "Unknown runtime code segment")
        code = code[0]
        require(all(not s["length"] for s in obj["segments"] if s is not code), "Unowned runtime data/BSS extent")
        start, end = row["start"], row["end"]
        require(row["unit"] == "root", "Overlay runtime binding not yet implemented")
        require(code["length"] == end - start and code["initialized_ranges"] == [[0, end - start]], "Incomplete runtime object contribution")
        require(bytes.fromhex(code["data_hex"]) == result[1][start:end], "Native runtime code differs")
        require(not any(start - 1 <= off + seg * 16 < end for off, seg in result[2]), "Unexpected root relocation in runtime contribution")
        reports.append({"id": row["id"], "proof_level": "PINNED_RUNTIME", "bytes": end - start,
                        "module": obj["name"], "member_sha256": row["member_sha256"],
                        "scope": "Complete member, no native storage/fixups/externals; full historical LINK build pending"})
    return reports


if __name__ == "__main__":
    rows = validate()
    write_json(ROOT / "build/runtime-validation.json", rows)
    print("PINNED_RUNTIME", sum(r["bytes"] for r in rows), "bytes", [r["module"] for r in rows])
