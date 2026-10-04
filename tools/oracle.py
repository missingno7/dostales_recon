"""Locked assets -> deterministic root unpack, ordered relocations and overlay MZs.

No lock creation/update command is exposed. Bootstrap creates the lock once
after reviewing the extraction; every normal call checks it without writing.
"""
import argparse
import struct
from pathlib import Path
from common import ROOT, build_path, identity, read_json, require, write_json
from inventory import inventory
from mz import parse, load_image
from resources import parse as parse_resource


def synthetic_mz(image, relocations, entry, stack, minalloc=0):
    """Serialization of canonical depacked content, not pre-pack header evidence."""
    header_size = (28 + len(relocations) * 4 + 15) // 16 * 16
    size = header_size + len(image)
    header = bytearray(header_size)
    ip, cs = entry
    sp, ss = stack
    struct.pack_into("<14H", header, 0, 0x5a4d, size % 512, (size + 511) // 512,
                     len(relocations), header_size // 16, minalloc, 0xffff, ss, sp, 0, ip, cs, 28, 0)
    for i, pair in enumerate(relocations):
        struct.pack_into("<HH", header, 28 + i * 4, *pair)
    return bytes(header) + image


def construct():
    from exepack import unpack
    inputs = inventory()
    exe = (ROOT / "assets/DUCKTALE.EXE").read_bytes()
    image, relocations, report = unpack(exe)
    packed = parse(exe)
    # Find structural MZ overlay blocks in the appended region only. Header
    # numbers and all boundaries must be validated, not just signature hits.
    overlays, cursor, number = [], packed["image_end"], 1
    while cursor < len(exe):
        start = (cursor + 255) // 256 * 256
        require(start <= len(exe) and not any(exe[cursor:start]), "Nonzero unaccounted overlay alignment gap")
        while start < len(exe) and exe[start:start + 2] != b"MZ":
            require(start + 256 <= len(exe) and not any(exe[start:start + 256]), "Nonzero/unbounded block before overlay header")
            start += 256
        if start == len(exe):
            cursor = start
            break
        mz = parse(exe, start, relocation_scope="shared-root")
        require(all(r["linear"] + 2 <= len(image) for r in mz["relocations"]), "Overlay shared-root fixup address outside root")
        require(mz["header"]["overlay_number"] == number, "Unexpected overlay numbering")
        overlays.append({"id": f"overlay-{number:02d}", "gap_start": cursor, "gap_end": start,
                         "mz": mz, "file": identity(exe[start:mz["image_end"]])})
        cursor, number = mz["image_end"], number + 1
    resources = {}
    for name in inputs:
        if Path(name).suffix.upper() in (".ARC", ".DRV"):
            resources[name] = parse_resource((ROOT / "assets" / name).read_bytes())[0]
            inputs[name]["basic_format"] = "IT-offset-table-container"
    derived = {"schema": 1, "inputs": inputs, "packed_mz": packed,
               "root_image": identity(image), "root_relocations": [[a, b] for a, b in relocations],
               "exepack": report, "overlays": overlays, "resources": resources,
               "unpacked_header_policy": "synthetic paragraph-aligned MZ; original pre-pack header unresolved"}
    return exe, image, relocations, derived


def verify(write=True, out=None):
    result = construct()
    expected = read_json(ROOT / "layout/oracle.lock.json")
    require(result[3] == expected, "Oracle identities/structure differ from immutable lock")
    if write:
        directory = build_path(out or ROOT / "build/oracle")
        directory.mkdir(parents=True, exist_ok=True)
        exe, image, relocs, report = result
        (directory / "root.bin").write_bytes(image)
        entry, stack = report["exepack"]["root_entry"], report["exepack"]["root_stack"]
        packed_mz = report["packed_mz"]
        # Memory-accounting reconstruction is a stated serialization policy.
        minalloc = (packed_mz["image"]["size"] + 15) // 16 + packed_mz["header"]["minalloc"] - len(image) // 16
        root_exe = synthetic_mz(image, relocs, (entry["ip"], entry["cs"]), (stack["sp"], stack["ss"]), minalloc)
        require(load_image(root_exe) == image, "Synthetic MZ serialization changed image")
        (directory / "root-unpacked.exe").write_bytes(root_exe)
        (directory / "packed.exe").write_bytes(exe)
        (directory / "tail.bin").write_bytes(exe[report["packed_mz"]["image_end"]:])
        for overlay in report["overlays"]:
            mz = overlay["mz"]
            (directory / (overlay["id"] + ".exe")).write_bytes(exe[mz["file_offset"]:mz["image_end"]])
            (directory / (overlay["id"] + ".bin")).write_bytes(load_image(exe, mz))
        write_json(directory / "report.json", report)
        write_json(directory / "root-relocations.json", report["root_relocations"])
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["verify"])
    p.add_argument("--out")
    args = p.parse_args()
    result = verify(out=args.out)
    print("STRUCTURE_VERIFIED", result[3]["root_image"], "overlays", len(result[3]["overlays"]))
