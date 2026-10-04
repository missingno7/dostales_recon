"""Locked unit context: bytes, disassembly, relocations, ownership and CFG edges."""
import argparse
from common import ROOT, identity, read_json, require, write_json
from oracle import verify
from match import image_for


def root_cfg(result):
    from cfg import run
    entry = result[3]["exepack"]["root_entry"]
    entries = [("overlay_init", entry["image_linear"], "restored_MZ_entry")]
    for row in read_json(ROOT / "layout/manifest.json")["owners"]:
        if row["kind"] == "PINNED_RUNTIME":
            entries.append((row["id"], row["start"], "strict_pinned_runtime_member"))
    report = run(result[1], entries, [], entry["cs"] * 16)
    write_json(ROOT / "build/analysis/root-cfg.json", report)
    return report


def disassemble(data, start=0, segment_base=0):
    from analysis_runtime import prepare
    prepare("capstone")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    return [{"offset": start + ins.address - ((start - segment_base) & 0xffff),
             "bytes": bytes(ins.bytes).hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str}
            for ins in decoder.disasm(data, (start - segment_base) & 0xffff)]


def context(unit, start, length):
    result = verify(write=False)
    image, relocs = image_for(unit, result)
    require(0 <= start < len(image) and length > 0, "Context bounds invalid")
    end = min(start + length, len(image))
    owners = [r for r in read_json(ROOT / "layout/manifest.json")["owners"]
              if r["unit"] == unit and r["start"] < end and r["end"] > start]
    base = result[3]["exepack"]["root_entry"]["cs"] * 16 if unit == "root" else 0
    cfg = root_cfg(result) if unit == "root" else None
    return {"unit": unit, "image": identity(image), "start": start, "end": end,
            "bytes_hex": image[start:end].hex(), "owners": [{k: v for k, v in row.items() if k != "object"} for row in owners],
            "relocations": [r for r in relocs if start - 1 <= r < end],
            "relocation_scope": "unit-local" if unit == "root" else "module-local; encoded MZ sites subtract shared arena 0xC170",
            "disassembly": disassemble(image[start:end], start, base),
            "disassembly_scope": "bounded diagnostic decoding; does not establish code/data or function boundaries",
            "cfg_callers": [c for f in cfg["functions"] for c in f["calls"] if start <= c.get("to", -1) < end] if cfg else [],
            "cfg_stops": [s for f in cfg["functions"] for s in f["stops"] if start <= s["at"] < end] if cfg else []}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("unit", nargs="?", default="root")
    p.add_argument("offset", nargs="?", type=lambda s: int(s, 0), default=0x8436)
    p.add_argument("--length", type=lambda s: int(s, 0), default=64)
    p.add_argument("--list", action="store_true")
    args = p.parse_args()
    if args.list:
        report = root_cfg(verify(write=False))
        print([(f["label"], hex(f["entry"]), f["origin"]) for f in report["functions"]])
    else:
        report = context(args.unit, args.offset, args.length)
        write_json(ROOT / "build/context.json", report)
        print(args.unit, hex(report["start"]), hex(report["end"]), report["relocation_scope"])
        for row in report["disassembly"]:
            print(f"{row['offset']:05x} {row['bytes']:<16} {row['mnemonic']} {row['operands']}")
        print("Relocations:", report["relocations"], "Callers:", report["cfg_callers"])
