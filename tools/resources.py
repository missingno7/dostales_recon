"""DuckTales offset-table containers: preserve opaque member prefixes/payloads."""
import argparse
import struct
from pathlib import Path
from common import ROOT, build_path, identity, read_json, require, write_json


def pack(members):
    require(0 < len(members) <= 65535, "Invalid resource count")
    starts, cursor = [], 2 + len(members) * 4
    for member in members:
        require(bool(member), "Empty member not supported by observed format")
        starts.append(cursor)
        cursor += len(member)
    return struct.pack("<H", len(members)) + struct.pack("<" + "I" * len(starts), *starts) + b"".join(members)


def parse(data):
    require(len(data) >= 2, "Truncated resource count")
    count = struct.unpack_from("<H", data)[0]
    table_end = 2 + count * 4
    require(count > 0 and table_end <= len(data), "Invalid/truncated resource index")
    starts = list(struct.unpack_from("<" + "I" * count, data, 2))
    require(starts[0] == table_end, "Unaccounted prefix or invalid first resource offset")
    require(all(a < b for a, b in zip(starts, starts[1:])), "Non-increasing resource offsets")
    require(starts[-1] < len(data), "Resource offset beyond EOF")
    members = [data[a:b] for a, b in zip(starts, starts[1:] + [len(data)])]
    entries = []
    for i, (start, member) in enumerate(zip(starts, members)):
        require(len(member) >= 16, "Truncated observed resource prefix")
        payload_len, kind = struct.unpack_from("<IH", member)
        require(payload_len == len(member) - 16, "Resource payload-length equation failed")
        entries.append({"index": i, "start": start, "end": start + len(member), **identity(member),
                        "prefix_hex": member[:16].hex(), "kind_observed": kind,
                        "payload": identity(member[16:]), "filename": f"{i:03d}.bin"})
    require(pack(members) == data, "Reconstructed index+members differs")
    return {"source": identity(data), "count": count, "table_end": table_end,
            "entries": entries, "alignment": "byte offsets; no universal alignment",
            "codec": "unresolved; exact raw preservation only", "roundtrip_exact": True}, members


def extract(data, out):
    out = build_path(out)
    report, members = parse(data)
    out.mkdir(parents=True, exist_ok=True)
    for row, member in zip(report["entries"], members):
        (out / row["filename"]).write_bytes(member)
    write_json(out / "index.json", report)
    return report


def repack(directory):
    directory = build_path(directory)
    report = read_json(directory / "index.json")
    members = []
    for row in report["entries"]:
        path = (directory / row["filename"]).resolve()
        require(path.parent == directory, "Member path escapes extraction directory")
        member = path.read_bytes()
        require(identity(member) == {k: row[k] for k in ("size", "sha256")}, "Extracted member changed")
        members.append(member)
    data = pack(members)
    require(identity(data) == report["source"], "Repacked original identity mismatch")
    return data


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("extract", "repack", "verify"))
    p.add_argument("input", nargs="?")
    p.add_argument("--out")
    args = p.parse_args()
    if args.command == "extract":
        print(extract(Path(args.input).read_bytes(), args.out or ROOT / "build/resources" / Path(args.input).name)["source"])
    elif args.command == "repack":
        data = repack(args.input)
        out = build_path(args.out or ROOT / "build/repacked.bin")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        print(identity(data))
    else:
        for path in sorted((ROOT / "assets").iterdir()):
            if path.suffix.upper() in (".ARC", ".DRV"):
                report = extract(path.read_bytes(), ROOT / "build/resources" / path.name)
                require(repack(ROOT / "build/resources" / path.name) == path.read_bytes(), "Disk roundtrip failed")
                print(path.name, report["count"], "STRUCTURE_VERIFIED; raw-entry repack exact")
