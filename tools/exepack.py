"""Bounded, target-validated EXEPACK-16 decoder for DuckTales.

This implements the verified EXEPACK-16 profile. It treats the MZ main image, its embedded EXEPACK block,
and the following DOS overlay modules as separate regions.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "tools"))
from common import identity, write_json  # noqa: E402
from mz import parse as parse_mz  # noqa: E402


MZ_FIELDS = ("signature", "last_page_bytes", "pages", "relocation_count",
             "header_paragraphs", "minalloc", "maxalloc", "ss", "sp",
             "checksum", "ip", "cs", "relocation_offset", "overlay_number")


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _parse_overlay_mz(data: bytes, offset: int) -> dict[str, object]:
    """Parse an MZ overlay extent, retaining shared load coordinates.

    The standalone MZ parser correctly rejects relocations outside the member's
    own loaded image. DuckTales records encode sites within the shared arena
    starting at root linear 0xc170, using 0x0c17 and higher segment values.
    This parser validates file bounds and preserves those encoded coordinates;
    overlays.py independently verifies every site against its loaded module.
    """
    _need(offset >= 0 and offset + 28 <= len(data), "truncated overlay MZ header")
    values = struct.unpack_from("<14H", data, offset)
    h = dict(zip(MZ_FIELDS, values))
    _need(h["signature"] == 0x5A4D, "missing overlay MZ signature")
    _need(h["pages"] > 0 and h["last_page_bytes"] < 512, "invalid overlay MZ page count")
    declared = h["pages"] * 512
    if h["last_page_bytes"]:
        declared -= 512 - h["last_page_bytes"]
    header_size = h["header_paragraphs"] * 16
    _need(28 <= header_size <= declared, "invalid overlay MZ header size")
    _need(offset + declared <= len(data), "overlay MZ extent exceeds input")
    rel_start = h["relocation_offset"]
    rel_end = rel_start + h["relocation_count"] * 4
    _need(not h["relocation_count"] or (28 <= rel_start and rel_end <= header_size),
          "overlay MZ relocation table outside its header")
    relocs = []
    for i in range(h["relocation_count"]):
        off, seg = struct.unpack_from("<HH", data, offset + rel_start + i * 4)
        relocs.append({"offset": off, "segment": seg,
                       "linear": seg * 16 + off})
    return {"header": h, "file_offset": offset, "declared_size": declared,
            "header_size": header_size, "image_start": offset + header_size,
            "image_end": offset + declared, "relocations": relocs,
            "trailing_size": len(data) - offset - declared}


def scan_overlays(data: bytes, primary_end: int | None = None) -> list[dict[str, object]]:
    """Return validated, sequential MZ overlay extents after the primary MZ.

    The target's modules begin at 256-byte boundaries. Alignment gaps must be
    all zero; each overlay's MZ header carries its 1-based overlay number.
    """
    main = parse_mz(data)
    cursor = main["image_end"] if primary_end is None else primary_end
    _need(cursor == main["image_end"], "overlay scan must begin at the primary MZ end")
    overlays: list[dict[str, object]] = []
    number = 1
    while cursor < len(data):
        start = (cursor + 255) // 256 * 256
        # The format pads each overlay to a 256-byte boundary, but the next
        # module is not guaranteed to use the first such boundary. Empty
        # 256-byte zero blocks can precede it.
        while start + 2 <= len(data) and data[start:start + 2] != b"MZ":
            _need(not any(data[start:min(start + 256, len(data))]),
                  f"nonzero bytes in unclassified overlay gap at 0x{start:x}")
            start += 256
        _need(start <= len(data), "overlay alignment exceeds input")
        _need(not any(data[cursor:start]), f"nonzero bytes in gap before overlay {number}")
        if start == len(data) or start + 2 > len(data):
            break
        mz = _parse_overlay_mz(data, start)
        _need(mz["header"]["overlay_number"] == number,
              f"overlay at 0x{start:x} has number {mz['header']['overlay_number']}, expected {number}")
        _need(mz["image_end"] <= len(data), "overlay extent exceeds input")
        overlays.append({
            "number": number,
            "file_start": start,
            "file_end": mz["image_end"],
            "gap_start": cursor,
            "gap_end": start,
            "gap_size": start - cursor,
            "declared_size": mz["declared_size"],
            "header_size": mz["header_size"],
            "image_start": mz["image_start"],
            "image_end": mz["image_end"],
            "header": mz["header"],
            "relocation_count": len(mz["relocations"]),
            "relocations": mz["relocations"],
            "file": identity(data[start:mz["image_end"]]),
            "load_image": identity(data[mz["image_start"]:mz["image_end"]]),
        })
        cursor = mz["image_end"]
        number += 1
    _need(cursor == len(data), f"unaccounted trailing bytes at 0x{cursor:x}")
    return overlays


def unpack(data: bytes) -> tuple[bytes, list[tuple[int, int]], dict[str, object]]:
    """Depack the primary MZ image and return `(load_image, relocations, report)`.

    The supported 16-byte EXEPACK header is immediately before the MZ entry
    stub. Reverse-stream token decoding preserves the uncompressed prefix at
    the beginning of the MZ image. Relocations are returned as `(offset,
    segment)` pairs grouped in the encoded 0000h..F000h subtable order.
    """
    mz = parse_mz(data)
    h = mz["header"]
    _need(h["relocation_count"] == 0, "expected EXEPACK to move primary relocations out of the MZ table")
    _need(mz["header_size"] == 0x200, "unexpected primary MZ header size")
    _need(h["sp"] == 0x0080, "unexpected EXEPACK entry stack pointer")
    entry_file = mz["image_start"] + h["cs"] * 16 + h["ip"]
    _need(mz["image_start"] <= entry_file < mz["image_end"], "MZ entry is outside the primary image")
    _need(h["ip"] == 0x0010, "unexpected primary EXEPACK entry IP")
    exepack_start = entry_file - 16
    _need(exepack_start >= mz["image_start"], "truncated EXEPACK header")
    _need(exepack_start % 16 == 0, "EXEPACK header is not paragraph aligned")
    words = struct.unpack_from("<8H", data, exepack_start)
    real_ip, real_cs, mem_start, exepack_size, real_sp, real_ss, dest_len, signature = words
    _need(signature == 0x4252, "missing 16-byte EXEPACK RB signature")
    _need(exepack_size == mz["image_end"] - exepack_start,
          "EXEPACK size does not terminate at the primary MZ boundary")
    _need(exepack_size >= 16, "invalid EXEPACK size")
    output_size = dest_len * 16
    _need(output_size > 0, "zero EXEPACK destination length")

    error_text = b"Packed file is corrupt"
    error_start = data.find(error_text, entry_file, mz["image_end"])
    _need(error_start >= entry_file, "EXEPACK error text not found after the entry stub")
    _need(data.count(error_text, entry_file, mz["image_end"]) == 1,
          "EXEPACK error text is not unique in the primary image tail")
    reloc_start = error_start + len(error_text)
    _need(reloc_start <= mz["image_end"], "EXEPACK relocation table begins outside the primary image")

    # Sixteen subtables: WORD count, followed by count WORD offsets. The
    # segment is implied by the table index (index * 1000h).
    pos = reloc_start
    relocations: list[tuple[int, int]] = []
    group_counts: list[int] = []
    for group in range(16):
        _need(pos + 2 <= mz["image_end"], "truncated EXEPACK relocation count")
        count = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        _need(pos + count * 2 <= mz["image_end"], "truncated EXEPACK relocation entries")
        group_counts.append(count)
        segment = group * 0x1000
        for _ in range(count):
            offset = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            relocations.append((offset, segment))
    _need(pos == mz["image_end"], "EXEPACK relocation groups do not fill the advertised block")

    packed = data[mz["image_start"]:exepack_start]
    src = len(packed) - 1
    pad_count = 0
    while src >= 0 and packed[src] == 0xFF:
        src -= 1
        pad_count += 1
    _need(pad_count <= 15, "EXEPACK paragraph padding exceeds 15 bytes")
    output = bytearray(output_size)
    dst = output_size - 1
    token_count = 0
    run_count = 0
    literal_count = 0
    while True:
        _need(src >= 0, "EXEPACK stream ended before a final token")
        marker = packed[src]
        src -= 1
        command = marker & 0xFE
        _need(command in (0xB0, 0xB2), f"unknown EXEPACK marker 0x{marker:02x}")
        _need(src >= 1, "truncated EXEPACK token count")
        count = (packed[src] << 8) | packed[src - 1]
        src -= 2
        _need(count > 0, "zero-length EXEPACK token")
        _need(dst + 1 >= count, "EXEPACK output exceeds destination length")
        if command == 0xB0:
            _need(src >= 0, "truncated EXEPACK run value")
            value = packed[src]
            src -= 1
            output[dst + 1 - count:dst + 1] = bytes((value,)) * count
            dst -= count
            run_count += 1
        else:
            _need(src + 1 >= count, "truncated EXEPACK literal data")
            for _ in range(count):
                output[dst] = packed[src]
                dst -= 1
                src -= 1
            literal_count += 1
        token_count += 1
        if marker & 1:
            break

    # EXEPACK leaves a leading, uncompressed image prefix in place. The
    # backwards decoder must stop at the same relative source/destination byte.
    source_prefix = src + 1
    destination_prefix = dst + 1
    _need(source_prefix == destination_prefix,
          f"EXEPACK prefix disagreement: source {source_prefix}, destination {destination_prefix}")
    _need(source_prefix <= len(packed), "EXEPACK prefix exceeds packed data")
    output[:destination_prefix] = packed[:source_prefix]

    invalid_relocations = [pair for pair in relocations
                           if pair[1] * 16 + pair[0] + 2 > len(output)]
    _need(not invalid_relocations, f"{len(invalid_relocations)} relocations exceed depacked image")
    _need(len(set(relocations)) == len(relocations), "duplicate EXEPACK relocation address")

    report: dict[str, object] = {
        "variant": "EXEPACK-16/RB",
        "packed_mz": {
            "file_size": len(data),
            "declared_size": mz["declared_size"],
            "header_size": mz["header_size"],
            "image_start": mz["image_start"],
            "image_end": mz["image_end"],
            "trailing_size": mz["trailing_size"],
            "entry": {"ip": h["ip"], "cs": h["cs"], "sp": h["sp"],
                      "ss": h["ss"], "file_offset": entry_file,
                      "image_linear": h["cs"] * 16 + h["ip"]},
        },
        "exepack": {
            "header_start": exepack_start,
            "header_end": exepack_start + 16,
            "header_size": 16,
            "signature": "RB",
            "real_ip": real_ip,
            "real_cs": real_cs,
            "mem_start": mem_start,
            "exepack_size": exepack_size,
            "real_sp": real_sp,
            "real_ss": real_ss,
            "dest_len_paragraphs": dest_len,
            "output_size": output_size,
            "stub_start": entry_file,
            "stub_end": error_start,
            "stub_size": error_start - entry_file,
            "stub_sha256": hashlib.sha256(data[entry_file:error_start]).hexdigest(),
            "error_text_start": error_start,
            "error_text_end": reloc_start,
            "relocation_table_start": reloc_start,
            "relocation_table_end": pos,
            "relocation_group_counts": group_counts,
            "relocation_count": len(relocations),
        },
        "stream": {
            "packed_start": mz["image_start"],
            "packed_end_exclusive": exepack_start,
            "packed_size": len(packed),
            "ff_padding_bytes": pad_count,
            "token_count": token_count,
            "run_token_count": run_count,
            "literal_token_count": literal_count,
            "source_prefix_size": source_prefix,
            "destination_prefix_size": destination_prefix,
        },
        "root_image": identity(bytes(output)),
        "root_entry": {"ip": real_ip, "cs": real_cs,
                       "image_linear": real_cs * 16 + real_ip},
        "root_stack": {"sp": real_sp, "ss": real_ss},
        "root_relocations": [[off, seg] for off, seg in relocations],
    }
    return bytes(output), relocations, report


def analyze(data: bytes) -> dict[str, object]:
    """Combine depacking and overlay boundary evidence without writing files."""
    image, relocs, report = unpack(data)
    report["overlays"] = scan_overlays(data)
    return report
