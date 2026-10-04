"""Conservative recursive x86-16 CFG seed inventory for a flat DOS image.

This reads one extracted image and marks only reachable instruction bytes as code.
Every unvisited byte remains unknown unless explicitly marked as data by the
caller. It never sweeps the whole image for plausible instruction sequences.
"""
import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path

from common import ROOT, build_path, identity
from analysis_runtime import prepare
prepare("capstone")
CAPSTONE_ROOT = ROOT / "build/python"
import capstone  # noqa: E402
from capstone import Cs, CS_ARCH_X86, CS_MODE_16  # noqa: E402
from capstone.x86_const import X86_OP_IMM  # noqa: E402


def merge_ranges(points):
    points = sorted(set(points))
    if not points:
        return []
    ranges = []
    start = prev = points[0]
    for point in points[1:]:
        if point != prev + 1:
            ranges.append([start, prev + 1])
            start = point
        prev = point
    ranges.append([start, prev + 1])
    return ranges


def complement_ranges(size, excluded):
    spans = sorted((max(0, a), min(size, b)) for a, b in excluded if a < size and b > 0)
    result = []
    cursor = 0
    for start, end in spans:
        if end <= cursor:
            continue
        if start > cursor:
            result.append([cursor, start])
        cursor = max(cursor, end)
    if cursor < size:
        result.append([cursor, size])
    return result


def parse_range(value):
    left, right = value.split(":", 1)
    start, end = int(left, 0), int(right, 0)
    if start < 0 or end <= start:
        raise argparse.ArgumentTypeError("ranges must be nonempty START:END byte offsets")
    return [start, end]


def parse_entry(value):
    return int(value, 0)


def run(image, entries, data_ranges, segment_base=0):
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    insns = {}
    covered = {}
    owners = defaultdict(set)
    functions = {}
    pending_functions = deque()
    for label, offset, origin in entries:
        pending_functions.append((label, offset, origin))

    overlap_conflicts = []
    bad_targets = []
    indirect_transfers = []

    while pending_functions:
        label, entry, origin = pending_functions.popleft()
        if label in functions:
            continue
        function = {"label": label, "entry": entry, "origin": origin,
                    "blocks": [], "calls": [], "edges": [], "stops": []}
        functions[label] = function
        blocks = deque([entry])
        seen_blocks = set()
        while blocks:
            start = blocks.popleft()
            if start in seen_blocks:
                continue
            seen_blocks.add(start)
            segment_end = min(segment_base + 0x10000, len(image))
            if not segment_base <= start < segment_end:
                bad_targets.append({"from": start, "target": start, "function": label,
                                    "reason": "block_start_out_of_image"})
                continue
            block = {"start": start, "end": start, "instructions": []}
            function["blocks"].append(block)
            pc = start
            while segment_base <= pc < segment_end:
                if pc in insns:
                    # Existing instruction boundary: sharing is allowed; entering
                    # the middle of one is recorded and left unclassified.
                    owners[pc].add(label)
                    if pc != start:
                        function["edges"].append({"kind": "fallthrough", "from": block["end"], "to": pc})
                    break
                if pc in covered:
                    overlap_conflicts.append({"function": label, "offset": pc, "reason": "enters_instruction_interior"})
                    function["stops"].append({"at": pc, "reason": "overlapping_decode"})
                    break
                logical_ip = pc - segment_base
                # Do not consume bytes beyond this CS window. Instructions
                # spanning the wrap need an explicit fetch model; stop here.
                decoded = next(md.disasm(image[pc:segment_end], logical_ip, count=1), None)
                if decoded is None or decoded.size <= 0:
                    function["stops"].append({"at": pc, "reason": "invalid_or_truncated_instruction"})
                    break
                end = pc + decoded.size
                if any(max(pc, a) < min(end, b) for a, b in data_ranges):
                    function["stops"].append({"at": pc, "reason": "explicit_data_range"})
                    break
                row = {"offset": pc, "size": decoded.size,
                       "bytes": bytes(decoded.bytes).hex(), "mnemonic": decoded.mnemonic,
                       "operands": decoded.op_str}
                insns[pc] = row
                for byte_offset in range(pc, end):
                    covered[byte_offset] = pc
                owners[pc].add(label)
                block["instructions"].append(pc)
                block["end"] = end
                pc = end

                mnemonic = decoded.mnemonic.lower()
                groups = set(decoded.groups)
                is_call = decoded.group(capstone.CS_GRP_CALL)
                is_jump = decoded.group(capstone.CS_GRP_JUMP)
                is_ret = decoded.group(capstone.CS_GRP_RET) or decoded.group(capstone.CS_GRP_IRET)
                imm = None
                imm_operands = []
                if decoded.operands and decoded.operands[0].type == X86_OP_IMM:
                    imm = decoded.operands[0].imm
                imm_operands = [operand.imm for operand in decoded.operands
                                if operand.type == X86_OP_IMM]
                is_far = mnemonic in {"lcall", "ljmp"}
                next_pc = segment_base + ((logical_ip + decoded.size) & 0xFFFF)
                if is_call and is_far:
                    if len(imm_operands) >= 2:
                        far_pointer = {"segment": imm_operands[0] & 0xFFFF,
                                       "offset": imm_operands[1] & 0xFFFF}
                        if far_pointer["segment"] == (segment_base >> 4):
                            target = segment_base + far_pointer["offset"]
                            if target < segment_end:
                                target_label = f"far_sub_{target:04X}"
                                function["calls"].append({"from": row["offset"], "to": target,
                                                          "kind": "far_direct_same_cs", "pointer": far_pointer})
                                if target_label not in functions:
                                    pending_functions.append((target_label, target, "direct_far_call_same_cs"))
                            else:
                                function["calls"].append({"from": row["offset"], "kind": "far_direct_same_cs_out_of_image",
                                                          "pointer": far_pointer})
                        else:
                            function["calls"].append({"from": row["offset"], "kind": "far_direct",
                                                      "pointer": far_pointer,
                                                      "resolution": "unmapped_runtime_segment"})
                            function["edges"].append({"kind": "far_call", "from": row["offset"],
                                                      "pointer": far_pointer})
                    else:
                        function["calls"].append({"from": row["offset"], "kind": "far_indirect",
                                                  "operands": decoded.op_str})
                        indirect_transfers.append({"function": label, "at": row["offset"],
                                                   "kind": "far_call", "mnemonic": mnemonic,
                                                   "operands": decoded.op_str})
                    function["edges"].append({"kind": "fallthrough", "from": row["offset"], "to": next_pc})
                    if next_pc < segment_end:
                        blocks.append(next_pc)
                    else:
                        function["stops"].append({"at": next_pc, "reason": "fallthrough_at_image_end"})
                    break
                if is_call:
                    target = segment_base + (imm & 0xFFFF) if imm is not None else None
                    if target is not None and segment_base <= target < segment_end:
                        target_label = f"sub_{target:04X}"
                        function["calls"].append({"from": row["offset"], "to": target, "kind": "near_direct"})
                        function["edges"].append({"kind": "call", "from": row["offset"], "to": target})
                        if target_label not in functions:
                            pending_functions.append((target_label, target, "direct_near_call"))
                    else:
                        reason = "indirect_call" if imm is None else "call_target_out_of_image"
                        function["calls"].append({"from": row["offset"], "kind": reason,
                                                  **({"logical_target": imm} if imm is not None else {})})
                        if imm is None:
                            indirect_transfers.append({"function": label, "at": row["offset"], "kind": "call",
                                                       "mnemonic": mnemonic, "operands": decoded.op_str})
                    function["edges"].append({"kind": "fallthrough", "from": row["offset"], "to": next_pc})
                    if next_pc < segment_end:
                        blocks.append(next_pc)
                    else:
                        function["stops"].append({"at": next_pc, "reason": "fallthrough_at_image_end"})
                    break
                if is_ret or mnemonic in {"hlt", "ud2"}:
                    function["stops"].append({"at": row["offset"], "reason": "return" if is_ret else mnemonic})
                    break
                if is_jump:
                    if is_far:
                        if len(imm_operands) >= 2 and (imm_operands[0] & 0xFFFF) == (segment_base >> 4):
                            target = segment_base + (imm_operands[1] & 0xFFFF)
                            if target < segment_end:
                                function["edges"].append({"kind": "far_jump_same_cs", "from": row["offset"],
                                                          "to": target})
                                blocks.append(target)
                                break
                        function["stops"].append({"at": row["offset"], "reason": "far_jump_unmapped"})
                        if len(imm_operands) >= 2:
                            indirect_transfers.append({"function": label, "at": row["offset"],
                                                       "kind": "far_direct_jump",
                                                       "pointer": {"segment": imm_operands[0] & 0xFFFF,
                                                                   "offset": imm_operands[1] & 0xFFFF}})
                        else:
                            indirect_transfers.append({"function": label, "at": row["offset"],
                                                       "kind": "far_indirect_jump",
                                                       "mnemonic": mnemonic, "operands": decoded.op_str})
                        break
                    conditional = mnemonic not in {"jmp", "ljmp"}
                    target = segment_base + (imm & 0xFFFF) if imm is not None else None
                    if target is not None:
                        if segment_base <= target < segment_end:
                            kind = "conditional_taken" if conditional else "jump"
                            function["edges"].append({"kind": kind, "from": row["offset"], "to": target})
                            blocks.append(target)
                        else:
                            bad_targets.append({"function": label, "from": row["offset"],
                                                "logical_target": imm, "target": target,
                                                "reason": "direct_branch_out_of_image"})
                        if conditional:
                            function["edges"].append({"kind": "conditional_fallthrough", "from": row["offset"], "to": next_pc})
                            if next_pc < segment_end:
                                blocks.append(next_pc)
                            else:
                                function["stops"].append({"at": next_pc, "reason": "fallthrough_at_image_end"})
                    else:
                        function["stops"].append({"at": row["offset"], "reason": "indirect_jump"})
                        indirect_transfers.append({"function": label, "at": row["offset"], "kind": "jump",
                                                   "mnemonic": mnemonic, "operands": decoded.op_str})
                    break
                if next_pc != pc:
                    function["edges"].append({"kind": "fallthrough", "from": row["offset"], "to": next_pc})
                    if segment_base <= next_pc < segment_end:
                        blocks.append(next_pc)
                    break
            else:
                function["stops"].append({"at": pc, "reason": "image_end"})

    code_bytes = set()
    for offset, row in insns.items():
        code_bytes.update(range(offset, offset + row["size"]))
        row["functions"] = sorted(owners[offset])
    explicit_data_bytes = {p for a, b in data_ranges for p in range(a, min(b, len(image)))}
    conflict_bytes = {x["offset"] for x in overlap_conflicts}
    categories = {
        "code": merge_ranges(code_bytes),
        "explicit_data": merge_ranges(explicit_data_bytes),
        "unknown": complement_ranges(len(image), [(p, p + 1) for p in code_bytes | explicit_data_bytes]),
    }
    candidates = []
    for func in functions.values():
        offsets = [p for b in func["blocks"] for p in b["instructions"]]
        candidates.append({"entry": func["entry"], "label": func["label"],
                           "origin": func["origin"], "decoded_bytes": sum(insns[p]["size"] for p in offsets),
                           "instruction_count": len(offsets), "direct_call_count": sum(c["kind"] == "near_direct" for c in func["calls"]),
                           "stop_reasons": sorted({s["reason"] for s in func["stops"]})})
    candidates.sort(key=lambda x: (x["decoded_bytes"], x["entry"]))
    return {"schema": "dos16-recursive-cfg-seed-v1", "decoder": {"name": "Capstone",
            "version": capstone.__version__, "api_version": ".".join(map(str, capstone.cs_version())),
            "architecture": "x86-16", "path": str(CAPSTONE_ROOT)},
            "image_size": len(image), "image_identity": identity(image), "segment_base": segment_base,
            "segment_bounds": [segment_base, min(segment_base + 0x10000, len(image))], "entries": [
            {"label": label, "offset": offset, "origin": origin} for label, offset, origin in entries],
            "categories": categories, "functions": list(functions.values()),
            "instructions": [insns[p] for p in sorted(insns)],
            "diagnostics": {"overlap_conflicts": overlap_conflicts, "bad_targets": bad_targets,
                            "indirect_transfers": indirect_transfers},
            "representative_small_function_candidates": candidates[:32],
            "classification_note": "Reachable decoded bytes are provisional code. Unvisited bytes remain unknown; explicit data requires caller ranges. An indirect call preserves fallthrough but its target is unresolved; an indirect jump terminates traversal."}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path, help="flat extracted DOS image bytes")
    ap.add_argument("--entry", action="append", type=parse_entry, default=[],
                    help="code entry image offset, decimal or 0x-prefixed (repeatable)")
    ap.add_argument("--segment-base", type=parse_entry, default=0,
                    help="flat image offset corresponding to CS:0000 for 16-bit relative flow (default: 0)")
    ap.add_argument("--data-range", action="append", type=parse_range, default=[],
                    help="explicit data byte range START:END (exclusive end), repeatable")
    ap.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = ap.parse_args()
    version = capstone.cs_version()
    if capstone.__version__ != "5.0.3":
        ap.error(f"expected pinned Capstone 5.0.3 from {CAPSTONE_ROOT}, got {capstone.__version__} / {version}")
    image = args.image.read_bytes()
    entries = [("entry" if i == 0 else f"seed_{offset:04X}", offset, "explicit_seed")
               for i, offset in enumerate(args.entry)]
    if not entries:
        ap.error("supply at least one --entry image offset; derive it from MZ CS:IP after confirming image layout")
    if any(end > len(image) for _, end in args.data_range):
        ap.error("data range extends outside image")
    report = run(image, entries, args.data_range, args.segment_base)
    args.out = build_path(args.out)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out), "image_size": len(image), "image_identity": identity(image),
                      "decoded_instructions": len(report["instructions"]),
                      "functions": len(report["functions"]),
                      "indirect_transfers": len(report["diagnostics"]["indirect_transfers"]),
                      "code_ranges": len(report["categories"]["code"]),
                      "unknown_ranges": len(report["categories"]["unknown"])}, indent=2))


if __name__ == "__main__":
    main()
