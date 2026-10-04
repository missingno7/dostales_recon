"""Independent execution of the executable's own 16-bit EXEPACK stub.

Uses hash-pinned Unicorn from ignored build/python/. The original stub
is executed; emulator output never supplies expected oracle bytes.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

from common import ROOT, identity, write_json
from analysis_runtime import prepare
prepare("unicorn")
from oracle import verify
from mz import parse as parse_mz

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_16
from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_CS, UC_X86_REG_DS,
                               UC_X86_REG_ES, UC_X86_REG_IP, UC_X86_REG_SS,
                               UC_X86_REG_SP)


SOURCE = ROOT / "assets" / "DUCKTALE.EXE"
OUT = ROOT / "build/stub-check"
BASE_SEG = 0x2000
BASE = BASE_SEG * 16
PSP_SEG = BASE_SEG - 0x10
MEMORY_SIZE = 2 * 1024 * 1024
INSTRUCTION_LIMIT = 5_000_000


def main() -> None:
    result = verify(write=False)
    data, root, relocations, summary = result
    report = summary["exepack"]
    OUT.mkdir(parents=True, exist_ok=True)
    packed_header = parse_mz(data)["header"]
    h = report["packed_mz"]["entry"]
    ep = report["exepack"]
    emu = Uc(UC_ARCH_X86, UC_MODE_16)
    emu.mem_map(0, MEMORY_SIZE)
    mz = parse_mz(data)
    emu.mem_write(BASE, data[mz["image_start"]:mz["image_end"]])
    emu.mem_write(PSP_SEG * 16, bytes(256))
    emu.reg_write(UC_X86_REG_AX, 0)
    emu.reg_write(UC_X86_REG_DS, PSP_SEG)
    emu.reg_write(UC_X86_REG_ES, PSP_SEG)
    emu.reg_write(UC_X86_REG_CS, BASE_SEG + h["cs"])
    emu.reg_write(UC_X86_REG_IP, h["ip"])
    emu.reg_write(UC_X86_REG_SS, BASE_SEG + packed_header["ss"])
    emu.reg_write(UC_X86_REG_SP, packed_header["sp"])

    target = BASE + ep["real_cs"] * 16 + ep["real_ip"]
    events: dict[str, object] = {"instructions": 0, "interrupts": [], "target": target}
    reached = False

    def code_hook(uc, address, size, _user):
        nonlocal reached
        events["instructions"] = int(events["instructions"]) + 1
        if address == target:
            reached = True
            events["target_cs"] = uc.reg_read(UC_X86_REG_CS)
            events["target_ip"] = uc.reg_read(UC_X86_REG_IP)
            uc.emu_stop()
        elif int(events["instructions"]) >= INSTRUCTION_LIMIT:
            events["instruction_limit_hit"] = True
            uc.emu_stop()

    def interrupt_hook(uc, intno, _user):
        events["interrupts"].append({"number": intno,
                                     "cs": uc.reg_read(UC_X86_REG_CS),
                                     "ip": uc.reg_read(UC_X86_REG_IP)})
        # A valid unpack path should transfer to the original entry point
        # without needing DOS services. Stop if that invariant is violated.
        uc.emu_stop()

    emu.hook_add(UC_HOOK_CODE, code_hook)
    emu.hook_add(UC_HOOK_INTR, interrupt_hook)
    start = BASE + h["cs"] * 16 + h["ip"]
    emu.emu_start(start, MEMORY_SIZE, count=INSTRUCTION_LIMIT)
    if not reached:
        raise RuntimeError(f"stub did not transfer to original entry; events={events}")

    actual = bytes(emu.mem_read(BASE, len(root)))
    expected = bytearray(root)
    for off, seg in relocations:
        address = seg * 16 + off
        word = struct.unpack_from("<H", expected, address)[0]
        struct.pack_into("<H", expected, address, (word + BASE_SEG) & 0xFFFF)
    mismatch = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), None)
    report_out = {
        "method": "Unicorn 2.1.4 executes original DOS stub in 16-bit mode",
        "unicorn_version": unicorn.__version__,
        "memory_size": MEMORY_SIZE,
        "load_base_segment": BASE_SEG,
        "psp_segment": PSP_SEG,
        "initial_registers": {"cs": BASE_SEG + h["cs"], "ip": h["ip"],
                              "ss": BASE_SEG + packed_header["ss"],
                              "sp": packed_header["sp"],
                              "ds": PSP_SEG, "es": PSP_SEG},
        "instructions": events["instructions"],
        "interrupts": events["interrupts"],
        "transfer_target": {"linear": target, "cs": events["target_cs"],
                            "ip": events["target_ip"]},
        "decoder_output_sha256": hashlib.sha256(root).hexdigest(),
        "emulator_dump_sha256": hashlib.sha256(actual).hexdigest(),
        "relocated_expected_sha256": hashlib.sha256(expected).hexdigest(),
        "relocation_count": len(relocations),
        "relocated_bytes_match": actual == bytes(expected),
        "first_mismatch_offset": mismatch,
    }
    if not report_out["relocated_bytes_match"]:
        raise RuntimeError(f"emulator output differs at {mismatch}: {report_out}")
    (OUT / "emulator-root-relocated.bin").write_bytes(actual)
    (OUT / "emulator.json").write_text(json.dumps(report_out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report_out, indent=2))


if __name__ == "__main__":
    main()
