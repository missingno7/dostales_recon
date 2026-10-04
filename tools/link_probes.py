"""Fresh C/ASM native-data and far-fixup LINK/run tests, independent of game matching."""
import shutil
from pathlib import Path
from common import ROOT, dos_text, identity, read_json, require, write_json
from historical import compile, run_program, verify_profile
from mz import parse


def run(profiles=("msc500-medium", "msc510-medium")):
    rows = []
    for name in profiles:
        cdir, cr = compile(ROOT / "evidence/probes/link.c", name, ROOT / "build/link-probes")
        adir, ar = compile(ROOT / "evidence/probes/link.asm", "masm510-game", ROOT / "build/link-probes")
        require(cr["success"] and ar["success"], "C-to-ASM probe compilation failed")
        # Complete objects are passed to LINK, never altered or stripped.
        shutil.copyfile(adir / "PROBE.OBJ", cdir / "ASM.OBJ")
        lock, profile = verify_profile(name)
        library = str(Path(profile["runtime_library"]))
        response = f"PROBE.OBJ+ASM.OBJ /NOD\nPROBE.EXE\nPROBE.MAP\n{library};\n"
        (cdir / "LINK.RSP").write_bytes(dos_text(response))
        linked = run_program(lock, profile, profile["linker"]["path"], ["@LINK.RSP"], cdir)
        write_json(cdir / "link-receipt.json", linked)
        require(linked["returncode"] == 0 and (cdir / "PROBE.EXE").is_file(), f"Historical LINK failed: {linked}")
        exe = (cdir / "PROBE.EXE").read_bytes()
        mz = parse(exe)
        require(mz["header"]["relocation_count"] > 0, "Far-call probe unexpectedly has no relocations")
        executed = run_program(lock, profile, cdir / "PROBE.EXE", [], cdir)
        write_json(cdir / "run-receipt.json", executed)
        require(executed["returncode"] == 0, f"Historical C-to-ASM/global-data execution failed: {executed}")
        verify_profile(name)
        rows.append({"profile": name, "directory": str(cdir), "native_exe": identity(exe),
                     "ordered_relocations": mz["relocations"], "compile": cr["success"],
                     "assemble": ar["success"], "link": linked, "run": executed,
                     "response": identity((cdir / "LINK.RSP").read_bytes()),
                     "proof_level": "COMPILER_LINK_PROBE_ONLY"})
    write_json(ROOT / "build/link-probes.json", rows)
    return rows


if __name__ == "__main__":
    print("PASS", [(r["profile"], r["native_exe"]["size"], len(r["ordered_relocations"])) for r in run()])
