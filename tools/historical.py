"""Fresh, hash-checked historical compilation/assembly under MS-DOS Player."""
import argparse
import os
import subprocess
import tempfile
from pathlib import Path
from common import ROOT, build_path, dos_text, identity, read_json, require, write_json


def verify_profile(name):
    lock = read_json(ROOT / "layout/toolchain.json")
    require(name in lock["profiles"], "Unknown historical profile")
    profile = lock["profiles"][name]
    for row in [lock["runner"], *profile["files"]]:
        path = Path(row["path"])
        require(path.is_file() and identity(path.read_bytes()) == {k: row[k] for k in ("size", "sha256")},
                f"Pinned historical identity differs: {path}")
    if profile.get("include_directory"):
        base = Path(profile["include_directory"])
        expected = {x["path"]: {k: x[k] for k in ("size", "sha256")} for x in profile["headers"]}
        actual = {p.relative_to(base).as_posix(): identity(p.read_bytes()) for p in base.rglob("*") if p.is_file()}
        require(actual == expected, "Pinned historical include tree differs")
    return lock, profile


def run_program(lock, profile, program, args, directory, timeout=30):
    # Only the profile tool directory and explicitly pinned environment enter
    # DOS. Inheriting the host developer PATH changes behavior and wastes the
    # player's small DOS environment block.
    env = {"PATH": profile["directory"], "MSDOS_PATH": profile["directory"],
           "TEMP": ".", "TMP": ".", "MSDOS_TEMP": "."}
    env.update(profile.get("environment", {}))
    runner = profile.get("runner_override", lock["runner"])
    require(identity(Path(runner["path"]).read_bytes()) == {k: runner[k] for k in ("size", "sha256")}, "Runner identity differs")
    command = [runner["path"], *runner["args"], str(program), *args]
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        result = subprocess.run(command, cwd=directory, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, **options)
        report = {"command": command, "environment": env, "returncode": result.returncode,
                  "timed_out": False, "log": result.stdout.decode("cp437", errors="replace")}
    except subprocess.TimeoutExpired as exc:
        report = {"command": command, "environment": env, "returncode": None,
                  "timed_out": True, "log": (exc.stdout or b"").decode("cp437", errors="replace")}
    return report


def compile(source, profile_name, out=None, headers=()):
    lock, profile = verify_profile(profile_name)
    parent = build_path(out or ROOT / "build/search")
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    source = Path(source).resolve()
    suffix = ".ASM" if profile["kind"] == "asm" else ".C"
    staged = directory / ("PROBE" + suffix)
    text = source.read_text(encoding="latin-1")
    require("\x1a" not in text, "DOS EOF in candidate source would hide part of the complete source")
    staged.write_bytes(dos_text(text))
    staged_headers = []
    if profile.get("include_directory"):
        base = Path(profile["include_directory"])
        for row in profile["headers"]:
            target = directory / "INCLUDE" / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            header_text = (base / row["path"]).read_text(encoding="latin-1").rstrip("\x1a")
            target.write_bytes(dos_text(header_text))
            staged_headers.append({"path": target.relative_to(directory).as_posix(), **identity(target.read_bytes())})
    for path in map(Path, headers):
        require(path.name.upper() not in {p.name.upper() for p in directory.iterdir()}, "Duplicate staged header")
        (directory / path.name.upper()).write_bytes(dos_text(path.read_text(encoding="ascii")))
    args = [*profile["flags"], *(["/IINCLUDE"] if profile.get("include_directory") else []),
            "PROBE.ASM,PROBE.OBJ,PROBE.LST;" if suffix == ".ASM" else "PROBE.C"]
    report = run_program(lock, profile, Path(profile["directory"]) / profile["executable"], args, directory)
    object_path = directory / "PROBE.OBJ"
    success = report["returncode"] == 0 and object_path.is_file()
    report.update({"profile": profile_name, "source": str(source), "source_identity": identity(source.read_bytes()),
                   "staged_input": identity(staged.read_bytes()), "staged_headers": staged_headers, "directory": str(directory),
                   "success": success, "object": identity(object_path.read_bytes()) if success else None})
    (directory / "tool.log").write_text(report["log"], encoding="utf-8")
    # The object parser is mandatory for successful compilation claims.
    if success:
        from omf import read_object
        try:
            write_json(directory / "object.json", read_object(object_path.read_bytes()))
        except ValueError as exc:
            report["success"] = False
            report["omf_error"] = str(exc)
    verify_profile(profile_name)
    write_json(directory / "receipt.json", report)
    return directory, report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source")
    p.add_argument("--profile", required=True)
    p.add_argument("--out", default="build/search")
    p.add_argument("--header", action="append", default=[])
    args = p.parse_args()
    directory, report = compile(args.source, args.profile, args.out, args.header)
    print("PASS" if report["success"] else "FAIL", directory)
    print(report["log"])
    if "omf_error" in report:
        print(report["omf_error"])
    raise SystemExit(0 if report["success"] else 1)
