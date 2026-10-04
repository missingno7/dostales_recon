"""Fresh bootstrap proof gates; never awards full reconstructed-game equality."""
import contextlib
import io
import tempfile
import traceback
import unittest
from datetime import datetime, timezone
from common import ROOT, identity, read_json, require, write_json


def run():
    directory = ROOT / "build/validation"
    directory.mkdir(parents=True, exist_ok=True)
    fresh = tempfile.mkdtemp(prefix="run-", dir=directory)
    from pathlib import Path
    fresh = Path(fresh)
    report = {"schema": 1, "result": "IN_PROGRESS", "directory": str(fresh),
              "started_utc": datetime.now(timezone.utc).isoformat(), "stages": {},
              "scope": "Forensic bootstrap and historical tool probes; no complete game source build"}
    latest = ROOT / "build/validation.json"
    write_json(latest, report)  # Invalidate any previous successful validation first.

    def stage(name, function):
        print(name, flush=True)
        report["stages"][name] = function()
        write_json(fresh / "report.json", report)
        write_json(latest, report)

    try:
        lock_before = identity((ROOT / "layout/oracle.lock.json").read_bytes())
        from oracle import verify
        result = verify(out=fresh / "oracle")
        stage("oracle", lambda: {"lock": lock_before, "root": result[3]["root_image"],
                                 "overlays": len(result[3]["overlays"]), "assets": len(result[3]["inputs"])})

        def tests():
            output = io.StringIO()
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
            outcome = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
            (fresh / "tests.log").write_text(output.getvalue(), encoding="utf-8")
            require(outcome.testsRun > 0 and outcome.wasSuccessful(), "Proof regression tests failed")
            return {"passed": outcome.testsRun, "log": str(fresh / "tests.log")}
        stage("proof_regressions", tests)

        def stub():
            import check_stub
            check_stub.OUT = fresh / "stub"
            with contextlib.redirect_stdout(io.StringIO()):
                check_stub.main()
            return read_json(check_stub.OUT / "emulator.json")
        stage("original_exepack_stub", stub)

        from overlays import analyze
        stage("shared_overlay_arena", lambda: analyze(result))

        def resources():
            from resources import extract, repack
            rows = []
            for name in result[3]["resources"]:
                original = (ROOT / "assets" / name).read_bytes()
                destination = fresh / "resources" / name
                parsed = extract(original, destination)
                actual = repack(destination)  # Read extracted disk members; rebuild the index.
                require(actual == original, f"Resource disk roundtrip differs: {name}")
                rows.append({"name": name, "entries": parsed["count"], "repacked": identity(actual)})
            return rows
        stage("raw_resource_roundtrips", resources)

        from compiler_probes import run as compiler_probes
        stage("fresh_compiler_probes", lambda: compiler_probes(
            ["msc500-medium", "msc510-medium", "msc510-medium-size", "msc600-medium"]))
        from link_probes import run as link_probes
        stage("fresh_link_and_execution", link_probes)

        def representatives():
            from historical import compile
            from match import compare_segment, image_for
            from omf import read_object
            rows = []
            for sample in read_json(ROOT / "layout/representatives.json")["samples"]:
                destination, receipt = compile(ROOT / sample["source"], sample["profile"], fresh / "representatives")
                require(receipt["success"], f"Representative compile failed: {sample['id']}")
                obj = read_object((destination / "PROBE.OBJ").read_bytes())
                image, relocations = image_for(sample["unit"], result)
                comparison = compare_segment(obj, image, sample["start"], sample["end"], sample["segment"], relocations)
                require(comparison["proof_level"] == sample["proof_level"] == "CODE_BYTES_EXACT",
                        f"Representative changed: {sample['id']}")
                require(not comparison["obligations"]["fixups"] and not comparison["obligations"]["other_segments"],
                        "Representative acquired unreviewed fixups/native storage")
                rows.append({"sample": sample, "receipt": receipt, "comparison": comparison})
            return rows
        stage("complete_region_byte_examples", representatives)

        from status import generate
        stage("ownership_and_runtime", lambda: generate(result))
        verified_again = verify(write=False)
        require(result[3] == verified_again[3], "Original inputs changed during validation")
        require(identity((ROOT / "layout/oracle.lock.json").read_bytes()) == lock_before, "Oracle lock changed")
        report["full_game_acceptance"] = report["stages"]["ownership_and_runtime"]["full_game_acceptance"]
        report["result"] = "BOOTSTRAP_VERIFIED"
    except Exception as exc:
        report["result"] = "FAILED"
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(fresh / "report.json", report)
    write_json(latest, report)
    print(report["result"], latest)
    if report["result"] == "FAILED":
        print(report["traceback"])
    return report


if __name__ == "__main__":
    raise SystemExit(0 if run()["result"] == "BOOTSTRAP_VERIFIED" else 1)
