"""Fresh twice-compiled historical behavior probes with complete OMF comparison."""
import argparse
from common import ROOT, read_json, require, write_json
from compare import object_diff
from historical import compile


def run(profiles):
    reports = []
    for profile in profiles:
        pair = [compile(ROOT / "evidence/probes/codegen.c", profile, ROOT / "build/probes") for _ in range(2)]
        require(all(r["success"] for _, r in pair), f"Compiler probe failed: {profile}; {pair}")
        objects = [read_json(d / "object.json") for d, _ in pair]
        comparison = object_diff(*objects)
        require(all(x["exact"] for x in comparison.values()), f"Repeated emitted OMF differs: {profile}")
        reports.append({"profile": profile, "directories": [str(d) for d, _ in pair],
                        "repeat_object_contribution_exact": True,
                        "segments": objects[0]["segments"], "publics": objects[0]["publics"],
                        "fixups": objects[0]["fixups"], "communals": objects[0]["communals"],
                        "comments": objects[0]["comments"],
                        "scope": "Compiler emission regression; does not claim these probes occur in the game"})
    write_json(ROOT / "build/compiler-probes.json", reports)
    return reports


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", action="append")
    args = p.parse_args()
    rows = run(args.profile or ["msc500-medium", "msc510-medium"])
    print("PASS", [(r["profile"], len(r["publics"]), len(r["fixups"])) for r in rows])
