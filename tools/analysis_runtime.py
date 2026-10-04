"""Load only the hash-pinned analysis packages in ignored build/python/."""
import sys
from pathlib import Path
from common import ROOT, identity, read_json, require


def prepare(package):
    lock = read_json(ROOT / "layout/analysis.json")["packages"][package]
    base = ROOT / "build/python"
    for row in lock["files"]:
        path = base / row["path"]
        require(path.is_file() and identity(path.read_bytes()) == {k: row[k] for k in ("size", "sha256")},
                f"Analysis dependency missing/changed: {path}; see docs/setup.md")
    if str(base) not in sys.path:
        sys.path.insert(0, str(base))
