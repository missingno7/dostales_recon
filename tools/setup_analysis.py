"""Copy user-local modern analysis packages into build/ and check pinned identities."""
import argparse
import shutil
from pathlib import Path
from common import ROOT, read_json, require
from analysis_runtime import prepare


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capstone-from", type=Path)
    parser.add_argument("--unicorn-from", type=Path)
    args = parser.parse_args()
    for name, source in (("capstone", args.capstone_from), ("unicorn", args.unicorn_from)):
        if source:
            require(source.name == name and source.is_dir(), "Source must be the named Python package directory")
            shutil.copytree(source, ROOT / "build/python" / name, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        prepare(name)
        print("PINNED", name)
