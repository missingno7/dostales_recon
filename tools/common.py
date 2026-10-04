"""Small shared primitives. Verification never writes tracked identities."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def identity(data):
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build_path(path):
    path = Path(path).resolve()
    require(path.is_relative_to((ROOT / "build").resolve()), "Output must be inside ignored build/")
    return path


def dos_text(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n").encode("latin-1")
