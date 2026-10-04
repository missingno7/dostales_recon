"""Inventory every original without modifying it."""
from common import ROOT, identity, write_json


def inventory(asset_dir=None):
    asset_dir = asset_dir or ROOT / "assets"
    result = {}
    for path in sorted(asset_dir.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            name = path.relative_to(asset_dir).as_posix()
            fmt = "MZ" if data[:2] == b"MZ" else "text" if path.suffix.upper() == ".TXT" else "unresolved"
            result[name] = {**identity(data), "basic_format": fmt}
    return result


if __name__ == "__main__":
    result = inventory()
    write_json(ROOT / "build/inventory.json", result)
    print(f"{len(result)} assets, {sum(x['size'] for x in result.values())} bytes; build/inventory.json")
