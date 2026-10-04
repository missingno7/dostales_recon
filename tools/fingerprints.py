"""Compact observed strings; observations alone do not identify compiler versions."""
import re
from common import ROOT, identity, write_json
from oracle import verify

NEEDLES = (b"Microsoft", b"ITALLOC", b"overlay", b"Library code", b"Incredible")


def observe(image):
    rows = []
    for match in re.finditer(rb"[\x20-\x7e]{8,}", image):
        if any(needle.lower() in match.group().lower() for needle in NEEDLES):
            rows.append({"unit": "root", "start": match.start(), "end": match.end(),
                         "text": match.group().decode("ascii"), "level": "fact"})
    return {"image": identity(image), "observations": rows,
            "inference": "Microsoft runtime and overlay-related infrastructure present; ITALLOC.ASM named by diagnostics",
            "unproven": ["compiler version", "assembler version", "original source module boundaries", "overlay manager attribution"]}


if __name__ == "__main__":
    result = observe(verify(write=False)[1])
    write_json(ROOT / "build/fingerprints.json", result)
    print(result)
