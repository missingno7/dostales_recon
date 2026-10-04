"""Check loader-grounded overlay extents; retain encoded and local relocations."""
import struct
from common import ROOT, read_json, require, write_json
from mz import load_image
from oracle import verify


def arena_base():
    return read_json(ROOT / "layout/overlays.json")["shared_arena_linear"]


def analyze(result=None):
    result = result or verify(write=False)
    base = arena_base()
    max_size = max(o["mz"]["image"]["size"] for o in result[3]["overlays"])
    require(base + max_size <= len(result[1]), "Shared arena exceeds root image")
    require(not any(result[1][base:base + max_size]), "Original shared arena is no longer zero-filled")
    rows = []
    for overlay in result[3]["overlays"]:
        mz = overlay["mz"]
        image = load_image(result[0], mz)
        sites = []
        for relocation in mz["relocations"]:
            local = relocation["linear"] - base
            require(0 <= local and local + 2 <= len(image), "Overlay relocation is outside its loaded module")
            sites.append({**relocation, "module_offset": local,
                          "native_word_in_overlay": struct.unpack_from("<H", image, local)[0]})
        rows.append({"id": overlay["id"], "e_ovno": mz["header"]["overlay_number"],
                     "file_start": mz["file_offset"], "file_end": mz["image_end"],
                     "image_size": len(image), "loaded_range": [base, base + len(image)],
                     "relocations": sites})
    root = result[1]
    thunks = [{"offset": i, "target_segment_id": root[i + 2],
               "target_offset": struct.unpack_from("<H", root, i + 3)[0]}
              for i in range(len(root) - 4) if root[i:i + 2] == b"\xcd\x3f"]
    report = {"schema": 1, "shared_arena": [base, base + max_size], "root_arena_zero_filled": True,
              "modules": rows, "raw_int3f_sequences": thunks,
              "sequence_scope": "Raw instruction-pattern inventory; reachability and segment-ID map need separate proof",
              "target_segment_to_e_ovno": "UNRESOLVED"}
    write_json(ROOT / "build/analysis/overlays.json", report)
    return report


if __name__ == "__main__":
    report = analyze()
    print("STRUCTURE_VERIFIED", report["shared_arena"],
          [(o["id"], o["image_size"], len(o["relocations"])) for o in report["modules"]])
