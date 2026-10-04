"""Bounds-checked DOS MZ structure; ordered relocation pairs stay ordered."""
import struct
from common import identity, require

FIELDS = ("signature", "last_page_bytes", "pages", "relocation_count", "header_paragraphs",
          "minalloc", "maxalloc", "ss", "sp", "checksum", "ip", "cs", "relocation_offset", "overlay_number")


def parse(data, offset=0, *, relocation_scope="module"):
    require(relocation_scope in ("module", "shared-root"), "Unknown MZ relocation scope")
    require(offset >= 0 and offset + 28 <= len(data), "Truncated MZ header")
    fields = dict(zip(FIELDS, struct.unpack_from("<14H", data, offset)))
    require(fields["signature"] == 0x5a4d, "Missing MZ signature")
    require(fields["pages"] > 0 and fields["last_page_bytes"] < 512, "Invalid MZ page size")
    size = fields["pages"] * 512
    if fields["last_page_bytes"]:
        size -= 512 - fields["last_page_bytes"]
    header_size = fields["header_paragraphs"] * 16
    require(28 <= header_size <= size and offset + size <= len(data), "MZ extent outside input")
    rel_start = fields["relocation_offset"]
    rel_end = rel_start + fields["relocation_count"] * 4
    require(not fields["relocation_count"] or (28 <= rel_start and rel_end <= header_size), "MZ relocation table outside header")
    image = data[offset + header_size:offset + size]
    relocations = []
    for i in range(fields["relocation_count"]):
        off, seg = struct.unpack_from("<HH", data, offset + rel_start + i * 4)
        linear = seg * 16 + off
        in_image = linear + 2 <= len(image)
        require(in_image or relocation_scope == "shared-root", "MZ relocation outside loaded image")
        relocations.append({"offset": off, "segment": seg, "linear": linear,
                            "in_module_image": in_image,
                            "word": struct.unpack_from("<H", image, linear)[0] if in_image else None})
    return {"header": fields, "file_offset": offset, "declared_size": size,
            "header_size": header_size, "image": identity(image),
            "image_start": offset + header_size, "image_end": offset + size,
            "relocations": relocations, "relocation_scope": relocation_scope,
            "trailing_size": len(data) - offset - size}


def load_image(data, report=None):
    report = report or parse(data)
    return data[report["image_start"]:report["image_end"]]
