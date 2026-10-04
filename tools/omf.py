"""Strict reader for the common 16-bit Intel OMF object records.

The reader intentionally rejects record types it does not model: silently
ignoring linker directives makes a byte-level comparison look more complete
than it is.  Returned data is JSON serializable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


NAMES = {
    0x80: "THEADR", 0x82: "LHEADR", 0x88: "COMENT", 0x8A: "MODEND", 0x8B: "MODEND32",
    0x96: "LNAMES", 0x98: "SEGDEF", 0x9A: "GRPDEF",
    0x8C: "EXTDEF", 0x90: "PUBDEF", 0xA0: "LEDATA",
    0xA2: "LIDATA", 0x9C: "FIXUPP", 0xB0: "COMDEF",
    0xF0: "LIBHDR", 0xF1: "LIBEND",
}
SUPPORTED = {0x80, 0x82, 0x88, 0x8A, 0x96, 0x98, 0x9A, 0x8C, 0x90, 0xA0, 0xA2, 0x9C, 0xB0}
# Comment classes emitted by Microsoft C 5.x/6.x and Microsoft-compatible
# linkers. Their payloads are retained byte-for-byte for exact comparison.
KNOWN_COMMENT_CLASSES = {0x00, 0x9D, 0x9F, 0xA1, 0xA2, 0xA3}


class OMFError(ValueError):
    """Malformed or unsupported OMF input."""


@dataclass
class Cursor:
    data: bytes
    pos: int = 0

    @property
    def left(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.left:
            raise OMFError("truncated record field")
        b = self.data[self.pos:self.pos+n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def index(self) -> int:
        a = self.u8()
        return ((a & 0x7f) << 8) | self.u8() if a & 0x80 else a

    def string(self) -> str:
        try:
            return self.take(self.u8()).decode("ascii")
        except UnicodeDecodeError as e:
            raise OMFError("non-ASCII OMF name") from e

    def done(self) -> None:
        if self.left:
            raise OMFError(f"{self.left} unexpected trailing record byte(s)")


@dataclass
class Segment:
    index: int
    name: str
    length: int
    alignment: str
    combine: str
    class_name: str
    use16: bool = True
    big: bool = False
    absolute_frame: int | None = None
    absolute_offset: int | None = None
    overlay_name: str = ""
    data: bytearray = field(default_factory=bytearray)
    ranges: list[list[int]] = field(default_factory=list)

    def add(self, offset: int, payload: bytes) -> None:
        end = offset + len(payload)
        if end > self.length:
            raise OMFError(f"initialized data exceeds segment {self.index} length")
        if not payload:
            return
        if len(self.data) < self.length:
            self.data.extend(b"\0" * (self.length - len(self.data)))
        # Conflicting overlapping initialized bytes are ambiguous.
        for a, b in self.ranges:
            lo, hi = max(a, offset), min(b, end)
            if lo < hi and self.data[lo:hi] != payload[lo-offset:hi-offset]:
                raise OMFError(f"conflicting initialized data overlap in segment {self.index}")
        self.data[offset:end] = payload
        spans = sorted([*self.ranges, [offset, end]])
        merged: list[list[int]] = []
        for a, b in spans:
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        self.ranges = merged

    def json(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name, "length": self.length,
                "alignment": self.alignment, "combine": self.combine,
                "class": self.class_name, "use16": self.use16, "big": self.big,
                "absolute_frame": self.absolute_frame,
                "absolute_offset": self.absolute_offset,
                "overlay_name": self.overlay_name,
                "data_hex": bytes(self.data).hex(),
                "initialized_ranges": [x[:] for x in self.ranges]}


def records(data: bytes, *, strict_checksums: bool = True) -> list[dict[str, Any]]:
    """Frame records and classify computed checksums versus omitted zeroes.

    Microsoft OMF producers commonly write a literal zero checksum byte. A
    nonzero checksum is still verified strictly; zero is accepted as either a
    valid computed checksum or an explicit omitted checksum.
    """
    out, p = [], 0
    while p < len(data):
        if len(data) - p < 3:
            raise OMFError("truncated record header")
        start = p
        kind = data[p]
        size = int.from_bytes(data[p+1:p+3], "little")
        p += 3
        if size < 1:
            raise OMFError("record length omits checksum")
        end = p + size
        if end > len(data):
            raise OMFError("truncated record body")
        raw = data[start:end]
        checksum_sum = sum(raw) & 0xff
        if checksum_sum == 0:
            checksum_state = "computed"
        elif raw[-1] == 0:
            checksum_state = "omitted_zero"
        else:
            checksum_state = "bad_nonzero"
        if strict_checksums and checksum_state == "bad_nonzero":
            raise OMFError(f"bad checksum in {NAMES.get(kind, hex(kind))} record")
        out.append({"type": kind, "name": NAMES.get(kind, f"{kind:02X}"),
                    "offset": start, "length": size + 3, "body": data[p:end-1],
                    "checksum": raw[-1], "checksum_sum": checksum_sum,
                    "checksum_state": checksum_state})
        p = end
    return out


def _numeric(c: Cursor) -> int:
    lead = c.u8()
    if lead <= 0x80:
        return lead
    if lead == 0x81:
        return c.u16()
    if lead == 0x84:
        return int.from_bytes(c.take(3), "little")
    if lead == 0x88:
        return int.from_bytes(c.take(4), "little")
    raise OMFError(f"unsupported communal length encoding 0x{lead:02x}")


def _iterated(c: Cursor, depth: int = 0) -> bytes:
    if depth > 64:
        raise OMFError("LIDATA nesting too deep")
    repeat = c.u16()
    blocks = c.u16()
    if blocks:
        chunk = b"".join(_iterated(c, depth + 1) for _ in range(blocks))
    else:
        chunk = c.take(c.u8())
    # Bound pathological expansions while still allowing practical assets.
    if repeat and len(chunk) > 65536 // repeat:
        raise OMFError("LIDATA expansion exceeds 16-bit segment")
    return chunk * repeat


def _fixups(c: Cursor, data_context: tuple[int, int, int] | None,
            threads: dict[tuple[str, int], dict[str, Any]],
            allow_fixups: bool = True) -> list[dict[str, Any]]:
    out = []
    while c.left:
        first = c.u8()
        if first & 0x80:  # FIXUP subrecord
            if not allow_fixups:
                raise OMFError("FIXUPP after LIDATA is unsupported without expansion-position mapping")
            loc_hi = first
            loc_lo = c.u8()
            loc_type = (loc_hi >> 2) & 0x0f
            widths = {0: 1, 1: 2, 2: 2, 3: 4, 4: 1, 5: 2}
            if loc_type not in widths:
                raise OMFError(f"unsupported 16-bit FIXUPP location type {loc_type}")
            relative = ((loc_hi & 3) << 8) | loc_lo
            fixdat = c.u8()
            fthread, frame_method = bool(fixdat & 0x80), (fixdat >> 4) & 7
            tthread, target_method = bool(fixdat & 8), fixdat & 7
            pbit = bool(fixdat & 4)
            def ref(is_thread: bool, method: int, category: str) -> dict[str, Any] | None:
                if is_thread:
                    num = method & 3
                    value = threads.get((category, num))
                    if value is None:
                        raise OMFError("FIXUPP uses an undefined thread")
                    result = {"thread": num, **value}
                    if category == "target":
                        # TARGET thread P is supplied by each referencing FIXUP.
                        tm = value["method_code"] + (4 if pbit else 0)
                        result["method"] = _target_method(tm)
                    return result
                if category == "frame":
                    names = {0: "segment", 1: "group", 2: "external"}
                    if method in names:
                        return {"method": names[method], "datum": c.index()}
                    if method == 3:
                        raise OMFError("explicit FIXUPP frame number is unsupported")
                    if method == 4:
                        return {"method": "location_segment"}
                    if method == 5:
                        return {"method": "target_frame"}
                    raise OMFError(f"unsupported FIXUPP frame method {method}")
                return {"method": _target_method(method),
                        "datum": c.u16() if method == 3 else c.index()}
            frame = ref(fthread, frame_method, "frame")
            target = ref(tthread, target_method, "target")
            disp = c.u16() if not pbit else None
            if data_context is None:
                raise OMFError("FIXUPP fixup without preceding LEDATA/LIDATA")
            seg_idx, data_off, data_size = data_context
            if relative + widths[loc_type] > data_size:
                raise OMFError("FIXUPP location is outside preceding LEDATA/LIDATA")
            out.append({"segment": seg_idx, "offset": data_off + relative,
                        "location_type": loc_type,
                        "segment_relative": bool(loc_hi & 0x40), "frame": frame,
                        "target": target, "displacement": disp})
        else:  # THREAD subrecord
            # D=0 defines a frame thread, D=1 a target thread.
            is_frame = bool(first & 0x40)
            if first & 0x20:
                raise OMFError("reserved FIXUPP thread bit is set")
            method = (first >> 2) & 7
            number = first & 3
            category = "frame" if is_frame else "target"
            names = {0: "segment", 1: "group", 2: "external"}
            if method in names:
                value = {"method": names[method], "method_code": method, "datum": c.index()}
            elif category == "frame" and method == 4:
                value = {"method": "location_segment", "method_code": method}
            elif category == "frame" and method == 5:
                value = {"method": "target_frame", "method_code": method}
            elif category == "target" and method == 3:
                value = {"method": "explicit_frame", "method_code": method, "datum": c.u16()}
            else:
                raise OMFError(f"unsupported FIXUPP {category} thread method {method}")
            threads[(category, number)] = value
    return out


def _target_method(method: int) -> str:
    names = {0: "segment", 1: "group", 2: "external",
             3: "explicit_frame", 4: "segment_no_displacement",
             5: "group_no_displacement", 6: "external_no_displacement"}
    if method not in names:
        raise OMFError(f"unsupported FIXUPP target method {method}")
    return names[method]


def read_object(data: bytes, *, strict: bool = True) -> dict[str, Any]:
    recs = records(data, strict_checksums=strict)
    if not recs or recs[0]["type"] not in (0x80, 0x82):
        raise OMFError("object must begin with THEADR or LHEADR")
    if recs[-1]["type"] != 0x8A or any(r["type"] == 0x8A for r in recs[:-1]):
        raise OMFError("16-bit object must end with MODEND")
    for r in recs:
        if r["type"] not in SUPPORTED:
            raise OMFError(f"unsupported record {r['name']} for strict comparison")
    names = [""]
    c = Cursor(recs[0]["body"])
    module = c.string(); c.done()
    segs: list[Segment] = []
    groups: list[dict[str, Any]] = []
    externals: list[dict[str, Any]] = []
    publics: list[dict[str, Any]] = []
    communals: list[dict[str, Any]] = []
    fixups: list[dict[str, Any]] = []
    comments: list[dict[str, Any]] = []
    threads: dict[tuple[str, int], dict[str, Any]] = {}
    last_data: tuple[int, int, int] | None = None
    last_data_kind: int | None = None
    modend: dict[str, Any] | None = None
    for r in recs[1:]:
        k, c = r["type"], Cursor(r["body"])
        if k == 0x96:
            while c.left: names.append(c.string())
        elif k == 0x88:
            if c.left < 2: raise OMFError("truncated COMENT header")
            flags, cls = c.u8(), c.u8()
            comment = {"flags": flags, "class": cls, "data_hex": c.take(c.left).hex(),
                       "strict_supported": cls in KNOWN_COMMENT_CLASSES}
            comments.append(comment)
            if strict and not comment["strict_supported"]:
                raise OMFError(f"unsupported COMENT class 0x{cls:02x} for strict comparison")
        elif k == 0x98:
            attr = c.u8(); align_code = (attr >> 5) & 7
            if attr & 1:
                raise OMFError("USE32 segment is unsupported for strict 16-bit comparison")
            align = {0:"absolute", 1:"byte", 2:"word", 3:"paragraph", 4:"page", 5:"dword"}.get(align_code)
            if align is None: raise OMFError(f"unsupported SEGDEF alignment {align_code}")
            combine = {0:"private", 2:"public", 4:"public", 5:"stack", 6:"common", 7:"public"}.get((attr >> 2) & 7)
            if combine is None: raise OMFError("unsupported SEGDEF combine type")
            abs_frame = c.u16() if align_code == 0 else None
            abs_off = c.u8() if align_code == 0 else None
            length = c.u16()
            big = bool(attr & 2)
            if big:
                if length != 0: raise OMFError("BIG SEGDEF must encode length zero")
                length = 0x10000
            ni, ci, oi = c.index(), c.index(), c.index()
            if not ni or not ci or ni >= len(names) or ci >= len(names) or oi >= len(names):
                raise OMFError("SEGDEF references undefined LNAMES entry")
            segs.append(Segment(len(segs)+1, names[ni], length, align, combine, names[ci],
                                True, big, abs_frame, abs_off, names[oi] if oi else ""))
        elif k == 0x9A:
            ni = c.index()
            if not ni or ni >= len(names): raise OMFError("GRPDEF references undefined group name")
            members=[]
            while c.left:
                if c.u8() != 0xff: raise OMFError("unsupported GRPDEF component")
                si=c.index()
                if not si or si > len(segs): raise OMFError("GRPDEF references undefined segment")
                members.append(si)
            groups.append({"name": names[ni], "segments": members})
        elif k == 0x8C:
            while c.left:
                name=c.string(); ti=c.index(); externals.append({"index":len(externals)+1,"name":name,"type_index":ti})
        elif k == 0x90:
            gi, si = c.index(), c.index()
            frame = c.u16() if si == 0 else None
            if gi > len(groups): raise OMFError("PUBDEF references undefined group")
            if si > len(segs): raise OMFError("PUBDEF references undefined segment")
            while c.left:
                name=c.string(); off=c.u16(); ti=c.index()
                if si and off > segs[si-1].length: raise OMFError("PUBDEF offset outside segment")
                publics.append({"name":name,"group_index":gi,"segment_index":si,"frame":frame,"offset":off,"type_index":ti})
        elif k in (0xA0, 0xA2):
            si, off = c.index(), c.u16()
            if not si or si > len(segs): raise OMFError("data record references undefined segment")
            if k == 0xA0:
                chunk = c.take(c.left)
            else:
                chunk = bytearray()
                while c.left:
                    block = _iterated(c)
                    if len(chunk) + len(block) > 65536: raise OMFError("LIDATA exceeds 16-bit segment")
                    chunk.extend(block)
                chunk = bytes(chunk)
            c.done(); segs[si-1].add(off, chunk); last_data=(si,off,len(chunk)); last_data_kind=k
        elif k == 0x9C:
            fixups.extend(_fixups(c,last_data,threads,allow_fixups=last_data_kind != 0xA2)); c.done()
        elif k == 0xB0:
            while c.left:
                name=c.string(); ti=c.index(); kind=c.u8()
                if kind == 0x62: value={"kind":"near","length":_numeric(c)}
                elif kind == 0x61: value={"kind":"far","count":_numeric(c),"element_length":_numeric(c)}
                else: raise OMFError(f"unsupported COMDEF communal type 0x{kind:02x}")
                communals.append({"name":name,"type_index":ti,**value})
                # COMDEF contributes to the same ordered external index space.
                externals.append({"index": len(externals) + 1, "name": name,
                                  "type_index": ti, "communal": True})
        elif k == 0x8A:
            # Preserve framing while accepting the flags and optional start
            # address bytes. The linker entry point is outside this API.
            raw=c.take(c.left)
            flags=raw[0] if raw else 0
            modend={"flags":flags,"raw_hex":raw.hex(),
                    "main_module":bool(flags & 0x80),
                    "has_start_address":bool(flags & 0x40),
                    "strict_supported":not bool(flags & 0x40)}
            if strict and not modend["strict_supported"]:
                raise OMFError("MODEND start address is unsupported for strict comparison")
        c.done()
    for fixup in fixups:
        for category in ("frame", "target"):
            ref = fixup[category]
            method = ref["method"].removesuffix("_no_displacement")
            maximum = {"segment": len(segs), "group": len(groups), "external": len(externals)}.get(method)
            if maximum is not None and not 1 <= ref["datum"] <= maximum:
                raise OMFError(f"FIXUPP references undefined {method}")
    return {"name":module,"segments":[s.json() for s in segs],"groups":groups,
            "externals":externals,"publics":publics,"fixups":fixups,
            "communals":communals,"comments":comments,
            "strict_comparison_supported":all(x["strict_supported"] for x in comments) and bool(modend and modend["strict_supported"]) and all(r["checksum_state"] != "bad_nonzero" for r in recs),
            "modend":modend,
            "records":[{k:v for k,v in r.items() if k != "body"} for r in recs]}


def split_library(data: bytes, *, strict: bool = True) -> list[bytes]:
    """Split modules. In inspection mode, preserve modules with bad checksums.

    ``strict=False`` relaxes only checksum validation while framing; returned
    bytes remain unchanged. Pass the same members to ``read_object`` in strict
    mode before using them for a comparison.
    """
    return _split_library_data(data, strict)[0]


def split_library_report(data: bytes, *, strict: bool = False) -> dict[str, Any]:
    """Return exact member bytes plus rows for malformed nonzero checksums."""
    members, anomalies = _split_library_data(data, strict)
    return {"members": members, "integrity_anomalies": anomalies}


def _split_library_data(data: bytes, strict: bool) -> tuple[list[bytes], list[dict[str, Any]]]:
    """Split concatenated object modules or page-aligned OMF library members.

    LIBHDR/LIBEND are special library framing records, not ordinary checksum
    records. Library modules begin on page boundaries and the dictionary after
    LIBEND is opaque to this object-module reader.
    """
    anomalies: list[dict[str, Any]] = []

    def at(pos: int, checksum: bool = True, *, strict_checksums: bool = True) -> tuple[int, int, int, str, int, int]:
        if pos + 3 > len(data): raise OMFError("truncated record header")
        kind=data[pos]; n=int.from_bytes(data[pos+1:pos+3],"little")
        end=pos+3+n
        if n < 1 or end > len(data): raise OMFError("truncated record body")
        total=sum(data[pos:end]) & 0xff
        state="computed" if total == 0 else "omitted_zero" if data[end-1] == 0 else "bad_nonzero"
        if checksum and strict_checksums and state == "bad_nonzero":
            raise OMFError(f"bad checksum in {NAMES.get(kind, hex(kind))} record at 0x{pos:x} (byte {data[end-1]:02x})")
        return kind,n,end,state,data[end-1],total

    if not data or data[0] != 0xF0:
        recs=records(data, strict_checksums=strict); modules=[]; start=None
        current_module=0
        for r in recs:
            if r["type"] in (0x80, 0x82):
                if start is not None: raise OMFError("nested THEADR before MODEND")
                start=r["offset"]
                current_module += 1
            elif r["type"] == 0x8A:
                if start is None: raise OMFError("MODEND without THEADR")
                modules.append(data[start:r["offset"]+r["length"]]); start=None
            if r["checksum_state"] == "bad_nonzero":
                anomalies.append({"module_index":current_module or None,
                                  "record_offset":r["offset"],"record_type":r["type"],
                                  "record_name":r["name"],"checksum_state":r["checksum_state"],
                                  "stored_checksum":r["checksum"],"checksum_sum":r["checksum_sum"],
                                  "expected_checksum":(-sum(data[r["offset"]:r["offset"]+r["length"]-1])) & 0xff})
        if start is not None: raise OMFError("truncated object module without MODEND")
        if not modules: raise OMFError("no object modules found")
        return modules, anomalies

    _, hdr_len, hdr_end, _, _, _=at(0, checksum=False)
    page_size=hdr_len+3
    if page_size < 16 or page_size > 32768 or page_size & (page_size-1):
        raise OMFError("invalid LIBHDR page size")
    if hdr_len < 7 or hdr_end != page_size: raise OMFError("invalid LIBHDR length")
    dict_blocks=int.from_bytes(data[3:7],"little")
    dict_size=int.from_bytes(data[7:9],"little")
    flags=data[9]
    if flags & ~1: raise OMFError("reserved LIBHDR flags are set")
    if dict_blocks == 0: raise OMFError("empty OMF library dictionary")
    # LIBHDR's dictionary offset is an absolute byte offset in the library.
    dict_start=dict_blocks
    if dict_start > len(data) or dict_start % 512 or dict_start <= page_size:
        raise OMFError("invalid LIBHDR dictionary offset")
    if dict_size and dict_start + dict_size*512 > len(data):
        raise OMFError("truncated OMF library dictionary")
    modules=[]; pos=page_size; module_index=0
    while pos < dict_start:
        kind,n,end,_,_,_=at(pos,checksum=False)
        if kind == 0xF1:
            if end != dict_start: raise OMFError("LIBEND does not end at dictionary offset")
            if not modules: _raise("OMF library has no object modules")
            return modules, anomalies
        if kind not in (0x80, 0x82): raise OMFError(f"expected THEADR/LHEADR at library page 0x{pos:x}")
        start=pos
        module_index += 1
        # Frame/checksum each member record until its MODEND; never scan padding
        # or the dictionary as if they were ordinary records.
        while True:
            rk,rn,rend,state,checksum,total=at(pos,strict_checksums=strict)
            if state == "bad_nonzero":
                anomalies.append({"module_index":module_index,
                                  "record_offset":pos,"module_offset":pos-start,
                                  "record_type":rk,"record_name":NAMES.get(rk,f"{rk:02X}"),
                                  "checksum_state":state,"stored_checksum":checksum,
                                  "checksum_sum":total,
                                  "expected_checksum":(-sum(data[pos:rend-1])) & 0xff})
            pos=rend
            if rk == 0x8A:
                modules.append(data[start:pos])
                break
            if rk in (0xF0,0xF1) or (rk in (0x80,0x82) and pos-rn-3 != start):
                raise OMFError("invalid library member record sequence")
        pos=((pos+page_size-1)//page_size)*page_size
    raise OMFError("OMF library is missing LIBEND")


def _raise(message: str):
    raise OMFError(message)
