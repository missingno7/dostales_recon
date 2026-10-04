# Resource container probe

Read-only inspection of every supplied `assets/*.ARC` plus `assets/IT.DRV`.
`tools/resources.py` recognizes the outer index and opaque member slices;
`build/resources/NAME/index.json` records exact starts, member sizes, prefixes,
and identities. Extraction and repacking reconstruct the index from the
separately stored entries rather than returning a saved source byte string.

## Outer layout established

The first two bytes are a little-endian member count `N`. They are followed by
`N` little-endian 32-bit absolute file offsets. The first offset is always
`2 + 4*N`, exactly the end of the index. Every start is strictly increasing;
member `i` is the half-open byte range `[start[i], start[i+1])`, and the final
member ends at EOF. Examples: `CAVEMAPS.ARC` has count 8, starts
`[34, 155, 270, 384, 498, 613, 725, 835]`; `EXP.ARC` has count 47, its first
member starts at 190 and its final member starts at 106350; `IT.DRV` has count 7, starts
`[30, 2359, 4555, 7230, 9240, 18388, 24185]`.

## Inner records and limits

All 400 indexed members inspected have a 16-byte prefix followed by a payload.
The prefix's first little-endian u32 exactly equals `member_size - 16`. The
u16 at byte 4 takes values 1 (48 members), 2 (225), or 4 (127). The remaining
10 prefix bytes vary by kind; for kind 4, the u16 at byte 8 is `0xffff` in all
127 records. Other kinds use varying values and also contain `0xffff` in other
word positions. These are observed fields only; their meanings are unknown.

Payloads look packed in samples, but no compression algorithm, nested format,
or sentinel semantics have been established. The implementation therefore
does not decompress, recurse, or normalize metadata. It derives the count and
starts from complete extracted members and concatenates their bytes, preserving
all unknown data. The next experiment should use the executable's
loader or runtime disassembly to identify the kind-specific prefix consumers
and decompression entry points, then validate a decoder against known loaded
buffers.

## Validation

`python tools/resources.py verify` checks
all 15 ARC files and IT.DRV for the index invariant, member boundaries,
payload-length equation, known kind values, and exact byte identity, plus
malformed-index rejection in `tests/test_resources.py`. It is a structural
check, not a decompression test.
