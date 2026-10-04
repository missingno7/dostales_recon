# Packed root and shared overlays

The authority is `assets/DUCKTALE.EXE`, 165,218 bytes, SHA-256
`f5454d4e3b760aede974f6e08f0b441ba5ebae556205ca86e99816da088381a9`.
Coordinates below are file offsets or unrelocated root-image offsets as marked.
`tools/oracle.py verify` checks every identity and structural field against
the immutable lock. Generated extracted binaries stay in ignored `build/`.

## EXEPACK facts

The primary MZ declares 61,787 bytes, including a 512-byte header and
61,275 loaded packed bytes. An appended 103,431-byte region follows. The
packed entry is `0E8F:0010` (file 60,160); stack is `15CE:0080`.
The RB EXEPACK header is **16 bytes**, file `[60144,60160)`, with RB at
60,158. It restores `040E:46C3` (root linear `0x87A3`) and `1B89:0800`.
The 255-byte stub occupies `[60160,60415)`, followed by the 22-byte corruption
message and the grouped relocation stream `[60437,61787)`.

The reverse decoder observes 230 tokens and nine `FF` padding bytes, including
padding before the immediate terminal pair. It preserves a 49,520-byte prefix
and expands the initialized image to 87,664 bytes. Root SHA-256 is
`47e622175ccf124edab2ed1b5ccb725045d5e54b5766428f8309303fcdf5564d`.
The recovered relocation stream has 659 entries: 612 in the first 64-K group,
47 in the second. The oracle preserves that decoded order. EXEPACK grouping
does not reveal the original pre-pack MZ table order/header bytes.

Independent Unicorn 2.1.4 execution runs the **original** stub with packed MZ
registers, load base segment `2000` and PSP `1FF0`. It reaches `240E:46C3`
after 50,849 instructions, with no interrupts, and its entire relocated root
matches the independent decoder after applying the 659 relocations. The
relocated image SHA-256 is
`adf4781853963aff1432fa364b7c70ecc1b114d05e86a99724c08f53627333ad`.
The emulator supplies validation evidence, never expected oracle bytes.

`root-unpacked.exe` is a synthetic paragraph-aligned MZ serialization of the
root and recovered relocation sequence. Its header/minalloc policy is explicit
in `oracle.py`; it is not proof of the original LINK output. Original root,
relocations, overlay records and packed bytes remain separate comparison layers.

Both installed standalone packers identify as Microsoft EXEPACK 4.06:

| Path | Size | SHA-256 |
|---|---:|---|
| `C:/tools/msc-5.00/EXEPACK.EXE` | 14,803 | `64e46a10375bd5fd14bcf3d2b0a06cdc8dfe24a178edee6fede455c0b091e26b` |
| `C:/tools/msc-5.10/EXEPACK.EXE` | 14,803 | `568554322d29e46f79c0c760ac2391cb0689dc7acb9aed79a428194ec6fb83e7` |

Oracle-derived synthetic-root packing, twice per packer, gives identical
61,731-byte outputs (SHA-256
`1d3b3b53635a146eb48dfe7f071a9a6ec244245d4e9cdc1ac565e1e483a5cfe9`).
Their header is 18 bytes with an extra `0001` word before RB, and their primary
MZ fields/packed bytes differ from the original. With an appended oracle tail,
the output also changes tail size/content and fails the observed overlay-gap
structure. These are packing diagnostics from original-derived input, not
source-build proof. Exact original packer/version/options remain unknown;
neither candidate is accepted as the final packing transform.

## Appended modules and loader evidence

All ten overlay MZ headers begin on 256-byte boundaries; intervening padding
is zero, sometimes including an extra 256-byte block. `e_ovno` is sequential.
The raw encoded relocation sites are in root-image coordinates, rather than
local file-image coordinates.

| `e_ovno` | File start | File end | Image bytes | Relocations |
|---:|---:|---:|---:|---:|
| 1 | 61,952 | 62,478 | 14 | 2 |
| 2 | 62,976 | 72,368 | 8,368 | 180 |
| 3 | 72,704 | 76,534 | 3,318 | 64 |
| 4 | 76,800 | 95,372 | 17,548 | 248 |
| 5 | 95,744 | 108,258 | 12,002 | 68 |
| 6 | 108,544 | 120,622 | 11,054 | 196 |
| 7 | 120,832 | 129,268 | 7,924 | 93 |
| 8 | 129,536 | 155,640 | 24,056 | 436 |
| 9 | 155,648 | 158,996 | 2,836 | 65 |
| 10 | 159,232 | 165,218 | 5,474 | 101 |

The library-matched overlay manager at root `0x8436` has complete CODE extent
1,346 bytes. Its `$$OVLINIT` public at member offset 877 lands exactly at
restored entry `0x87A3`, whose opcode is `PUSH DS`. The preceding byte is RET.
The match is fixup-masked and does not yet prove the entire object's bindings
and native storage.

Direct linked-code inspection at root `0x8468` sets the destination segment
to `0x0C17`, starts a DOS read at `DS:0000`, and advances it in chunks. Thus
all modules load into the shared arena starting at root linear `0xC170`.
The maximum image ends at `0x11F68`; the root's entire 24,056-byte arena is
initially zero. **Every overlay's two-byte relocation site lies inside its own
loaded extent** `[0xC170,0xC170+image_size)`. `overlays.py` verifies this and
reports both encoded coordinates and local offsets/native overlay words.
Do not apply those records to zero bytes from the resident root.

Further linked manager locations: `0x850F` selects/open-seeks using a table at
DGROUP-relative operand `0x328E`; `0x859D` checks MZ word `+0x1A` against the
requested number; `0x8603` loads bytes; `0x8616` handles relocation records.
Dispatch at `0x867E` consumes target segment/offset state and indexes maps at
group operands `0x3234` and `0x3270`. These are **group offsets**, not root
file addresses. DGROUP origin and full map contents remain unresolved.

There are 13 raw `CD 3F <segment-byte> <offset-word>` candidate sequences in
the root at `00E2,013A,01A4,01C2,01D3,030B,084D,0F90,1069,2C1B,2C4E,2C78,2CA2`.
They fit the Microsoft overlay thunk convention, but current recursive CFG
does not establish those sites as reachable instructions. Treat them as raw
inventory. IDs include `0x12`, `0x1C` and `0x1D`, so equating that operand
directly with the ten `e_ovno` values is unsupported. Recover `$$MPGSNBASE`,
`$$MPGSNOVL`, `$$MPOVLLFA`, their exact LINK layout, and DGROUP binding next.
Interrupt installation, cache and nested-call policy still need direct proof.

This layout supports eleven distinct ownership units. Their byte counts sum
to 180,258, but the overlays reuse one runtime address arena and cannot be
flattened into a single imaginary simultaneously loaded program.
