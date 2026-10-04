# Toolchain facts, inferences and open attribution

Exact executable/library/header identities and commands are in
`layout/toolchain.json`. These locally supplied tools were not downloaded or
modified during bootstrap. Tool banners establish versions of tested
installations; they do not identify the original game's compiler.

| Tested profile | Result | Attribution limit |
|---|---|---|
| MSC 5.00 `/c /AM /O /Gs /W0` | Full codegen probe compiles twice identically; LINK 3.61 far-call/data executable runs | Plausible era; fewer diagnostic CRT hits |
| MSC 5.10 same flags | Full probe and LINK 3.65 run pass | Strongest startup/runtime-family inference |
| MSC 5.10 `/Os` instead of `/O` | Full probe passes; exact 22-byte `_abs` code example | Optimization evidence for one stock CRT region, not all game TUs |
| MSC 6.00 `/c /AM /O /Gs /W0` | Full OMF emission probe passes | LINK 5.10 file-open failures under tested players leave this link path unverified |
| MASM 5.10 `/Mx /I.` | Symbolic printer and native global/far-call probe assemble | Working reproduction choice; original assembler unproven |

Medium model and default C conventions are experimental choices (far code,
near data), not a proven whole-program ABI. Explicit CPU variants, floating
point, original DOSSEG command, original TU names and exact linker switches
remain open. The normal runner is hash-pinned nmlgc/ReC98 MS-DOS Player
`-e -v5.00`. Minimal environment fixes the observed MSC 6.00 compiler hang;
its LINK still reports L1093 for an existing object or L1089 for its generated
response file under ReC98 and upstream x64/x86 players. Older LINK versions
can cross-link that MSC 6.00 tiny object. This isolates a tool/runner path
limitation rather than proving a compiler mismatch.

`evidence/probes/codegen.c` covers prologues, signed/unsigned branches, switch
lowering, far/near calls and pointers, struct returns, long arithmetic and
shifts, memcpy/memset, DGROUP globals, initialized/static/BSS and external
fixups. Fresh full OMF comparison, including data, groups, publics, externs,
fixups and communals, checks repeat emission. `link.c` and `link.asm` additionally
exercise far C-to-ASM calls, a C global and native ASM `DW` storage through
historical LINK and DOS exit-code assertions. These prove the machinery;
they are not matched game functions.

The canonical masked fingerprint scanner currently finds 34, 46 and 12 code
segment hits for MSC 5.00, 5.10 and 6.00 respectively. It masks only parsed
OMF fixup spans and reports unsupported members and integrity anomalies.
Masked matches remain diagnostic. Counts depend on the supported parser
surface and cannot be interpreted as accepted reconstruction coverage.
Regenerate them with `python tools/runtime_fingerprints.py`.

MSC 5.10 `dos\\crt0.asm` matches a complete 197-byte code segment at root
`0x5D2C` over 131 non-fixup bytes. Corresponding MSC 5.00/6.00 startup segments
do not match in this scan. `dos\\crt0dat.asm` matches 354 bytes at `0x5DF2`,
with 266 non-fixup bytes; its runtime-message segment matches 36 bytes at
`0x5F54`. The Microsoft 1988 copyright and ITALLOC diagnostics are separately
recorded in `evidence/string-fingerprints.json`. This supports MSC 5.10-family
runtime ancestry; it does not establish the exact compiler or all flags.

The 1,346-byte overlay manager code matches MSC 5.00 `OVLM6L` and MSC 5.10
`dos\\ovlm6l.asm` at root `0x8436` over 1,080 unmasked bytes. Its fixups,
linker-generated maps and 1,348 bytes of native data still need independent
binding, so the whole member is unresolved ownership. It is Microsoft overlay
support rather than evidence that Incredible Technologies authored the manager.

Three entire strict-parsed MSC 5.10 library members have no fixups, externs,
communals or additional positive segment extents, and reproduce their full
root intervals without relocation sites:

| Member | Root interval | Bytes | Proof |
|---|---|---:|---|
| `strcat.asm` | `[0x7E1A,0x7E59)` | 63 | `PINNED_RUNTIME` |
| `strcpy.asm` | `[0x7E5A,0x7E8C)` | 50 | `PINNED_RUNTIME` |
| `strlen.asm` | `[0x7E8C,0x7EA7)` | 27 | `PINNED_RUNTIME` |

The manifest pins full member/library identities and native object signatures.
These implementations are shared across the nearby releases, so they alone
do not distinguish a compiler version. MSC 5.10's archive contains one bad
nonzero COMENT checksum in a different startup member, recorded unchanged in
`library-integrity.json`; selected accepted members validate strictly. Zero
OMF checksum bytes represent omitted checksums and are tracked explicitly.
The parser follows the [TIS OMF specification](https://openwatcom.org/ftp/devel/docs/omf.pdf)
and rejects unsupported records/fixup forms from strict comparison.

`abs.c` emits the complete 22-byte stock CRT interval `[0x8410,0x8426)` with
MSC 5.10 `/Os`. MSC 5.00 `/Os` uses a different return arrangement, MSC 5.10
`/O`/`/Ot` differs, and MSC 6.00 produces shorter branchless code. `putstr.asm`
emits all 22 bytes at `[0x8436,0x844C)` from symbolic instructions with no
fixups. Both are `CODE_BYTES_EXACT`, with historical object/TU identity open.
The printer is inside the stock manager; it is not accepted game ASM.
