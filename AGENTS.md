# Reconstruction workflow

Read `README.md`, `docs/methodology.md` and `docs/setup.md`. Run
`python tools/status.py` for the one authoritative current accounting in
`build/status.json`; historical scratch reports are not a current queue.

Treat `assets/` and `layout/oracle.lock.json` as immutable. Normal verification
must recompute from originals, never rewrite the lock or expectations from a
candidate. No original game binaries, runtime libraries, historical tools or
generated extraction belong in Git. Never use `git clean -fdx`.

Use context -> experiment -> review contribution -> promote -> validate.
Choose a bounded root/overlay unit, inspect callers/relocations/storage, and
keep complete candidates and TU experiments under `build/workers/NAME/`.
`historical.py` stages complete DOS source and headers, verifies pinned tools,
and creates a fresh directory. Its receipts record exact commands and inputs.
Inspect the complete native OMF, including segment attributes, initialized
extents, BSS/communal storage, publics/externs, groups and frame/target FIXUPPs.
Never trim, patch, replace emitted data, or hide original code in arrays.

The matcher reports only `CODE_BYTES_EXACT` for the present source examples.
Original object/TU identity and declarations still need proof. Do not count
these as `C_EXACT` or `ASM_EXACT`, or add them to accepted source ownership.
Diagnostic masked runtime fingerprints likewise cannot award runtime ownership.
The current manifest permits `UNRESOLVED` and fully validated `PINNED_RUNTIME`
only. Extend the proof gates before adding another accepted ownership kind.
Keep BSS unknown until its size and DGROUP/communal partition are grounded.

Root/overlay images are separate ownership units. Overlay raw MZ relocation
sites are in root-image coordinates, but loaded module offsets subtract
`0xC170`. Do not flatten the ten overlays or patch their sites against root
zero storage. INT 3F target segment IDs are not MZ overlay numbers; their
linker-generated map still needs proof. Bounded disassembly and recursive CFG
are provisional; stop at unsupported indirect flow and do not infer data from
unvisited bytes.

Use MSC 5.00/5.10/6.00 experiments rather than assuming the exact compiler.
MSC 5.10 is currently the strongest runtime inference; MASM 5.10 is a tested
reproduction choice. An original packed 16-byte RB header does not match the
tested standalone EXEPACK 4.06 18-byte header. Packing is a separate future
gate. The synthetic unpacked MZ header does not prove the original header or
original relocation-table order before EXEPACK regrouping.

Independent investigations may use isolated worker directories, with one
writer integrating canonical sources, manifests and proof infrastructure.
Review delegated evidence and retain compact, reproducible findings instead
of scratch binaries or entire transient reports.

After a meaningful infrastructure or ownership change, run
`python tools/validate.py`. It fresh-compiles probes, runs historical LINK and
DOS execution, compares full objects, validates runtime ownership, executes
the original decompressor and rechecks inputs. `BOOTSTRAP_VERIFIED` does not
award full game equality. Record actual limits and commit coherent changes.
