# DuckTales historical reconstruction

This repository bootstraps a matching reconstruction of the original DOS
**Disney's DuckTales: The Quest for Gold**. The target is historical C/ASM,
native object contributions, ordered relocations, overlays and eventually the
packed executable. An SDL port is outside this milestone.

The supplied originals in ignored `assets/` are immutable. Their inventory,
identities and extracted structure are pinned in `layout/oracle.lock.json`.
Every verification regenerates expectations from those originals and compares
them to the lock. No verification command updates the lock.

The bootstrap identifies an EXEPACK root and ten appended MZ overlays, plus
16 resource containers with 400 raw entries. Original-stub emulation verifies
the independent root decoder. MSC 5.10-family runtime evidence is strongest;
MSC 5.00 and 6.00 remain tested alternatives. Three complete CRT members have
strict runtime ownership. Two symbolic C/ASM examples reproduce complete code
regions, with original translation-unit/object bindings still unresolved.

There is **no complete reconstructed game build yet**. Accepted game C/ASM
bytes are zero. The single authoritative current accounting is generated
`build/status.json`; `build/validation.json` records the latest fresh bootstrap
validation. See [setup](docs/setup.md), [proof rules](docs/methodology.md),
[toolchain evidence](evidence/toolchain.md), [EXEPACK/overlays](evidence/exepack-overlays.md)
and [resource evidence](evidence/resource-containers.md).

Run from the repository root with the pinned tools available:

```powershell
python tools/oracle.py verify
python tools/validate.py
python tools/context.py root 0x8410 --length 0x26
python tools/context.py --list
python tools/overlays.py
```

For one bounded candidate, put the complete source in ignored worker scratch:

```powershell
python tools/historical.py build/workers/example/candidate.c --profile msc510-medium-size
python tools/inspect_omf.py build/search/run-REPLACE/PROBE.OBJ
python tools/match.py build/search/run-REPLACE/PROBE.OBJ root 0x8410 0x8426 --segment PROBE_TEXT
```

Use the fresh directory printed by the compiler. `CODE_BYTES_EXACT` is a
diagnostic code gate; it cannot promote a source or waive declarations, other
storage, FIXUPPs, original TU membership or linked bindings. Overlay context
and matching use module-local offsets; reports preserve encoded shared-arena
relocation coordinates too.

`tools/` contains deterministic analysis, historical compile/link probes,
OMF inspection, matching and validation. `layout/` contains identities and
ownership. `evidence/` retains reviewed conclusions and reproducible source
probes. `tests/` exercises malformed inputs and proof gates. All generated
objects, disassembly, extracted originals and worker scratch belong under
ignored `build/`. Accepted `src/`, `asm/`, `include/` and module recipes will
be added when their contribution proof exists.
