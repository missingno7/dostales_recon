# Proof model and working rules

The authority is the supplied original byte set, pinned in
`layout/oracle.lock.json`. Generated material is disposable and belongs in
ignored `build/`. Verification recomputes it from original inputs. It never
updates the lock or expected bytes from candidates.

Facts are observations with identities and coordinates. Supported inferences
combine facts and reproducible experiments. Attribution hypotheses are kept
separate from a compiler that happens to reproduce a contribution. Source
semantics and historical translation-unit membership require additional
evidence even when standalone code bytes match.

## Separate acceptance layers

* `STRUCTURE_VERIFIED`: bounded parsing and deterministic extraction agree
  with the locked original. This says nothing about source recovery.
* `CODE_BYTES_EXACT`: complete candidate code contribution equals a bounded
  oracle region. Fixups and declarations may remain unproven.
* `OBJECT_CONTRIBUTION_EXACT`: complete declared segments, initialized data,
  publics, externals, frame/target fixups and native relocation order agree
  with independently grounded bindings. Never trim inconvenient object bytes.
* `C_EXACT` / `ASM_EXACT`: reviewed source emits that exact contribution using
  pinned historical tools; ancestry is a separate inference.
* `PINNED_RUNTIME`: identified stock library member, including required
  storage and bindings, passes contribution proof. A substring fingerprint
  alone is insufficient.
* `HYBRID_EXACT`: generated hybrid image equals the oracle, with raw debt
  explicitly counted. This does not mean full source recovery.
* `UNPACKED_IMAGE_EXACT`, `RELOCATIONS_EXACT`, `OVERLAYS_EXACT`, and
  `PACKED_EXE_EXACT`: distinct full-artifact comparisons. Synthetic unpacked
  MZ header bytes are a serialization policy, not original pre-pack evidence.

A fresh full source reconstruction is not yet available at bootstrap. The
bootstrap validator must say so explicitly; passing structural and probe gates
cannot award full game equality. Diagnostic similarity cannot award any exact
proof level.

## Context, experiment, promote, validate

Choose one bounded region in one root/overlay image. Read its context and
relocations before proposing types. Write a self-contained candidate in
`build/workers/NAME/`. Compile with a selected pinned profile, inspecting the
full OMF contribution. Investigate signedness, calls, native data and segment
ownership together; do not patch candidate bytes after compilation.

One writer integrates canonical sources, recipes, ownership and proof-tool
changes. Keep original arrays and opaque capsules out of `src/` and `asm/`.
Unresolved bytes remain unresolved debt. Validate meaningful infrastructure or
promotion boundaries, using fresh historical tools rather than cached objects.
Retain compact conclusions and reproducible probes; avoid transient disassembly
dumps in Git. Never run blanket `git clean -fdx`.

## Patterns adapted from siblings

The current Stunts workflow separates immutable layout identities, full OMF
extents, ordered relocations, DGROUP/BSS ownership and diagnostic LINK
hypotheses. Its exact hybrid gate is distinct from proving an original link
command. Its runtime profiles do not automatically identify DuckTales tools.

Empires uses one production module plan, fresh uncached acceptance, MS-DOS
Player for regular work, CRLF DOS text staging and explicit per-program runner
overrides. Its upstream player requirement for TLINK is tool-specific evidence;
it cannot establish a Microsoft LINK requirement. Recursive CFG recovery stops
at unsupported indirect flow. This repository adopts those invariants without
copying either game's ownership, queue, raw-layout or port framework.
