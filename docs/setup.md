# Local setup and verification

Use Windows, Python 3.10 or newer, and the user-supplied original release under
`assets/`. The lock requires all 18 supplied files, including `README.TXT`.
This repository carries neither game assets nor historical tool binaries.

`layout/toolchain.json` pins each executable, compiler support file, runtime
library and complete historical include tree by size/SHA-256. Tested paths:

| Profile | Installation | Compiler / linker |
|---|---|---|
| `msc500-medium` | `C:/tools/msc-5.00` | C 5.00 / Overlay LINK 3.61 |
| `msc510-medium`, `msc510-medium-size` | `C:/tools/msc-5.10` | C 5.10 / Overlay LINK 3.65 |
| `msc600-medium` | `C:/tools/msc-6.00/BIN` | C 6.00 / LINK 5.10 |
| `masm510-game` | `C:/tools/msc-5.10-msdos` | MASM 5.10 |

The runner is the existing nmlgc/ReC98 MS-DOS Player at
`C:/tools/nmlgcdos/msdos.exe`, size 686,592, SHA-256
`f7f6cb0a3e816c5edb13112d327c1bddbf7463fe7bf9a005ca1eb5317751bd02`.
The working invocation is `msdos.exe -e -v5.00 PROGRAM args...`. Exact runner
and component pins are mandatory. Available local provenance is recorded in
`evidence/tools-provenance.json`; the MSC 5.x installation origins remain
unknown. Tested banners/file identities are independent of those origin claims.

The compile helper uses a unique ignored directory, stages Latin-1 CRLF source
as `PROBE.C`/`PROBE.ASM`, and copies hash-checked historical headers into
`INCLUDE/`. Candidate DOS EOF characters are rejected. Only trailing historical
header EOF markers are removed during text staging. Minimal process environment:
`PATH` and `MSDOS_PATH` point to the selected tools, and `TEMP`, `TMP`,
`MSDOS_TEMP` are `.`. No inherited host SDK/compiler environment is used.
Each tool call times out after 30 seconds and creates no visible window.

MSC 6.00 compiles valid OMF in this environment. Its own LINK fails opening
existing object/response files under the tested ReC98 and upstream players.
The 5.00/5.10 link/run probes pass. See `evidence/toolchain.md` for the limits;
do not reject the MSC 6.00 compiler based on its runner/linker problem.

The modern analysis dependencies are Capstone 5.0.3 and Unicorn 2.1.4, pinned
file-by-file in `layout/analysis.json`. They decode/emulate originals and never
supply historical candidate bytes. Copy the matching locally available Python
package folders into ignored `build/python/`:

```powershell
python tools/setup_analysis.py --capstone-from C:/tools/capstone-5.0.3/capstone --unicorn-from D:/Prog/stunts_recon/build/python/unicorn
```

Pass actual named package directories, not their parent `site-packages`.
Those were the actual available package sources at bootstrap. Once copied,
the sibling checkout is unnecessary. The bootstrap used packages already available locally; no historical tools
were downloaded or replaced. Reprovisioning must satisfy the tracked hashes.
There is no runtime dependency on a sibling repository or a worker's scripts.

Run `python tools/validate.py` for the strongest implemented gate. It starts
by invalidating the previous validation result, extracts a fresh oracle,
runs malformed-input/proof regressions, executes the original EXEPACK stub,
checks shared overlay patch sites, extracts/rebuilds all raw resource files,
compiles all four C profiles twice and compares complete OMF, links/runs fresh
C-to-ASM/global-data probes with two historical LINK versions, re-emits two
complete code examples, revalidates runtime/ownership, and rechecks unchanged
assets and lock. Output is `build/validation.json`, with per-run material in
`build/validation/run-*/`. No cached candidate object is an acceptance input.

`python tools/status.py` refreshes `build/status.json` from the lock, full
partitioned ownership and pinned runtime members. It is the only current
status location. `python tools/runtime_fingerprints.py` regenerates diagnostic
masked library comparisons; those results are not source/runtime acceptance.
`python -m unittest discover -s tests -v` is the focused tool regression suite.
