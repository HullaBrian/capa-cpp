# capa-cpp

> [!Warning]
>This project was entirely generated using Claude. I performed testing for my own use cases, but
> you may run into issues. If you do, feel free to open an issue on this repository!

A C++ port of [capa](https://github.com/mandiant/capa), Mandiant's tool for identifying
capabilities in executable code. It loads the YAML rules from
[capa-rules](https://github.com/mandiant/capa-rules) unchanged, and **same rules + same features =
the same JSON result document as capa**. capa (the Python implementation) is the
reference; any difference from it is a bug. See [Verifying parity](#verifying-parity) for how
that is checked and what currently passes.

It is also driven by other tools, such as ttd-capa, and runs as an IDA plugin.

Inputs:
- capa freeze files (`.frz`) from any capa backend: vivisect, IDA, dnfile (.NET), CAPE, DRAKVUF, VMRay, ...
- Microsoft's Time Travel Debugging (TTD) reports
- Windows process memory dumps
- Windows x86/x64 PE files (**IDA Pro only**: the plugin, or headless through idalib)

## How it works

Each backend extracts features, such as API calls, strings and numbers, and a common engine
matches rules against them. The engine is a self-contained library, `capa-core`, with no
analysis backend in it: rules in, features in, result document out.

| Input | Backend | Scopes |
|---|---|---|
| capa freeze file (`.frz`) | none: replays features another backend extracted (capa's `NullFeatureExtractor`) | static or dynamic, as frozen |
| TTD report JSON (from `ttd-capa`) | Parses recorded API calls | process / thread / span of calls / call |
| TTD `--scan-code` manifest + `.bin` snapshots | Disassembles reconstructed code (unpacked, injected, JIT'd) with [Zydis](https://github.com/zyantific/zydis) | file / function / basic block / instruction |
| Process minidump (`.dmp`) | Parses loaded modules and executable memory, disassembles with Zydis | file / function / basic block / instruction |
| IDA database | uses IDA's CFG, imports, exports, strings and FLIRT names | file / function / basic block / instruction |

### Layout

| Directory | What |
|---|---|
| `capa-core/` | static library: address/feature model, rule parser (incl. capa's optimizer and `com/` database), matcher, static and dynamic capability drivers, freeze format, result document. No backend, no Zydis, no IDA SDK. |
| `capa-cpp/` | `capa-cpp.exe`: the CLI and the TTD, TTD-code-scan and minidump backends (plus the IDA backend sources the IDA projects compile) |
| `capa-tests/` | `capa-tests.exe`: capa's language-agnostic test suites run against `capa-core` |
| `capa-idalib/` | `capa-idalib.exe`: the IDA backend headless through idalib (capa's `-b ida` equivalent) |
| `ida-capa/` | the IDA Pro plugin |
| `tests/fixtures/` | capa's matcher and feature fixtures, vendored from mandiant/capa |
| `scripts/` | parity tooling (`parity.py`, `compare_results.py`) and the COM database generator |

## Requirements

- To compile `capa-cpp.exe` and `ida-capa.dll` (Windows):
  - Windows x64
  - Visual Studio 2022 or 2026 (MSVC v143/v145, C++ 20)
  - vcpkg (the copy bundled with Visual Studio works)
  - For the IDA Pro plugin: the ida-sdk (currently added as a submodule)
- To compile `ida-capa.so` (Linux, IDA Pro plugin only -- `capa-cpp.exe`'s TTD/minidump
  CLI is not ported to Linux):
  - Linux x64
  - CMake 3.25+, a C++20 compiler (GCC or Clang)
  - `nlohmann-json` and `yaml-cpp` dev packages (`sudo dnf install json-devel
    yaml-cpp-devel yaml-cpp-static` on Fedora -- `-devel` for headers, `-static` for
    the static archive; `sudo apt install nlohmann-json3-dev libyaml-cpp-dev` on
    Debian/Ubuntu)
  - the ida-sdk submodule, which ships prebuilt Linux SDK libraries
- To use:
  - capa [rules](https://github.com/mandiant/capa-rules)

## Building

Builds are located in `build/<Configuration>/`
- **`capa-core.lib`**: the engine, as a static library to embed
- **`capa-cpp.exe`**: standalone CLI for freeze files, TTD traces and Windows process minidumps
- **`capa-tests.exe`**: capa's matcher fixtures and capa-cpp's own checks
- **`ida-capa.dll`**: IDA Pro 9.x plugin that runs capa against the open database
- **`capa-idalib.exe`**: capa on a PE file through IDA, headless (needs an IDA installation with idalib)

### CLI, library and tests

Dependencies are `nlohmann-json`, `yaml-cpp`, `zlib` and `zydis`, linked statically, so the
exes have no runtime dependencies.

```sh
vcpkg install --triplet x64-windows-static --x-manifest-root=capa-cpp --x-install-root=capa-cpp/vcpkg_installed
./build.sh Release          # capa-core.lib, capa-cpp.exe, capa-tests.exe
./build.sh test Release     # ... and run capa-tests
```

### IDA plugin (`ida-capa.dll`) and `capa-idalib.exe`

```powershell
vcpkg install --triplet x64-windows-static-md --x-manifest-root=ida-capa --x-install-root=ida-capa/vcpkg_installed
.\ida-capa\build.ps1
MSBuild capa-idalib\capa-idalib.vcxproj /p:Configuration=Release /p:Platform=x64 /m:1
```

### IDA plugin on Linux (`ida-capa.so`)

`nlohmann-json` is header-only, and `yaml-cpp` links statically into the plugin
(when a static build of it is available), so the built `.so` needs nothing beyond
IDA itself on the target system.

```sh
sudo dnf install json-devel yaml-cpp-devel yaml-cpp-static   # or: apt install nlohmann-json3-dev libyaml-cpp-dev
./ida-capa/build.sh              # build/ida-capa/ida-capa.so
./ida-capa/build.sh --install    # also copy it into ~/.idapro/plugins
```

Debian/Ubuntu don't package a static `libyaml-cpp.a`; there, the build falls back to
linking `libyaml-cpp.so`, which then must also be installed on whatever system runs
the plugin.

The build locates the ida-sdk submodule automatically (`ida-capa/../ida-sdk/src`);
point elsewhere with `-DIDASDK=<path>` or the `IDASDK` environment variable if it's
installed somewhere else.

## Usage
### Command Line (`capa-cpp.exe`)
The command line accepts **capa freeze files, TTD reports or Windows process memory dumps**. It
does not read a raw TTD trace: ttd-capa turns the trace into a JSON report and, for code
scanning, a code manifest and memory snapshots.

A freeze file holds the features some backend extracted from one sample; capa writes one with
`python -m capa.features.freeze <sample> <out.frz>` (any of its backends: `-b vivisect`,
`-b ida`, `-f cape`, ...). capa-cpp matches it exactly as capa does, and writes capa's result
document. `-r` may be repeated, as in capa.

```sh
capa-cpp <sample.frz> -r <rules-dir>                    # capability table
capa-cpp <sample.frz> -r <rules-dir> -vv                # with match trees
capa-cpp <sample.frz> -r <rules-dir> -j -o out.json     # capa's result document
```

```sh
# TTD dynamic: report of recorded API calls
capa-cpp <report.ttd.json> -r <rules-dir>               # capability table
capa-cpp <report.ttd.json> -r <rules-dir> -vv           # with match trees
capa-cpp <report.ttd.json> -r <rules-dir> -j -o out.json
capa-cpp <report.ttd.json> -r <rules-dir> --matches-only --msgpack -o out.mp

# TTD static: reconstructed code regions
capa-cpp --scan-code-manifest <manifest.json> -r <rules-dir> [--dumps-dir <dir>] [-o out.json]
```

To scan a Windows process memory dump, use the command below. The file type comes from the file's
magic bytes, so the `.dmp` extension is optional.
```
capa-cpp <process.dmp> -r <rules-dir> [-j | -vv] [--module <name>] [--all-modules]
```

`capa-cpp --rules <rules-dir>` loads a rule directory and reports what was skipped, without
analysing anything. Set `CAPA_CPP_TIMING=1` to print per-phase timings and peak memory use
to stderr.

#### Flags: TTD Reports

The four after `--msgpack` are what keeps a large trace's output manageable.

| Flag | What it does |
|---|---|
| `-r`, `--rules-dir <dir>` | capa rules directory; required for matching |
| `-j`, `--json` | JSON ResultDocument instead of the capability table |
| `-vv`, `--vverbose` | capability table plus the match tree behind every hit |
| `-o`, `--output <path>` | write to a file instead of stdout |
| `--dump-features` | print the extracted features and exit; needs no rules |
| `--check-report-parse` | parse the report and exit |
| `--no-feature-filter` | keep extracted features no loaded rule reads (parity runs) |
| `-f <format>` | accepted and ignored; TTD is the only report format |
| `--msgpack` | encode the JSON document as MessagePack; needs `-j` or `--matches-only` |
| `--matches-only` | rule metadata and match addresses only, with no evidence trees or call layout; implies `-j` |
| `--match-evidence` | one leaf per match, the feature that completed it, instead of a tree |
| `--sparse-evidence` | emit a match whose tree was dropped as a bare address rather than an empty placeholder |
| `--max-match-trees <n>` | evidence trees kept per rule (default 256; `0` keeps all) |
| `--top-level-calls` | match only calls made outside every other recorded call on their thread, using each call's `returnPosition` |
| `--dump-freeze <out.frz>` | write the report's features as a capa freeze file and exit; needs no rules |

Unknown options are rejected rather than ignored.

TTD has no counterpart in capa, so its defaults are tuned for very large traces: the feature
filter is on (which changes only the reported feature counts, flagged as
`feature_counts.filtered`), and at most 256 match trees per rule are kept (the rest become
`"truncated": true` stubs). Those two members, and everything `--matches-only`,
`--match-evidence` and `--sparse-evidence` produce, are capa-cpp extensions outside capa's
schema. With `--no-feature-filter --max-match-trees 0` the document is exactly what capa writes
for the same features: `--dump-freeze` the report and run capa on the freeze file to see it.

#### Flags: TTD Code Manifests

| Flag | What it does |
|---|---|
| `-r`, `--rules-dir <dir>` | required |
| `--dumps-dir <dir>` | where the manifest's `.bin` snapshots are (default: the manifest's own directory) |
| `-o`, `--output <path>` | write the per-region capability records to a file |
| `--quiet` | no per-region progress on stderr |
| `--no-feature-filter` | as above |
| `--scan-dump-features <manifest>` | in place of `--scan-code-manifest`: dump one region's features, `--base <hex>` choosing it |

#### Flags: process memory dumps

This path always writes to stdout; `-o` is not read.

| Flag | What it does |
|---|---|
| `-r`, `--rules-dir <dir>` | required |
| `-j`, `--json` / `-vv`, `--vverbose` | as above |
| `--module <name>` | only regions whose name contains this, case-insensitive |
| `--all-modules` | include Windows system modules, which are skipped by default |
| `--region <hex>` | only the region at this base address |
| `--region-arch <arch>` | decode arch for headerless regions: `x86`/`i386`/`32` or `x64`/`amd64`/`64` |
| `--max-region-size <n>` | skip regions larger than this (default 64M; decimal, `0x` hex, or a K/M/G suffix) |
| `--linear-sweep` | add a linear sweep to code discovery; perturbs a well-formed PE, so it is opt-in |
| `--quiet` | no per-region progress on stderr |
| `--dump-info` / `--dump-modules` / `--dump-symbols [-v]` | describe the dump and exit |
| `--dump-features` | print the extracted features and exit |

### IDA Pro Plugin
Open an x86/x64 binary with the plugin loaded, choose `Edit > Plugins > CAPA C++ > Analyze`, and
give the path to a capa ruleset. When analysis completes, the matches appear as a hierarchy.

![](assets/IDA-Matches.png)

The plugin can also annotate matches in the database with highlighting and comments.

![](assets/IDA-Annotation.png)

### Headless IDA (`capa-idalib.exe`)
capa's preferred verification backend is IDA through idalib: with the same analysis under both
implementations, any difference in the output belongs to the port. `capa-idalib` opens the
sample the way capa's `-b ida` backend does (Lumina disabled, resources loaded) and runs
capa-cpp's IDA extractor over it.

```sh
capa-idalib <sample.exe> -r <rules-dir> [-j | -vv] [-o out.json]
capa-idalib <sample.exe> --dump-freeze out.frz     # compare with capa's own `-b ida` freeze
```

It needs an IDA Pro 9.x installation with idalib. It has been built and link-checked, but not
yet run against a live IDA.

## Verifying parity

The contract: same rules + same binary + same backend =
same JSON output, with only timestamps and run metadata allowed to differ. Three suites check it,
all built on capa's own test data:

| Check | What it compares | Status |
|---|---|---|
| `capa-tests match-fixtures` | capa's 106 data-driven matcher fixtures (`tests/fixtures/matcher`): rule + feature listing + exact expected matches, with capa's "paranoid" indexed-vs-naive matcher check at every scope | 106/106 pass |
| `scripts/parity.py` | result documents from capa and capa-cpp for the same freeze file and rules, compared with `compare_results.py` | equivalent for all 9 inputs tried (see below) |
| `capa-tests feature-fixtures` | capa's backend feature fixtures (`tests/fixtures/features`) evaluated against a backend's freeze file | all selected fixtures pass for capa's IDA and vivisect freezes |
| `capa-tests freeze-roundtrip` | load + re-write of freeze files | byte-identical to capa 9.4.0's writer |

The parity inputs were capa-testfiles' feature snapshots (vivisect PE32, PE64 and ELF, dnfile
.NET, and **IDA** for mimikatz) plus three CAPE sandbox reports frozen with capa, against
capa-rules at `805f9ea`. The same ruleset loads identically: 1,054 rules, 1,397 with subscope
rules extracted, the same counts per scope as capa.

```sh
pip install flare-capa            # the reference implementation
./build.sh test Release
python scripts/parity.py --capa-cpp build/Release/capa-cpp.exe --rules <capa-rules> <files.frz>
build/Release/capa-tests.exe feature-fixtures --backend idalib --include-tag static \
    --exclude-tag dotnet --exclude-tag ghidra --freeze mimikatz=<mimikatz-exe-ida.frz>
```

`compare_results.py` canonicalizes only what capa itself leaves unordered (location sets, and the
children it splices under a `match:` in set order) and the subscope rule names capa generates
from a fresh UUID on every run; everything else must be identical.
[docs/parity-notes.md](docs/parity-notes.md) records the capa behaviors that took care to
reproduce, and why.

## Supported

- capa's rule format in full: every rule in capa-rules loads, including `com/class`,
  `com/interface` and bare `property` features, and rules are parsed with PyYAML's typing of
  values, validated per scope, and optimized as capa does.
- capa's freeze format, static and dynamic, read and written.
- capa's result document, member for member.
- Any capa backend's features through freeze files, including .NET (dnfile) and the sandbox
  formats (CAPE, DRAKVUF, VMRay).
- TTD static and dynamic analysis of x86/x64 traces given the proper manifests/reports
- Process minidumps: full x86/x64 dumps, including private RWX shellcode regions.

## Not supported

- Native extraction of .NET assemblies, ELF, and PE files on disk without IDA: capa's dnfile,
  vivisect, Binary Ninja and Ghidra backends aren't ported (their freeze files work). The IDA
  plugin warns when it detects a .NET assembly.
- Native parsing of sandbox reports (CAPE, DRAKVUF, VMRay): freeze them with capa first.
- Minidumps without memory (`MiniDumpNormal`) are refused.
- Regular expressions are Python's, run on `std::regex` through a translation layer
  (`capa-core/src/pyregex.h`); constructs with no ECMAScript equivalent (lookbehind, atomic
  groups) are reported when the rules load and never match. No capa rule uses one today.
- Plain-text tables instead of capa's Rich formatting (only the JSON is part of the contract).
- IDA plugin limits:
  - x86/x64 only.
  - No ELF OS detection.
  - No rule generator.
  - Matches with a MAEC analysis conclusion aren't filtered out.
  - The UI uses IDA's own form, chooser and dirtree instead of Qt.
  - It has been built and link-checked, but not yet tested inside a running IDA.
