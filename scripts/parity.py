#!/usr/bin/env python3
"""
Check capa-cpp against capa: same rules + same freeze file = same result document.

For each freeze file, runs capa (the reference implementation, `pip install flare-capa`)
and capa-cpp with the same rules, and compares the two result documents with
compare_results.py. capa's output is cached next to the freeze file as
<name>.<capa version>.json, so later runs only re-run capa-cpp.

Freeze files to use: capa-testfiles/fixtures/snapshots/features/*.frz (static: vivisect,
IDA, dnfile), or any `python -m capa.features.freeze <sample> <out.frz>` -- including the
sandbox formats (`-f cape`, `-f drakvuf`, `-f vmray`) for dynamic analysis.

usage:
    parity.py --capa-cpp build/Release/capa-cpp.exe --rules <capa-rules> <file.frz> [...]
"""

import sys
import argparse
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare_results  # noqa: E402


def capa_version(python: str) -> str:
    out = subprocess.run([python, "-c", "import capa.version; print(capa.version.__version__)"],
                         capture_output=True, text=True, check=True, cwd=Path.home())
    return out.stdout.strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capa-cpp", required=True, help="path to capa-cpp.exe")
    parser.add_argument("--rules", required=True, help="capa rules directory (the same one for both)")
    parser.add_argument("--python", default=sys.executable, help="python with flare-capa installed")
    parser.add_argument("--out", default=None, help="where to write capa-cpp's documents (default: beside each .frz)")
    parser.add_argument("freeze", nargs="+")
    args = parser.parse_args(argv)

    args.capa_cpp = str(Path(args.capa_cpp).resolve())
    version = capa_version(args.python)
    failures = 0
    for frz in map(Path, args.freeze):
        golden = frz.with_name(f"{frz.stem}.capa-{version}.json")
        if not golden.exists():
            print(f"[capa {version}] {frz.name} ...", flush=True)
            # run from the home directory: a `capa` checkout in the working directory
            # would shadow the installed package
            with golden.open("wb") as f:
                subprocess.run([args.python, "-m", "capa.main", "-q", "-j", "-r", args.rules, str(frz.resolve())],
                               stdout=f, check=True, cwd=Path.home())
        out_dir = Path(args.out) if args.out else frz.parent
        actual = out_dir / f"{frz.stem}.capa-cpp.json"
        subprocess.run([args.capa_cpp, str(frz), "-r", args.rules, "-j", "-o", str(actual)], check=True)
        print(f"{frz.name}: ", end="", flush=True)
        failures += compare_results.main([str(golden), str(actual)])
    print(f"{len(args.freeze) - failures}/{len(args.freeze)} equivalent")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
