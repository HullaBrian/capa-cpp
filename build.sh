#!/usr/bin/env bash
# Convenience build wrapper for capa-cpp (Git Bash).
#
# Usage: ./build.sh [Debug|Release]   build that configuration (default: Debug):
#                                     capa-core.lib, capa-cpp.exe and capa-tests.exe
#        ./build.sh test [Debug|Release]
#                                     build, then run capa-tests (capa's matcher fixtures
#                                     plus capa-cpp's own checks)
#        ./build.sh clean [Debug|Release|all]
#                                     delete build output (default: all)
#
# Every artifact -- the exe, its pdb and every .obj -- lands under build/<Configuration>/,
# which is why cleaning is just an rm. See the comment in capa-cpp/capa-cpp.vcxproj.
#
# The plugin has its own wrapper: ida-capa/build.ps1, writing to the same build/<Config>/.
# capa-idalib needs the IDA SDK too: build capa-idalib/capa-idalib.vcxproj with MSBuild /m:1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"

if [[ "${1:-}" == "clean" ]]; then
    case "${2:-all}" in
        all)   targets=("$BUILD") ;;
        Debug|Release) targets=("$BUILD/${2}") ;;
        *) echo "usage: $0 clean [Debug|Release|all]" >&2; exit 2 ;;
    esac
    for t in "${targets[@]}"; do
        if [[ -d "$t" ]]; then
            rm -rf "$t"
            echo "removed: $t"
        else
            echo "nothing to remove: $t"
        fi
    done
    exit 0
fi

RUN_TESTS=0
if [[ "${1:-}" == "test" ]]; then
    RUN_TESTS=1
    shift
fi

CONFIG="${1:-Debug}"
if [[ "$CONFIG" != "Debug" && "$CONFIG" != "Release" ]]; then
    echo "usage: $0 [test] [Debug|Release] | $0 clean [Debug|Release|all]" >&2
    exit 2
fi

VS="/c/Program Files/Microsoft Visual Studio/18/Community"
MSBUILD="$VS/MSBuild/Current/Bin/amd64/MSBuild.exe"
export VCPKG_ROOT="$VS/VC/vcpkg"

# Both reference capa-core/capa-core.vcxproj, which MSBuild builds first.
for proj in capa-cpp/capa-cpp.vcxproj capa-tests/capa-tests.vcxproj; do
    "$MSBUILD" "$ROOT/$proj" -p:Configuration="$CONFIG" -p:Platform=x64 -m -nologo -v:minimal
done

# Checked rather than announced. This line used to print a path the build had not written
# to for weeks, where an old binary happened to sit -- so it looked like a successful build
# of code that was never compiled.
for exe in capa-cpp.exe capa-tests.exe; do
    if [[ ! -f "$BUILD/$CONFIG/$exe" ]]; then
        echo "error: build reported success but $BUILD/$CONFIG/$exe is missing" >&2
        exit 1
    fi
    echo "built: $BUILD/$CONFIG/$exe"
done

if [[ "$RUN_TESTS" == 1 ]]; then
    "$BUILD/$CONFIG/capa-tests.exe"
fi
