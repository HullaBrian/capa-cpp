#!/usr/bin/env bash
# Builds ida-capa, the capa plugin for IDA Pro, on Linux.
#
# Produces build/ida-capa/ida-capa.so (Release by default).
#
# Usage: ./ida-capa/build.sh [Debug|Release] [--install]
#
#   --install   also copy the .so into ~/.idapro/plugins
#
# Dependencies (nlohmann-json, yaml-cpp) come from the system by default:
#   Fedora:  sudo dnf install json-devel yaml-cpp-devel
#   Debian:  sudo apt install nlohmann-json3-dev libyaml-cpp-dev
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build/ida-capa"

CONFIG="Release"
INSTALL=0
for arg in "$@"; do
    case "$arg" in
        Debug|Release) CONFIG="$arg" ;;
        --install) INSTALL=1 ;;
        *) echo "usage: $0 [Debug|Release] [--install]" >&2; exit 2 ;;
    esac
done

cmake -S "$ROOT/ida-capa" -B "$BUILD" -DCMAKE_BUILD_TYPE="$CONFIG"
cmake --build "$BUILD" -j

SO="$BUILD/ida-capa.so"
if [[ ! -f "$SO" ]]; then
    echo "error: build reported success but $SO is missing" >&2
    exit 1
fi
echo "built: $SO"

if [[ "$INSTALL" -eq 1 ]]; then
    # IDA keeps the plugin .so open for as long as it runs, so installing over a
    # live IDA either fails outright or -- worse -- appears to work while the old
    # binary stays loaded (see the equivalent comment in build.ps1).
    if pgrep -x -f 'ida64|ida|idat64|idat' > /dev/null 2>&1; then
        echo "error: IDA is running. Close it before installing, or the .so cannot" >&2
        echo "       be replaced and IDA will keep running the old build." >&2
        exit 1
    fi

    PLUGIN_DIR="$HOME/.idapro/plugins"
    mkdir -p "$PLUGIN_DIR"
    DST="$PLUGIN_DIR/ida-capa.so"
    cp -f "$SO" "$DST"

    SRC_HASH="$(sha256sum "$SO" | cut -d' ' -f1)"
    DST_HASH="$(sha256sum "$DST" | cut -d' ' -f1)"
    if [[ "$SRC_HASH" != "$DST_HASH" ]]; then
        echo "error: installed copy at $DST does not match the build output -- it was not replaced" >&2
        exit 1
    fi
    echo "installed to $PLUGIN_DIR"
    echo "IDA prints its build stamp on load: 'capa: ida-capa loaded (build ...)'"
fi
