#!/usr/bin/env bash
# Builds the release ida-capa.so: the Linux IDA plugin, made to load on as many
# distributions as the build machine allows.
#
# Produces build/linux-release/ida-capa.so (stripped) and prints its glibc floor and
# SHA-256.
#
# Usage: ./scripts/build-linux-release.sh
#
# What makes it a release build rather than ida-capa/build.sh:
#   - yaml-cpp 0.8.0 is built from source and linked statically. Debian and Ubuntu
#     package only a shared libyaml-cpp, which the target would then need too.
#   - libstdc++ is linked statically and kept private (--exclude-libs), so the plugin
#     needs no particular GLIBCXX version and cannot clash with IDA's own copy.
#     libgcc stays dynamic: the static unwinder needs glibc 2.35's _dl_find_object.
#
# The plugin then needs only libc, libz.so.1 and IDA's libida.so. Its glibc floor is
# set by the machine it is built on, so build on the oldest distribution it should
# load on. On Ubuntu 22.04 with g++-12 the floor is glibc 2.34: Ubuntu 22.04+,
# Debian 12+, RHEL/Rocky/Alma 9+. A newer machine raises it (glibc >= 2.38 headers
# also redirect strtoll to C23 symbols).
#
# Ubuntu 22.04 prerequisites (CMake 3.25+ is not packaged there; pip has it):
#   sudo apt install build-essential g++-12 git python3-pip zlib1g-dev nlohmann-json3-dev
#   pip3 install cmake
# The ida-sdk submodule must be checked out.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/build/linux-release"
YAML_CPP_TAG="0.8.0"

# g++-12 where it is installed (Ubuntu 22.04's default g++ 11 is weaker on C++20),
# else whatever the environment or PATH provides.
if [[ -z "${CXX:-}" ]] && command -v g++-12 >/dev/null; then
    export CC=gcc-12 CXX=g++-12
fi

if [[ ! -f "$ROOT/ida-sdk/src/cmake/idasdk_init.cmake" ]]; then
    echo "error: ida-sdk is missing; run: git submodule update --init" >&2
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# yaml-cpp, static and position-independent so it can go into a shared object.
# -include cstdint: 0.8.0 omits it, which GCC 13+ rejects (fixed upstream after 0.8.0).
git clone -q -c advice.detachedHead=false --depth 1 --branch "$YAML_CPP_TAG" \
    https://github.com/jbeder/yaml-cpp "$WORK/yaml-cpp-src"
cmake -S "$WORK/yaml-cpp-src" -B "$WORK/yaml-cpp-build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-include cstdint" -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DYAML_BUILD_SHARED_LIBS=OFF -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF \
    -DYAML_CPP_BUILD_CONTRIB=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$WORK/yaml-cpp" -Wno-dev -Wno-deprecated >/dev/null
cmake --build "$WORK/yaml-cpp-build" -j >/dev/null
cmake --install "$WORK/yaml-cpp-build" >/dev/null

# The plugin. Naming the static yaml-cpp's targets file makes ida-capa/CMakeLists.txt
# take it instead of searching the system for one.
cmake -S "$ROOT/ida-capa" -B "$WORK/plugin" -DCMAKE_BUILD_TYPE=Release \
    -DYAML_CPP_STATIC_TARGETS_FILE="$WORK/yaml-cpp/lib/cmake/yaml-cpp/yaml-cpp-targets.cmake" \
    -DCMAKE_SHARED_LINKER_FLAGS="-static-libstdc++ -Wl,--exclude-libs,ALL"
cmake --build "$WORK/plugin" -j

SO="$WORK/ida-capa.so"
cp "$WORK/plugin/ida-capa.so" "$SO"
strip --strip-unneeded "$SO"

# Checked, not assumed: a stray export or a C++ runtime dependency would make this a
# worse release than it claims to be.
needed="$(readelf -d "$SO" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')"
exports="$(objdump -T "$SO" | awk '$2 == "g" && $4 != "*UND*" {print $NF}' | tr '\n' ' ')"
if [[ "$needed" == *libstdc++* || "$needed" == *yaml-cpp* ]]; then
    echo "error: $SO still links $needed" >&2
    exit 1
fi
if [[ "$exports" != "PLUGIN " ]]; then
    echo "error: $SO exports more than PLUGIN: $exports" >&2
    exit 1
fi
floor="$(objdump -T "$SO" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"

echo
echo "built:  $SO"
echo "needs:  $needed"
echo "floor:  ${floor#GLIBC_} (glibc)"
echo "sha256: $(sha256sum "$SO" | cut -d' ' -f1)"
