#!/bin/bash
# Build only the iOS static libraries used by the app, never the Linux-oriented
# shared targets. Reconfigure existing trees too so old caches get these fixes.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
B="$R/FEX/build-ios"
JOBS="${BUILD_JOBS:-2}"
case "$JOBS" in ''|*[!0-9]*|0) echo "BUILD_JOBS must be a positive integer" >&2; exit 1;; esac
python3 "$R/build/fex-ios/apply-source-repairs.py"
cmake -S "$R/FEX" -B "$B" -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_PROCESSOR=arm64 \
    -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 -DCMAKE_BUILD_TYPE=Release -DTUNE_CPU=none \
    -DENABLE_LTO=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_DISABLE_FIND_PACKAGE_fmt=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_unordered_dense=TRUE \
    -DCMAKE_DISABLE_FIND_PACKAGE_range-v3=TRUE \
    -DBUILD_TESTING=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF -DBUILD_FEX_LINUX_TESTS=OFF \
    -DENABLE_FEX_ALLOCATOR=OFF -DENABLE_ASSERTIONS=OFF -DENABLE_CLANG_THUNKS=ON -DENABLE_CCACHE=ON
cmake --build "$B" --parallel "$JOBS" --target FEXCore FEXCore_Base JemallocLibs softfloat_3e
for archive in \
    FEXCore/Source/libFEXCore.a FEXCore/Source/libFEXCore_Base.a FEXCore/Source/libJemallocLibs.a \
    External/cephes/libcephes_128bit.a External/fmt/libfmt.a \
    External/SoftFloat-3e/libsoftfloat_3e.a External/xxhash/cmake_unofficial/libxxhash.a; do
    [ -s "$B/$archive" ] || { echo "Missing FEX archive: $B/$archive" >&2; exit 1; }
    echo "$B/$archive"
done
