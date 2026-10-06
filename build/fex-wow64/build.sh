#!/bin/bash
# Reconfigure the PE iOS host explicitly on every build. Keep existing DLLs
# until repair verification, configuration checks and the complete link succeed.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="${LLVM_MINGW_ROOT:-$R/toolchains/llvm-mingw-20260421-ucrt-macos-universal}/bin:$PATH"
B="${FEX_PE_BUILD_DIR:-$R/FEX/build-wow64}"
JOBS="${BUILD_JOBS:-2}"
case "$JOBS" in ''|*[!0-9]*|0) echo "BUILD_JOBS must be a positive integer" >&2; exit 1;; esac
case "${FEX_PE_STAGE:-1}" in 0|1) ;; *) echo "FEX_PE_STAGE must be 0 or 1" >&2; exit 1;; esac
python3 "$R/build/fex-ios/check-pe-configuration.py" before "$B" "wow64"
python3 "$R/build/fex-ios/apply-source-repairs.py"
cmake -S "$R/FEX" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="$R/FEX/Data/CMake/toolchain_mingw.cmake" \
    -DMINGW_TRIPLE=aarch64-w64-mingw32 \
    -DFEX_IOS_HOST_BUILD=ON -DENABLE_GUEST_WINDOW=ON \
    -DCMAKE_C_FLAGS=-DFEX_IOS_HOST -DCMAKE_CXX_FLAGS=-DFEX_IOS_HOST \
    -DCMAKE_ASM_FLAGS=-DFEX_IOS_HOST -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DENABLE_LTO=OFF -DENABLE_ASSERTIONS=OFF -DENABLE_JEMALLOC_GLIBC_ALLOC=OFF \
    -DENABLE_CCACHE=OFF -DBUILD_TESTING=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF \
    -DTUNE_ARCH=generic -DTUNE_CPU=none -DCMAKE_POLICY_VERSION_MINIMUM=3.5
python3 "$R/build/fex-ios/check-pe-configuration.py" after "$B" "wow64"
cmake --build "$B" --parallel "$JOBS" --target wow64fex
[ -s "$B/Bin/libwow64fex.dll" ] || { echo "Missing linked FEX PE DLL" >&2; exit 1; }
if [ "${FEX_PE_STAGE:-1}" = 1 ]; then
    cp "$B/Bin/libwow64fex.dll" "$R/app/Madeira/aarch64-windows/xtajit.dll"
    cmp "$B/Bin/libwow64fex.dll" "$R/app/Madeira/aarch64-windows/xtajit.dll"
fi
