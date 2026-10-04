#!/bin/bash
# Configure real native and ARM64EC trees; do not alias them or mask failures.
# include/all builds Wine's own host generators and their complete header graph,
# not the Wine DLL farm. Both trees are required by the native library scripts.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JOBS="${JOBS:-2}"
case "$JOBS" in 1|2) ;; *) echo 'Wine bootstrap requires JOBS=1 or 2' >&2; exit 2 ;; esac
TC="$R/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
export PATH="$TC:$PATH"
# Native configure probes and host tools must use the macOS SDK, not the
# Windows compiler at the front of PATH or an inherited iOS SDKROOT.
export CC="$(xcrun --sdk macosx --find clang)"
export CXX="$(xcrun --sdk macosx --find clang++)"
export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
OPTS=(
    --without-x --disable-tests --without-freetype --without-gnutls
    --without-gstreamer --without-sdl --without-vulkan --without-opencl
    --without-cups --without-krb5 --without-pcap --without-usb --without-capi
    --without-sane --without-gphoto --without-netapi --without-pcsclite
    --without-inotify
)
for spec in build-macos:aarch64 build-arm64ec:arm64ec; do
    tree="${spec%:*}" arch="${spec#*:}"
    B="$R/wine/$tree"
    [ ! -e "$B" ] || { echo "Expected fresh Wine tree: $B" >&2; exit 1; }
    mkdir -p "$B"
    (
        cd "$B"
        ../configure "--enable-archs=$arch" "${OPTS[@]}"
        make -j"$JOBS" include/all
        for header in config.h dwrite.h dwrite_1.h dwrite_2.h dwrite_3.h mfobjects.h mftransform.h; do
            test -s "include/$header" || { echo "Missing generated $tree/include/$header" >&2; exit 1; }
        done
    )
done
