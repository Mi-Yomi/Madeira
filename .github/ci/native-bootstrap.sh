#!/bin/bash
# One bounded native stage. Deliberately no app, LLVM, DXMT, PE farm or signing.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$R"
: "${NATIVE_LOG_DIR:?Set NATIVE_LOG_DIR to a fresh diagnostics directory}"
: "${NATIVE_ARTIFACT_DIR:?Set NATIVE_ARTIFACT_DIR to a fresh output directory}"
JOBS="${JOBS:-2}"
case "$JOBS" in 1|2) ;; *) echo 'Native bootstrap requires JOBS=1 or 2' >&2; exit 2 ;; esac
export JOBS BUILD_JOBS="$JOBS" CMAKE_BUILD_PARALLEL_LEVEL="$JOBS" CARGO_BUILD_JOBS="$JOBS" MAKEFLAGS="-j$JOBS"
mkdir -p "$NATIVE_LOG_DIR"
exec > >(python3 .github/ci/native-log-stream.py "$NATIVE_LOG_DIR/bootstrap.log") 2>&1
trap 'code=$?; printf "Native bootstrap exit: %s\n" "$code"; exit "$code"' EXIT
stage() { printf '\n=== %s (%s) ===\n' "$1" "$(date -u +%FT%TZ)"; }

stage 'Preflight: source, Apple SDK, tools and disk'
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || { echo 'Requires a native Apple ARM64 macOS runner'; exit 1; }
for tool in git xcodebuild xcrun cmake ninja python3 brew rustup rustc cargo curl shasum; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool"; exit 1; }
done
# Record only an explicit allowlist. Never emit env, printenv, git config or secrets.
python3 .github/ci/native-artifacts.py record "$NATIVE_LOG_DIR/provenance-inputs.json"
xcodebuild -version
SDK_VERSION="$(xcrun --sdk iphoneos --show-sdk-version)"
case "$SDK_VERSION" in 27.*) ;; *) echo "Expected iOS 27 SDK, found $SDK_VERSION"; exit 1 ;; esac
case "$(xcodebuild -version | sed -n '1p')" in 'Xcode 27'*) ;; *) echo 'Expected Xcode 27'; exit 1 ;; esac
xcrun --sdk iphoneos --find clang
# The approved optional Apple component is installed only if actually missing.
# Xcode agreement EA2002 (2026-06-08): https://www.apple.com/legal/sla/docs/xcode.pdf
# The helper fails on new terms/auth/payment, verification failure or smoke failure.
# Its seven-minute cap is included in this stage's existing 35-minute budget.
python3 .github/ci/ensure-metal-toolchain.py --allow-install --log-dir "$NATIVE_LOG_DIR"
df -h .
# Clean builds only: no stale archives/headers/markers can create a false pass.
for path in FEX/build-ios wine/build-macos wine/build-arm64ec build/freetype-ios/build build/gnutls-ios/obj build/ffmpeg/obj build/ntdll-unix/obj build/win32u-unix/obj build/wineserver/obj build/wineserver/libwineserver_base.a build/rppairing-ios/target toolchains/gnutls-ios toolchains/ffmpeg-ios; do
    [ ! -e "$path" ] || { echo "Refusing non-clean build path: $path"; exit 1; }
done
# These source tarballs and Apple's redistributable converter are already tracked.
# The Metal component above uses only Apple's documented downloader.
(cd build/gnutls-ios/src && shasum -a 256 -c SHA256SUMS)
(cd build/ffmpeg/src && shasum -a 256 -c SHA256SUMS)
(cd madeira-d3d12/third_party/metal-shader-converter && shasum -a 256 -c SHA256SUMS)
printf '%s  %s\n' 073f903be98e973ff38f4d79f2c48d61ef938754a77b1caedda79c9f05a068c2 app/Madeira/d3d12/libmetalirconverter.dylib | shasum -a 256 -c -
for path in app/Madeira/d3d12/NOTICE.txt app/Madeira/d3d12/LICENSE-metal-shader-converter-headers.txt madeira-d3d12/third_party/metal-shader-converter/include/metal_irconverter/LICENSE.txt; do
    test -s "$path"
done

stage 'Build tools'
# Wine needs bison >=3; macOS ships an older system bison. Official Homebrew only.
brew install bison flex
export PATH="$(brew --prefix bison)/bin:$(brew --prefix flex)/bin:$PATH"
bison --version
flex --version
rustup target add aarch64-apple-ios

stage 'Pinned llvm-mingw and FreeType'
TC=llvm-mingw-20260421-ucrt-macos-universal
mkdir -p toolchains research
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 30 --max-time 600 \
    "https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/$TC.tar.xz" -o "toolchains/$TC.tar.xz"
printf '%s  %s\n' bd85a3975723815cef28dbbd2ca2cb0c926f6b348a12a0453f39f7af273cb3f7 "toolchains/$TC.tar.xz" | shasum -a 256 -c -
tar -xJf "toolchains/$TC.tar.xz" -C toolchains
export PATH="$R/toolchains/$TC/bin:$PATH"
"$R/toolchains/$TC/bin/arm64ec-w64-mingw32-clang" --version
[ ! -e research/freetype ] || { echo 'Refusing pre-existing FreeType checkout'; exit 1; }
git init research/freetype
git -C research/freetype remote add origin https://github.com/freetype/freetype.git
git -C research/freetype -c credential.helper= fetch --depth 1 origin 42608f77f20749dd6ddc9e0536788eaad70ea4b5
git -C research/freetype checkout --detach 42608f77f20749dd6ddc9e0536788eaad70ea4b5
test "$(git -C research/freetype rev-parse HEAD)" = 42608f77f20749dd6ddc9e0536788eaad70ea4b5
python3 .github/ci/native-artifacts.py record "$NATIVE_LOG_DIR/provenance-inputs.json" --ready

# Keep native C/C++ builds on Apple's compiler even with llvm-mingw on PATH.
export CC="$(xcrun --sdk iphoneos --find clang)"
export CXX="$(xcrun --sdk iphoneos --find clang++)"

stage 'FreeType'
bash build/freetype-ios/build.sh
stage 'GMP, Nettle, Hogweed and GnuTLS'
bash build/gnutls-ios/build.sh
for lib in gmp nettle hogweed gnutls; do
    cp "toolchains/gnutls-ios/lib/lib$lib.a" "app/Madeira/lib$lib.a"
done
stage 'FFmpeg LGPL media libraries'
bash build/ffmpeg/build.sh
stage 'FEX native libraries'
bash build/fex-ios/build.sh
stage 'Wine native and ARM64EC generated headers'
bash .github/ci/prepare-wine-headers.sh
stage 'Wine ntdll native library'
bash build/ntdll-unix/build.sh
python3 .github/ci/native-artifacts.py crypto-symbols
stage 'Wine win32u native library'
bash build/win32u-unix/build.sh
stage 'Wine in-process server native library'
bash build/wineserver/build.sh
stage 'Rust on-device pairing'
bash build/rppairing-ios/build.sh
stage 'Validate every archive member and stage provenance'
python3 .github/ci/native-artifacts.py collect "$NATIVE_LOG_DIR/provenance-inputs.json" "$NATIVE_ARTIFACT_DIR"
stage 'Native dependency stage complete; app and device testing remain'
