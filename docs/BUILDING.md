# Building Madeira from a clean checkout (reproducibility record, 2026-09-16)

This is the "scripts to control compilation and installation" record the
LGPL relink obligation depends on (docs/LICENSING.md). Each step says
whether it has been re-executed from a clean checkout. A fresh recursive
clone of the repository at commit 8a8cabe was tested on 2026-09-16 (with
the submodule URLs redirected to the local forks, since nothing is pushed):
the app target does NOT build from the clone alone, because the inputs
marked "not in the repository" below are absent. Two further findings:
`app/Madeira/x86_64-vcruntime` is required by the project but ignored, and
the submodule commits (FEX, its nested rpmalloc fork, wine branch
`madeira-lgpl`, dxmt) exist only locally: the forks named in `.gitmodules`
(all under github.com/willfaust) do not yet carry them, so a recipient's
recursive clone fails at the first submodule until every fork is pushed. This document is the
remediation; steps marked UNVERIFIED have not yet been re-run from scratch.

## Current source availability and bounded bootstrap (2026-10-04)

The paragraph above records the historical 2026-09-16 attempt, not the current
availability of the forks. The pinned FEX, Wine, DXMT and Madeira Dock commits,
including the nested FEX/rpmalloc/DXMT gitlinks, are now publicly available.
A recursive checkout still does not supply the ignored generated libraries,
headers and cross-toolchains required for the app link.

`.github/workflows/native-bootstrap.yml` prepares only the first native stage.
It starts with portable failure-injection tests, then uses the standard
[`xcode-27` public runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories).
The [runner inventory](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md)
currently lists Xcode 27 and the iOS 27 SDK; the job verifies the actual native
compiler and SDK instead of accepting a missing prerequisite or license prompt.
The audited image has a Metal discovery stub without the optional component.
The authorized temporary-runner setup may install only Apple's compatible
Metal Toolchain using its documented downloader, under the linked Xcode and
Apple SDKs Agreement EA2002 (2026-06-08). The helper requires explicit
`--allow-install`, pins Xcode 27.0 / 27A266a and its developer directory, and
stops on any new terms, sign-in or payment indication. It never invokes
`-license accept`, a broad update or another component installer.

Metal setup has a 300-second download / 420-second total cap inside the existing
35-minute build budget. Actual Apple-signed compiler/linker paths, versions and
a disposable iOS shader compile/link smoke must pass. Receipt fields and hashes
are retained in standard job logs and successful native provenance; a configured
workflow or located shim is not an installation result. These checks prepare
later DXMT/app stages; native C/C++/Rust libraries themselves need no Metal
compiler (FFmpeg explicitly disables it).

- Native job timeout: 45 minutes, including a 35-minute build step; at most
  two compile jobs. No signing account, new secret or larger paid runner
- Exact submodule pins, tool versions and source hashes are recorded. The
  official llvm-mingw archive is checksum-verified before use. FreeType uses
  commit `42608f77f20749dd6ddc9e0536788eaad70ea4b5`
- Separate native and ARM64EC Wine trees generate real headers. Failed header
  generation or compilation is fatal; stale archives cannot satisfy the stage
- FEX builds all seven app-linked static archives. Its pinned source has two
  iOS-host-only diagnostic reporters outside their declaration guard. A local,
  hash/revision-checked Madeira build repair puts the existing reporters under
  `FEX_IOS_HOST`; it changes no external repository or submodule pin. The patch,
  original/result source hashes and applied record are validated and included
  in native provenance (see `build/fex-ios/README.md`)
- Wineserver builds its base
  from current sources, overlays the maintained iOS objects, and validates
  the archive members and required symbol renames before replacing an output
- Every non-index member of all 20 required dependency archives is checked as
  an arm64 iOS Mach-O object. Host, simulator, unknown-bitcode, missing and
  partial results are rejected. Rust LTO output is verified, not assumed
- Bounded diagnostics are printed in the normal GitHub job log. The first
  push-triggered run does **not** upload artifacts: artifact storage has a
  separate [billing allowance](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
  The default-false manual upload option must be used only after confirming
  free capacity or explicitly authorizing storage use. Optional dependency
  output is capped at 400 MiB, diagnostics at 16 MiB, with 3-day retention

The workflow stops before LLVM, DXMT, the Xcode app link and IPA packaging.
A green native stage is therefore not an IPA or an on-device result. The next
stages must build the pinned LLVM libraries, generate DXMT's three AIR headers,
create `libdxmt_combined.a` from a clean build, stage notices and link the app in
**Debug**. The separate Apple converter installer is unnecessary when using
the already tracked, checksum-verified converter library and notices.

Microsoft runtime DLLs are not required merely to produce an app bundle: the
ignored `app/Madeira/x86_64-vcruntime/` resource directory can be empty. Exact
Windows applications may need their own runtime installation later, under its
applicable terms. An unsigned/ad-hoc build likewise needs no Apple account,
while installation/signing and JIT on an iPhone remain separate steps.

This section describes the new build recipe and its gates. It does not mark
any formerly unverified native or clean-app build as passed before its CI
result is recorded.

## Inputs that are not in the repository

| Input | Why absent | How to obtain | Verified from clean |
|---|---|---|---|
| `toolchains/llvm-mingw-20260421-ucrt-macos-universal/` | 122 MB third-party toolchain | `llvm-mingw-20260421-ucrt-macos-universal.tar.xz` from https://github.com/mstorsjo/llvm-mingw/releases/tag/20260421, SHA-256 `bd85a3975723815cef28dbbd2ca2cb0c926f6b348a12a0453f39f7af273cb3f7`, extracted under `toolchains/` | tarball hash recorded; download UNVERIFIED |
| `toolchains/llvm-project/` + `toolchains/llvm-ios-build/` + `toolchains/llvm-host-build/` | LLVM built for iOS (hours) | upstream llvm-project at commit `8dfdcc7b7` ("[libc++] Fix memory leaks when throwing inside std::vector constructor"); configure `llvm-ios-build` with `-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_BUILD_TYPE=Release -DLLVM_HOST_TRIPLE=arm64-apple-ios17.0 -DLLVM_DEFAULT_TARGET_TRIPLE=arm64-apple-ios17.0 -DLLVM_TARGET_ARCH=host -DLLVM_TARGETS_TO_BUILD= -DLLVM_ENABLE_PROJECTS= -DLLVM_BUILD_TOOLS=Off -DLLVM_INCLUDE_TESTS=Off -DLLVM_ENABLE_ZLIB=Off` (values read back from the existing CMakeCache); a host build for tablegen lives in `llvm-host-build` | recipe reconstructed; UNVERIFIED |
| `research/GPTK/Metal Shader Converter 4.0 beta 2.pkg` | Apple installer, 30 MB, licence-bound | Apple developer downloads; SHA-256 `1acc33c87ea663933df89721a998d066106685473020bcbe007cee7a16155734` (pinned in `build/madeira-d3d12/deps.sh`). Only needed to REBUILD the converter fetch; the library itself is tracked | n/a |
| `app/Madeira/x86_64-vcruntime/` | Microsoft Visual C++ 2015-2022 x64 runtime DLLs (concrt140, msvcp140*, vcamp140, vccorlib140, vcruntime140*), redistributable under Microsoft's terms, not under this repository's licence | extract from Microsoft's `vc_redist.x64.exe` (or copy from `C:\Windows\System32` of a licensed Windows install) into that folder | UNVERIFIED |
| A free Apple ID; StikDebug or a pairing file plus LocalDevVPN | signing and JIT runtime requirements | see `docs/JIT.md` | n/a |

## Native build chains (all in the repository)

Run in this order after the inputs above are in place. Outputs are
git-ignored and consumed by the app project.

1. `build/gnutls-ios/build.sh`: GMP 6.3.0, Nettle 3.10.1, GnuTLS 3.8.9 from
   the tracked tarballs in `build/gnutls-ios/src` (SHA256SUMS there) ->
   `app/Madeira/lib{gmp,nettle,hogweed,gnutls}.a` (these four outputs are
   also tracked). Verified: built on the development machine; not re-run
   from a clean checkout.
   `build/ffmpeg/build.sh`: FFmpeg 7.1.1 in an LGPL-only configuration (WMA,
   MPEG audio and PCM decoders; mp3/wav/mov demuxers; no H.264/HEVC/AAC),
   built from the tracked, unmodified release tarball in `build/ffmpeg/src`
   after verifying it against `build/ffmpeg/src/SHA256SUMS` -> headers in `toolchains/ffmpeg-ios/include`
   (read by `build/ntdll-unix/build.sh` for winegstreamer's unix side) and
   `app/Madeira/lib{avformat,avcodec,swresample,avutil}.a` (ignored; the app
   target links them together with VideoToolbox, CoreMedia, CoreVideo,
   AudioToolbox and CoreFoundation). The configure arguments are the ones the
   port was built and device-tested with on the WSL toolchain; the macOS form
   of the script is UNVERIFIED.
2. FEX (submodule, branch ios-port-2607):
   - `FEX/build-ios`: `build/fex-ios/build.sh` (same options as the development CMakeCache) -> `FEX/build-ios/FEXCore/Source/lib{FEXCore,FEXCore_Base,JemallocLibs}.a` and the `External/{cephes,fmt,SoftFloat-3e,xxhash}` archives. UNVERIFIED from clean.
   - `FEX/build-arm64ec`: `build/fex-arm64ec/build.sh` (configures with `FEX/Data/CMake/toolchain_mingw.cmake` and the recorded options on first run, builds target `arm64ecfex`, copies `Bin/libarm64ecfex.dll` to `app/Madeira/arm64ec-windows/xtajit64.dll`). The build step was verified this session; the first-run configure in the script is reconstructed from CMakeCache and UNVERIFIED.
3. Wine (submodule, branch madeira-lgpl):
   - unix side: `build/ntdll-unix/build.sh`, `build/wineserver/build.sh`,
     `build/win32u-unix/build.sh` -> `app/Madeira/lib{ntdll_unix,wineserver,win32u_unix}.a`. Verified on the development machine.
   - PE side: `build/wine-pe/build-ntdll.sh` (configures `wine/build-arm64ec` with `--enable-archs=arm64ec --without-x --disable-tests --enable-winegstreamer` on first run, builds `dlls/ntdll`, strips, pads to SizeOfImage + 0x50000, copies to the app). Other PE modules: `make -C dlls/<name>` in that tree and copy the DLL, as the script's header says; winegstreamer (enabled by `--enable-winegstreamer` although GStreamer is absent, since its unix side is `build/ntdll-unix/winegstreamer_unixlib_ios.c`) is built as the target `dlls/winegstreamer/arm64ec-windows/winegstreamer.dll`, never with `make -C`. The strip/pad step was verified this session; the configure step is UNVERIFIED from clean.
   - `app/Madeira/arm64ec-windows/` is the DLL farm: every file in it is linked into the prefix (`system32` for x64 sessions, and `sysx64`), so a Wine module is only available if it was built and copied there. The native D3D12 path needs two stock modules in addition to the existing ones: `dcomp.dll` (`make -C dlls/dcomp`; a 64-bit Godot 4 engine loads it before it creates its D3D12 device, and gives up on D3D12 without it) and `ktmw32.dll` (`make -C dlls/ktmw32`; an optional import the same engine probes).
4. DXMT (submodule, branch ios-port):
   - unix side: `build/dxmt-ios/build.sh` (needs `toolchains/llvm-ios-build`) -> `app/Madeira/libdxmt_combined.a` (ignored; the app links it). Verified this session.
   - PE side: `meson setup dxmt/build-arm64ec dxmt -Dbuildtype=release -Dwine_build_path=../../wine/build-arm64ec --cross-file=dxmt/build-arm64ec-win.txt` then `ninja -C dxmt/build-arm64ec src/winemetal/winemetal.dll` (and d3d11.dll) -> copied to `app/Madeira/arm64ec-windows/`. Verified this session (winemetal.dll).
4b. In-app pairing (Built-in StikJIT on iOS 27): `build/rppairing-ios/build.sh`
   (Rust with the `aarch64-apple-ios` target; crates from crates.io at the
   versions in `build/rppairing-ios/Cargo.lock`) -> `app/Madeira/libmadeira_rppairing.a`
   (ignored; the app links it) and the bundled crate notices
   `app/Madeira/legal/LICENSES-rppairing-crates.txt` (tracked). `cargo test`
   in that folder runs its host tests. Verified on the development machine.
5. Native D3D12 runtime: `build/madeira-d3d12/build-pe.sh` -> `d3d12.dll`, `madeira_d3d12.dll` and the test executables in `app/Madeira/arm64ec-windows/` (tracked). Verified this session. `build/madeira-d3d12/fetch-converter.sh` re-verifies the converter library; `build/stage-licenses.sh` refreshes the bundled licence copies (the Xcode build fails if they are stale).
6. App: `xcodebuild -project app/Madeira.xcodeproj -scheme Madeira -destination 'generic/platform=iOS' -allowProvisioningUpdates build` (Debug is the configuration that runs the games; Release builds have crashed the guest), then zip `Payload/Madeira.app` into an IPA and sideload. Verified this session on the development machine.
7. WoW64 (32-bit programs, optional): `build/wine-i386/build.sh` (i386 Wine farm
   -> `app/Madeira/i386-windows/`), `build/fex-wow64/build.sh` (FEX WOW64 module
   -> `app/Madeira/aarch64-windows/xtajit.dll`) and the aarch64 `wow64.dll` /
   `wow64win.dll`; see docs/WOW64.md, "Building". UNVERIFIED on macOS.

## Status of the LGPL relink question

A recipient of a built package can obtain the complete corresponding
source of every LGPL library (Wine fork, GnuTLS, Nettle, GMP, FFmpeg) from the
repository, and the application source and build scripts above. Whether
they can actually relink depends on assembling the "not in the repository"
inputs and re-executing the UNVERIFIED steps; that end-to-end clean-machine
rebuild, signing and installation has NOT been performed. Until it is,
docs/LICENSING.md keeps the relink capability marked unverified. The
alternative the LGPL offers, shipping the application's object files, is
not currently done.
