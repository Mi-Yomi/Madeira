# Bounded native bootstrap

`native-bootstrap.yml` adds a separate first-stage check for the
`compatibility/desktop-apps` branch. The existing desktop compatibility checks
continue alongside this workflow. It runs on GitHub's standard public-repository `xcode-27` ARM64
runner after a five-minute portable Linux validation gate, with a 45-minute native job limit, a 35-minute build-step limit, and at most two
compile jobs. See the [runner specification](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [installed Xcode/SDK image](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md).

The stage verifies exact recursive submodule commits, the iOS 27 SDK, tracked
tarballs/converter inputs, checksum-pinned llvm-mingw and commit-pinned FreeType.
Optional Metal tool availability is reported separately for later stages. It builds FreeType, the crypto stack, FFmpeg, seven FEX
archives, separate native/ARM64EC Wine header trees, Wine's three native
libraries and Rust pairing. Header generation and compilation failures are
fatal. The generated crypto symbol table must contain its bootstrap essentials.
No Apple installer, LLVM source build, DXMT build, Windows DLL farm, app link,
IPA, signing or device test is attempted.

`native-artifacts.py` checks all 20 expected archives member by member. Every
object must be little-endian arm64 Mach-O with an explicit iOS platform command;
macOS, simulator, arm64e, empty, partial and opaque bitcode outputs are rejected.
Rust's ordinary release LTO is expected to yield native staticlib objects, but
the first real build must establish that for this toolchain. This validation
proves output format/completeness, not linkability or 1C/Blender compatibility.
The temporary dependency bundle contains only verified archives, provenance and
license/notice text, capped at 400 MiB. Its actual size is printed after build.

Automatic push runs do **not** upload artifacts. GitHub's free public-runner
compute is distinct from [pooled artifact-storage billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
The manual `upload_artifacts` input defaults to false and may be enabled only
after free storage has been verified or storage charges explicitly approved.
When authorized, successful dependency bundles and always-collected diagnostic
artifacts have a three-day retention. The live build log is capped at 8 MiB
(head and tail); allowlisted diagnostics plus provenance stay under 16 MiB.
Failure excerpts and exact provenance are printed to native GitHub job logs,
which do not require artifact uploads. Environment dumps, Autoconf cache logs,
object/source trees, proprietary converter and VC-runtime binaries are excluded.
A hard job cancellation or runner failure can still prevent final diagnostics.

Portable local checks, requiring no Apple SDK or downloaded toolchain:

```sh
python3 tests/host/check-native-bootstrap-artifacts.py
python3 tests/host/check-native-bootstrap-workflow.py
python3 tests/host/check-native-bootstrap-scripts.py
for script in .github/ci/*.sh build/fex-ios/build.sh build/freetype-ios/build.sh build/gnutls-ios/build.sh build/ffmpeg/build.sh build/ntdll-unix/build.sh build/wineserver/*.sh; do
  bash -n "$script"
done
```

The fixtures test iOS/host/mixed/malformed archives, complete-bundle gating,
strict generated-header failure handling, capped log output and build-script
orchestration. They do not substitute for native compilation.

## Metal component boundary

The native-only stage does not compile Metal shaders. It executes a Metal
version probe and records `available` or `unavailable`; finding an xcrun stub
alone is not success. Missing Metal is non-fatal only here, with an explicit
warning that later DXMT/app work is blocked. No Apple component is downloaded
and no license prompt is accepted. Future shader/app jobs must require a real
working Metal toolchain before attempting those targets.
