# Bounded native bootstrap

`native-bootstrap.yml` adds a separate first-stage check for the
`compatibility/desktop-apps` branch. The existing desktop compatibility checks
continue alongside this workflow. It runs on GitHub's standard public-repository `xcode-27` ARM64
runner after a five-minute portable Linux validation gate, with a 45-minute native job limit, a 35-minute build-step limit, and at most two
compile jobs. See the [runner specification](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [installed Xcode/SDK image](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md).

The stage verifies exact recursive submodule commits, the iOS 27 SDK, tracked
tarballs/converter inputs, checksum-pinned llvm-mingw and commit-pinned FreeType.
The authorized Apple Metal component setup prepares the later shader stages;
its exact install/verification outcome is recorded separately. It builds FreeType, the crypto stack, FFmpeg, seven FEX
archives, separate native/ARM64EC Wine header trees, Wine's three native
libraries and Rust pairing. Header generation and compilation failures are
fatal. The pinned FEX reporter guards and CASPAL diagnostic platform split are checked
by revision/source hash before configure; successful provenance verifies the unchanged submodule
revision, exact patch inputs, applied record and resulting source bytes. The generated crypto symbol table must contain its bootstrap essentials.
The repair, header-orchestration and archive-verifier fixtures run again
on macOS before dependency downloads/builds, within a two-minute gate and the
existing overall time limit. Explanatory compiler/generator fixtures run in a
separate optional step after the required native build succeeds. This catches host differences such as macOS
`/var` temporary-directory aliases that Linux-only checks cannot establish.

FEX explicitly disables its default ThinLTO for native deliverables. A bounded
same-source `JitSymbols.cpp` reproduction records the actual Apple IR target
with target-override warnings fatal; its temporary object/IR are deleted. Every
deliverable archive member must be native ARM64 iOS Mach-O. Required provenance
checks the actual LTO-off CMake configuration, source repairs and recipe hashes
without depending on an explanatory receipt. The optional step uses at most
two minutes after the required build, within the existing 45-minute job limit.
It is skipped if fewer than ten reserved minutes remain; its success, failure
or budget skip is explicitly reported. Optional failure does not invalidate
a valid native dependency bundle, whose provenance marks it not run at collection. All seven FEX
archives are strictly checked immediately after compilation, before the probe;
final collection still checks the complete 20-archive set and provenance.

No separate Metal Shader Converter installer, LLVM source build, DXMT build,
Windows DLL farm, app link, IPA, signing or device test is attempted.

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
python3 tests/host/check-fex-source-repairs.py
python3 tests/host/check-fex-wow64-smc-write-fault.py
python3 tests/host/check-fex-arm64ec-jit-rw-alias.py
python3 tests/host/check-fex-pe-configuration.py
python3 tests/host/check-fex-native-object.py
python3 tests/host/check-fex-cmake-layout.py # requires installed CMake, Ninja and host C++ compiler
python3 tests/host/check-metal-toolchain-setup.py
for script in .github/ci/*.sh build/fex-ios/build.sh build/freetype-ios/build.sh build/gnutls-ios/build.sh build/ffmpeg/build.sh build/ntdll-unix/build.sh build/wineserver/*.sh; do
  bash -n "$script"
done
```

The fixtures test iOS/host/mixed/malformed archives, complete-bundle gating,
strict generated-header failure handling, capped log output and build-script
orchestration. They do not substitute for native compilation.

## Authorized Metal component setup

The native libraries do not compile Metal shaders, but later DXMT/app work does.
The audited Xcode 27.0 / 27A266a image has a discovery stub instead of the optional
Metal compiler. `ensure-metal-toolchain.py` probes by execution, and only its
explicit `--allow-install` mode may use Apple's documented component downloader.
Download/use is subject to the [Xcode and Apple SDKs Agreement](https://www.apple.com/legal/sla/docs/xcode.pdf),
EA2002 dated 2026-06-08. Review and authorize those terms before enabling this
mode outside the currently authorized temporary-runner build.

No broad update, `-license accept`, other component, login or payment action is
performed. New terms/auth/payment indications stop execution. The helper pins
the Xcode version, build and developer directory; checks Apple signatures on
separate entrypoint/component executables; and requires a disposable iOS
shader compilation and link. The receipt distinguishes attempted download,
command result and verified availability. A found shim or success exit from
the downloader alone is not sufficient.

Limits are 300 seconds for download and 420 seconds overall, both inside the
existing 35-minute build budget. Compact receipt fields/hash are printed in
normal job logs and copied into successful native provenance; artifact uploads
remain off for automatic pushes. No successful installation is claimed until
the native run produces the actual verified receipt.
