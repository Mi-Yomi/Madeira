# FEX guest DLL build and static compatibility evidence

The two reviewed guards compile and link successfully from the exact pinned FEX source. Both baseline and patched builds pass the current Madeira PE farms' bounded symbol-resolution audit. No guest DLL was executed or installed, no primary source or binary was changed, and no IPA or remote job was created.

## Source identity and phase separation

- Madeira reference: `6406b09801026e7211b9f9e26d4f526327eb8c2b`
- FEX: `https://github.com/willfaust/FEX.git` at `1adb337a2f2270434ba731346438c072337a5d5f`
- Baseline: pinned FEX **plus all three existing approved repairs** from Madeira `build/fex-ios/source-repairs.json`
- Patched: the exact same baseline plus the reviewed WOW64 SMC gate and ARM64EC alias refusal patches
- Existing repair manifest SHA-256: `e96b2afe2a2919e8a879f9ce7660c8c1b5916b5f8650cf4ddff037ba1eede0a9`
- Proposed five-repair manifest SHA-256: `8ece9467d4bd9a00aa051336f1fc73654f907b15a91ba728ca7cff39226bfd1f`

The three existing patch hashes and their resulting source hashes were verified before configuring. The two Module.cpp Git blobs match the prior review (`fbaf76f…` ARM64EC, `6732edc…` WOW64); both exact post-patch hashes match the reviewed manifest. `evidence/baseline-source.diff` and `evidence/patched-source.diff` retain each state. `evidence/patched-source-manifest.json` hashes 6,871 tracked source files across FEX and its six initialized source dependencies. No foreign DLL farm or release binary was used as a build input.

Four fresh build directories were used. The isolated source tree was restored to each phase before its complete builds. Both production Module.cpp files were compiled separately in each phase before complete links. The final source tree remains in the five-repair state. `set-source-phase.py` and `source_phase.py` enforce the pinned revision, all five expected source hashes, absence of staged edits, and the exact approved changed-file set for subsequent reproductions.

## Verified build configuration

Common effective settings:

```text
-G Ninja -DCMAKE_BUILD_TYPE=Release
-DCMAKE_TOOLCHAIN_FILE=$FEX/Data/CMake/toolchain_mingw.cmake
-DFEX_IOS_HOST_BUILD=ON
-DCMAKE_C_FLAGS=-DFEX_IOS_HOST
-DCMAKE_CXX_FLAGS=-DFEX_IOS_HOST
-DCMAKE_ASM_FLAGS=-DFEX_IOS_HOST
-DENABLE_LTO=OFF -DENABLE_ASSERTIONS=OFF
-DENABLE_JEMALLOC_GLIBC_ALLOC=OFF -DENABLE_CCACHE=OFF
-DBUILD_TESTING=OFF -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF
-DTUNE_ARCH=generic -DTUNE_CPU=none
-DCMAKE_POLICY_VERSION_MINIMUM=3.5
```

ARM64EC additionally uses `-DMINGW_TRIPLE=arm64ec-w64-mingw32 -DENABLE_GUEST_WINDOW=OFF`; target `arm64ecfex`. WOW64 uses `-DMINGW_TRIPLE=aarch64-w64-mingw32 -DENABLE_GUEST_WINDOW=ON`; target `wow64fex`.

`FEX_IOS_HOST_BUILD` and the compiler macro have separate roles. The CMake variable selects `CRT_iOS.cpp` and the default MinGW startup/link path. The compiler flags select the actual iOS code. The exact pin defaults guest-window mode only for a non-ARM64EC architecture, but the tested commands set it explicitly. ARM64EC's effective Module.cpp command includes `ARCHITECTURE_arm64ec=1` and `FEX_IOS_HOST`, excludes `FEX_GUEST_WINDOW`, and its generator commands exclude `--feature=GuestWindow`. WOW64 includes that macro and generator feature. The snapshots under `evidence/configuration/` preserve these facts for all four configurations.

Use the recorded scripts for complete argument vectors, environment and output paths:

```sh
python3 set-source-phase.py baseline
python3 configure-and-compile.py arm64ec baseline
python3 configure-and-compile.py wow64 baseline
python3 build-dll.py arm64ec baseline
python3 build-dll.py wow64 baseline
python3 set-source-phase.py patched
python3 configure-and-compile.py arm64ec patched
python3 configure-and-compile.py wow64 patched
python3 build-dll.py arm64ec patched
python3 build-dll.py wow64 patched
```

The actual full-build command is `cmake --build BUILD_DIR --parallel 2 --target arm64ecfex|wow64fex --verbose`. Builds ran sequentially, at most two compiler workers at a time. These commands reuse their named directories on a second run; use fresh directories for another clean-build claim. Do not configure only when CMakeCache is absent. Durable scripts must explicitly configure and reject an incompatible cached compiler/triple/generator, or use a fresh directory.

## Toolchain and dependencies

Official cached LLVM-MinGW `20260421`, Linux x86_64 UCRT package, archive SHA-256 `f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`. The extracted Clang, LLD, llvm-readobj and llvm-ar/llvm-dlltool executable bytes were checked against that archive. Verification is in `evidence/toolchain-extraction-verification.json`.

Task-local PyPI CMake `3.31.6` and Ninja `1.11.1.4` were used. `evidence/build-tools-install.json` records the exact official wheel URLs and hashes. No global installation or persistent pip cache was used. CMake and Ninja were initially absent; this was resolved. One initial configure used an incorrect task-local Ninja path and failed before compilation; its log is retained separately. All four subsequent fresh configurations passed.

Only these pinned source submodules were fetched:

- fmt `407c905e45ad75fc29bf0f9bb7c5c2fd3475976f`
- range-v3 `ca1388fb9da8e69314dda222dc7b139ca84e092f`
- rpmalloc `812c2b9cf4310ffacf14e6b64066e78ab0c394b5`
- unordered_dense `3234af2c03549bc85656bfd3a86993bf1cd8aef1`
- xxHash `e626a72bc2321cd320e953a0ccf1584cad60f363`
- cpp-optparse `9f94388a339fcbb0bc95c17768eb786c85988f6e`

No unresolved build dependency remains for these Linux cross-builds. The repository's existing macOS toolchain route was not tested.

## Outputs and static checks

| Target and phase | Seconds | Bytes | SHA-256 |
|---|---:|---:|---|
| ARM64EC baseline | 81.46 | 5,410,816 | `c32578766cd125bb6a53539b11006d9f66948f92f3614d5c05e2755974e623ce` |
| ARM64EC patched | 80.31 | 5,410,816 | `4c508cea3d7fd66cee756ba08098c1df3eb334b275c2b6127c3dc313e81e2fb8` |
| WOW64 baseline | 82.36 | 4,857,856 | `4773b1cafc3e343c0623ac56a53a7a1025a348b9845eccc08248c20793e1785c` |
| WOW64 patched | 81.44 | 4,857,856 | `6c1e397f10c4bfbc7e4abc1eca97f2aba207dbbc301f01df7a089430b1ac830e` |

ARM64EC output is `build-arm64ec-patched/Bin/libarm64ecfex.dll`; future destination is `app/Madeira/arm64ec-windows/xtajit64.dll`. Its raw PE machine is `0x8664` with CHPE metadata, recognized by the independent PE parser as ARM64EC and normalized by LLVM to `0xa641`. WOW64 output is `build-wow64-patched/Bin/libwow64fex.dll`; future destination is `app/Madeira/aarch64-windows/xtajit.dll`. It is an ARM64 PE (`0xaa64`) providing an i386 guest backend; it is not an i386 DLL.

Every baseline and patched DLL has exactly the shipped counterpart's import and export sets. ARM64EC has all 30 pinned DEF exports. WOW64 has all 23 DEF exports plus the intentional iOS-only `BTCpuIosSetMonoBridge` export. The unchanged Madeira `symbol_audit.py` was copied into the isolated workspace and checked the single freshly built DLL overlay against the current primary farm, including actual API-set schema and required export-forwarder chains:

- Each ARM64EC phase: 211 import symbols, 30 exports, 98 API-set resolutions, zero failures
- Each WOW64 phase: 216 import symbols, 24 exports, 96 API-set resolutions, zero failures

The audit hashes every farm input it used and is bounded to these DLLs' imports and required forwarders. It does not prove all transitive imports in the whole farm, dynamic symbol resolution, calling-convention behavior or runtime compatibility. Each successful audit explicitly records `runtime_tested: false`.

Shipped ARM64EC already contains the pin's iOS alias, allocation-failure and dispatcher diagnostics, including the old fatal alias diagnostic. The baseline reproduces that old diagnostic. The patched linked DLL contains the new bounded refusal diagnostic and does not contain the old diagnostic. See `evidence/linked-arm64ec-guard-string-check.json`.

Source-owned extracted-production regressions were rerun from the freshly cloned source: ARM64EC baseline reproduces 99 failures of 144 iOS cases, patched iOS passes all 144, both non-iOS variants pass all 144; WOW64 baseline reproduces four failures of 12 cases and patched passes all 12. These tests execute host C++ fixtures with stub dependencies, never either guest DLL.

## Licensing and remaining integration

`evidence/licenses/` retains the upstream FEX and dependency notices, the FEX and rpmalloc Madeira-fork GPL-3.0-or-later notices and exceptions, and the toolchain/runtime notices. The original Playport GPL license and additional permission remain verbatim in `evidence/PLAYPORT-LICENSE*`; patch headers retain source URLs and attribution. Do not describe these assembled DLLs as MIT-only. `evidence/licenses-manifest.json` binds the retained notice bytes.

Before replacing a shipping PE, integrate and independently review the shared five-repair manifest, repair-applier wiring, host tests and explicit fresh PE configuration. Bind the final integration revision and repair manifest to these actual source/toolchain/configuration/output hashes. Preserve the original shipped binaries and update the two distinct PE receipts, copied-output hash checks, provider inventories and corresponding-source/license inventory. A source-only integration commit does not itself replace either DLL.

The untouched shipped hashes remain `38b68f69909aea0dae3ce88934936275e9415accf22fc0823568eda244962b07` (xtajit64.dll) and `682ed22a3e60aff6f0bca8d5d62ec59bc67a2330dd318b70937174244c5c3cb6` (xtajit.dll). Final primary HEAD remains `6406b098…` with no tracked changes. The active IPA was not touched. On-device Wine/FEX startup, JIT mappings, exception delivery, 32-bit execution and application/rendering regressions remain untested; no 32-bit-readiness or runtime-success claim follows from these builds.

`evidence/BUILD-SUMMARY.json` is the compact machine-readable result; `evidence/*-full-build.json`, logs, configuration snapshots and symbol-audit directories supply the detailed evidence.
