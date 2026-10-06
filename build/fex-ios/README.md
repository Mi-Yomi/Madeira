# Pinned FEX source repairs

`build.sh`, `../fex-arm64ec/build.sh` and `../fex-wow64/build.sh` apply the
same ordered patches in `source-repairs.json` before configuring their native
archives or PE DLL. The repair applier does not change FEX's submodule pin,
commit, index, build targets, or allocator configuration.

The pinned fork commit `1adb337a2f2270434ba731346438c072337a5d5f` declares
`IosFfsBypassLog` and `IosCbEntryLog` only under `FEX_IOS_HOST` in
`FEXCore/Source/Interface/Core/Core.cpp`, but reads them unconditionally in
`ContextImpl::CompileBlock`. The callback storage and emitted counter writes
in `Dispatcher/Dispatcher.cpp` have the same `FEX_IOS_HOST` guard. Native
Mach-O builds do not define this PE-host option and therefore fail to compile.
The failure was reproduced by Madeira's native bootstrap at main-fork commit
`323a3be939728de1507a8601cfeb7eee4603bd9a` (GitHub job `111436639274`).

The reporter guard gives the two reporter blocks the same guard as their
producers. It leaves reporting fully active for both ARM64EC and non-EC
`FEX_IOS_HOST` builds, including WoW64's existing zeroed FFS fallback. It adds
no fake counters and does not define `FEX_IOS_HOST` globally, which would
change unrelated ABI and execution paths. The following low/invalid guest-RIP
rejection remains outside the guard in every build mode.

## Allocator diagnostic link dependency

The unsigned app build at commit `8ababe8266cbdd48251124bcd6cbf41df495fcb8`
(run `37219502185`) compiled the native archives and app sources, then failed
to link `_rpm_cas_snapshot_take` from `Core.cpp.o`. This is an allocator-specific
diagnostic accidentally retained in a build without its allocator. The pinned
[FEX root CMake](https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/CMakeLists.txt)
explicitly disables both jemalloc and rpmalloc for Apple. Despite its historical
name, `JemallocLibs` then contains
[system-allocator wrappers](https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/FEXCore/Source/Utils/AllocatorHooks.cpp),
not an omitted rpmalloc implementation. The actual allocation-free snapshot
producer/drain is in pinned
[rpmalloc `812c2b9`](https://github.com/willfaust/rpmalloc/blob/812c2b9cf4310ffacf14e6b64066e78ab0c394b5/rpmalloc/rpmalloc.c).

`0003-guard-core-allocator-diagnostics.patch` supersedes `0001`, retaining its
reporter fix and guarding only the rpmalloc POD declaration and diagnostic drain
with the value-aware `ENABLE_FEX_ALLOCATOR` feature test. The surrounding compile
summary and execution paths remain unchanged. `0004-wire-rpmalloc-snapshot-feature.patch`
sets that definition for `Core.cpp` only inside the existing CMake branch which
enables and links the real rpmalloc provider. Both undefined and explicitly zero
values omit the diagnostic; enabled builds keep its original body and real
symbol dependency. No stub, weak-symbol fallback, or extra native allocator is
introduced. The old two-line patch remains checked in as review history.

`python3 tests/host/check-fex-snapshot-link.py` reproduces the original undefined
symbol using extracted source, inspects object/executable symbols, and links/runs
allocator-disabled fixtures with no snapshot definition or reference. Enabled
fixtures require the real extracted C producer and verify the captured fields
and one-time drain, including PE-host feature combinations. The test also checks
enabled preprocessor equivalence and configures/builds a small real CMake
on/off/reconfigured-off link fixture when CMake is installed; an absent CMake is
reported as an explicit skip. These tests do not compile the full allocator,
exercise its CAS loops, or substitute for the actual iOS app link in CI.

## CASPAL diagnostic platform split

The same pinned source calls Windows `VirtualQuery` unconditionally from
`IosLogUnimplementedCASPAL` in `FEXCore/Source/Utils/ArchHelpers/Arm64.cpp`.
Native CI at commit `e6b72e06b2f0069bfb130e9ae2171f8bef3309e1` built
`FEXCore_Base`, then failed on the Windows-only types in this logger (GitHub
job `111445089390`). This is not evidence of a missing `FEX_IOS_HOST` setting:
the native `__APPLE__` dual-map path and PE iOS-host alias bridge are separate.
The native recipe intentionally keeps its original compiler definitions.

`0002-split-caspal-platform-diagnostics.patch` keeps the Windows query and
message unchanged under `_WIN32`. Other hosts log the same instruction,
address and misalignment facts without Windows memory-region fields. Both
branches retain the early return and eight-report limit. `HandleCASPAL`,
`RunCASPAL`, the aligned atomic operation and misaligned rejection are unchanged;
this fixes native compilation, not unsupported misaligned atomic emulation.

## Playport PE guards

`0005-wow64-smc-write-fault-only.patch` routes only write access violations
with an existing thread to the WOW64 SMC tracker. Read and execute faults
continue normal exception delivery. The target's existing host-space
`FaultAddress` reaches the tracker unchanged.

`0006-arm64ec-require-jit-rw-alias.patch` returns `STATUS_UNSUCCESSFUL` from
the existing iOS zero-offset branch before `CTX->InitCore()` can emit code.
The error text is fixed and its `WriteFile` length is `sizeof(message) - 1`.
Valid aliases and non-iOS initialization keep their existing behavior. This
is not validation of alias mapping, pool size, or permissive `strtoull` parsing.

These two repairs adapt Playport v0.3.3. Original authors, source URLs and
exact GPL/additional-permission texts are retained in
[patches/playport/NOTICE.md](patches/playport/NOTICE.md). The upstream MIT
notice does not relicense Playport's or Madeira's additions.

The standalone checks need a host C++ compiler, not initialized submodules:

```sh
python3 tests/host/check-fex-wow64-smc-write-fault.py
python3 tests/host/check-fex-arm64ec-jit-rw-alias.py
python3 tests/host/check-fex-pe-configuration.py
```

The first two verify complete pinned source snapshot and patch hashes, apply
the actual patches in temporary directories, then compile extracted production
control flow with dependency stubs. Original WOW64 fails 4 of 12 routing cases;
original iOS ARM64EC fails 99 of 144 cases. Repaired code passes, with non-iOS,
tracker-declines and deliberate broken-code controls. These host binaries do
not execute FEX, Wine startup, Mach mappings or emitted iOS instructions.

## Explicit PE configuration

Both PE build scripts always configure, use the shared repair applier, and
check the effective `Module.cpp` command and iOS CRT selection before building.
Both require `FEX_IOS_HOST_BUILD=ON` plus `FEX_IOS_HOST` for C, C++ and ASM.
ARM64EC explicitly selects `arm64ec-w64-mingw32` and disables the guest window;
WOW64 selects `aarch64-w64-mingw32` and enables it. The WOW64 DLL is an aarch64
PE backend for an i386 guest. Both disable LTO and use Ninja.

Before reconfiguration, `check-pe-configuration.py` rejects incompatible
source, toolchain, target, generator or cached compiler identities. It never
deletes a cache. Set `FEX_PE_BUILD_DIR` to an empty build directory when an
older configuration is incompatible. `LLVM_MINGW_ROOT` selects an installed
LLVM-MinGW root; the default remains the existing macOS toolchain path.
`BUILD_JOBS` defaults to 2. `FEX_PE_STAGE=0` builds without copying into the app.
The default copies the DLL only after the complete link and configuration
checks pass, then verifies source and destination bytes with `cmp`.

Configuration checks are not build receipts. DLL delivery still needs exact
source/toolchain/command/output hashes, PE architecture/export checks and the
DLL farm's existing replacement/provenance gates. The configuration was
exercised independently with official Linux LLVM-MinGW 20260421 for complete
pin-plus-three and pin-plus-five ARM64EC/WOW64 builds. This does not establish
the macOS build or device runtime, or prove inclusion in a packaged app.

## Verification and provenance

`source-repairs.json` is the checked-in source-of-truth: exact revision,
original/patched source SHA-256, and patch SHA-256. `apply-source-repairs.py`
accepts only that revision and its exact committed source. Each repair owns
disjoint files that must be wholly original, wholly repaired, or match an exact
reviewed prior output explicitly listed in `previous_patched_sha256`; unknown
edits and partly applied repairs fail. The Core upgrade accepts only the old
reporter repair's exact hash in addition to the pinned original and new output.
A previous known repair may already be applied when a new repair is added.
All patches are first applied to committed bytes in
a disposable directory, checking every output and touched path before changing
the FEX checkout. It then replaces only changed files and verifies every result.
If a write fails, it attempts to restore its own exact writes while preserving
detected concurrent edits, and reports any incomplete rollback.
Repeated runs are idempotent. It writes the same specification atomically to
`FEX/build-ios/madeira-source-repairs.json` only after successful verification,
for the source and native artifact provenance gates. This path is a source
record, not proof that either PE Module.cpp was built. Native archive builds
do not compile those modules. Adding these repairs changes the shared source
manifest and native contract hash, so old native provenance must be rebuilt
and recaptured; no contract, ABI, farm seal or artifact gate is relaxed.
A future FEX update must explicitly
review and replace or remove these repairs; they cannot silently fuzz onto new code.

Portable checks: `python3 tests/host/check-fex-source-repairs.py` exercises
revision/hash/patch rejection, multi-repair preflight and upgrade behavior. It
compiles the exact reporter regions in native and PE-host fixtures and checks
that Windows CASPAL preprocessing is unchanged. The native CASPAL fixture tests
early returns, captured fields and the report cap without supplying Windows
APIs. These are host checks, not an iOS build or proof that 1C/Blender runs.
Native CI must still build and validate all seven archives. The repairs are
maintained only in Madeira; do not submit AI-generated patches to FEX-Emu
upstream (see `CONTRIBUTING.md`).

## Native objects, not ThinLTO bitcode

The [pinned FEX CMake project](https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/CMakeLists.txt#L227) defaults `ENABLE_LTO` to `TRUE` and assigns it to
`CMAKE_INTERPROCEDURAL_OPTIMIZATION`. [CMake's AppleClang IPO recipe](https://github.com/Kitware/CMake/blob/v4.4.3/Modules/Compiler/Clang.cmake#L58-L98) uses
`-flto=thin`; such objects can remain LLVM bitcode inside a static archive.
The first completed native compilation run (`f2fd856`, job `111454525730`)
failed the final strict object-format gate at `libFEXCore.a(JitSymbols.cpp.o)`.
That runner's archive was not retained, so its precise magic/triple was not
inspected. The source configuration explains the likely format mismatch.

The native recipe now explicitly passes `ENABLE_LTO=OFF` on every configure
and exports compile commands. It keeps the ARM64 iOS target and Release
optimization. All 20 deliverable archives must still pass the unchanged
Mach-O/iOS acceptance rules; raw or wrapped LLVM bitcode remains rejected.

After the required 20-archive build and verification succeeds, a separate
optional CI step runs `check-native-object.py` with a two-minute overall budget. It verifies the actual non-LTO `JitSymbols.cpp.o`, then recompiles that
same pinned source and explicit device-target compile flags with ThinLTO enabled
in a sanitized environment. Dependency outputs are removed, primary output is
redirected to a disposable object, and default compiler config files are disabled. Apple clang reads the resulting IR with an explicit iOS
target and `-Werror=override-module`, so a host/simulator target cannot be
silently rewritten into an apparent success. [LLVM's IR reader](https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/clang/lib/CodeGen/CodeGenAction.cpp#L1141-L1146) otherwise warns and replaces a mismatched module target. Only format, hash, target and
compiler evidence is logged; the probe object and textual IR are discarded.
This is a fresh same-source reproduction, not recovery of the old archive.
The small receipt and its current source/object/helper hashes are checked by
a separate optional verifier. Core artifact provenance instead requires the
actual LTO-off CMake configuration, source repairs and recipe hashes. A failed
or skipped explanatory replay is reported separately and never counted as
verified, but does not invalidate correctly verified native archives. No guest
code is executed by this diagnostic.

The compile-command parser accepts only CMake's build-root layout (Ninja) or
its exact `FEXCore/Source` target directory (Unix Makefiles). Resolved source
and production-object paths must match in either layout; unrelated directories
and escaping paths remain rejected. `tests/host/check-fex-cmake-layout.py`
configures both real generators and checks their command databases without
building or executing the synthetic target. Missing CMake/Ninja fails the test.
It runs in the independent Linux desktop-helper workflow and in the separate
optional macOS step after the core build. Neither generator-fixture run is a
prerequisite for the required native archive job; its own source-test outcome
remains visible.

Immediately after FEX builds, all seven archives receive the same strict
member-by-member format/platform checks used by final collection, before the
extra compiler diagnostic. This early result does not substitute for the final
20-archive and provenance gate.
