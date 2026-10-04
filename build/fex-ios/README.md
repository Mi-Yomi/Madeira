# Pinned FEX native source repairs

`build.sh` applies the ordered patches in `source-repairs.json` before
configuring the seven app-linked native static archives. It does not change
FEX's submodule pin, commit, index, build targets, or compiler definitions.

The pinned fork commit `1adb337a2f2270434ba731346438c072337a5d5f` declares
`IosFfsBypassLog` and `IosCbEntryLog` only under `FEX_IOS_HOST` in
`FEXCore/Source/Interface/Core/Core.cpp`, but reads them unconditionally in
`ContextImpl::CompileBlock`. The callback storage and emitted counter writes
in `Dispatcher/Dispatcher.cpp` have the same `FEX_IOS_HOST` guard. Native
Mach-O builds do not define this PE-host option and therefore fail to compile.
The failure was reproduced by Madeira's native bootstrap at main-fork commit
`323a3be939728de1507a8601cfeb7eee4603bd9a` (GitHub job `111436639274`).

The two-line patch gives the two reporter blocks the same guard as their
producers. It leaves reporting fully active for both ARM64EC and non-EC
`FEX_IOS_HOST` builds, including WoW64's existing zeroed FFS fallback. It adds
no fake counters and does not define `FEX_IOS_HOST` globally, which would
change unrelated ABI and execution paths. The following low/invalid guest-RIP
rejection remains outside the guard in every build mode.

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

## Verification and provenance

`source-repairs.json` is the checked-in source-of-truth: exact revision,
original/patched source SHA-256, and patch SHA-256. `apply-source-repairs.py`
accepts only that revision and its exact committed source. Each repair owns
disjoint files that must be wholly original or wholly repaired; unknown edits
and partly applied repairs fail. A previous known repair may already be applied
when a new repair is added. All patches are first applied to committed bytes in
a disposable directory, checking every output and touched path before changing
the FEX checkout. It then replaces only changed files and verifies every result.
If a write fails, it attempts to restore its own exact writes while preserving
detected concurrent edits, and reports any incomplete rollback.
Repeated runs are idempotent. It writes the same specification atomically to
`FEX/build-ios/madeira-source-repairs.json` only after successful verification,
for the native artifact provenance gate. A future FEX update must explicitly
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

After building, CI runs `check-native-object.py` with a two-minute overall
budget. It verifies the actual non-LTO `JitSymbols.cpp.o`, then recompiles that
same pinned source and explicit device-target compile flags with ThinLTO enabled
in a sanitized environment. Dependency outputs are removed, primary output is
redirected to a disposable object, and default compiler config files are disabled. Apple clang reads the resulting IR with an explicit iOS
target and `-Werror=override-module`, so a host/simulator target cannot be
silently rewritten into an apparent success. [LLVM's IR reader](https://github.com/llvm/llvm-project/blob/llvmorg-21.1.0/clang/lib/CodeGen/CodeGenAction.cpp#L1141-L1146) otherwise warns and replaces a mismatched module target. Only format, hash, target and
compiler evidence is logged; the probe object and textual IR are discarded.
This is a fresh same-source reproduction, not recovery of the old archive.
The small receipt and its current source/object/helper hashes are checked by
the final provenance gate. No guest code is executed by this diagnostic.
