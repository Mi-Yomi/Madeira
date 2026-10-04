# Pinned FEX native source repair

`build.sh` applies `patches/0001-guard-ios-diagnostic-reporters.patch` before
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

`source-repairs.json` is the checked-in source-of-truth: exact revision,
original/patched source SHA-256, and patch SHA-256. `apply-source-repairs.py`
accepts only that revision, its exact committed source, and either the exact
original or exact repaired working file; other tracked source edits fail.
It validates all bytes before applying and verifies the result afterward.
Repeated runs are idempotent. It writes the same specification atomically to
`FEX/build-ios/madeira-source-repairs.json` only after successful verification,
for the native artifact provenance gate. A future FEX update must explicitly
review and replace or remove this repair; it cannot silently fuzz onto new code.

Portable checks: `python3 tests/host/check-fex-source-repairs.py` exercises
revision/hash/patch rejection and compiles the exact repaired reporter region
in native, ARM64EC-host, and non-EC-host fixtures. These are host checks, not an
iOS build or proof that 1C/Blender runs. Native CI must still build and validate
all seven archives. The repair is maintained only in Madeira; do not submit
AI-generated patches to FEX-Emu upstream (see `CONTRIBUTING.md`).
