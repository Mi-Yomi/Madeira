# Source-only FEX backports and deferred DXMT ABI audit

Reviewed against Madeira parent commit `57b8f58`, pinned FEX
`1adb337a2f2270434ba731346438c072337a5d5f`, pinned DXMT
`020a848080b861266e04fc0e5f7f6d921614037c`, and Playport v0.3.3
`e962e9b75b04503dfbf476e76cb7264d19368ed2`.

## Delivered artifacts

- `0001-wow64-smc-write-fault-only.patch`: reject read/execute faults from the
  SMC-only tracker gate; retain the target's host-space `FaultAddress`
- `0002-arm64ec-require-jit-rw-alias.patch`: return `STATUS_UNSUCCESSFUL` from
  the existing iOS zero-offset branch, before `CTX->InitCore()`; replace the
  failing branch's variable-length diagnostic with a fixed string and
  `sizeof(message) - 1`
- `source-repairs.additions.json`: two hash-bound, disjoint-file repair entries
- `source-repairs.proposed.json`: the complete existing three-entry manifest
  from parent `57b8f58`, with those two entries appended
- `check-wow64-smc-write-fault.py` and `wow64-smc-regression.log`
- `check-arm64ec-jit-rw-alias.py` and `arm64ec-alias-regression.log`
- `audit-winemetal-slots.py` and `winemetal-slots-audit.log`
- `snapshot-provenance.json`: exact source URLs and Git blob identities
- `PLAYPORT-LICENSE` and `PLAYPORT-LICENSE-EXCEPTION.md`: verbatim retained
  license texts from the pinned Playport commit
- `SHA256SUMS`: hashes of the delivered artifacts

Original source snapshots are in `../fex/` and `../dxmt/`; the two patched
FEX files are in `../fex-patched/`. Source snapshots were fetched from the
GitHub connector at the exact revisions above. All six FEX/DXMT snapshot
files have been checked with `git hash-object` against their GitHub blob IDs.

## Verification performed

Both patches pass forward `git apply --check` on original snapshots and reverse
`git apply --check` on patched snapshots. Their exact post-patch file hashes
are in both manifest artifacts.

The WOW64 test compiles the actual extracted gate and tracker call with C++
stubs. Original source fails four cases; patched source passes all 12:
read/write/execute x absent/present thread x low/high host address. The tracker
receives the original host address and PC without an extra window translation.

The ARM64EC test compiles the entire actual alias initialization block, including
its `#ifdef FEX_IOS_HOST`, environment parsing, offset calculation, both logging
branches, and the subsequent `CTX->InitCore()` call. Only dependencies are stubbed.
Results are 144 cases per build:

- Original iOS block: 99 expected failures, reproducing fall-through on invalid aliases
- Patched iOS block: all 144 pass
- Original non-iOS block: all 144 pass
- Patched non-iOS block: all 144 pass

Cases cover absent, empty, zero, equal, nonnumeric and very long nonnumeric values;
positive, negative and high-host-address offsets; hexadecimal prefixes; the
existing acceptance of trailing junk; absent process parameters, absent stderr,
present stderr; and `WINE_IOS_JIT_SIZE` unset, zero and nonzero. No invalid case
reaches InitCore in the patched iOS block. Valid offsets are installed before
InitCore. The fixed failing diagnostic remains bounded and excludes raw values.

Compilation uses `g++ -std=c++17 -Wall -Wextra -Werror -pedantic` (non-iOS
fixtures additionally suppress unused stub-function warnings). Test executables
exist only in temporary directories and are deleted automatically.

Reproduction from the Playport checkout:

```sh
R=.work/submodule-source-review
python "$R/artifacts/check-wow64-smc-write-fault.py" \
  "$R/fex/Source/Windows/WOW64/Module.cpp" \
  "$R/fex-patched/Source/Windows/WOW64/Module.cpp"
python "$R/artifacts/check-arm64ec-jit-rw-alias.py" \
  "$R/fex/Source/Windows/ARM64EC/Module.cpp" \
  "$R/fex-patched/Source/Windows/ARM64EC/Module.cpp"
python "$R/artifacts/audit-winemetal-slots.py" . "$R/dxmt"
git apply --check --directory="$R/fex" "$R/artifacts/0001-wow64-smc-write-fault-only.patch"
git apply --check --directory="$R/fex" "$R/artifacts/0002-arm64ec-require-jit-rw-alias.patch"
git apply --reverse --check --directory="$R/fex-patched" "$R/artifacts/0001-wow64-smc-write-fault-only.patch"
git apply --reverse --check --directory="$R/fex-patched" "$R/artifacts/0002-arm64ec-require-jit-rw-alias.patch"
```

## Exact integration plan; not implemented

1. Retain the current FEX gitlink. Place the two patch bytes at the proposed
   manifest paths: `build/fex-ios/patches/0005-wow64-smc-write-fault-only.patch`
   and `build/fex-ios/patches/0006-arm64ec-require-jit-rw-alias.patch`.
   Append both entries to the existing shared `build/fex-ios/source-repairs.json`.
   They touch separate Module.cpp files and do not overlap any of the three
   existing repairs. Do not apply them manually as unlisted FEX edits: the
   applier rejects unlisted tracked source modifications and staged edits.
2. Use the same repair set for native and both PE build routes. Add the existing
   no-argument command `python3 "$R/build/fex-ios/apply-source-repairs.py"` before
   configuration/build in `build/fex-arm64ec/build.sh` and
   `build/fex-wow64/build.sh`. Do not invent a CLI destination argument: the
   current applier rejects all CLI arguments. It always writes
   `FEX/build-ios/madeira-source-repairs.json`; that is a verified source record,
   despite its native-named location, and is not evidence that either PE module
   was compiled. Rename/refactor that record only in a separately reviewed change.
3. Reconcile the final manifest hash in
   `build/i386-native-contract/contract.json` -> `source_sha256` ->
   `build/fex-ios/source-repairs.json`. The delivered complete proposed manifest
   has SHA-256 `8ece9467d4bd9a00aa051336f1fc73654f907b15a91ba728ca7cff39226bfd1f`.
   This hash applies only if those exact proposed bytes are adopted. Keep all
   other contract entries unchanged except independently authorized work.
4. Extend `tests/host/check-fex-source-repairs.py` for the new disjoint entries,
   first application, already-applied/idempotent state, unknown/tampered module,
   patch/hash failure, unlisted dirtiness and multi-repair preflight. Preserve
   rollback and concurrent-edit protections. Incorporate the two extracted
   production regressions. Re-run the source-repair and native-contract checks.
5. Review and fresh-configure or explicitly reconfigure each PE build cache.
   Both current scripts configure only when their cache is absent. In particular,
   ARM64EC's current script does not explicitly enable `FEX_IOS_HOST`; require
   effective compile-command evidence that the macro is active on the repaired
   `Source/Windows/ARM64EC/Module.cpp`. Do not infer it from file presence or an
   old cache. Do not blindly copy WOW64's `FEX_IOS_HOST_BUILD=ON` configuration:
   that route enables the guest-window mode which is not the ARM64EC mode.
6. Produce separate PE build receipts, for example under
   `build/fex-arm64ec/receipts/` and `build/fex-wow64/receipts/`, only after real
   builds. Bind each receipt to the parent revision, FEX revision, repair-manifest
   hash, patch/source hashes, toolchain identity and hashes, cache/configuration,
   compile database and effective Module.cpp command, configure/build commands
   with results, and output DLL hashes. Record actual PE machine/architecture,
   headers and exports from tool output. Verify target `arm64ecfex` output
   `FEX/build-arm64ec/Bin/libarm64ecfex.dll` and copied
   `app/Madeira/arm64ec-windows/xtajit64.dll`; verify target `wow64fex` output
   `FEX/build-wow64/Bin/libwow64fex.dll` and copied
   `app/Madeira/aarch64-windows/xtajit.dll` independently. Require matching source
   and copied output hashes. The WOW64 backend is an aarch64 PE DLL serving an
   i386 guest; do not describe it as an i386 DLL.
7. Check exports against the pinned DEF files, including ARM64EC `ProcessInit`,
   `ResetToConsistentState`, `ThreadInit`, and WOW64 `BTCpuProcessInit`,
   `BTCpuResetToConsistentState`, `BTCpuSimulate`. The WOW64 iOS-only
   `BTCpuIosSetMonoBridge` is exported from its implementation, not its DEF file;
   account for that separately. References:
   https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/Source/Windows/ARM64EC/libarm64ecfex.def
   and https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/Source/Windows/WOW64/libwow64fex.def

A native libFEXCore archive build does not compile these PE Module.cpp files.
Neither the native source-repair record nor a native-FEX build receipt can serve
as a PE compile receipt. No receipt is pre-created here and no runtime success
is claimed.

## Winemetal audit retained for a future tooling change

`audit-winemetal-slots.py` loads the unchanged Playport `tools/slots.py` without
its CLI-only phonelib dependency. Original checker: 151 slots, 146 calls,
39 naming mismatches. Target-specific normalization removes the terminal `32`
wrapper suffix and permits the explicit `WMTNop` / `_d3d9_nop` alias. Result:
151 slots, 146 calls, zero mismatches. Mutation tests reject swaps in either
the native or WOW64 table. No source table is edited.

This verifies table/thunk names and slot order only; it does not prove pointer
marshalling, C structure layout, runtime calling conventions, or every indirect
ABI dependency. Do not transplant Playport's rebased dispatch table or change
Madeira's slot count. This checker is a future audit candidate, not runtime
integration. The DXMT compression optimization remains deferred pending target
device/Metal validation and rendering regressions.

## Attribution and licensing

Both patch headers retain the original Playport authors and exact source links.
Playport's pinned `docs/LICENSING.md` explicitly assigns its own FEX/DXMT patch
lines GPL-3.0-or-later with its additional permission; upstream FEX source retains
its original license. Do not label the entire backport MIT merely because the
existing FEX file starts with an MIT marker.

Suggested durable location: `build/fex-ios/patches/playport/NOTICE.md` with the
two source URLs, base revisions, local patch mappings and adaptation summary;
alongside it retain the exact `PLAYPORT-LICENSE` and
`PLAYPORT-LICENSE-EXCEPTION.md` delivered here. Reference that notice from the
FEX repair README and any corresponding-source distribution inventory. The
exception text is preserved verbatim, not replaced with a summary or treated as
a new license grant over somebody else's code.

## Limits

No primary-tree changes, pin movement, production FEX build, PE/native binary
replacement, device execution, release payload download or publication occurred.
Alias size, backend selection, mapping validity, permissive strtoull parsing,
pool ownership and trap-mode implementation remain unchanged. The host test
proves extracted control flow with stubs, not the behavior of Wine startup,
exception delivery, Mach mappings, or actual iOS instruction emission.
