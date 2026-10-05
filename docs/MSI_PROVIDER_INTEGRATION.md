# Reviewable add-only MSI provider integration

The integration is a source-tree proposal for fourteen PE files: msi.dll,
msiexec.exe, cabinet.dll, sxs.dll, mspatcha.dll, odbccp32.dll and regsvr32.exe
for each of AArch64 and ARM64EC. The existing farms and notices are preserved.
The source-only tooling/document patch and exact add-only copy plan must be
reviewed and applied together to a fresh disposable checkout. Neither the
planner nor the verifier installs files or executes guest code.

## Source and evidence

Wine stays pinned to `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`. Only the provider
build's `dlls/msi/custom.c` is patched; the repository gitlink is not changed.
The original patch, source identities, precise compiler/configure/make/strip
commands, prerequisite hashes, successful logs and complete static audits are
retained unchanged at `build/wine-pe/receipts/msi-2026-10-05/`.

That compact receipt has 108 indexed files plus the original `SHA256SUMS`, whose
SHA-256 is `3d748dc6f9fa84d386c79acdaf9b4952755719daa79f8ac161f1c07d27fee0fe`.
The original build workspace also has unsealed source/build/snapshot directories;
do not pass that whole workspace to the complete-package verifier. Materialize
exactly the indexed files and the index in a fresh compact receipt, verifying
the pinned index digest before trusting its paths and every copied file after.
Extra files, symlinks, altered bytes and untracked evidence are rejected.

The package's `SOURCE-REBUILD.md` explains how to reconstruct the original
three-architecture evidence build. Retaining its i386 output does not add that
output to the app. Retain complete corresponding Wine source and the exact
patch, not just a network link, before any later redistribution. The LGPL Wine
component and bundled dependency license/header terms continue to apply.
The Madeira GPL/exception applies to its own build and test tools.

The app manifest `build/wine-pe/msi-integration.json` records the exact hashes
of fourteen providers and ten required legal/source resources, including three
already-bundled Wine notices that must remain byte-identical. Six new notices
are copied exactly from the sealed evidence; the separately authored
`legal/Wine-MSI-INTEGRATION.md` explains the evidence location and limits.
No current notice is overwritten or replaced. Existing Xcode folder references
include these additions without per-file project changes.

## Gates and the original desktop seal

The existing twelve-DLL, 55-file desktop receipt and integration manifest remain
unchanged. `verify_desktop_integration.py` verifies them before considering the
specific MSI extension. The MSI verifier must bind its recorded pre-state to
the entire original desktop inventory, byte for byte and dependency for
dependency. It then permits only the fixed seven new names per architecture,
requires every original module unchanged and verifies the complete new farm.
There is no arbitrary overlay or ignored-addition parameter.

The only permitted dependency change is setupapi's missing cabinet.dll delay
edge closing. The historical 14/11 gap record is preserved; the current combined
farms have 13/10 gaps. The new providers' normal/delay import symbols and required
forwarder chains bind to the same complete farm inputs in the sealed symbol
audits. This is neither recursive all-export closure nor runtime/ABI proof.
Exact provider architecture checks also require ARM64EC CHPE metadata, rather
than accepting ordinary AMD64 merely because it is in the ARM64EC farm.

The app's tracked-resource rule remains. Any part of an MSI integration, even
an untracked record, receipt or new resource, activates full validation. Removing
one half of the pair, deleting the record, substituting a notice, or staging an
arbitrary PE cannot bypass it. The app diagnostics record the MSI stage seal and
all fourteen hashes alongside the original desktop seal and hashes. Normal
post-link resource hashing continues to apply if a later app build is authorized.
The native gate still binds the whole checkout to its native receipt/source
commit, and packaging stays separately opt-in.

The i386 `msi.dll` and 71-component peer are not app copy operations. The app gate's unverified-32-bit rejection remains in place. PE classification
now uses the existing farm inventory's suffix set case-insensitively, so upper-
or mixed-case .dll/.exe and the recognized .drv/.cpl/.acm/.ax/.ocx/.sys suffixes
cannot bypass the guard or guest-PE receipt. In particular,
`i386-windows/ntdll.dll` would enable a new native/WoW64 startup path; retaining it
as evidence outside app resources does not authorize that path.

## Review and validation commands

Before integration, use the compact original MSI receipt and an untouched target:

```sh
python3 build/wine-pe/plan_msi_integration.py --stage /path/to/compact-msi-receipt --root /path/to/untouched-checkout
```

The planner requires the current Wine gitlink, exact original farm files and
desktop seal. It prints 129 add-only copy operations: fourteen app providers,
six exact app notice copies, and 109 evidence files outside app resources.
The authored integration notice, manifest, gates, tests and this document are
in the separate source-only patch. A stale local Git HEAD is not source identity:
verify the patch's recorded pre-state hashes against the intended published
source checkpoint before applying it. Resolve any intervening change explicitly.

After all parts are applied and tracked in a disposable checkout:

```sh
python3 build/wine-pe/verify_desktop_integration.py
python3 tests/host/check-msi-integration.py
python3 -O tests/host/check-msi-integration.py
python3 tests/host/check-desktop-integration.py
python3 -O tests/host/check-desktop-integration.py
python3 tests/host/check-app-bootstrap.py
python3 tests/host/check-desktop-overlay-plan.py
python3 tests/host/check-desktop-symbol-audit.py
```

The mutation suites use isolated temporary Git fixtures and static PE reads.
They cover complete paired integration, missing and untracked resources/evidence,
substitution despite manifest edits, wrong architecture despite test-only trust
anchor changes, symlinks, partial pairs, tracked i386 suffix/case-variant rejection, original-farm
substitution, extra tracked modules, baseline/symbol/dependency mutations and
`core.autocrlf=true` preservation. The copy planner also rejects collisions,
unexpected non-PE farm files and conflicting notices without writing anything.

## Startup/error behavior and remaining limits

The patch reports DLL-load, missing-entrypoint and caught-exception failures,
checks custom-action server startup and path capacity, accepts the
ERROR_PIPE_CONNECTED race and avoids creating the client thread after startup
failure. Successful action returns and outer Continue/Async policy are retained.
Native process launch and custom-action IPC are still unproved on Wine/iOS.
Synchronous ConnectNamedPipe can still hang if a started child never connects;
dead-server reuse and asynchronous action exit handling are unchanged.

The corrected source-owned canary passed on native Windows at commit
`142ca1e4851d644cec3519feaa5c9110194c8c7f` (run `37271589974`): two property/SID
round trips, a distinct child PID, missing-export rejection with 1603, and session
close. This establishes fixture/reference Windows behavior only. It does not run
the candidate Wine DLLs, validate Wine/iOS IPC or activate a 32-bit farm.
WinNT ADS, dynamic COM/CLR/SxS, native Unix bindings, transactions, SEH, device
runtime, 1C and Blender support remain open. No app/IPA build or runtime claim is
part of this proposal, and independently bitwise-reproducible output is not proven.

## Apply/rollback preconditions

Before an authorized apply, recheck both seals, every original farm byte, every
existing notice, all text-patch pre-state hashes, and absence of every added
destination. Use a fresh disposable checkout and treat the two architectures,
complete evidence, matching legal files and source gates as one transaction.
Keep a verified copy of each changed source file. Track every required output;
an index-only add does not replace the native source-commit gate.

Rollback removes an added file only if its current byte count/SHA-256 still
matches its recorded post-state. Restore a changed text file from its verified
pre-state only if the current file still matches the reviewed post-state. Stop
for review on any intervening modification, destination collision or unexpected
file; do not use broad directory deletion. Retain source/evidence needed for any
already distributed build. Device-prefix links and persistent installer state
are outside this source transaction and require separate assessment after any
later installation/downgrade. Never use source rollback to claim runtime cleanup.
