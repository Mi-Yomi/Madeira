# Isolated MSI client failure candidate

This source-only candidate fixes a reproduced error path in Wine's
`custom_client_thread`. It has not been linked into providers, installed, pushed,
or published. It is separate from the already integrated MSI provider set.

## Reproduced problem

The baseline is the exact `custom.c` retained by the sealed patched-provider build:
`31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5`.
It already includes the two earlier reviewed MSI patches against Wine fork commit
`4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`.

Compiled production-function fault injection shows:

- `WriteFile`/`ReadFile` failure with `ERROR_BROKEN_PIPE` becomes return 0 when
  diagnostics or critical-section release overwrite LastError. The outer
  synchronous action then reports success. Both failure paths skip COM teardown.
- A successful short transfer uses stale LastError, and may report success.
- A failed `WaitForSingleObject` is ignored; a subsequent successful status query
  can report success even though the wait failed.
- A failed `GetExitCodeThread` leaves `rc` unwritten. With compiler automatic
  variable pattern initialization, the baseline returns `0xfefefefe`. This is a
  diagnostic compiler pattern, not a claim about the value on an actual device.
- Failed COM initialization is ignored and later followed by `CoUninitialize`.

The unchanged baseline fails 46 of 102 host scenarios; the candidate passes all
102. The baseline failure log is retained, and its runner intentionally exits 1.

## Narrow change

Only `custom_client_thread` changes. The patch:

1. Stops with `ERROR_FUNCTION_FAILED` if COM initialization fails; balances every
   successful S_OK or S_FALSE initialization exactly once
2. Captures an API error before logging or cleanup; supplies
   `ERROR_FUNCTION_FAILED` for a zero error or successful short transfer
3. Releases the critical section on all pipe failures and performs COM cleanup
4. Checks the thread wait before querying its exit code, checks the query result,
   and closes only the successfully duplicated local thread handle
5. Leaves successful custom-action return values untouched

Raw nonzero Win32 errors continue to be propagated as before; this is not a new
MSI error-mapping policy. The existing outer Continue/Async implementation remains
byte-identical, as do all source bytes outside this one function.

## Verification

- 102/102 host fault-injection scenarios pass with optimized compilation
- 102/102 pass with AddressSanitizer and UndefinedBehaviorSanitizer
- Full `custom.c` translation units compile without diagnostics for AArch64 and
  ARM64EC with recorded, pre-existing trusted Wine build inputs; LLVM independently
  verifies each object machine type
- The patch applies cleanly with whitespace errors rejected, yielding the exact
  candidate source hash
- All 16,911 regular files and symlinks in the sealed provider workspace retain
  their original hashes or link targets
- An independent read-only review found no source blocker. Suggested test
  improvements for COM cleanup ordering and I/O doubles were incorporated; the
  production source is unchanged from the reviewed version

The tests extract the actual production functions byte for byte. They do not
reimplement the function under test. Coverage includes nonzero/zero errors,
diagnostic and cleanup clobbering, zero/partial transfers, duplicate failure,
failed wait and failed exit query, S_OK/S_FALSE/failed COM initialization,
critical-section balance and COM teardown ordering, local handle ownership,
success/cancel/arbitrary/suspend/no-more-items results, both 32/64-bit routing
branches, and every Continue/Async flag combination. The outer suspend/reboot and
no-more-items mappings are exercised too.

## Reproduce

From this directory:

```
sha256sum -c SHA256SUMS
python3 tests/run_portable.py --source baseline/custom.c --output /tmp/msi-client-baseline
# Expected exit 1: baseline fails 46 of 102 scenarios.
python3 tests/run_portable.py --output /tmp/msi-client-patched
python3 tests/run_portable.py --sanitize --output /tmp/msi-client-sanitized
python3 tests/compile_production.py --output /tmp/msi-client-cross
python3 tests/verify.py
```

Use fresh output directories. The full-TU check reads the sibling
`madeira-msi-patched-provider-build-20261005` and its recorded llvm-mingw toolchain.
It changes only the source/output arguments of the recorded compiler commands;
it never invokes make/configure/link or writes into that sibling. The verification
script writes a local preservation report only.

To use the patch later, independently copy the exact baseline source tree,
verify the baseline hash, and apply `msi-client-failure.patch` from that tree root
with `git apply --check --whitespace=error-all` followed by
`git apply --whitespace=error-all`. The patch is incremental to the two previous
reviewed changes, not to pristine Wine. It requires separate review and a fresh
provider rebuild before integration. The candidate source hash is
`9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50`.

## Precise limits

No guest executable, installer, application/IPA build, linked provider, or runtime
canary was run. No download, paid resource, provider replacement, remote write, or
primary source edit was performed. Host shims validate control flow and ownership,
not actual Windows/Wine IPC, threads, COM marshaling, concurrency, exceptions, or
cross-bitness. The two routing values in the host tests are not two host machine
ABIs. The object builds check two target ABIs but do not execute them.

WAIT_TIMEOUT with INFINITE and WAIT_ABANDONED for a thread are synthetic defensive
cases. Failed APIs with LastError zero are defensive fault injection, not a claim
about ordinary conforming Win32 implementations. The ASan/UBSan runs disable Leak
Sanitizer; this shim allocates no application heap objects, and COM/handle cleanup
is tested using explicit counters. The async outer cases verify its immediate
policy branch, not eventual background execution/cleanup.

The existing child-before-connect hang, synchronous pipe read/write blocking,
dead cached server recovery, protocol resynchronization after partial transfer,
and asynchronous action exit-status handling are unchanged. A failed wait can
return while the remote action remains alive; no process termination policy is
introduced. No blanket claim of failure-closed MSI behavior is made: existing
outer MSI mapping and its separate unchecked status query remain unchanged.

## Attribution

Wine MSI `custom.c` is Copyright 2005 Aric Stewart for CodeWeavers and
LGPL-2.1-or-later. The existing Madeira LGPL branch notices and the earlier local
modification record are retained in `licenses/`. The incremental change record is
`licenses/CLIENT-MODIFICATIONS.md`. New test/verification code is provided under
LGPL-2.1-or-later. No upstream author, license, or copyright notice is removed.
This local review does not establish distribution or LGPL relinking compliance.
