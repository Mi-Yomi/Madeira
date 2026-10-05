# MSI custom-action child startup wait audit

The published `custom.c` can wait indefinitely after an `msiexec -Embedding` child dies before connecting. The isolated patch changes only this startup protocol and the three required I/O call sites on its server handle. It is a proposal, not an installed provider or a 1C runtime acceptance result.

## Exact reachability

Baseline SHA-256: `9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50`.

- `ACTION_CustomAction` dispatches type 1 at line 1590 and type 17 at 1605
- The two DLL-action handlers reach `do_msidbCustomActionTypeDll` at lines 927 and 1033
- That routine calls `custom_start_server` at line 900 before creating the action-client thread
- `custom_start_server` creates a byte-mode synchronous pipe at 612, launches the architecture-selected `msiexec.exe -Embedding <parent pid>` at 651 or 666, and calls `ConnectNamedPipe(pipe, NULL)` at 673
- Its child process handle is stored in the package only after connection, at 681 or 686. No child-process wait occurs while connecting

This affects an actual first DLL custom action, including an asynchronous custom action because startup precedes `CreateThread`. An already-running architecture-specific server bypasses startup. The defect does not establish that a particular 1C installer contains a triggering custom action or has failed this way on a device.

Microsoft documents that process creation may succeed before DLL initialization fails and terminates the child. Synchronous pipe connection then waits for a connection or pipe error, with no knowledge of which process was intended to connect. [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw), [ConnectNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)

## Exact Wine implementation evidence

The eight files in `reference/` came from the build's source-owned Wine fork at `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`. Every file's SHA-256 matches the existing MSI build receipt; `reference/identity-checks.json` records the comparison. These are the pinned implementation, not a substituted upstream revision.

- `dlls/kernelbase/sync.c:1350–1373` sends `FSCTL_PIPE_LISTEN`; the non-overlapped pending path waits infinitely on the pipe. At 1438, the absence of `FILE_FLAG_OVERLAPPED` selects `FILE_SYNCHRONOUS_IO_NONALERT`
- `server/named_pipe.c:1330–1355` queues the listen request and returns `STATUS_PENDING`. It tracks pipe state, not the target child process. Client connection completes the queue at 1512
- `programs/msiexec/msiexec.c:410–433` connects through `CreateFileW` and can return before doing so. The `-Embedding` dispatch calls this routine. Its own client pipe handle remains synchronous and is unaffected by making the server end overlapped
- `dlls/kernelbase/file.c:3073` forwards `CancelIoEx` to `NtCancelIoFileEx`; `dlls/ntdll/unix/file.c:7392` uses the caller's I/O status block to target cancellation
- `server/async.c:746–792,1003–1018` targets matching requests. `CancelIoEx` is a cancellation request, so its return is not used as proof of completion
- `dlls/kernelbase/file.c:3323–3356` shows why a failed `GetOverlappedResult` wait must not release stack I/O storage: failure can return before the status becomes terminal. Its TRUE return can also require a terminal-status check

Verified source URLs are in `reference/sources.json`; for example [pinned connection implementation](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/kernelbase/sync.c#L1350) and [pinned pipe listener](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/server/named_pipe.c#L1330).

## Minimal coherent change

`proposal.patch` applies to the exact baseline and changes only `dlls/msi/custom.c`. `generate_proposal.py` deterministically regenerates it without writing to the primary checkout. `proposal-identity.json` records all identities.

1. Open the server pipe with `FILE_FLAG_OVERLAPPED`
2. Connect using a private manual-reset event and wait on `{child process, connection event}` with no time limit. Putting the process first rejects a dead child when both handles are already signaled. Immediate success and `ERROR_PIPE_CONNECTED` skip the pending-I/O machinery
3. On child death or wait failure, request targeted cancellation, then establish terminal completion before closing the event or returning past the stack `OVERLAPPED`. Return a nonzero failure even if the child exited with code zero. The existing caller converts startup failure to `ERROR_FUNCTION_FAILED`
4. Also check child liveness on immediate connection paths before publishing handles
5. Convert all subsequent operations on that same handle: shutdown `GUID_NULL` write (baseline 704), action GUID write (742), and action-thread-handle read (750). Each uses a fresh `OVERLAPPED` and blocks for its own completion, retaining existing byte-count checks
6. Use a shared finisher that checks actual completion with `GetOverlappedResult(FALSE)` after the wait. If a wait failed with an operation still pending, preserve that error, cancel, and poll until terminal. The 1 ms sleep is only an exceptional completion poll interval, not an installer or action deadline

The later operations may use the pipe's completion signal because there is only one outstanding operation: the initial connect drains before publishing the handle; GUID write/read are serialized under `custom_action_cs`; each action holds a package reference; destruction sends the stop GUID only after those references are released. This avoids adding package fields or per-operation event allocation. The proof depends on preserving that ownership/serialization invariant. Microsoft permits eventless completion for a single outstanding operation. [Synchronization and overlapped I/O](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-and-overlapped-input-and-output)

Adding only the overlapped flag and connection wait would be incorrect: all later reads/writes require valid `OVERLAPPED` storage too. Pipe read/wait modes do not remove the overlapped handle contract. [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile), [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile), [SetNamedPipeHandleState](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-setnamedpipehandlestate)

Cancellation completion can race with successful connection. A cancellation failure of `ERROR_NOT_FOUND` is therefore drained and handled safely. Closing the handle/event or returning immediately after cancellation would not provide the required lifetime guarantee. [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex), [GetOverlappedResult](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresult)

## Validation completed

- Exact primary baseline and all eight pinned supporting source files verified by SHA-256
- 33 deterministic C API-model tests passed, compiled with GCC `-Wall -Wextra -Werror -pedantic` and ASan/UBSan. Coverage includes immediate success, early connection, pending success/error, child death, death/completion races, cancellation `ERROR_NOT_FOUND`, failed multi-wait, failed drain wait while still pending, TRUE-but-pending completion, cleanup order, full/short read/write, and delayed terminal completion. The model asserts the event is never closed with I/O pending
- LeakSanitizer cannot run under this executor's ptrace setup; it was disabled explicitly. AddressSanitizer and UndefinedBehaviorSanitizer remained enabled
- The same helper source compiled with the existing LLVM-MinGW toolchain for aarch64, arm64ec, and i686, with warnings treated as errors. Only isolated object files were produced
- Both active farms' kernel32 and kernelbase export the four expected added APIs: `CancelIoEx`, `CreateEventW`, `GetOverlappedResult`, and `WaitForMultipleObjects`. The full provider rebuild must verify the exact actual import delta and resolution; a symbol's presence is not runtime acceptance
- No provider was replaced, no i386 farm activated, no third-party installer executed, and no remote device test or publication performed

`test-results.txt`, `compile-results.json`, the per-ABI `compile-*-readobj.txt` files, and the review report contain the evidence. Host models exercise branch/lifetime logic; ABI compiles exercise declarations and target code generation. Neither proves Windows, Wine, Madeira, or 1C runtime behavior.

## Bounded implementation recommendation

Rebuilding the three matched MSI providers and their receipts is practical within the remaining deadline if the pinned inputs are restored. The prior receipt records approximately 12 seconds of configure and 19 seconds of MSI make per architecture, roughly 95 seconds total plus provenance and audits. Those timings are historical evidence, not a new-build guarantee; input restoration is the larger current uncertainty.

Rebuild all three together, preserve the export name/ordinal/forwarder contract, and permit only the reviewed import additions instead of demanding import identity. `SetLastError` is also newly called in source; verify whether Wine's headers inline it as they do the existing `GetLastError` calls. Rerun the provider symbol resolver and existing MSI/host integration gates, then refresh sealed source, object, binary, license/change, rebuild, and integration receipts. Preserve inactive i386 status. The restored build worker owns the actual full build and receipts.

For later authorized runtime acceptance, use a source-owned process/pipe fixture: child exits before open, child connects immediately or after an event, connection/death races, broken post-connect pipe, repeated successful GUID/thread-handle exchange, and clean stop. Use an outer test watchdog solely to detect a hung test. Do not introduce that watchdog as a production installer timeout. A real 1C install remains a separate authorized acceptance gate.

## Explicit remaining limits

An alive child that never connects can still wait indefinitely. Custom-action execution and shutdown retain their existing unlimited waits. If the OS both refuses cancellation and never completes the operation, the exceptional finisher must keep waiting to preserve I/O storage lifetime; returning or closing live stack-backed I/O would be unsafe. This patch intentionally does not claim to solve those different hangs.
