# MSI child startup: Windows API reference fixture

This source-owned fixture checks the reviewed startup helper and pipe I/O helper
against real Windows process, event, named-pipe, cancellation and job APIs. It
compiles and runs only its own two C programs. It neither launches an installer
nor loads a Wine/Madeira provider.

## Exact source, independent of provider replacement

`source/custom.c` is the full frozen reviewed production proposal, SHA-256
`0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f`.
Its existing Wine copyright/license notice is retained; `COPYING.LIB` contains
the LGPL 2.1 text. `source/provenance.json` records the baseline, patch and helper
identities. The fixture files are also LGPL-2.1-or-later.

`extract-helpers.ps1` verifies the complete source hash, unique function-boundary
markers, all three exact declarations, and the final extracted byte hash. It
generates the include in the empty output directory. There is no separately
maintained helper implementation. The 4,196-byte extracted span includes the
blank line before `custom_start_server`; its hash is
`4eab607ab3dd71f8df9e03b46b7f5cd7757f889c38f9f93a26072a002e1d0f7b`.

The workflow can be published and run before any MSI binary replacement. If the
sealed integration source exists at
`build/wine-pe/receipts/msi-startup-2026-10-05/build/source/custom.c`, it must match
the frozen source too. A mismatch fails before compilation. A deliberate future
production change requires a new source review and explicit hash update.

The directory's narrow `.gitattributes` marks each hash-bound source/build input,
the request and provenance as `-text`. An isolated local Git commit/clone/checkout
with `core.autocrlf=true` verified that their exact bytes survive Windows-style
checkout policy without requiring a repository-wide text-policy change.

## Running

On Windows with PowerShell 7 and preinstalled MSVC x64 tools / Windows SDK:

```powershell
./tests/msi-startup-windows/run.ps1 -OutputDirectory ./windows-reference-output
```

Use a fresh empty output directory. `-SourcePath` may supply the same final
production `custom.c` elsewhere; its hash must match. `-IntegratedSourcePath`
additionally requires another source path to match the reviewed source.

The GitHub Actions workflow runs only when `reference-request.json` changes on
`compatibility/desktop-apps`, and only in the public `Mi-Yomi/Madeira` repository.
Ordinary app/document/source pushes do not trigger it. The request pins the six
source/build inputs; the run script verifies all hashes and scope before building.
It uses the standard `windows-2025` runner with a 10-minute job limit and read-only
repository permissions. The only Action is the repository-approved official
`actions/checkout@11d5960a326750d5838078e36cf38b85af677262`, with credentials not
persisted, submodules and LFS disabled, depth 1, and a 2-minute checkout limit.
The next step verifies `HEAD` equals the exact requested `GITHUB_SHA`. Builds use
preinstalled PowerShell/MSVC/Windows SDK. The workflow installs nothing, fetches
no submodule or LFS object, invokes no third-party installer or IPA, and uploads
no artifacts. It contains no manual credential configuration. There is no broad push or PR trigger and
no default-branch change. It uses the existing standard public-repository runner
convention, with no paid-resource selection.

## Eight runtime cases and their actual assertions

| Case | Required evidence |
| --- | --- |
| Child exits before pipe open, pending listen | The real listen was pending; zero-exit child process won; helper rejected startup and requested cancellation |
| Already-dead child | Child exited before the helper; pending connect was cancelled/drained and rejected |
| Immediate connection | Child opened before `ConnectNamedPipe`; real `ERROR_PIPE_CONNECTED` observed; live child completed an exchange and stop |
| Event-delayed connection | Child gate released only after the real listen returned `ERROR_IO_PENDING`; connection event won; live exchange and stop |
| Both connection and death signaled | Own child connected/exited before the real multi-object wait; both objects were set; process index won; startup rejected; real cancellation `ERROR_NOT_FOUND` observed |
| 64 connection/death races | Every own child opened and exited successfully; each helper call completed with success or `ERROR_FUNCTION_FAILED`; both outcome counts recorded |
| Broken post-connect pipe | Read was genuinely pending before the child disconnected; finisher returned a pipe error and zero bytes; subsequent broken read/write failed |
| 256 GUID/thread64 exchanges and clean stop | Every 16-byte GUID and 8-byte reply matched; all reply reads were genuinely pending; serialized eventless operations completed; `GUID_NULL` stopped the child cleanly |

The immediate case does **not** claim to force the API's `TRUE` synchronous
completion branch. It forces the distinct `ERROR_PIPE_CONNECTED` branch.
An uncontrolled connection/death race may return success if the child is alive
at the helper's final check. That result is not an assertion of later liveness.
Successful live cases independently assert child liveness and exchange content.
The 8-byte reply is a deterministic thread-handle-sized value, not a real thread
handle or a test of remote thread-handle ownership.

Test-only adapters surround four real APIs solely to count observed outcomes
and schedule the fixture's own child through private events. They preserve the
real API return value and last error; they do not fabricate success, errors,
completion events or process death. All three production function bodies remain
byte-identical. The exceptional Win32 API failure branches tested by the separate
deterministic API model are not claimed as exercised by this runtime fixture.

## Bounded execution and cleanup

Every case runs in a new instance of `fixture.exe`, created suspended and assigned
to a private kill-on-close job before it can run or create `own_child.exe`.
There is no breakaway flag. A 20-second **outer test watchdog** catches hung cases;
the production helpers retain their infinite waits and acquire no timeout.

After a watchdog or supervisor error, only the newly created case/job process
handles can be terminated. If job assignment fails, the still-suspended own case
is killed before it can spawn a child. The supervisor's cleanup waits are bounded
to 5 seconds each and verifies the private job has zero active processes; any
cleanup uncertainty fails the case. Closing that job is the final containment
backstop. No PID enumeration, taskkill, process-name matching or unrelated process
termination is used. All child shutdowns in passing cases occur through their
intended protocol or their explicit exit mode.

## Results and limits

The runtime emits `windows-results.json` listing every planned case, whether it
actually ran, result, exit code, elapsed time, watchdog status, cleanup status and
detail log. `case-*.log` reports actual branch/exchange/race counts. The script
prints all of these into the job log and writes a per-case job summary. It also
writes `source-identity.json` and `build-identity.json` locally. There are no
artifact-upload steps. Build failure, missing report, unrun case, watchdog,
cleanup uncertainty or test failure makes the job fail.

A successful workflow is x64 Windows API compatibility evidence for these exact
helpers. It does not establish full `msi.dll`, Wine, Madeira, arm64/arm64ec/i386
runtime, iOS, remote device or 1C installation acceptance. It does not validate
production token selection, architecture dispatch, package lifetime or installer
policy. An alive child that never opens the pipe still intentionally waits in
production; the fixture watchdog detects only a hung test.
