# Independent review of the combined Wine MSI fixes

The supplied DLL-action and corrected server-startup patches combine cleanly.
No additional blocker was found in the changed production code. Both extracted
production regression suites pass, and the complete combined `custom.c`
compiles without diagnostics for Windows aarch64 and ARM64EC. This is isolated
source/object validation; it is not a linked or runtime-validated provider.

## Exact inputs and deliverables

Wine baseline revision: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`.

| Input or output | SHA-256 |
| --- | --- |
| Baseline `dlls/msi/custom.c` | `201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25` |
| DLL-action input patch | `bdba46fbec2064a6404288a74b7a6652985b538ff3d6b84b3cfad3f8d37a283a` |
| Corrected server-startup input patch | `3feda659087a98fd9195eba0d5f21cf4cf80a501ed659cf6e1c0df99414eb42b` |
| Combined `candidate/dlls/msi/custom.c` | `31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5` |
| Combined `msi-combined.patch` | `3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8` |

`msi-combined.patch` is relative to the Wine root. `verification.json` records
every before/after hash, application order, suite result, and protected-input
check. Original scripts/harnesses and patches are copied under `inputs/` without
modification. `reports/` and `test-results/` retain full logs and compiled objects.

Both action-then-server and server-then-action orders were dry-run and applied
with `patch --fuzz=0 --batch`; both produced exactly the same combined bytes.
When the server patch follows the action patch, its hunks have an expected
four-line offset, with no fuzz. The generated combined patch was independently
dry-run/applied with zero fuzz and checked by `git apply --check
--whitespace=error-all` against the pristine baseline copy.

## Independent source review

Production changes remain confined to three functions:

- `__wine_msi_call_dll_function`: loading failure, missing export, and the
  existing caught-page-fault handler return `ERROR_INSTALL_FAILURE` (1603).
  Returned action codes, exception filter, normal cleanup and proxy ownership
  remain as in the baseline
- `custom_start_server`: checks setup API results, initializes `STARTUPINFO.cb`,
  validates system-directory/suffix capacity, accepts `ERROR_PIPE_CONNECTED`,
  and publishes process/pipe ownership only after successful connection
- `do_msidbCustomActionTypeDll`: zero-initializes action ownership, releases
  action data on either RPC initialization failure, and stops before creating
  a client thread when server startup fails

Replacing those three baseline functions with the combined versions reconstructs
the entire combined file byte for byte. The DLL-action suite's production
extraction matches the individually reviewed action candidate exactly. The two
server-patch functions match the corrected standalone server candidate exactly.
The patches therefore do not overwrite or partially undo one another.

Cleanup was checked for pipe creation failure, directory lookup/capacity failure,
redirection disable/restore failure, process creation failure, connection failure,
RPC failure, and client-thread creation failure. Errors are captured before
logging/cleanup can replace `GetLastError`. A separate success Boolean prevents
a failed API with a zero last-error value from reaching a success path; fallback
status is `ERROR_FUNCTION_FAILED` (1627). `calloc` keeps an action-thread handle
null on pre-thread failures, making the existing destructor safe. Existing
linked-token acquisition/fallback is unchanged, and only acquired handles are
released. A connected server stays package-owned if client-thread creation later
fails, allowing normal package cleanup/reuse.

The two patches operate at different failure boundaries. A running DLL custom
action's 1603 result is read by the existing synchronous wait/mapping path.
Continue still suppresses that result; Async still returns success immediately
and retains the pending action. A server setup failure returns no action object,
so Type 1 and Type 17 report their existing setup-failure code 1627 for every
Continue/Async combination. This is consistent with the pre-existing
client-thread creation failure path. It is not a new promise that Continue
suppresses initialization failures. Type 1 is executed by the startup harness;
Type 17 uses the identical source-reviewed `NULL` mapping.

## Verification results

| Suite/source | Profiles | Cases per run | Checks per run | Failures per run |
| --- | --- | ---: | ---: | ---: |
| DLL action, exact baseline | Optimized, ASan+UBSan | 113 | 5,344 | 50 expected |
| DLL action, combined | Optimized, ASan+UBSan | 113 | 5,344 | 0 |
| Server startup, exact baseline | Optimized, ASan+UBSan | 52 | 1,267 | 211 expected |
| Server startup, combined | Optimized, ASan+UBSan | 52 | 1,231 | 0 |

The baseline checks reproduce the identified failures before accepting the
combined result. The action suite verifies the exact 50-failure signature.
Startup baseline results retain the expected count and explicit attempted
connection without a child. The unchanged harnesses exercise independent
resource, reference, pending-list, invalid-free and invalid-close counters.

Complete translation-unit cross-compiles use only the retained provider's
recorded compiler commands, generated headers and existing toolchain. Only the
source and object-output paths are changed; no `make` or link is run. Both
compiler exits are zero with empty diagnostic logs. Object headers independently
confirm `IMAGE_FILE_MACHINE_ARM64` (0xAA64) and `IMAGE_FILE_MACHINE_ARM64EC`
(0xA641). Exact commands/object hashes are in
`test-results/cross-compile/manifest.json`.

The primary/shared `custom.c`, retained provider `custom.c`, private MSI header
and both config headers have matching before/after hashes. Inventories of all
1,827 aarch64 and 1,783 ARM64EC retained build-tree files have identical
size/mtime values before and after. All new sources, test binaries, objects and
logs are inside this review directory. No source tree, farm, app, submodule pin,
published artifact or remote branch was changed.

## Evidence limits and remaining work

- Both harnesses use deterministic boundary stubs on a 64-bit Linux host; they
  do not exercise real Windows/Wine DLL loading, RPC, process creation,
  scheduling, cross-bitness IPC, the 32-bit-host-only rejection path, or MSI
  transactions. Two independent suites are not an end-to-end runtime test
- The exception case uses a `setjmp`/`longjmp` substitute to reach the existing
  handler. It does not establish real SEH/page-fault handling. Cross-compilation
  validates the actual Wine headers/types and target code generation, not SEH
  runtime behavior
- LeakSanitizer is disabled because the executor uses ptrace; AddressSanitizer,
  UndefinedBehaviorSanitizer and explicit ownership counters remain active
- The unchanged `ACTION_FinishCustomActions` waits and frees asynchronous DLL
  actions without reading their exit status. This existing loss of asynchronous
  action results remains outside the patch
- A child that is created successfully but exits or fails initialization before
  connecting can still leave synchronous `ConnectNamedPipe` waiting indefinitely.
  This requires a separate process-exit/overlapped-I/O design. Cached dead-server
  recovery is also unchanged
- A restoration failure is reported, but the patch cannot guarantee OS
  filesystem-redirection recovery. If a child exists when a later setup step
  fails, its handles are closed without forced termination or a wait

The next evidence step is a separate inactive MSI provider link/build followed
by source-owned runtime canaries on a supported guest. This review does not
authorize or claim integration, deployment, proprietary installer execution,
Blender/1C success, an IPA, downloads, or paid resources.

## Reproduce

From this workspace, with the existing source inputs and provider trees present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 verify_combined.py
```

The runner writes only within this review directory, verifies the exact input
hashes, rebuilds the checks, and rechecks protected inputs. It requires existing
Python, `cc`, `patch`, Git and the retained LLVM-MinGW tools. Do not apply the
patch to a primary/shared checkout as part of this review.
