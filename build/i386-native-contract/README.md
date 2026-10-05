# Bounded native prerequisites for an i386 diagnostic build

This opt-in checker consumes **real produced archives**. It does not enable i386,
build an app, run guest code, make an IPA, or replace any native/PE component.
The existing explicit app-link diagnostic is the only workflow that selects this
check. Its request defaults to `native_archive_contract: false`; the existing
request-file/workflow triggers and 45-minute, two-job limits are unchanged.

## Scope and evidence

The ordinary 20-archive `native-artifacts.py` platform/provenance gate remains a
prerequisite. This checker rehashes that exact archive set, checks every member's
iOS ARM64 Mach-O platform, and inspects actual section definitions and relocations.
It rejects undefined/weak/duplicate/wrong-member definitions of the selected
contract symbols and unrenamed Unix-call/init symbols.

The selected contract covers:

- ntdll's guest-window data and reserve/bind/release definitions in `virtual.o`,
  including the local registry that the non-iOS fallback lacks
- `NtQueryInformationProcess` in `process.o`, its compiled references to both
  current-process and PEB-keyed guest-base functions, and loader/server bindings
- the native win32u initialization wrapper, its registration edge into ntdll,
  and ntdll's reference to `KeServiceDescriptorTable`
- NSI's separate native and WoW64 three-slot tables, exact byte extents, one
  64-bit unsigned relocation per slot, expected slot ordering and real compiled
  code targets, plus all six native/WoW64 argument record layouts emitted by
  Clang during compilation of the actual NSI translation unit
- in optional final-link mode, live map ownership and final-image symbol
  addresses for cross-object contract entry points/data; the real FEXBridge
  host-probe entry and its Config/Context providers in the native FEX archives

NSI is deliberately the first bounded Unix-call slice: it is a small
source-owned fallback with three fully distinct WoW64 wrappers, and it exercises
NULL-preserving embedded-pointer conversion, scalar preservation and an in/out
count. The existing crypto checker remains required. ws2_32, bcrypt, secur32,
crypt32, DNS, dwrite, audio and enabled graphics/media **do not acquire ABI
coverage** from this result. Neither do the full ntdll/win32u syscall arrays.
Missing netapi32/winspool Unix backends remain unsupported; their PE presence
does not establish Samba or printing support.

The source-owned host harnesses compile the exact class-1010 case, NSI wrappers,
guest-pointer helpers and win32u/ntdll registration bodies with narrow test
doubles. They check class 1010's current/remote/error paths, high and NULL guest
pointers, scalar fields, and actual slot-1 updates. Deliberately removing a
conversion or changing slot 1 to slot 0 must fail. These are host fixture results,
not evidence that a live iOS process registered or called a service.

`contract.json` pins reviewed source **bytes**, including the Wine headers and
PE NSI call sites for codes 0/1/2. It does not trust a stale checkout HEAD. Update
these hashes only after reviewing the corresponding source change. There is no
"accept current source" or "ignore missing evidence" option.

## Capturing the real selected compilations

`capture.py` wraps an existing, authorized native compile command. It performs
one dependency-only preprocessing pass, hashes those inputs, runs the same
compiler command with dependency output (and NSI record-layout output), then
compares all dependency and compiler bytes again. A successful record binds the
actual object bytes to its source, transitive headers, compiler and arguments.
It does not replay commands when validating evidence. On preprocessing, compiler
or timeout failure, the wrapper reports at most 32 KiB from each captured
stdout/stderr tail, plus a short status. It handles byte/text output without
dumping the command or environment, replaying work, or writing a success record.

Use a fresh record directory in the same trusted job. Route only these eight
normal source compilations through the wrapper:

| Archive | Object | Capture filename |
| --- | --- | --- |
| ntdll | virtual.o | ntdll-virtual.o.json |
| ntdll | process.o | ntdll-process.o.json |
| ntdll | loader.o | ntdll-loader.o.json |
| ntdll | server.o | ntdll-server.o.json |
| ntdll | syscall.o | ntdll-syscall.o.json |
| ntdll | nsi_unixlib_ios.o | ntdll-nsi_unixlib_ios.o.json |
| ntdll | nsi_network_ios.o | ntdll-nsi_network_ios.o.json |
| win32u | syscall.o | win32u-syscall.o.json |

For example, replace only the selected command prefix with:

```sh
python3 "$REPO_ROOT/build/i386-native-contract/capture.py" \
  --root "$REPO_ROOT" \
  --record "$CONTRACT_LOG_DIR/ntdll-$name.o.json" \
  --source "$src" --output "$OBJ_DIR/$name.o" -- \
  "$(xcrun --sdk iphoneos -f clang)" \
  ...the existing compile_one arguments, unchanged...
```

This is a template, not a runnable command with the ellipsis. Keep the full
existing flags, include order, source path and output path. Resolve the real
Clang executable rather than recording the xcrun dispatcher. The wrapper
intentionally refuses LTO, response files, preexisting capture records and
externally supplied dependency flags. It removes only the selected old object
before compiling, so a failed compile cannot leave that old output for staging.
The first integration must also update the two reviewed build-script hashes in
`contract.json`; merely wiring the wrapper changes those scripts' bytes.

Keep the native object directories, capture records, compiler/SDK and source
tree until validation finishes. Archive member bytes must equal both the record
hash and the still-present production object. Source/header changes or a stale
member invalidate the capture. Records and receipts are audit evidence from a
trusted job, **not authenticated attestations** that can be accepted from an
arbitrary submitter.

## Default-off diagnostic wiring

The `compile_one` functions in `build/ntdll-unix/build.sh` and
`build/win32u-unix/build.sh` retain their original compiler arguments and normal
`xcrun -sdk iphoneos clang` dispatch. Only the eight named objects above switch
to `capture.py` when `MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR` is nonempty. That
branch resolves Apple Clang using `xcrun --sdk iphoneos --find clang`; it never
records the xcrun dispatcher as the compiler. No other compilation is captured.

The only request change for a later authorized diagnostic is:

```json
"native_archive_contract": true
```

This field is in `build/app-ios/link-diagnostic-request.json` and is committed as
`false`. Both JSON booleans are accepted; missing, string, integer or additional
options are rejected. Every other reviewed request field remains fixed. A
request-file change uses the existing explicit diagnostic push trigger; there
is no new general push trigger or separate build workflow.

The workflow calls the fixed native entry point:

```sh
python3 build/app-ios/link_diagnostic.py native \
  --native-log-dir "$NATIVE_LOG_DIR" \
  --native-artifact-dir "$NATIVE_ARTIFACT_DIR"
```

The entry point clears inherited capture settings and enables them only for a
true request. It requires a fresh `$NATIVE_LOG_DIR/i386-native-contract`
directory, then runs the existing `.github/ci/native-bootstrap.sh` unchanged.
After its full 20-archive collection succeeds, the entry point immediately runs
`check.py` with the produced native receipt, eight captures and retained
production objects, compiler and SDK. A native-stage failure skips the checker;
a checker failure stops the workflow before graphics or application builds.

Evidence remains local to that job:

- `$NATIVE_LOG_DIR/i386-native-contract/captures/{ntdll,win32u}-<object>.json`
- `$NATIVE_LOG_DIR/i386-native-contract/archive-contract.json`
- `$NATIVE_ARTIFACT_DIR/provenance.json` for the existing twenty archives
- `build/{ntdll,win32u}-unix/obj/<object>.o` and `<object>.err`
- `$NATIVE_LOG_DIR/bootstrap.log` for the native stage, plus the workflow step's
  console output for the archive-check result and receipt hash

In the current workflow `$NATIVE_LOG_DIR` is
`$RUNNER_TEMP/madeira-link-native-logs` and `$NATIVE_ARTIFACT_DIR` is
`$RUNNER_TEMP/madeira-link-native-artifacts`. No new cache, artifact upload,
packaging, signing, IPA or guest action is added. Keep the source and these
outputs through the check. This wiring creates no long-term evidence upload.

The 14 fixture groups run in the explicit diagnostic's native job after its
recursive checkout using installed Apple `clang`, `ar` and `ld`. Portable wiring
fixtures also run before native builds. Local fixtures use trusted existing
Clang/LLVM tools; no tool download is needed by these checks.

First production scope is strictly archive evidence: `final_link: null`,
`runtime: not_run`, and `application_support: not_established`. The later normal
Debug app compile/link in this same diagnostic remains independent and still
needs its existing `link-diagnostic.json` and `provenance.json` receipts.
The dispatcher cannot take final-link or FEXBridge capture arguments.

For a separately authorized future final-contract integration, retain the
unstripped executable, its actual map, and the actual FEXBridge object/capture.
Use the fully expanded real Xcode command; response and dependency options are
not silently interpreted. This patch does not invent that capture, request a
map or force-retain any symbols. Source presence or an ordinary app link alone
cannot provide final-contract evidence. Leave all i386 farm and launch settings
off; broader Gate 2 and device evidence remain.

The final map checks addresses and ownership; they do not decode rebased/chained
pointer contents or authenticate a manually supplied map. They do not
independently reconstruct the exact historical input hashes used by the linker;
the receipt records that limit explicitly. Final executable,
map, bridge object and native bundle must be produced together by the trusted
job. Native FEXCore here supports the app's host probe. It is distinct from the
PE xtajit WoW64 path, which still needs its own binary/device evidence.

## Local validation limits

The tests use real compiler-produced iOS ARM64 objects, real archives and a tiny
freestanding LLD-linked iOS fixture. They never execute that ARM64 image. The
host C harnesses execute only test-owned native processes. No production native
archive or Madeira app has been checked locally, because those outputs are
absent. Apple Clang/ld64 production output remains a required first-use check;
unsupported evidence formats fail rather than being silently skipped.
