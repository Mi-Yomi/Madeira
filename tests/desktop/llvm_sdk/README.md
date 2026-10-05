# Official LLVM SDK: Windows ABI/dependency preflight

This is a separate prerequisite experiment for a future Mesa 26.2.4 llvmpipe
reference. It does not build Mesa. A green result means that the exact official
LLVM 22.1.4 Windows development SDK supports a source-owned C++/MCJIT program
with the preinstalled runner's x64 MSVC and static release CRT. It does not mean
that MinGW C++ objects can link to this SDK, or that LLVM/Mesa works in Madeira,
Wine, FEX, ARM64EC or iOS. It cannot establish iPhone performance.

## Exact run request

Workflow: `.github/workflows/llvm-sdk-windows-preflight.yml`

Repository and branch: public `Mi-Yomi/Madeira`, `compatibility/desktop-apps`.
The workflow runs on a change to its own file or
`tests/desktop/llvm_sdk/preflight-request.json`, or by explicit
`workflow_dispatch` on that branch. The request token starts at
`official-llvm-sdk-msvc-abi-preflight-20261005-1`. Ordinary source edits do not
automatically repeat a download; a reviewed request-token change can request
the next run. The job checks the public-repository/ref/event restrictions again
inside Python. Publishing either trigger file on the branch triggers this job.

There is one standard `windows-2025` job, a 45-minute workflow limit, a
42-minute execution step, and an independent 40-minute script watchdog. Tools
must already be installed: CPython 3.12.10 x64, Visual Studio x64 C++ tools,
Windows SDK and CMake >=3.25. Their actual paths, versions and executable hashes
are recorded. There is no installer, package-manager fallback, private input,
credential, uploaded artifact, cache, signing, IPA or paid/larger runner.

Visual Studio discovery preserves the runner's `ProgramData` and
`AllUsersProfile` in the otherwise filtered tool environment: the Setup
Configuration server [needs `ProgramData`](https://github.com/microsoft/vswhere/issues/236#issuecomment-985741650).
It uses the preinstalled `vswhere`, requires x86/x64 C++ tools, and reads at
most 64 KiB / 16 instances of UTF-8 JSON for complete, launchable, non-prerelease
VS 2022/2026 (major 17/18) installations with no pending reboot. Multiple
qualifying installations are ordered by numeric version, newest first, with a
case-insensitive path tie-breaker. Each path must stay below Program Files and
contain its developer script. Empty, malformed, duplicate, unsupported or
unsafe discovery stops before download; no filesystem search or installer
fallback is used. `VS_SELECTION` records the chosen identity/version/path and
candidate count before setup. This only selects a candidate: the subsequent
verified tool paths, x64 `/MT` compile/link, dependency audits and MCJIT proof
remain mandatory.

A small source-owned CMake fixture checks the exact conditional link-expression
evaluation mechanism with those preinstalled tools before any SDK download.
Its placeholder libraries are never linked or executed and cannot satisfy the
real SDK checks. The same template then inspects the unchanged official exports.

Only the official 861,945,788-byte SDK archive in `inputs.lock.json` is fetched.
Its exact SHA-256 is
`ed775bdaea7087c6c1aeac9498352cfcd8610d92dc4fe9eda9aecb15ce712a2c`.
The SDK has not been downloaded by the source-only preparation/review.

## Stop guards and archive handling

- Fresh work root strictly below `RUNNER_TEMP`, separate from the checkout
- 6 GiB maximum expanded SDK including copies of archive hardlinks, inspected
  before writing any archive member; unknown size is not assumed to fit
- 8 GiB total-work stop threshold, 3 GiB remaining-free-space stop threshold; checked during
  download/extraction/commands and by an independent watchdog
- 16 active processes and 10 GiB committed process-tree memory in a Windows
  job with kill-on-close; failure to establish containment stops before input
  download
- One compiler and one linker invocation at a time, below the authorized
  two-compile/one-link limits; no LLVM compilation or parallel build is launched
- 8 MiB per command log, 64 MiB aggregate logs, bounded command timeouts,
  128 MiB per inspected runtime executable

Disk/log totals are polled at intervals up to ten seconds, not enforced by a
filesystem quota; a stopped run can overshoot a threshold between checks.
Process-tree memory and active-process limits are enforced by Windows. The
expanded SDK cap is checked against its complete inventory before extraction.

The complete archive is inspected with a bounded streaming tar reader. Reject
absolute/traversal/ADS/device paths, Windows name aliases and duplicate names,
symlinks, device entries, sparse members, oversized members and file-as-parent
collisions. Hardlinks must target a regular in-archive file and are materialized
as independent copies charged to the size cap. No archive permissions, owners,
timestamps or links are restored. The full accepted archive is retained,
including its LLVM and third-party notices. An archive above the declared cap
is an explicit failure; the harness does not enlarge its budget or silently
drop archive content to force a pass.

## Evidence required for success

1. Exact SDK archive size/hash, entry count and expanded-byte inventory; hashes
   of key generated/public headers, configuration exports and license files
2. `LLVMConfig.cmake` identifies Release, x64 MSVC ABI and `MultiThreaded` (/MT),
   with generated `abi-breaking.h` confirming disabled ABI-breaking checks
3. The real SDK `llvm-config.exe` agrees on version, host, static mode, RTTI and
   the native X86 backend; its PE imports must resolve to reviewed system DLLs
4. The real `--link-static --libnames` result covers Mesa's current components,
   including LTO/Passes and coroutines. The unchanged SDK CMake exported
   dependencies are evaluated for MSVC C++; every resulting edge must resolve
   to another selected static library or a specifically reviewed Windows
   system library/link option. Exact library paths and hashes are retained
5. Each selected `.lib` is independently inspected as x64 COFF/bigobj code,
   with static release CRT directives. Import libraries, bitcode needing an
   unreviewed toolchain, alternate CRTs, missing CRT evidence, hidden external
   default libraries, and linker override/suppression directives fail. The
   pinned SDK's implicit `uuid` directive is recorded separately from the CRT
   and accepted only when UUID also appears in the verified explicit closure.
   LLVM's [Windows support source](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.4/llvm/lib/Support/CMakeLists.txt)
   already requires it for `FOLDERID_Profile`; this adds no new system provider
6. The source-owned probe compiles with MSVC `/MT`, `LLVM_BUILD_STATIC`, release
   iterator ABI and matching RTTI/EH configuration, then links the exact audited
   libraries with all audited exported options. No `/FORCE`, ignored errors,
   metadata editing, guessed external libraries or fake `llvm-config` is used
7. The probe uses LLVM C++ IR construction/destruction and C API ownership,
   runs `LLVMRunPasses(default<O1>)`, generates executable memory with MCJIT,
   calls that code with two distinct input pairs and verifies exact independent
   integer results, then destroys the engine before emitting final success
8. The resulting executable's normal/delayed PE imports pass the system-only
   audit, it runs from an isolated runtime directory, and its hash is unchanged

`llvm-config --system-libs` is retained as diagnostic data. LLVM 22's upstream
tool appends WindowsManifest system dependencies globally; that output alone
does not prove a selected llvmpipe closure needs libxml2. This preflight does not
filter that string and claim success. Instead it requires a complete independent
exported dependency graph, explicit absence of LLVMWindowsManifest, no unknown
library edges or implicit COFF dependencies, and a successful real link. A
needed but unbundled libxml2, zlib, zstd, or other third-party library stops the
job. Missing/unknown metadata also stops the job.

The exported delay-load options for `shell32.dll` and `ole32.dll`, `delayimp`,
and allocator `/INCLUDE:malloc` semantics are preserved, not removed to make a
link succeed. The checked allowlist is grounded in the exact upstream
[LLVMSupport source](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.4/llvm/lib/Support/CMakeLists.txt).

## Expected log proof

`INPUT verified`, `ARCHIVE inspected`, `SDK_METADATA`, `LLVM_CONFIG` and
`GLOBAL_SYSTEM_LIBS diagnostic_only` precede the dependency audit. `CLOSURE`
names every selected component library and exact system/link-option sets;
`LIBRARY` records each file's hash/size and COFF/CRT evidence. `PROBE_PE` durably
records the generated executable's exact PE machine, decoded architecture,
size, SHA-256 and every normal/delayed imported module and name/ordinal, before
runtime. That record is capped at 1 MiB/4,096 symbols; excess fails explicitly
rather than silently truncating the binary's import evidence. Successful command
stages include metadata evaluation, probe compilation, CRT directives, linking
and runtime. The runtime must produce precisely two `JIT seed=...` lines and:

`PASS llvm=22.1.4 abi=msvc-x64 crt=MT pointer_bits=64 passes=O1 jit=MCJIT seeds=2 cleanup=complete`

The final `PREFLIGHT` JSON must say `native-windows-sdk-abi-jit-passed`, bind the
source commit and runner image, give the dependency-manifest digest, elapsed
time and actual JIT proof, and keep the scope limitation explicit. Full bounded
logs, dependency manifest and receipt stay in the ephemeral work root; there is
no artifact upload. Absence of the final record or any failing stage is a failed
preflight. An SDK-tool execution result is separate from the source-owned probe
result, and neither is a Mesa result. The final summary includes the probe's
machine/hash/size/import counts and points to its exact `PROBE_PE` record.
The PE audit covers normal/delayed import tables and rejects unknown API-set
names. It does not inventory every possible dynamic LoadLibrary/COM request.

`MADEIRA_IMPORT_ASSESSMENT` separately compares those selected imports against
the same checkout's `app/Madeira/arm64ec-windows` providers. It reuses unchanged
pure PE/export/API-set readers, preserves the original importer through
forwarders and API-set aliases, and records the source commit plus hashes and
architectures of every provider/schema read. It follows only selected export
forwarders, bounded to 64 providers, 128 MiB of provider bytes, 32 hops, 20
seconds and 1 MiB of log evidence. No provider is executed. Missing modules,
exports, unresolved API sets and cycles are explicit gaps; malformed evidence
and resource limits yield `incomplete`, never a complete result.
The comparison's 20-second deadline is checked between bounded reader
operations; the existing overall watchdog and Windows job limits still apply.

This comparison is report-only and cannot change the native Windows acceptance
into a Madeira compatibility claim. `selected-imports-resolved-statically`
means named/ordinal exports exist along the inspected paths. It does not audit
the providers' own transitive imports or prove implementations, calling
conventions, x64-to-ARM64EC transitions, guest FEX/JIT behavior, iOS JIT memory
coherency or performance. The probe is plain x86_64, and its MCJIT emits x86_64
code; neither becomes native ARM64EC/iPhone code through static symbol matching.

## Portable verification and a possible later stage

Run `python tests/host/check-llvm-sdk-preflight.py`. It tests archive/resource
failure inputs, COFF/bigobj CRT restrictions, complete dependency edges and
preserved linker flags, real-byte PE normal/delay dependency controls, and exact
two-seed proof rejection. Inert Visual Studio fixtures also check single and
multiple installations, numeric/tied ordering, missing or malformed discovery,
unsafe paths/states, and preservation of Windows discovery variables without
inheriting compiler flags or search paths. A mocked command runner exercises
the complete tool-environment assembly and proves empty discovery stops before
the developer script. It uses the repository's existing pure PE readers in
`build/wine-pe/symbol_audit.py` and `guest_inventory.py`. These synthetic
controls do not demonstrate that the real SDK fits, links or runs on Windows.

Only after a reviewed green SDK receipt, consider a separate Mesa llvmpipe
workflow. It must use the same verified SDK, MSVC-compatible C++ ABI, `/MT`
release CRT, exact dependency manifest and Meson's documented binary dependency
wrap (not a rewritten `llvm-config`). Retain LLVM/Mesa notices. Pin all other
Mesa/parser/wheel inputs from the already green softpipe reference, keep
`--wrap-mode=nodownload`, limit compile/link jobs and preserve the same disk/free
space/process guards. Set `llvm=enabled`, `draw-use-llvm=true`, static LLVM,
`llvm-orcjit=false` and matching RTTI; build only the WGL/GDI target.

A separately reviewed <=45-minute second job can be considered if measured SDK
size/time leaves sufficient space and time for the Mesa compile; the existing
softpipe duration does not establish MSVC llvmpipe time. Require real core 4.3
context, llvmpipe renderer, GLSL430 shaders, twelve active SSBO blocks per
vertex/fragment/compute stage with changed-seed readback, actual draw-parameter
and clip-control behavior, and window-backing pixels. Such a job still would not
prove Blender startup, Wine/FEX execution, iOS JIT permission, compositor
presentation or useful iPhone performance. This workflow never starts it.
