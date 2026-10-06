# Bounded DIA member-selection diagnostic

This experiment answers one question: can the selected preinstalled Microsoft
DIA archive satisfy LLVM's three recorded external references in an ordinary
MSVC x64 release `/MT` link without selecting its incompatible MD-tagged member?
It compiles one tiny source file and links it once. **It never executes the
generated executable.** No LLVM download, JIT, Mesa build or Madeira runtime is
part of this experiment. It cannot approve the complete SDK provider closure.

## Request, inputs and bounds

Publishing `tests/desktop/llvm_sdk/dia-link-request.json` on public
`Mi-Yomi/Madeira`, branch `compatibility/desktop-apps`, opts into the job in
`.github/workflows/llvm-dia-link-diagnostic.yml`. Only that exact request path
triggers it. Ordinary source, documentation and workflow-file edits do not.
The existing LLVM SDK/inventory workflows and their requests remain unchanged.
The Python entry point independently checks repository/ref/event/public status.

One standard `windows-2025` job has a ten-minute limit, an eight-minute diagnostic
step and a seven-minute internal watchdog. The single compile is limited to
60 seconds; the single link to 90 seconds. Existing process containment limits
the entire tree to 16 active processes and 10 GiB committed memory. Work files
are capped at 64 MiB, each command log at 8 MiB, evidence at 32 MiB, each provider
at 256 MiB and all provider inputs at 1 GiB, with a 3 GiB free-space floor.
Filesystem/log limits are polled, so writes can overshoot between checks.

Only preinstalled CPython 3.12.10 x64, selected Visual Studio/MSVC and Windows SDK
tools are used. Discovery and environment filtering reuse the existing verified
preflight. Exact tool paths/hashes and image identity are recorded; inherited
compiler/linker flags and arbitrary search paths are discarded. No installer,
SDK download, fallback, system mutation, credentials, signing, IPA, cache or
artifact upload is included. Complete bounded evidence is emitted into the
Actions log; work files are ephemeral.

The unchanged `provider-requirements.json` anchors the original LLVM archive
(`ed775bdaea7087c6c1aeac9498352cfcd8610d92dc4fe9eda9aecb15ce712a2c`) and its
70-library inventory. The diagnostic inventories the same exact preinstalled
provider roles, permitting the previously optional `libconcrt` to remain absent.
Any absent required provider or incomplete structural read stops the diagnostic.
All existing unreviewed provider findings are emitted and remain unapproved.

Explicit link inputs are the compiled probe, unchanged selected-VS
`DIA SDK/lib/amd64/diaguids.lib`, and selected Windows SDK `uuid.lib`,
`advapi32.lib`, `kernel32.lib`. Ordinary `/MT` defaults may select the recorded
MSVC and Windows CRT providers. `LIB` is limited to the exact selected versioned
roots; any unrecorded library search/load rejects the diagnostic. DIA and all
other recorded providers are hashed before/after link. The SDK producer's old
VS2022 DIA path is recorded alongside this diagnostic input; no vendor CMake
metadata or system path is rewritten, and this does not approve its later use
in the SDK preflight.

## Required evidence

The source-owned declarations must produce these exact strong undefined symbols,
each with an actual non-debug relocation in the compiled x64 object:

- `?NoRegCoCreate@@YAJPEB_WAEBU_GUID@@1PEAPEAX@Z`
- `CLSID_DiaSource`
- `IID_IDiaDataSource`

Those identities are captured from LLVM 22.1.4 `DIASession.cpp.obj`, SHA-256
`6a36ac648ae330ca3de33af3e0a51621a7b09c31d6ea5ddb7a85e96ec4f7de83`, inside
`LLVMDebugInfoPDB.lib`, SHA-256
`ccfe7b5753307aa62633ab2b0b843f604863bdc7c1cf604bb9a0eab2a0aebad1`.
The source makes a real helper call to preserve all three references, but that
call is never executed. It checks `_MT`, absence of `_DLL` and `_DEBUG` during
compilation. `/MT`, `/WX`, release iterator ABI, disabled RTTI/EH and no `/DEBUG`
match the intended narrow release reference.

Success requires all of the following:

1. Successful compilation with `libcmt` defaults and no contradictory CRT tags
2. Successful `/WX` link with unchanged defaults and no FORCE, NODEFAULTLIB,
   WHOLEARCHIVE, IGNORE, LIBPATH or warning suppression in selected directives
3. Exact DIA archive identity in `/VERBOSE:LIB` searched/loaded records,
   agreeing with actual symbol definitions and `/MAP` ownership for all three
   references; only their exact owning DIA members may be selected
4. Selected static members have no MD/debug CRT defaults/tags; selecting
   `stdafx.obj` therefore fails even if the linker otherwise returns zero
5. Hash-stable provider/source bytes and a resulting x64 PE whose normal/delayed
   imports pass the unchanged SDK preflight's exact system-module audit

Windows import archives repeat DLL member names. The diagnostic retains those
loaded records and validates every candidate's architecture, import/module and
directive shape. It explicitly reports `exact_import_member_selection_proven:
false` for that ambiguity; it never invents an object offset. DIA's exact
member/symbol selection remains mandatory. Unknown trace/map formats fail
closed, and the Windows formatting has not yet been verified by this preparation.

Microsoft documents [verbose library selection](https://learn.microsoft.com/en-us/cpp/build/reference/verbose-print-progress-messages)
and [map-file symbol ownership](https://learn.microsoft.com/en-us/cpp/build/reference/map-generate-mapfile).
The terminal `DIA_LINK_DIAGNOSTIC` receipt reports compile/link outcomes even
when later auditing fails. Only `minimal-dia-mt-link-selection-observed` is a
successful diagnostic status; `provider_closure_approved`, `sdk_abi_jit_verified`,
`runtime_tested`, `jit_executed` and `madeira_abi_or_runtime_verified` stay false.

`DIA_COMPILED_OBJECT_BYTES` preserves the actual source-owned compiled probe
before semantic parsing/CRT gates. It records size, SHA-256, source hash and
base64 bytes, with an explicit 128 KiB object cap. The maximum encoded record
is below 176 KiB, within the existing 256 KiB per-record and 32 MiB aggregate
evidence caps; no original provider object or dependency binary is embedded.
An oversized object rejects explicitly, without truncation. The captured probe
is not executed, and malformed/unsupported bytes remain rejected by the same
semantic gates. This provides a real compiler fixture after the ephemeral job.

`DIA_COMPILED_OBJECT` is then emitted before evaluating the source CRT gate, with
the object identity, parsed defaults/tags, decoded directive text and exact
section hashes, and the
three symbol/relocation records. Its `crt_gate_status: not-yet-evaluated` is
explicit: evidence collection is not acceptance. A source-default rejection
therefore leaves its deciding evidence in the log while still stopping before
linking. The decoded directive strings represent NUL bytes as spaces; exact
original bytes remain in `DIA_COMPILED_OBJECT_BYTES`. This instrumentation does
not add any accepted source default.

## Neutral COFF collection correction

The previous inventory stopped at `libcmt`/`oldnames` members with machine 0,
one `.debug$S` section and weak aliases. Microsoft defines
[IMAGE_FILE_MACHINE_UNKNOWN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)
as architecture-neutral. The shared reader now recognizes only the bounded
observed debug/alias form, retains machine 0, and continues scanning subsequent
members. Code, ordinary data, imports, directives, relocations, unknown metadata
tags and non-alias weak searches remain rejected. This is a collection fix,
not an architecture or CRT waiver.

`tests/host/fixtures/llvm-providers/README.md` explains the captured Windows
header/native-reader evidence and the explicitly reconstructed neutral-object
witnesses. Full original CRT object bytes were not retained. Separately,
`tests/host/fixtures/llvm-dia-link/` contains an actual upstream LLVM compiler
object, captured DIA member evidence, hashes and licensing. Host checks use
synthetic trace/map contracts and mocked orchestration; they never claim a
Windows compilation or link occurred.

Run the three controls in the workflow locally with Python. A successful
diagnostic still leaves complete provider/directive approval, the actual LLVM
C++/two-seed MCJIT probe, Mesa 26.2.4 llvmpipe compilation and modern graphics
acceptance undone. Dynamic DIA COM/LoadLibrary behavior, Wine/FEX, iOS JIT,
UIKit presentation and Blender GUI compatibility remain unproved.
