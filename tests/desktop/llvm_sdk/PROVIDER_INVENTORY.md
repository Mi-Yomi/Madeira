# Preinstalled Windows provider inventory

This is a separate read-only prerequisite for reviewing the official LLVM
22.1.4 MSVC SDK. It does not download the SDK, compile/link anything, run JIT
code, load a provider library or change system files/settings. It is not an ABI,
SDK, Mesa, Madeira, Wine/FEX, ARM64EC, iOS or performance pass.

The source-owned `provider-requirements.json` records all 70 selected library
identities, hashes, defaults, mismatch tags and exported edges established by a
full static inspection of the pinned official archive. This archive has a DIA
dependency outside its payload and implicit ATL/OS defaults. Exact selection
comes from the generated llvm-config component table and the complete exported
graph, not generic CMake aliases: this SDK's `engine` maps to Interpreter and
`native` includes X86TargetMCA/MCA. PDB is required through BitWriter →
ProfileData → Symbolize → DebugInfoPDB. Components are not pruned.

`provider-inventory-request.json` binds the requirement file's SHA-256 and
explicitly prohibits downloads, compilation, linking, JIT, installation, system
mutation, cache/artifact upload, signing and IPA work. Only pushing that request
file to the public Mi-Yomi/Madeira compatibility/desktop-apps branch triggers
`.github/workflows/llvm-provider-inventory.yml`. Ordinary source edits do not
trigger this job. Publishing a new request is a distinct experiment request.

The standard windows-2025 job is capped at ten minutes, its inventory step at
eight, and its internal watchdog at seven. It reuses the existing trusted Visual
Studio/tool discovery and its pinned preinstalled Python requirement. Discovery
executes vswhere, VsDevCmd and CMake --version only. Compiler/linker paths/hashes
are recorded but those tools are not invoked. Discovery's process environment
is temporary; no system environment/path or SDK metadata is edited.

Provider roots are exact subdirectories of the selected VS/MSVC and Windows SDK
version: MSVC lib/x64, MSVC atlmfc/lib/x64, Windows SDK Lib/version/um/x64 and
ucrt/x64, and VS DIA SDK/lib/amd64. There is no filesystem search, package-manager
fallback or generic basename rewrite. The exact SDK producer DIA edge and the
candidate installed provider are recorded together without modifying or linking
the vendor CMake metadata. The optional installed static concurrency library
libconcrt is inventoried in the same pass; it becomes required only if an actual
directive names it. Provider identity is not dependency approval.

The scanner records every provider member's x64 COFF/bigobj or short-import
identity, raw linker directives, CRT/mismatch tags, import module evidence and
archive offset. It hashes each provider before and after reading. GUID/data
providers have a distinct role from static code and OS import providers. Known
provider edges must resolve to an inventoried file. Unknown default libraries,
wrong architectures/types, alternate CRT/debug tags, and non-default linker
directives remain explicit rejected/unreviewed findings. The inventory does not
silently approve ALTERNATENAME, INCLUDE, MERGE, EXPORT, LIBPATH, NODEFAULTLIB or
FORCE. Sources explaining the required roles are included in the requirement
file; full LLVM/third-party notices remain unchanged in the original SDK.

The optional DIA runtime record reads msdia140.dll's size/hash/x64 PE headers
only. It does not load, register, copy, approve, or audit that DLL's imports.
DIA can be activated dynamically by COM/NoRegCoCreate; inventorying link inputs
or a later executable's import table does not prove all DIA behavior.

Bounds: 256 MiB per provider, 1 GiB aggregate provider bytes, 100,000 archive
members per provider, bounded COFF tables/directive/string sections, 256 KiB per
emitted JSON record, 32 MiB aggregate evidence, 64 MiB work root, 3 GiB free-space
floor, and the existing 16-process/10-GiB Windows job containment. No provider
code is loaded by the scanner. Hash/data reads stay below the selected roots.

`PROVIDER_OBJECT`, `PROVIDER_LIBRARY`, `PROVIDER_FINDING`, `PROVIDER_DIA_MAPPING`
and `PROVIDER_DIA_RUNTIME` contain the evidence in the Actions log. A final
`PROVIDER_INVENTORY` receipt always sets `provider_closure_approved` and
`sdk_abi_jit_verified` false. Rejected/unreviewed findings produce exit code 2;
an error or resource stop produces `incomplete-rejected`, never a green SDK
claim. Raw evidence is also retained in the ephemeral work directory; there is
no artifact/cache upload. A missing final receipt means incomplete inventory.

Run `python tests/host/check-llvm-provider-inventory.py` for inert parser, path,
requirement and failure tests. These tests do not establish real installed
provider availability, runtime compatibility or a successful Windows link.

## Final read-only member-evidence pass (request 3)

The second run collected 18 providers but stopped before the first libcmt and
oldnames object. The error did not contain the actual failing header. It also
found mixed contents inside diaguids.lib: an MD-tagged stdafx.obj, executable
guidstr.obj, and data-only dia2_i.obj. This archive-wide union does not prove an
actual mixed-CRT link: normal archive member selection matters.

The new diagnostic pass preserves every existing rejection and adds no provider
or linker-option approval. It reads all DIA members and only the first object
that blocked each CRT archive. The latter is explicitly a prefix diagnosis,
not a completed libcmt/oldnames audit. It prints raw header bytes, member/archive
hashes and offsets before interpreting anything. Machine-zero, sectionless
metadata can be inspected for weak aliases, but stays architecture-neutral and
unreviewed; it is never relabeled x64 or accepted by the existing provider gate.

DIA evidence includes section ownership, defined/undefined/common/absolute
symbols, storage classes, raw auxiliary records, weak-alias targets, COMDAT
selection/association, relocations and modern CodeView LF_PRECOMP/LF_ENDPRECOMP
records. Unknown formats/signatures remain explicit/incomplete. The required
consumer references were independently established in the pinned LLVM
DIASession.cpp.obj: NoRegCoCreate, CLSID_DiaSource and IID_IDiaDataSource. A
GUID-data-only binding is not justified while the helper reference is retained.

The selected, hash-recorded preinstalled dumpbin is invoked only as a reader:
/HEADERS, /SYMBOLS, /DIRECTIVES and /RELOCATIONS, plus /LINKERMEMBER for DIA. No
compiler/linker runs. For CRT header diagnosis, the first member is copied
byte-for-byte into the fresh work root and inspected; the original provider is
never modified, and the copy is never linked or executed. This is diagnostic
extraction, not a substitute provider or a new binding policy.

Bounds remain the same for the workflow and aggregate evidence. Additional
limits are 8 MiB per diagnostic object, 64 DIA members, 100,000 symbols and
relocations per object, bounded symbol/string/auxiliary references, 45 seconds
per native-reader command and the existing 8 MiB command-log cap. Unsupported
extended relocations or malformed evidence stop that interpretation explicitly.
All detailed records keep provider_approved and actual_link_selection_proven
false. A bounded raw header/native-reader result may explain a rejection; it
cannot turn that rejection into an ABI/JIT result.

This is the final static-format pass for the current experiment window. Review
whether the helper/GUID owners reach stdafx through external/PCH symbols,
/INCLUDE roots, aliases or COMDAT associations. If evidence remains insufficient,
stop static retries and either reject this prebuilt route for the current window
or obtain separate authorization for a tiny compile/link-only probe. Such a
probe would force exactly the three verified symbols through source-owned
references, use /MT and /WX with ordinary defaults and the unchanged DIA archive,
and record /VERBOSE:LIB member selection and a map. It would not execute, download
the LLVM SDK, establish the complete 70-library closure, or authorize runtime.
No /WHOLEARCHIVE, /NODEFAULTLIB, /FORCE, fake GUIDs, stripped objects or altered
vendor semantics are part of this proposal.

Microsoft references:

- [Normal archive selection](https://learn.microsoft.com/en-us/cpp/build/reference/wholearchive-include-all-library-object-files)
- [PCH reference injection](https://learn.microsoft.com/en-us/cpp/build/reference/yl-inject-pch-reference-for-debug-library)
- [COFF format and neutral machine value](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Archive member index](https://learn.microsoft.com/en-us/cpp/build/reference/linkermember)
- [Symbol ownership](https://learn.microsoft.com/en-us/cpp/build/reference/symbols)
- [Link-member tracing](https://learn.microsoft.com/en-us/cpp/build/reference/verbose-print-progress-messages)
