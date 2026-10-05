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
