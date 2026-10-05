# Patched MSI provider candidate, 2026-10-05

## Result

A new, inactive candidate contains the seven requested providers for aarch64 and
ARM64EC, plus a separately patched i386 msi.dll. All 15 fresh PE outputs linked,
passed architecture checks, and resolved their normal/delay import symbols and
required export-forwarder chains against the correct architecture's recorded
farm and peers. Runtime execution, app integration, publication and IPA creation
were not performed.

| Static check | aarch64 | ARM64EC | i386 |
|---|---:|---:|---:|
| Fresh output files | 7 | 7 | 1 |
| Checked imported symbols | 664 | 666 | 328 |
| Enumerated exports | 387 | 387 | 296 |
| Missing new symbols or required forwarders | 0 | 0 | 0 |
| Delay-import descriptors in new outputs | 0 | 0 | 0 |

The 64-bit sets contain msi.dll, msiexec.exe, cabinet.dll, sxs.dll, mspatcha.dll,
odbccp32.dll and regsvr32.exe. The i386 stage contains **only msi.dll**; it requires
the separate existing 71-file peer candidate. It is not a standalone i386 farm.

## Exact source change

Base Wine revision: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`

Only `dlls/msi/custom.c` differs from that pinned tree. The unchanged independently
reviewed combined patch is retained in `patches/msi-combined.patch`:

- Patch SHA-256: `3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8`
- Original custom.c: `201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25`
- Patched custom.c: `31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5`

The patch makes DLL-load, missing-entrypoint and caught-exception failures report
failure; checks custom-action server startup, buffer capacity and resource
ownership; accepts an already-connected named pipe; and stops client-thread
creation after startup failure. The reviewed Continue/Async behavior is retained.
All three architectures compile and link this exact patched source. Objects and
independent machine-header dumps are in `evidence/compiled-custom/`.

The combined source review's two host harnesses and complete 64-bit translation-unit
checks passed before this build. Their result and input identities are copied in
`review-inputs/`; this build did not repeat or relabel those checks as runtime
execution. The actual complete i386 translation unit compiled and linked here.

## Audit and preservation

Every output's export-name/ordinal/forwarder contract and normal/delay import
contract matches its corresponding unpatched baseline, including the i386 MSI
comparison against the 71-file peer. Only RVAs, linked bytes and metadata may
change; this contract check does not imply binary identity. See
`evidence/all-architecture-contract-comparison.json` for both sets of hashes.

The resolver uses copied snapshots of the primary aarch64/ARM64EC farms, with the
new seven-provider candidates overlaid. The i386 resolver uses a copied snapshot
of `madeira-installer-provider-audit-20261005/extension-modern-i386/experimental-i386-candidate`,
with just its msi.dll replaced in memory by the fresh candidate. The original
71-file directory is unchanged and its SHA256SUMS still verifies. The snapshot
contains all 71 files. The generic PE inventory counts 70 because stdole2.tlb is
not in its executable-file suffix allowlist; that unchanged typelib is retained
and hashed in the complete snapshot inventory.

The primary farms retain all original bytes. The prior sealed 64-bit MSI candidate
and pristine Wine checkout still verify; neither was overwritten. The independently
reviewed patch inputs are unchanged. Full-file preservation hashes and old seal
verification logs are retained in `evidence/`.

The combined 64-bit inventories still have 13/10 pre-existing DLL-level dependency
edges. The i386 inventory still has the legacy kernel32-to-krnl386.exe16 forwarder
edge; the peer's earlier complete export audit records 141 such ordinal forwarders.
No legacy export was removed and no fake provider was added. The new i386 MSI's
own 328 imported symbols all resolve. This is not full all-export farm closure.

The existing static parser's 21 host regression tests and the EXE name/ordinal/
delay-import/failure fixture passed again. LLVM independently agreed with each
new PE's import/export counts and load-config architecture metadata. All source
files, recipes, tools, commands, host prerequisite data and notices are bound by
receipts. Bison emitted the same existing sql.y and wrc/parser.y conflict warnings;
there were no build failures.

## Budgets and remaining limits

Each attempt used two jobs, a 45-minute limit, a 64 MiB log limit and a 2 GiB
build-tree limit. An 8 GiB free-disk floor was checked before commands and at least
every five seconds while they ran. Configure plus make took approximately 36, 38
and 31 seconds for aarch64, ARM64EC and i386. Toolchains/prerequisites were reused
read-only. Only the necessary source copy, resolver snapshots and build outputs
were created. No download or paid resource was used.

This remains an inactive source-built candidate. Real DLL loading, MSI custom
host IPC, cross-bitness Unix/native bindings, guest-window behavior, child exit,
SEH, transactions and device execution remain unverified. The source-owned canary
must still prove negative-action rejection and two actual property round trips.
A child that starts but never connects can still hang synchronous ConnectNamedPipe;
this patch does not implement an overlapped/process-exit wait. Cached dead-server
recovery and asynchronous action exit-status handling remain unchanged.

WinNT ADS provider support, dynamic CLR/COM/SxS behavior, proprietary 1C behavior,
licensing, and Blender execution are not established. Source hashes, contract
checks and compile/link success are not runtime or redistribution-compliance
claims. No source integration/tooling patch is proposed for the primary repository;
`build_msi_overlay.py` is an isolated reproducible recipe for review.

## Output hashes

| Architecture | File | Bytes | SHA-256 |
|---|---|---:|---|
| aarch64 | `cabinet.dll` | 589824 | `07ac3b1407d192019d5076baa11ab7e9dfbfba8a06641d843caa0cee86ea1ee0` |
| aarch64 | `msi.dll` | 1572864 | `12bbe1e84a6ef12b6775f1e081e69e404736d9be5b118fa322d989d9f1b93221` |
| aarch64 | `msiexec.exe` | 524288 | `2d4e5238d0be4d683e3490eea81ea3e09262392fc5cb95d082fd68ea545adfed` |
| aarch64 | `mspatcha.dll` | 524288 | `a60218a5f34e1635c66685074c67f4b3bb1d7c32f352a4c0ba185136f09325dc` |
| aarch64 | `odbccp32.dll` | 458752 | `4a2c553140b3db43f1670080b81460549bc808650a60c33157e57db4e0a9d5da` |
| aarch64 | `regsvr32.exe` | 524288 | `0a9bfdd6bf351971b05e295a269546df2eb5182a5d5ffc9a0942b33911cdcfdf` |
| aarch64 | `sxs.dll` | 458752 | `2d298097cc8d40f47610bf906791e752479b7ac72edfd11968fb58c579a270ee` |
| arm64ec | `cabinet.dll` | 720896 | `35d713f638431348d0720327157571d6bc037cdd5cc6ac26332fbf4f74523784` |
| arm64ec | `msi.dll` | 1769472 | `30fca59166929f1300d7708d45d56b401e680d0318b0ce7d7ff754987177f30d` |
| arm64ec | `msiexec.exe` | 655360 | `dd46bf408250057474b4376880f3c81073477240587d0c551f54c37c99725549` |
| arm64ec | `mspatcha.dll` | 655360 | `922a4e61fcdf2807e0eee4e0951be28a923cd9d471c02e9320958cfc8f23029f` |
| arm64ec | `odbccp32.dll` | 589824 | `6ce8525c446e7bf6a43ddf317a2beaff690f13e1b0dd26178d0408675a6c74a6` |
| arm64ec | `regsvr32.exe` | 655360 | `1501d3bc5c59dabb3e15d4fa32caae10f14db88f23b045d3f055481f414cbbde` |
| arm64ec | `sxs.dll` | 589824 | `20f055955274cb2a5f8520eccdbaa7980cafea8000916bb09bcd73242da2fff2` |
| i386 | `msi.dll` | 1208320 | `fe345c3ce9b2414d014c2eb98a8b82c53221d7eafdf2a57c7b24c06f713a7746` |
