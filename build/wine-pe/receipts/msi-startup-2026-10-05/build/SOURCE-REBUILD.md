# MSI startup-provider rebuild

Use a new copy of the compact sealed receipt. Do not run the build inside the
published receipt or reuse old build directories. This recipe only builds three
inactive MSI DLLs and writes new local evidence; it does not install, activate,
execute, sign or publish anything.

## Inputs

- Public Wine source archive:
  `https://codeload.github.com/willfaust/wine/tar.gz/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`
  stored as `wine-4f5b19718f4de88ecc5cb0dc08b119497a67ba8f.tar.gz`.
  `evidence/source-inputs.json` binds the archive digest, every original Git
  blob/mode, every final source SHA-256, and all three applied patches
- Exact official Debian Bison, Flex and M4 archive URLs/digests in
  `evidence/prerequisite-downloads.json`. Their complete extracted identities
  are in `evidence/restored-prerequisites.json`
- Exact official LLVM-MinGW 20260421 archive, 82,139,820 bytes, SHA-256
  `f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`,
  plus its matching installation. Both live under sibling
  `madeira-desktop-overlay-build/toolchains/`. The builder verifies the archive
  and every extracted entry before executing any cross-toolchain program
- Copied tools, notices, `build/madeira_cfg.h`, original provider bytes and
  source-review evidence in this sealed receipt
- The active AArch64/ARM64EC farms under sibling `madeira-graphics-bootstrap`.
  The exact snapshots used for this build are bound by
  `evidence/current-resolver-snapshot.json`. A later changed farm requires fresh
  validation; it is not the historical resolver evidence
- Host tools and versions recorded in `evidence/rebuild-host.json`. Host system
  headers, libraries and the OS are not a hermetic image

The original restored archives are currently retained in sibling
`madeira-msi-rebuild-inputs-20261005/downloads/`; no network is used by the
following preparation/build commands. If restored elsewhere, fetch only the
recorded public official URLs and verify every recorded digest before use.

## Prepare and build

Start with a copy of the files listed in `SHA256SUMS`, preserving their relative
paths. Do not copy working directories `wine/`, `build-aarch64/`,
`build-arm64ec/`, `build-i386/`, `resolver-baseline/`, `prerequisites/` or
`prerequisite-bin/`. Preserve all existing evidence in an archival copy before
running; a fresh build writes replacement local evidence.

Run from the new receipt copy:

```sh
sha256sum -c SHA256SUMS
PYTHONDONTWRITEBYTECODE=1 python3 prepare_startup.py --downloads /path/to/verified/downloads
PYTHONDONTWRITEBYTECODE=1 python3 build_startup.py > build-run.log 2>&1
```

`prepare_startup.py` checks the exact archive bytes, every source Git blob and
mode, applies the retained three patches with `git apply --check` first, then
checks every final source byte. It extracts the exact host prerequisite packages
without running maintainer scripts, checks their full file/link sets and creates
a relocated Bison data wrapper. This path was exercised independently in a fresh
directory; see `evidence/prepare-recipe-validation.json`.

The builder configures fresh AArch64, ARM64EC and i386 directories sequentially,
uses the original unprefixed Clang/MSVC target setup, adds only `-v -save-temps`
to the generated MSI link command, builds each `dlls/msi/<arch>-windows/msi.dll`
with `make -j2`, copies the output and strips debug information. The ARM64EC
stdole2 architecture alias is preserved. A 30-minute build limit, 2 GiB local
workspace cap, 8 GiB free-disk floor and 64 MiB per-log cap are enforced.

Every resulting DLL must preserve all 296 export-name/ordinal/forwarder entries.
Exactly four normal `kernel32.dll` imports may be added: `CancelIoEx`,
`CreateEventW`, `GetOverlappedResult`, `WaitForMultipleObjects`. No import may be
removed or other import added. `SetLastError` is an inline TEB update under
Wine's `__WINESRC__` headers and adds no import. Active-architecture imports are
resolved against copied current farms. The missing historical i386 peer farm
prevents a fresh full i386 closure check; raw i386 PE/API checks still run.

Each source/object/link command, explicit link input, retained temporary input,
full build-tree manifest, toolchain file and current host-tool executable is
recorded. No prior build object or library was reused. Original provider copies
and source/toolchain/resolver snapshots remain separate.

## Reproducibility and scope

Fresh baseline MSI builds with the same recorded source/toolchain/flags
preserved API contracts but differed from historical bytes. Absolute source
paths remain embedded in stripped images, and PE timestamps differ. The baseline
comparison is retained in `evidence/baseline-reproduction-analysis.json`.
Byte-for-byte reproducibility across paths/times/hosts is not established.

The 33 source-review scenarios use host API doubles. Fresh build/static checks
do not prove Wine/Windows/iOS runtime behavior, IPC scheduling, COM, custom-action
execution, app compatibility or distribution/relinking compliance. i386 is
evidence-only and must remain inactive. No full app, IPA or signing step occurs.
