# Reproduce the separate patched MSI candidate

Use the unchanged Wine source pin
`4f5b19718f4de88ecc5cb0dc08b119497a67ba8f` from
https://github.com/willfaust/wine.git, plus the retained exact combined patch.
No change to the upstream pin or additional Wine file is permitted by this recipe.

## Prepare a fresh layout

Verify this package's `SHA256SUMS`. Under a common parent directory create a fresh
`madeira-msi-patched-provider-build-20261005/` and copy these sealed inputs:
`build_msi_overlay.py`, `check_exe_audit.py`, `tools/`, `reference-inputs/`,
`review-inputs/`, `patches/`, and `build/madeira_cfg.h`. Create empty `evidence/`.
Do not reuse old candidate, build or generated evidence directories.

Place a clean checkout of the exact pinned Wine tree at `wine/`, adjacent to
`build/`. Before applying the patch, verify that `git status --porcelain` is empty
and custom.c hashes to
`201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25`.

From `wine/`, run:

```
git apply --check --whitespace=error-all ../patches/msi-combined.patch
git apply --whitespace=error-all ../patches/msi-combined.patch
```

The patch must hash to
`3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8`,
and resulting custom.c to
`31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5`.
The builder rechecks both, the pinned original blob, every actual Wine source
file, file modes, and absence of any other tracked/untracked modification.
The source receipt distinguishes the pinned blob from the patched blob.

Supply recorded farm bytes at `baseline/app/Madeira/{aarch64,arm64ec,i386}-windows`.
The aarch64/ARM64EC farm originals must also exist at sibling
`madeira-graphics-bootstrap/app/Madeira/{aarch64,arm64ec}-windows`.
The original 71-file i386 peer must exist at sibling
`madeira-installer-provider-audit-20261005/extension-modern-i386/experimental-i386-candidate`.
These exact bytes are identified by `evidence/all-original-farm-files.json`;
use those hashes rather than a stale primary Git HEAD as their identity.
The i386 farm is a resolver input only and remains untouched.

Recreate or reuse sibling `madeira-desktop-overlay-build/` with the recorded
read-only toolchain and host prerequisites. Use its `downloads/` archive and
`toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin` installation.
The official archive is 82139820 bytes with SHA-256
`f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`:
https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz
The builder verifies every extracted file/link before invoking it. No download is
automatic. Host tools and relocated bison/flex/m4 data are recorded separately;
the wrapper must point to the matching data. Relocation that changes wrapper
bytes is a new host input and should be recorded as such.

## Compile, audit and retain evidence

From the new MSI directory:

```
PYTHONDONTWRITEBYTECODE=1 python3 build_msi_overlay.py --build > build-run.log 2>&1
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tools python3 reference-inputs/tests/host/check-desktop-symbol-audit.py
PYTHONDONTWRITEBYTECODE=1 python3 check_exe_audit.py
```

The recipe configures three fresh out-of-tree build directories, explicitly uses
unprefixed verified clang so Wine selects its Windows/MSVC targets, and builds
exact PE paths with make -j2. ARM64EC receives the required stdole2 alias.
The i386 make target is only `dlls/msi/i386-windows/msi.dll`. No guest PE executes.
The exact flags, compiler environment, configure/make/strip commands and timings
are in `evidence/host-tools.json` and `evidence/commands.json`.

All three audits must pass before the final status is written. Retain logs,
per-architecture symbol inventories and LLVM dumps, source/tool/patch identities,
original preservation evidence and unchanged legal notices. Compare output
contracts with the recorded baseline; no replacement of baseline artifacts is
part of this recipe. Reconstruct the final integrity index over deliverable files
and verify it; the retained source/build/snapshot directories are evidence inputs,
not part of the compact seal. Copies of their relevant bytes are independently
bound by source and farm manifests.

Keep complete corresponding pinned source, this explicit patch and rebuild
instructions available for any later redistribution. Binary identity across
paths/hosts/timestamps and license/relinking compliance are not established here.
Activation, runtime canaries, primary-source integration, publication and IPA
creation are separate work and are not commands in this recipe.
