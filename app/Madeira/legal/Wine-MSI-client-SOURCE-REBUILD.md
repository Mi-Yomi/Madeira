# Offline MSI-only rebuild

Use a new empty sibling directory. Never run this recipe in the old sealed
provider directory or reuse an existing build directory. No network access or
download is part of this recipe.

## Required retained inputs

1. `madeira-msi-patched-provider-build-20261005/`, with its complete Wine source
   tree at pin `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`, old combined patch,
   candidate peers, original-farm snapshots, tools, configuration and notices
2. `madeira-msi-client-fix-20261005/`, the reviewed incremental patch/source/test
   package. Verify its `SHA256SUMS` before using it
3. `madeira-desktop-overlay-build/`, containing the already available official
   LLVM-MinGW 20260421 installation/archive and recorded host prerequisites.
   Archive bytes: 82139820; SHA-256:
   `f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`

All exact input identities are bound by this package's source, toolchain,
host-tool, old-workspace, source-review and resolver receipts. Recreate equivalent
recorded bytes for a different host/layout; do not use an archive digest alone
as proof of the extracted installation. This is a reproducible recipe, not a
claim that another path/host/time produces identical DLL bytes.

## Prepare and build

From a fresh sibling directory, copy only this package's `prepare_inputs.py`,
`build_msi_client.py`, `build_msi_overlay.py` and `check_exe_audit.py`. The last two
files are unmodified retained helper code from the previous build. Then run:

```
PYTHONDONTWRITEBYTECODE=1 python3 prepare_inputs.py
PYTHONDONTWRITEBYTECODE=1 python3 build_msi_client.py > build-run.log 2>&1
```

Preparation checks at least 8 GiB plus an 800 MiB reserve before choosing
independent byte copies. It verifies all old file/link identities against the
source review's snapshot, copies Wine and the exact needed inputs without
hardlinks, and applies only the incremental client patch with
`git apply --check --whitespace=error-all` followed by `git apply`. The new source
must hash to `9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50`.

The inherited recipe helpers verify all Wine source blobs against the pinned
tree except the explicitly reviewed custom.c, and hash all actual copied bytes.
The new wrapper records both patch identities. The historical
`main_published_revision` field inherited from the old source receipt is context
for that prior recipe; it is not a claim about current primary HEAD or publication
of these replacements.

The wrapper configures fresh AArch64, ARM64EC and i386 directories. It keeps the
recorded unprefixed Clang override so Wine selects the Windows/MSVC target ABI;
ARM64EC retains the stdole2 architecture alias. The sole PE target for each is
`dlls/msi/<arch>-windows/msi.dll`; required host tools, import libraries and source
objects are built as prerequisites. No other provider target is requested.

The final generated MSI link command receives `-v -save-temps`. Its emitted
commands, temporary spec objects, fresh custom.o and every full build file are
hashed. The recipe independently verifies object machine headers, copies only
MSI to the candidate, and strips debug info using the verified target tool.

Static auditing overlays the fresh MSI on copied old peer providers and resolves
its imports against the unchanged original farm snapshot. It compares the whole
MSI architecture/export-name/ordinal/forwarder and normal/delay import contract
against the preserved original and captures independent LLVM PE/load-config
evidence. A changed contract or unresolved symbol aborts the success result.

## Host verification

Use fresh output folders when repeating these checks:

```
PYTHONDONTWRITEBYTECODE=1 python3 review-inputs/client-fix/tests/run_portable.py --source wine/dlls/msi/custom.c --output /tmp/msi-client-normal-new
PYTHONDONTWRITEBYTECODE=1 python3 review-inputs/client-fix/tests/run_portable.py --source wine/dlls/msi/custom.c --sanitize --output /tmp/msi-client-sanitized-new
PYTHONDONTWRITEBYTECODE=1 python3 review-inputs/client-fix/tests/run_portable.py --source review-inputs/client-fix/baseline/custom.c --output /tmp/msi-client-baseline-new
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tools python3 reference-inputs/tests/host/check-desktop-symbol-audit.py
PYTHONDONTWRITEBYTECODE=1 python3 check_exe_audit.py
```

The baseline runner intentionally exits 1 with 46/102 failures. The candidate
and sanitizer runs must pass 102/102. The host sanitizer uses the already
recorded test setup and disables LeakSanitizer; control-flow/resource ownership
is assessed by explicit counters. Do not label these tests as guest execution.

For the delivered package, run `sha256sum -c SHA256SUMS` from its root. The seal
excludes large working directories, whose source/build manifests retain their
individual identities. `verify_package.py` can recheck these working receipts
read-only and all preserved original inputs without rewriting historical files.

Activation, current integration manifest changes, guest runtime testing,
publication, app builds and signing are deliberately outside this recipe.
