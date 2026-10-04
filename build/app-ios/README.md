# Unsigned Debug app gate

Run this only after `.github/ci/native-bootstrap.sh` and the complete graphics
bootstrap in the **same fresh Xcode 27 ARM64 runner checkout**, native first.
Keep `FEX/build-ios` and its generated headers; restoring the archive bundle is
not enough. No app/device success is implied by the native or graphics gates.

```sh
python3 build/app-ios/build_unsigned.py \
  --native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json" \
  --products "$RUNNER_TEMP/madeira-app-products" \
  --intermediates "$RUNNER_TEMP/madeira-app-intermediates" \
  --stage "$RUNNER_TEMP/madeira-app-stage"
```

The three output paths must not exist, including empty directories or dangling
symlinks. The driver rechecks all 20 native archives, all 34 LLVM archives, DXMT
archives, exact source/submodule metadata and build/hash receipts. It requires
the FEX generated include directory, creates an empty VC-runtime folder and
refreshes the two generated licence copies. It then builds the `Madeira` target
in Debug for device ARM64 with both signing flags disabled and blank identity,
team and provisioning settings. The helper dependency and deployment targets
remain those in the project. There is no shared-scheme requirement.

After a successful link it validates the app, helper and StikJIT Mach-O platform
and architecture, unchanged tracked converter bytes, processed bundle metadata,
resources and notices. It uses `ditto` to copy `Payload/Madeira.app` and create
`Madeira-unsigned.ipa` locally, verifies every ZIP file against that validated
app, and writes `provenance.json` plus a compact hash/scope line. The IPA remains ephemeral on the runner; persistent storage or delivery needs
separate authorization. No signing,
archive/export, provisioning request, cache, upload or installation is performed.
The converter may retain its pre-existing vendor signature; “unsigned” means
this gate performs no signing of the package or its contents.

Guest PE binaries are **tracked inputs reused, not source-rebuilt**. Their exact
hashes are in the receipt. The 32-bit Wine runtime and x86_64 VC runtime are
missing. A passed gate establishes only unsigned app linking and local package
integrity, never device launch, JIT, rendering, 1C or Blender compatibility.

Portable regression checks (no Xcode or external downloads):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/host/check-app-bootstrap.py
```
