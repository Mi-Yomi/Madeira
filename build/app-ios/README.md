# Unsigned Debug app link gate

The default invocation **does not create an IPA**. It links and validates the
unsigned app, then writes a diagnostic receipt. The automatic app job is paused;
these commands document the driver, not permission to restart a build or package.

Run only after `.github/ci/native-bootstrap.sh` and the complete graphics
bootstrap in the **same fresh Xcode 27 ARM64 runner checkout**, native first.
Keep `FEX/build-ios` and its generated headers; restoring the archive bundle is
not enough. No app/device success is implied by the native or graphics gates.

```sh
python3 build/app-ios/build_unsigned.py \
  --native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json" \
  --products "$RUNNER_TEMP/madeira-app-products" \
  --intermediates "$RUNNER_TEMP/madeira-app-intermediates" \
  --stage "$RUNNER_TEMP/madeira-app-diagnostics"
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
resources and notices. By default, `--stage` contains only `provenance.json`:
its packaging status is `not_requested`, and there is no `Payload` directory,
IPA file or `ditto` invocation. A compact log summary describes only this link
and bundle-validation scope.

## Optional packaging requires explicit authorization and opt-in

Packaging remains disabled unless `--package` is explicitly supplied to the
same command. Do not add that flag while the user's stop on IPA creation is in
effect. A technical flag does not replace authorization to resume packaging.

When separately authorized, `--package` uses `ditto` to copy
`Payload/Madeira.app` and create `Madeira-unsigned.ipa` under the fresh `--stage`
directory. It revalidates the staged app and every ZIP file, executable mode and
empty runtime placeholder, then records the IPA hash and packaging status
`passed` in `provenance.json`. A packaging failure does not write a passed
receipt. The IPA remains ephemeral on the runner; persistent storage or
delivery requires separate authorization.

Neither mode performs signing, Xcode archive/export, provisioning requests,
caching, uploads or installation. The converter may retain its pre-existing
vendor signature; “unsigned” means this gate performs no signing of its contents.

Existing guest PE binaries are **tracked inputs reused**. Twelve reviewed
source-built Wine desktop DLLs (six for each 64-bit farm) are now integrated as
tracked additions. The gate verifies the sealed 55-file build evidence, paired
DLL hashes and architecture, exact Wine notices and reviewed bundle notice
merge. The captured rebuild inputs remain authoritative; later published tooling
can include hardening absent from the actual build. No arbitrary untracked
overlay route is accepted. See `docs/DESKTOP_OVERLAY_INTEGRATION.md`.
Their exact hashes are in the receipt. Full-farm dependency gaps remain.
The 32-bit Wine runtime and x86_64 VC runtime are
missing. A passed default gate establishes only unsigned app linking and bundle
validation. An explicitly requested package gate also establishes local package
integrity. Neither establishes device launch, JIT, rendering, 1C or Blender
compatibility.

Portable regression checks (synthetic fixtures; no Xcode or external downloads):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/host/check-app-bootstrap.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/host/check-desktop-integration.py
```
