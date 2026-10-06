# iOS app link diagnostic (no IPA)

This is a separate bounded compile/link diagnostic. It does not resume the
paused `unsigned-app` job and cannot opt in to IPA creation. Apply it only after
the reviewed twelve-DLL desktop integration and its tests pass.

The new workflow is `.github/workflows/app-link-diagnostic.yml`. Pushes trigger
it only when that file or `build/app-ios/link-diagnostic-request.json` changes
on `compatibility/desktop-apps`; ordinary app/document/test pushes do not. Its
manual trigger has no configurable inputs. Both jobs require the public
`Mi-Yomi/Madeira` fork and that branch. A request-file edit is a technical CI
trigger, not independent authorization to change scope or create a package.

The portable job verifies the sealed twelve-DLL integration and all relevant
failure gates. The single standard `xcode-27` job repeats integration checks
before builds, uses at most two compile jobs, and has a **45-minute total cap**.
Individual step limits do not extend that total. It reuses the existing native
bootstrap, including the already approved official Metal component setup, then
the pinned LLVM host/iOS and full DXMT gates in the same fresh checkout. There
is no cache, artifact upload, paid/larger runner, signing, installation, export,
new agreement acceptance or source-pin change.

## Fixed link-only entry point

After those prerequisites, on that same runner:

```sh
python3 build/app-ios/link_diagnostic.py build \
  --native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json" \
  --products "$RUNNER_TEMP/madeira-link-products" \
  --intermediates "$RUNNER_TEMP/madeira-link-intermediates" \
  --diagnostics "$RUNNER_TEMP/madeira-link-diagnostics"
```

All output roots must be distinct, non-nested, fresh directories outside the
source checkout. `--package`, abbreviated flags, `--stage`, Xcode flags and
extra positional arguments are rejected; environment variables cannot opt in.
The wrapper calls the existing app library directly with `package=False`, not
its package-capable CLI. During that call its command dispatcher permits only
the exact verified Dock producer, license staging, then the exact unsigned Debug Xcode build command. All
other commands, including `ditto`, ZIP tools, signing and archive/export, fail
before execution. Its ZIP-validation entry point and Python ZIP API are also disabled.

The wrapper runs the mandatory same-job Dock producer first. Its fresh outputs
stay outside the sealed source farm in `build/madeira-dock/generated/`; the app
gate exclusively copies and checks the verified x86-64 host and notices after
linking. The diagnostic verifier independently rebinds the Dock receipt and all
final resource hashes. See `README.md` for the source/toolchain contract.

A successful diagnostic directory contains exactly `provenance.json` from the
existing app gate and `link-diagnostic.json` from the wrapper. The second receipt
binds the exact command sequence, request hash and app receipt hash, and reports
`packaging: disabled`, `ipa_created: false` and `runtime_tested: false`.
Independent verification requires the current source commit, twelve reviewed
DLL hashes/seal, unchanged bundle-file hashes and no package fields.

The `scan` subcommand checks the checkout and three output roots for any
case-variant `.ipa` or `.xcarchive` names, including hidden paths, and rejects
`Payload` staging directories in the output roots. It does not follow symlinks
or inspect Git object databases. Missing outputs after a failure are normal:
a clean scan alone is never evidence that app linking passed. A final
always-run workflow scan is separate from the success-only receipt recheck.
The wrapper also scans in its failure cleanup. A runner timeout/interruption
can prevent cleanup/rechecks; such a run is incomplete, never a link pass.

For an existing successful diagnostic, use the same three output arguments
with `link_diagnostic.py verify`. Use `scan` alone after an earlier build failure.
Both commands are read-only. Logs and temporary receipts stay on the runner.

## Portable verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/host/check-app-link-diagnostic.py
PYTHONDONTWRITEBYTECODE=1 python3 tests/host/check-app-link-workflow.py
```

Fixtures exercise the actual app library with synthetic bundles and mocked
Xcode, native/graphics inputs and external commands. They do not run Xcode,
create an IPA, or establish real compile/link success. A real green diagnostic
establishes only unsigned app linking and bundle validation. Device launch,
JIT, rendering, 1C and Blender behavior remain separate untested outcomes.
