# Reviewed experimental desktop source-tree integration

This integration adds only six DLLs to each existing 64-bit app-resource farm:
`avifil32`, `msftedit`, `msvfw32`, `netprofm`, `riched20` and `sensapi`. Existing
farm bytes are preserved. The Wine pin remains
`4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`. No i386 or Microsoft VC runtime is added.
The existing Xcode architecture and legal folder references need no per-file
resource edits.

This is an experimental source-tree change, not a runtime-compatibility result.
No app build, IPA creation, signing, installation or guest execution was done
as part of integration. The packaging gate remains separately paused/opt-in.

## Authoritative evidence and legal records

The complete **55-file** original sealed package is retained byte-for-byte in
`build/wine-pe/receipts/desktop-2026-10-05/`, outside app resources. The SHA-256 of
its `SHA256SUMS` is
`a0f56fd773375a2c2cc2bd76d01db0fbf28973ca1d7bf36a7dd6dbd6c9a02023`.
All other 54 files are indexed. This binds the twelve exact outputs, complete
successful logs, input/module/symbol/toolchain receipts, LLVM metadata, original
notices and captured rebuild inputs. The seal is an integrity record, not a
digital signature or independent proof of provenance.

`build/wine-pe/desktop-integration.json` is the reviewed app-consumption record.
It binds the two DLL farms, the four exact Wine notice/source copies and the
two integration-specific bundled documents. `published_recipe_commit` names the
later published tooling checkpoint, not a claim that its bytes all match the
earlier build. The sealed `rebuild-inputs/` and `source-inputs.json` remain the
authoritative recipe and source identities for these DLLs. A missing final
tooling-commit binding is rejected. No independent clean-build bitwise
reproducibility is claimed.

The original `SOURCE-REBUILD.md` is copied unchanged to
`app/Madeira/legal/Wine-desktop-SOURCE-REBUILD.md`. It intentionally retains the
historical standalone-overlay context and rebuild-base revision. Its adjacent
`Wine-desktop-INTEGRATION.md` explains where the complete evidence and source
are available. Retain complete corresponding Wine source at the pinned
revision, as well as the captured rebuild/toolchain evidence, for any later
distribution; this integration does not settle redistribution/relinking duties.

The bundled `legal/THIRD-PARTY-NOTICES.md` is a selective Wine LGPL-branch and
compiler-rt correction. The original StikJIT, idevice and Rust notice rows and
their valid bundle-relative references are preserved. The top-level source
notice is never copied blindly over the bundle notice. The original Wine LGPL,
fork and bundled compiler-rt MIT/NCSA notice bytes are retained exactly.

## Fail-closed resource gate

The app gate still accepts only Git-tracked resource files, apart from its
existing two explicitly generated Madeira license copies. It now additionally
requires the exact desktop integration manifest, all 55 sealed evidence files,
all twelve DLLs and matching notices to be tracked. It checks:

- The pinned checksum seal, complete evidence set and exact app/source hashes
- The original same-architecture farm bytes/dependency reports and Wine gitlink
- The complete six-module pair and architecture, including ARM64EC CHPE metadata
- The reviewed merged notice and separate integration record
- No arbitrary untracked DLL or notice exception

The native prerequisite check still requires the whole source checkout to match
its recorded source commit (apart from its existing receipt-bound generated
inputs). Adding files to the index is not permission to bypass that check.
After linking, normal bundle-resource hash checks protect the same reviewed
bytes. These checks do not execute guest code, install DLLs, select an alternate
runtime, fix missing dependencies or grant permission to package an IPA.

The `.gitattributes` rules mark the sealed evidence, exact `legal/Wine-*` copies
and hash-bound merged notice as `-text`, preventing Git line-ending conversion.
The separate `-whitespace` flag preserves existing notice/log whitespace without
diff warnings; it does not disable line-ending conversion. A temporary-Git
`core.autocrlf=true` checkout regression verifies the seal and all hash-bound
resource bytes, with an unprotected control file proving CRLF conversion runs.

Run the static integration verifier and portable suites after all files are
tracked and the published tooling reference is bound:

```sh
python3 build/wine-pe/verify_desktop_integration.py
python3 tests/host/check-desktop-integration.py
python3 -O tests/host/check-desktop-integration.py
python3 tests/host/check-app-bootstrap.py
python3 tests/host/check-desktop-overlay-plan.py
```

The integration suite uses temporary Git commits and static PE fixtures. It
also reads the real integrated farms to compare every existing module identity
and the residual dependency list against the sealed inventory. It does not
perform an app build or package the reviewed binaries.

## Residual gaps and rollback

The six new modules have no direct missing DLL dependencies in the reviewed
static audits. The full farms still contain **14 AArch64** and **11 ARM64EC**
dependency gaps. Every pre-existing module and gap is preserved, including the
ARM64EC `bthprops.cpl` normal import of missing `bluetoothapis.dll`. Dynamic
loads, COM/installer behavior, API implementations, actual networking, Wine
loader behavior and device/runtime testing remain open. For example, the
pinned `sensapi!IsNetworkAlive` stub is not evidence of working connectivity.

Keep both architectures, matching legal files, the complete evidence package
and source gate changes together. Do not publish a partial pair. An integration
handoff includes an add-only binary-copy manifest and a text patch with
before/after hashes. Revalidate them immediately before applying; refuse any
destination collision. Keep verified backups of the separately reviewed text
changes. Roll back added files only when their current hashes still match the
recorded post-state, and restore reviewed text changes only under the same
condition. Stop for review if another change intervened.

The read-only `plan_desktop_overlay.py` intentionally rejects an already
integrated target because its original contract is an add-only plan against
the pre-integration farms. It remains the correct preflight for a fresh target;
use `verify_desktop_integration.py` to inspect the integrated source tree.
Device-prefix symlinks are outside this source-tree transaction and would need
separate validation if an app containing these additions were later installed
and then downgraded.
