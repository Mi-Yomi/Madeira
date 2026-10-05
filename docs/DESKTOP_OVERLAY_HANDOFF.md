# Read-only desktop overlay integration plan

This helper closes a **consumption-time** gap: a sealed build was checked against
its original DLL farms, but a later integration target can have different bytes.
It rebinds the current target to the exact recorded inventory and symbol inputs,
checks both architectures, preserves original files, and prints a file plan.
It never installs files, edits a prefix, launches guest code, builds an app,
packages an IPA, signs or publishes anything.

## Prerequisite and invocation

Apply the source-built desktop overlay tooling and its automated evidence patch
first. The latter provides the bounded `guest_inventory.py` API. This patch adds
only the new planner, its regression suite and this document; it neither
replaces the existing builder nor changes the unsigned-app resource gate.

```sh
python3 build/wine-pe/plan_desktop_overlay.py \
  --stage /path/to/reviewed/receipt-final-desktop \
  --root /path/to/integration-checkout \
  --expected-seal SHA256_OF_REVIEWED_SHA256SUMS > /tmp/overlay-file-plan.json

python3 tests/host/check-desktop-overlay-plan.py
python3 -O tests/host/check-desktop-overlay-plan.py
```

Get the expected checksum-index digest from the reviewed build handoff. Computing
it anew from an untrusted replacement stage would discard that binding. The
index is not a digital signature or independent proof of source-build origin.
The helper never executes a tool, recipe or executable from the stage. Its only
subprocess is read-only `git ls-tree` to obtain the integration target's Wine pin.

The supported contract is exactly the six reviewed desktop modules for both
`aarch64-windows` and `arm64ec-windows`. Build order may differ. Neither another
architecture nor an i386/VC2012 DLL fills a missing component. The existing
same-architecture farms must match the build audit byte for byte; a changed
farm needs a fresh symbol audit/build receipt rather than a silent fallback.
Existing desktop filename collisions are refused even if bytes match.

## Meaning of the plan

- `proposed_files` contains **additions only**, with exact stage source, destination,
  byte count and SHA-256. No current file is replaced
- `blocking_notice_merges` identifies differing existing notice destinations.
  The source-tree third-party notice always requires bundle-path adaptation,
  even when no destination exists or equal source bytes were already copied.
  Review and merge these separately while preserving target-only notices and
  working bundle-relative license references; the candidate is not a blind copy
- `unchanged_notices` are equal-byte no-ops
- `architectures` reports the unchanged residual dependency gaps. No new desktop
  module may have a direct gap. The new modules can still transitively reach
  existing delayed/forwarder gaps; full-farm strict closure remains separate
- `package_ready` and `runtime_tested` remain false. Success means that a
  point-in-time plan was verified, not that it is approved, installed or runnable

The current target's bundled `legal/THIRD-PARTY-NOTICES.md` deliberately uses
local StikJIT, idevice and Rust notice paths. Replacing it with the top-level
source notice regresses those references. Merge the corrected Wine LGPL branch
and compiler-rt information while retaining the valid bundle paths. Include the
three exact Wine source notices and source/rebuild record with eventual DLL
integration. Preserve complete corresponding source and captured rebuild inputs
outside this minimal bundle-file plan; record the final published recipe commit.
This check is not a determination of overall redistribution/relinking compliance.

## Reversible integration design, not an installer

Use a fresh disposable checkout and revalidate the stage, base-farm and destination
identities immediately before any authorized write. Keep the original target
intact until all additions and reviewed notice edits pass. Retain verified backups
of every separately reviewed existing-file change. Treat both farms and their
legal/source records as one transaction; never publish a partial pair.

The unsigned-app gate currently requires tracked resource bytes. It must retain
that protection: integrate a reviewed tracked inventory or a new receipt-bound
explicit overlay route rather than accepting arbitrary untracked resources.
The three architecture folders and `legal` already are Xcode folder references;
these six DLLs need no new per-file Xcode resource entries. The runtime enumerates
the selected architecture and mixed-mode farms.

Rollback additions only when their current hashes still match this plan; stop
for review if another change intervened. Restore separately edited notices from
verified backups under the same precondition. A packaged downgrade may leave
stale device-prefix symlinks because the runtime only enumerates current bundle
files. Prefix cleanup and runtime/device validation are outside this planner.
