# Pinned FEX PE source fixtures

`ARM64EC/Module.cpp` and `WOW64/Module.cpp` are complete, unmodified source
snapshots from willfaust/FEX revision
`1adb337a2f2270434ba731346438c072337a5d5f`, the FEX submodule revision pinned
by Madeira when these regressions were added. `provenance.json` records each
source URL, upstream Git blob identity and SHA-256. The snapshots retain their
original SPDX headers and comments.

The upstream FEX portions retain MIT terms (`LICENSES/MIT-FEX.txt` in the
repository root); Madeira changes retain their GPL-3.0-or-later terms, as
explained in `THIRD-PARTY-NOTICES.md`. The tests apply the reviewed Playport-derived
repairs from `build/fex-ios/patches` only inside temporary directories. Their
additional provenance and license notices are in that directory's `playport/`
subdirectory. These fixtures are source inputs, not compiled FEX or PE binaries.

`tests/host/fex_guard_test_support.py` checks these identities against the
production repair manifest, applies the actual checked-in patches and verifies
the complete patched file hashes before extracting production control flow.
The host tests compile those extracted blocks with explicit dependency stubs;
they need no initialized FEX submodule, network, Apple SDK or ARM host. They do
not substitute for a PE build or on-device validation.
