# Inactive MSI client-error replacements

Three fresh `msi.dll` providers compile and link the independently reviewed
`custom_client_thread` fix. All three pass static architecture, import-resolution,
and original import/export contract checks. None has been integrated, published,
loaded, or executed as a guest. i386 remains an inactive single-provider overlay.

| Target | Bytes | SHA-256 |
|---|---:|---|
| AArch64 | 1572864 | `c04b4aa74963caa1043229c8d2fbf4b4a09c94a7684107335cddb5fde2b2356a` |
| ARM64EC | 1769472 | `3c69a7becb0ee31974fb7b0cf9785095b0d3d77551a87dd337257358c37924ae` |
| i386 | 1208320 | `1fe600254f476fb48e9b9694f7b4e9ef7b7bdc1980358cc5d0727186d9dc2b23` |

The exact replacement mapping is `replacement-identity.json`; outputs are under
`candidate/<arch>-windows/msi.dll`. `preserved-original/` contains independent
byte copies of all three superseded provider candidates.

## Source identity

- Wine pin: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`
- Existing combined patch: `3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8`
- Incremental baseline custom.c: `31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5`
- Client patch: `6dc3802f26e98a0cc03462b989e2d3619b74f9374d325784009c1df5a8623ebe`
- Final custom.c: `9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50`

Only `custom_client_thread` changes relative to the reviewed incremental
baseline. The successful custom-action return values and outer Continue/Async
policy remain unchanged. The complete copied Wine tree, including its original
copyright/license notices, remains at `wine/`. No old build intermediates were
reused. Each final `custom.o` was compiled in a fresh build directory and differs
from its corresponding old object; the exact compile command and object hash
are in `evidence/<arch>-link-inputs.json`.

## Evidence and boundaries

Each replacement preserves all 296 export-name/ordinal/forwarder entries and
the exact normal/delay import-symbol contracts of its sealed original. AArch64
resolves 327 imported symbols; ARM64EC and i386 resolve 328 each. There are no
delay-import descriptors and no new unresolved symbols. The bounded parser and
LLVM independently agree on PE architecture and export/import counts. The
ARM64EC PE's AMD64 on-disk header is validated through its load-config CHPE
metadata, not treated as an ordinary x86-64 PE.

Resolver audits use the unchanged recorded original farms and the old reviewed
peer providers, replacing only MSI in a local overlay. All resolver module hashes
are retained. These are MSI-specific closure checks, not complete farm closure:
the pre-existing 13/10 64-bit DLL dependency gaps and the legacy i386 kernel32
forwarder gap remain unchanged. No missing provider is invented or export removed.

The 102 production-function host scenarios were rerun against the exact built
source: normal and ASan/UBSan runs pass 102/102; the unchanged baseline still
fails 46/102. These are host API doubles, not Wine/Windows runtime tests. The
source review and its detailed limitations are retained under
`review-inputs/client-fix/`. Parser/EXE regression results are in
`evidence/post-build-tests.json` and corresponding logs.

An independent read-only artifact review found no blocker and rechecked source,
objects, linker inputs, toolchain, original preservation, PE contracts and the
compact seal. Its result is `evidence/independent-review.md`.

The copied source files, generated build files, all explicit link objects and
archives, temporary spec objects/assembly, host tools, relocated prerequisites,
and the complete verified LLVM-MinGW installation are bound by receipts. The
recorded official LLVM-MinGW 20260421 archive was verified against every installed
file/link, before and after the build. Host system headers/libraries and the OS
are not a hermetic image; byte-for-byte reproduction across paths/times/hosts
is not established.

Fresh MSI link recipes add only `-v -save-temps` to the generated Makefile so
temporary spec inputs remain inspectable. The single-line generated-file changes
and their before/after hashes are retained. This changes no Wine source or
production compiler flags. One initial attempt was interrupted before make
because generating a whole 520,451-line Makefile diff was too slow; that attempt
is retained under `attempts/initial-trace-diagnostic/`. The successful attempt
uses an exact single-line patch receipt. No failed provider was used.

## Preservation and budgets

The complete 16,911-file/link old provider workspace and the source-only review
workspace were hashed before and after, with no differences. The old snapshot
also matches the snapshot previously checked by the source-review task. No
primary tree or original farm was written. `evidence/preservation.json` is the
result; full before snapshots and independent old provider bytes are retained.

Builds ran sequentially with `make -j2`, under a 45-minute session deadline,
a 2 GiB cap for the entire new logical workspace, a 64 MiB per-architecture log
cap, and an 8 GiB free-disk floor checked at least every five seconds while
commands ran. Receipts contain observed timings and budget samples. No downloads,
paid resources, remote writes, app/IPA builds, signing, installers, or guest
execution were performed.

`SHA256SUMS` seals the compact deliverable. Large copied Wine/build directories,
resolver working copies, and the interrupted attempt are retained as workspace
evidence and separately bound by their manifests; they are not duplicated in
the compact seal. `SOURCE-REBUILD.md` explains the offline recipe and its inputs.

## Integration implications

Integration is separate reviewed work. The existing MSI integration record binds
the old DLL hashes, prior source hash and old stage seal. Its strict validator
must not accept these replacement bytes under that historical identity. The
loader receipts additionally bind every module in the historical MSI baseline.

Preserve the old MSI and loader receipts and seals exactly. Introduce a distinct
replacement receipt and explicit old-to-new hash mapping, then bind the current
farm/inventories through that layer. Update any current identity checks and
legal source/change/rebuild references deliberately; do not rewrite history to
make old receipts appear to describe new providers. Re-run strict MSI/loader
integration tests and current import resolution on the resulting combined farm.
The i386 file must stay inactive unless separately authorized and audited with
its complete 71-file peer set.

Runtime canaries still need to prove custom-action failure rejection, real
property round trips, COM/IPC/handle behavior, and actual cross-bitness. Existing
child-before-connect hangs, synchronous pipe blocking, dead cached server
recovery, protocol resynchronization and asynchronous exit-status handling are
unchanged. This package establishes compile/link/static contracts, not device
behavior, app compatibility, security, or distribution/relinking compliance.

## Licenses

Original Wine, Madeira, compiler-rt, zlib and LLVM-MinGW notices are retained in
`licenses/`, with the client modification notice in `licenses/client-fix/`.
Source file headers remain intact. The copied audited tooling retains its
original GPL-3.0-or-later/Madeira exception notices and license files under
`reference-inputs/`; new helper files declare their licenses in their headers.
