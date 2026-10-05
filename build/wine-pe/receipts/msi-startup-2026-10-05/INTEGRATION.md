# Reviewed MSI child-startup replacement, October 5, 2026

Only AArch64 and ARM64EC msi.dll replace the exact earlier reviewed client-fix
providers. The desktop, original MSI, loader and client-fix receipts, retained
binaries and existing app notices remain byte-for-byte historical evidence.
The new three-architecture build is retained under build/ with its unchanged
SHA256SUMS. The new i386 MSI stays inactive evidence outside app resources.

The incremental custom.c patch waits for a pending named-pipe connection or the
custom-action child process to exit. Pending I/O is cancelled and drained before
its OVERLAPPED storage or buffers go out of scope. The server pipe is opened for
overlapped I/O, and later server-handle reads/writes use a completion wrapper to
preserve synchronous behavior. Existing action serialization remains in place.

This fixes the dead-child-before-connect path. A living child that never
connects, later stalled action I/O and shutdown remain unbounded. This change
adds no general runtime timeout. Host API-model scenarios and cross-compilation
do not establish Wine, Windows, iOS, installer, 1C or application acceptance.

The fixed Wine revision remains 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f.
Final dlls/msi/custom.c SHA-256 is
0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f.
The incremental patch SHA-256 is
a3c010ea77cf18c3b37ad2bc249692758839d9f83fbe7b081b08312dc8e36bae.
It applies after the historical MSI combined patch and client-failure patch.

Corresponding source consists of the complete pinned Wine source plus all
three retained patches and captured Madeira configuration/rebuild inputs. The
final changed source is build/source/custom.c; all source identities, original
Git blobs/modes, commands, object/link input identities, current resolver
snapshots and toolchain identities are retained in build/evidence/. Rebuild
instructions and limitations are in build/SOURCE-REBUILD.md. Fresh builds do not
establish byte-for-byte reproducibility across source paths, times or hosts.

Original Wine, Madeira, compiler-rt, zlib and toolchain notices remain unchanged
and applicable. The additional modification notice is
build/licenses/startup-fix/MODIFICATIONS.md. Retain the complete corresponding
source and any required relinking material when redistributing; this compact
evidence directory alone does not establish complete LGPL compliance.

Fresh integration inventories bind all 150 AArch64 and 159 ARM64EC modules.
Only the two MSI identities change. Module names, architecture, normal/delay
module dependencies, API-set metadata, export-forwarder dependencies and the
13/10 residual missing-module edges are unchanged. Fresh MSI symbol audits
resolve 331/332 imports and retain 296 exports per active architecture.
Exactly four normal kernel32.dll imports are added: CancelIoEx, CreateEventW,
GetOverlappedResult and WaitForMultipleObjects. Every prior import and the exact
export-name/ordinal/forwarder contract are preserved. SetLastError is inlined
by Wine's headers and introduces no import.

The inactive i386 DLL has the same reviewed four-import delta and unchanged
export API. Its historical peer farm was unavailable for a fresh complete
symbol-resolution audit. It is not added to app resources and its build cannot
authorize general i386 activation. No app link, IPA, signing or device success
is established here. Runtime-tested, package-ready and i386-activated remain
false in this integration contract.

The read-only planner requires the exact paired predecessor and complete
historical farm. It proposes precisely two app-provider replacements and
otherwise add-only notices/receipt files. Rollback restores the prior client
providers from the unchanged client receipt only when both current providers
match their reviewed after identities. Remove added files only if their current
identity matches the delivered one, and reverse source edits only with exact
after-state preconditions. Preserve unrelated work and all earlier receipts.
