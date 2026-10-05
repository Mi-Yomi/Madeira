# Reviewed MSI custom-client replacement, October 5, 2026

Only AArch64 and ARM64EC msi.dll replace the exact earlier reviewed providers.
All original desktop, MSI and loader receipts, binaries retained inside them,
and their existing app notices remain byte-for-byte historical evidence. The
new three-architecture build is retained under build/ without modifying its
SHA256SUMS. The new i386 MSI stays evidence-only outside app resources.

The incremental patch changes custom_client_thread error handling: unavailable
or malformed custom actions report failure while preserving the ordinary
success and supported 64-bit execution paths. It applies after the previously
reviewed MSI patch. Final dlls/msi/custom.c SHA-256 is
9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50.
The incremental patch SHA-256 is
6dc3802f26e98a0cc03462b989e2d3619b74f9374d325784009c1df5a8623ebe.

The fixed base Wine revision remains 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f.
Corresponding source consists of that complete pinned Wine source with the
historical combined MSI patch and this incremental patch, plus the captured
Madeira configuration and rebuild inputs. The final changed source is included
at build/source/custom.c, both patches under build/patches/, all Wine source
identities under build/evidence/source-inputs.json, and rebuild instructions
at build/SOURCE-REBUILD.md. Retain the complete source and any required relinking
material when redistributing; this compact evidence directory alone is not
complete LGPL compliance. Original Wine, compiler-rt, zlib and toolchain
notices remain applicable and unchanged. See the additional modification notice
in build/licenses/client-fix/CLIENT-MODIFICATIONS.md.

The new integration inventories bind all 150 AArch64 and 159 ARM64EC modules.
Only the two MSI hash identities change. Module names, machine interpretation,
normal/delay dependencies, API-set schema, forwarded dependencies, and the
13/10 residual missing-module edges remain unchanged. Fresh MSI audits resolve
327/328 imports and retain 296 exports for each architecture. The complete
export name/ordinal/forwarder and normal/delay symbol contracts match the old
MSI providers, independently checked from both PE byte streams.

102/102 host scenarios pass normally and under the recorded sanitizer setup;
the historical baseline fails 46. This checks extracted production control flow,
not guest execution. No installer, custom-action DLL in Wine, app link, IPA,
signing, device, Blender or 1C success is established. Runtime-tested,
package-ready and i386-activated remain false.

Rollback requires both current replacements to match their reviewed after
identities before restoring the old binaries from the unchanged MSI receipt.
Remove added files only if they still match the delivered identities. Reverse
source edits only with exact after-state preconditions; preserve unrelated work.
