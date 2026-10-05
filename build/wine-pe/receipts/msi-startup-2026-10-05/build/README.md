# Inactive MSI startup-provider replacements

All three providers were compiled and linked in fresh directories from the
independently reviewed source `0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f`.
The complete corrected source is `source/custom.c`; its Wine tree, official
archive, per-file identities, preceding patches and new patch are bound by
`evidence/source-inputs.json`.

| Architecture | Bytes | SHA-256 |
|---|---:|---|
| AArch64 | 1572864 | `6845b17db8b5650fd7637718c2fbcd8467b02060d179354e78ed3037321d2f6e` |
| ARM64EC | 1769472 | `6b611ac3a9c9b1200314397ab033e03ce1a5d9e93f6be3337a935ca33f124a9f` |
| i386 | 1208320 | `46d3348f16188e5b05a13b3e01564a652b0b3f7af0b6555d23d110e8169bd0e0` |

Every provider preserves the exact 296-entry export name/ordinal/forwarder
contract of its published client-fix predecessor. Exactly four normal
`kernel32.dll` imports are added: `CancelIoEx`, `CreateEventW`,
`GetOverlappedResult`, and `WaitForMultipleObjects`. No import is removed and
there are no other new imports. `SetLastError` is inline in Wine's internal
headers. ARM64EC is checked through CHPE metadata, not its AMD64 file header alone.

The new AArch64 provider resolves all 331 imported symbols against a copied
current active farm; ARM64EC resolves all 332. These are MSI-specific static
closure checks, not proof of full-farm closure or runtime/ABI behavior. The
historical i386 peer farm was absent after reset, so only its fresh compile,
object architecture, raw PE metadata and exact import/export delta were checked.
i386 remains inactive and has no fresh full-resolution claim.

`replacement-identity.json` maps each predecessor hash to its fresh replacement.
All three original provider byte copies are under `preserved-original/`.
Fresh compiled custom objects and machine-header checks are retained under
`evidence/compiled-custom/`; source-specific compile commands, link commands,
explicit object/archive inputs and temporary link inputs are in the per-arch
link receipts. Full source/build-tree/toolchain file identities are recorded.

The exact official LLVM-MinGW 20260421 archive and installation were verified
before and after the build. All 10,958 original Wine source Git blobs/modes and
all 381 prerequisite file/link entries were checked against published receipts.
Host compiler versions and the original flags are preserved. External host
headers/libraries and the OS remain non-hermetic. Builds use two jobs, a
30-minute limit, a 2 GiB workspace cap and an 8 GiB free-disk floor.

Before the new patch, fresh builds of all three current baseline providers
preserved their exact API contracts. They did not reproduce historical bytes:
embedded absolute source paths and PE timestamps differ, while custom compile
commands match after normalizing only the workspace prefix. Section comparison
and baseline identities are retained. Bitwise reproducibility is not established.

The source review and its 33 host API-model cases are retained under
`review-inputs/startup-fix/`. A separate fresh reconstruction test passed for
`prepare_startup.py`, recreating the exact final source and host prerequisite
files from the recorded archives. This is not a guest/runtime test.

`SHA256SUMS` seals the compact files. Large working Wine, build, resolver and
prerequisite directories are excluded and bound separately by manifests.
The compact package list is in `evidence/compact-files.json`.
`SOURCE-REBUILD.md` describes the offline rebuild and external input locations.
Wine, Madeira, compiler-rt, zlib and LLVM-MinGW notices are retained, together
with the startup modification notice in `licenses/startup-fix/MODIFICATIONS.md`.

No primary file, farm, submodule pin, prefix, remote repository, IPA, signing or
proprietary installer was changed by this build. No DLL was executed, loaded,
installed or activated. Integration/publication requires a separate receipt;
historical MSI and loader receipts must remain unchanged.
