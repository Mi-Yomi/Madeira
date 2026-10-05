# Experimental Wine MSI providers, 2026-10-05

The reviewed add-only resource change contains msi.dll, msiexec.exe, cabinet.dll,
sxs.dll, mspatcha.dll, odbccp32.dll and regsvr32.exe for each of AArch64 and
ARM64EC. No existing farm file or notice is replaced. The separate i386 msi.dll
and 71-component i386 peer remain outside app resources and inactive.

## Corresponding source and original notices

Wine source: https://github.com/willfaust/wine/tree/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f

Exactly `dlls/msi/custom.c` is changed from that source. The byte-exact patch is
bundled as `Wine-MSI-custom-actions.patch`; its SHA-256 is
`3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8`.
The resulting custom.c SHA-256 is
`31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5`.
`Wine-MSI-MODIFICATIONS.md` identifies the changes and date. The Wine component
source headers and license terms continue to apply to the patch and binaries;
the Madeira build/test tools' GPL/exception headers do not relicense Wine.

Retain the existing `Wine-LGPL-2.1.txt`, `Wine-LICENSE-MADEIRA.md`,
`Wine-compiler-rt-LICENSE.txt` and all unrelated bundled notices unchanged.
The MSI/cabinet build also retains zlib's original `Wine-zlib-LICENSE.txt` and
the complete `Wine-zlib-header-with-notice.h` with its newer copyright notice.
`Wine-MSI-toolchain-LICENSE.txt` retains the recorded toolchain's license text.
The existing `THIRD-PARTY-NOTICES.md` and its bundle-relative paths are preserved.

`Wine-MSI-SOURCE-REBUILD.md` is the unchanged build's reconstruction record.
Its relative paths refer to the full evidence package in the corresponding
Madeira source tree: `build/wine-pe/receipts/msi-2026-10-05/`. That directory
contains 108 indexed files plus `SHA256SUMS`, whose SHA-256 is
`3d748dc6f9fa84d386c79acdaf9b4952755719daa79f8ac161f1c07d27fee0fe`.
The package retains source, patch, recipe, toolchain, successful logs, static
audits, original notices and the inactive i386 output. Its recorded historical
source paths and earlier Madeira revision describe the original build and are
not claims about the later integration commit.

Keep complete corresponding pinned Wine source plus this exact patch and
rebuild inputs available with any later redistribution. These integrity and
source records do not establish independent bitwise reproducibility or settle
redistribution/relinking obligations. The Wine gitlink itself is unchanged;
rebuilding it without the separately recorded patch produces different MSI code.

## Behavioral scope and limits

The patched MSI returns failure for DLL-load, missing-entrypoint and caught
exception failures. It checks custom-action server creation and path capacity,
accepts an already-connected pipe, cleans up owned failure-path resources and
does not start a client thread when server initialization fails. Successful
action return values and outer Continue/Async policy remain unchanged.

A child that starts but never connects can still block synchronous
ConnectNamedPipe. Cached dead-server recovery and asynchronous exit-status
handling remain unchanged. Native child-process/IPC, loader, SEH, COM/CLR/SxS,
WinNT ADS, 1C, Blender and device behavior have not been established.
The Windows reference fixture validates Windows behavior only; it does not test
these Wine providers or the iOS runtime.

Static checks resolve the new providers' imports and required forwarder chains
against the recorded same-architecture farms. They close only setupapi's missing
cabinet.dll delay-import edge. Thirteen AArch64 and ten ARM64EC full-farm gaps
remain. No 32-bit runtime is enabled: the app's i386 rejection remains intact.
No app/IPA build, signing, installation or guest execution is implied.
