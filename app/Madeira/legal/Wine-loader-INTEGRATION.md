# Experimental Wine AVICAP32 and ACTIVEDS providers, 2026-10-05

This add-only resource change contains avicap32.dll and activeds.dll for each
of AArch64 and ARM64EC. All existing core DLLs, desktop/MSI evidence and notices
remain unchanged. No i386 provider or runtime is activated.

## Corresponding source and original notices

Exact pristine Wine source:
https://github.com/willfaust/wine/tree/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f

The Wine gitlink stays at this revision. These four DLLs use no Wine source
patch. The original receipt records all 10,958 source files with Git blob,
mode, SHA-256 and size; its tree is 91d4283d3287eda28daf932254db8c6a790a8eb4.
The MSI-specific custom.c patch is irrelevant to these pristine providers.
Wine source headers and original licenses continue to apply; Madeira's
build/test tool headers do not relicense Wine code or binaries.

Preserve the existing Wine-LGPL-2.1.txt, Wine-LICENSE-MADEIRA.md and
Wine-compiler-rt-LICENSE.txt unchanged. Their bytes match this build's copies.
The same LLVM-MinGW toolchain's original license is already bundled as
Wine-MSI-toolchain-LICENSE.txt. All other notices remain unchanged.

Wine-loader-SOURCE-REBUILD.md is the unchanged build reconstruction record.
Its relative paths refer to build/wine-pe/receipts/loader-2026-10-05/build/
in the corresponding Madeira source tree. That directory preserves every
original indexed file plus SHA256SUMS, whose SHA-256 is
d3f405e38d8a4749e54ee6aab53fd034400424b8233555500dfde3cbdaca08ae.
The parent receipt adds four static reports against the combined MSI farm.
Historical paths/revisions in the nested receipt describe the original build.

The complete pristine source remains available through the pinned Wine source
repository and was retained offline in the build workspace. A source manifest
is an integrity record, not a substitute for corresponding source. Preserve
complete corresponding source, build inputs and applicable relinking material
with any later redistribution. These records do not establish hermetic or
path/time/host-independent bitwise reproducibility or package readiness.

## Behavior and limits

AVICAP32 supplies its four public entry points. On the inspected existing
Madeira unavailable-backend path, description queries return FALSE without
altering output buffers; 24 native-host failure cases passed with ASan/UBSan.
This adds no camera backend, device enumeration success, permission request or
capture success. DLL attach registers a window class and remains untested on
iOS; actual ARM64/ARM64EC dispatch and load/unload need an owned device canary.

ACTIVEDS ordinal 3 supplies real ADsGetObject dispatch to registered ADS COM
providers. It does not supply or register a WinNT or LDAP provider, create an
account, or establish successful service-user setup. Several other APIs remain
unimplemented. No COM registration was executed.

All 86 imports per architecture resolve statically against the actual combined
farm, including API sets and forwarded exports. Thirteen AArch64 and ten
ARM64EC pre-existing full-farm dependency gaps remain exactly unchanged.
This closes only the measured module/name and ordinal loader gaps. Blender,
1C, directory services and Wine/iOS runtime compatibility remain unproven.
No app/IPA build, signing, installation or guest execution is implied.
