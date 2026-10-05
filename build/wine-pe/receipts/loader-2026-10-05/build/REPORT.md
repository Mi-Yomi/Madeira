# Inactive AVICAP32 and ACTIVEDS providers

2026-10-05. Four pristine Wine PEs built and statically audited successfully,
for aarch64 and ARM64EC only. Nothing was installed into Madeira, published,
or executed as a Windows guest. No Wine or Madeira production source patch
was necessary or made. No existing core DLL was rebuilt or replaced.

## Exact result

| Architecture | File under `candidate/` | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| aarch64 | `aarch64-windows/avicap32.dll` | 458752 | `870e5d818712f751029c47c038c201aa8a846ca7b5d3f5622633dd027d228b2c` |
| aarch64 | `aarch64-windows/activeds.dll` | 655360 | `39c0505d43d773a6173a96b1ca7fca1777785223b944b18c24d17858f919ad63` |
| ARM64EC | `arm64ec-windows/avicap32.dll` | 589824 | `f9e500425444a9cb82cb76def929d5591308b68b7d8b4d61b85367616a966ffd` |
| ARM64EC | `arm64ec-windows/activeds.dll` | 851968 | `407bd4949ae12bf22861d96695a4047af63ff1081364eaebaf623702eafcacad` |

Both architectures have the same measured symbol counts:

- AVICAP32: 32 normal import symbols in four descriptors; four public exports
- ACTIVEDS: 54 normal import symbols in six descriptors; 28 exports
- No delay imports or export forwarders in either candidate
- All 86 candidate imports resolve against the recorded same-architecture
  primary farm, including required API-set and dependency-forwarder chains
- AVICAP32 exports `capGetDriverDescriptionA/W` and `capCreateCaptureWindowA/W`
- ACTIVEDS ordinal 3 is the implemented `ADsGetObject` entry, not an alias
  to a success stub or a missing function

AVICAP32 normally imports KERNEL32, NTDLL, UCRTBASE and USER32. ACTIVEDS normally
imports ADVAPI32, KERNEL32, NTDLL, OLE32, OLEAUT32 and UCRTBASE. The source UUID
library is a static link input, not a missing runtime DLL.

`evidence/{aarch64,arm64ec}-symbol-audit.json` records every imported name or
ordinal, export, resolved chain, input hash and independently checked LLVM
count. LLVM metadata is under `evidence/readobj/`. The required public API
checks are also recorded separately. The underlying full-farm module audit
still has 14 aarch64 and 11 ARM64EC pre-existing missing edges. None is new.
The 141/150 baseline farm PEs were checked unchanged after compilation.
Selected-provider closure does not assert that every existing farm function,
dynamic load, COM activation or side-by-side assembly is supported.

These candidates close the measured AVICAP32 module/name gap of the reference
FFmpeg consumer and the measured ACTIVEDS ordinal-3 loader gap. They do not
establish Blender startup, a working 1C installation, or application support.
Private application metadata and proprietary bytes are not included here.

## Why pristine AVICAP32 is a reasonable inactive candidate

The pinned Wine DllMain ignores the result of `__wine_init_unix_call()`, then
registers a window class; DLL loading therefore has USER32 initialization
side effects. Actual class registration and DLL attach remain untested on iOS.
The capture window is a window with an unimplemented capture-message handler,
not a functioning capture device.

The existing Madeira 64-bit Unix-library binder has no AVICAP-specific backend.
Its generic branch initializes and returns a real function table whose entries
return `STATUS_NOT_SUPPORTED` without touching argument outputs. Native ARM64
and ARM64EC both use the 64-bit `MemoryWineLoadUnixLib` path here. The pinned
`capGetDriverDescriptionW` checks the Unix-call status before reading either
device field; on any failure it returns FALSE. The ANSI wrapper converts only
after the wide function succeeds. Thus this existing path reports no available
device; it does not turn unavailable capture into success.

If Unix-library initialization fails and leaves the initially zero handle,
Madeira's ARM64 dispatcher checks that handle before dereferencing the table,
then returns `STATUS_NOT_IMPLEMENTED`. The same public function checks that
nonzero status. An absent dispatcher export instead uses Wine's existing
`STATUS_DLL_NOT_FOUND` fallback. This source analysis does not prove the actual
runtime dispatcher pointer or ARM64EC ABI on a device.

Host-only checks compiled the exact extracted production binder, generic
failure function, and pristine Wine A/W description functions with ASan/UBSan.
Twenty-four failure calls across three statuses and four indices returned
FALSE, preserved sentinel-filled caller buffers, and never copied device
output or performed ANSI conversion. A static source-order check confirmed
the real ARM64 zero-handle branch precedes the table load. The existing
production binder host test also passed. LeakSanitizer was disabled because
this executor uses ptrace; the initial unsupported LeakSanitizer run is not
claimed as a pass. AddressSanitizer and UndefinedBehaviorSanitizer remained on.

No camera backend, Unix `.so`, device enumeration success, camera request,
permission, synthetic device or capture success was added. No production
unavailable-backend patch is proposed: the narrow failure path already exists.
The appropriate later runtime gate is an owned load/unload and unavailable-device
canary for both architectures, without requesting camera access.

Source references: [Wine AVICAP32](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/avicap32/avicap32_main.c),
[Wine Unix-call initialization](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/libs/winecrt0/unix_lib.c),
[Madeira binder](https://github.com/Mi-Yomi/Madeira/blob/142ca1e4851d644cec3519feaa5c9110194c8c7f/build/ntdll-unix/virtual_ios.c#L9122),
[Madeira dispatcher](https://github.com/Mi-Yomi/Madeira/blob/142ca1e4851d644cec3519feaa5c9110194c8c7f/build/ntdll-unix/signal_arm64_ios.c#L13639).

## ACTIVEDS is not WinNT ADS support

`ADsGetObject` delegates to `ADsOpenObject`, first with secure-authentication
flags and then, for eligible failures, without those flags. `ADsOpenObject`
reads `HKLM\Software\Microsoft\ADs\Providers`, matches the URI scheme, resolves
the registered ProgID and creates `IADsOpenDSObject` through OLE32. A missing
registration/provider returns failure. Supplying the DLL does not create any
provider registration, account, group, user-management facility or directory
service. No COM registration function was executed.

The pinned Wine tree's ADS LDAP provider lives in a separate `adsldp.dll`, with
normal imports of OLE32/OLEAUT32/SECUR32/ACTIVEDS and a delayed WLDAP32 import.
Its registration maps `LDAP` to `LDAPNamespace`; this is not a WinNT provider.
Neither ADSLDAP provider DLLs nor WLDAP32 are present in the recorded farms,
and none was added. `adsldpc.dll` is separate again. No WinNT ADS provider
registration/implementation was found in the pinned provider sources. Merely
adding LDAP DLLs would not establish WinNT URI or service-user behavior.

ACTIVEDS itself has a limited set of pathname/data COM classes and multiple
unimplemented API entries. ADsBuildEnumerator/ADsFreeEnumerator/ADsEnumerateNext
return E_NOTIMPL; several other exported entries are Wine specification stubs.
The tested ordinal-3 export is real dispatch code, but the downstream COM,
authentication, directory, WinNT and service-account behavior is unproven.

Source references: [ACTIVEDS dispatch](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/activeds/activeds_main.c#L163),
[exports](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/activeds/activeds.spec),
[LDAP dependencies](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/adsldp/Makefile.in),
[LDAP registration](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/adsldp/adsldp.rgs).

## Provenance and bounds

Wine commit `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`, tree
`91d4283d3287eda28daf932254db8c6a790a8eb4`: all 10,958 source files and modes
were checked against Git blobs, then compared to the untouched original
checkout before and after building. Complete corresponding source is retained
under `wine/`; SHA-256 and blob identities are in `evidence/source-inputs.json`.

The original LLVM-MinGW 20260421 archive and every extracted member were
verified before and after the build. Host-tool executables and relocated
prerequisite data were hashed. The three previously verified Debian Bison,
Flex and M4 archives were rechecked, including all 381 extracted files/links.
Host tools/OS are recorded; this is not a hermetic or bitwise-reproducible build
claim. The selected compiler is unprefixed Clang with Wine's explicit Windows
target. The standard ARM64EC typelib directory alias is confined to its build
tree and makes no source change.

Madeira binder/dispatcher/loader source bytes were checked against the existing
publication audit cache for `142ca1e4851d644cec3519feaa5c9110194c8c7f`; stale local
Git HEAD was not used to identify the current app-farm bytes. This attempt did
not download or re-fetch anything. Original Wine/Madeira/compiler-rt license
notices are preserved under `licenses/` and in source headers.

Configure/build/strip ran sequentially with at most two compiler jobs. The
whole attempt had a 45-minute cap, cumulative 2-GiB logical-work cap, 64-MiB
per-architecture log cap and 8-GiB free-disk floor. The last build operation
recorded approximately 542 MB of logical work, with over 12 GiB free. Only the
two requested PE targets were produced per architecture; import libraries and
host build tools are incidental build prerequisites, not rebuilt core DLLs.

See `SOURCE-REBUILD.md`, `evidence/commands.json`, `evidence/build-status.json`
and `SHA256SUMS`. Checksums are integrity records, not signatures. Preserve
complete corresponding source and license/relinking obligations with any later
redistribution. No app/IPA build, signing, publication, paid resource, primary
write, guest execution or device test occurred.
