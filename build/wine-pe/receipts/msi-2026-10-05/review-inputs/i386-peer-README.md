# Approved modern-i386 provider extension

The original 69-output candidate, audit and SHA256SUMS remain unchanged in the parent directory. This extension contains only the separately approved source additions cryptbase.dll and sspicli.dll. No krnl386.exe16 or other Win16 component was added.

Both additional providers built from the byte-reverified clean Wine pin with the existing official llvm-mingw toolchain in 0.534s, using <=2 jobs under the same 45-minute/log/disk bounds. No new tool, Unix runtime, DXMT component, app/IPA or installer was built/executed beyond these PE targets. All71 candidate files are left in an isolated experimental directory; none was installed in app resources or shipped.

Static result:
- 71 valid i386 PE images, 38,281,216 bytes total after strip-debug (typelib unstripped)
- 9,725 normal imported symbols: all resolve
- 452 delay imported symbols: all resolve
- 21,037 exports and 1,065 export-forwarders audited against the same candidate
- 141 unresolved export-forwarders remain, all legacy kernel32 ordinal entries naming krnl386.exe16; no missing exports or remaining normal/delay import failures
- All701 measured direct-import symbols across six original1C i386 helper/setup PEs resolve; the scheduled WellKnownSIDsDLL accounts for33, including msi ordinal144=MsiSetPropertyA and145=MsiSetPropertyW
- LLVM import/export/load-config metadata counts agree with the bounded byte parser for all71 images

This is NOT full all-export closure or a complete i386 runtime. The legacy16-bit exports are preserved and reported, not removed or hidden. The direct helper imports also do not prove instruction execution, correct ABI/calling conventions, custom-action IPC, server/user behavior, COM registration, licensing, or1C compatibility.

The separate native integration gate still needs a matching FEX WoW64 guest-window build and aarch64 ntdll/wow64/wow64win/xtajit/native server/Win32u. Source table binding is recorded in unix-wow64-source-audit.json; no native archive/device ABI was verified. Missing netapi32/winspool Unix behavior is not implemented by these PE builds. A matched64-bit MSI/cactions chain also remains absent from the app baseline, and the external1C Data1.cab remains unavailable.

No new library-license family is added by these two source modules. i386-licenses includes exact Wine, compiler-rt,zlib,JPEG,PNG,TIFF,musl,TomCrypt notices for the entire combined candidate and the IJG documentation acknowledgement. Source/tool and scripts retain reproducible input provenance. Nothing here accepts license terms or redistributes Microsoft/1C proprietary payload.

Use gate-summary.json for concise status, i386-static-audit.json for every import/forwarder check, i386-helper-imports.json for measured helper checks, build-command.json/build-result.json for only the two-provider extension, combined-build-result.json for the baseline-plus-extension audit input mapping, and SHA256SUMS for artifact integrity.
