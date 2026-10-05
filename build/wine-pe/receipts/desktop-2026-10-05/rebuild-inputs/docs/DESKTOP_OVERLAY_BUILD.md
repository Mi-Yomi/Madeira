# Source-built desktop Wine overlay, 2026-10-04

## Result

Six modules compiled and stripped for each of aarch64 and ARM64EC; all 12 images passed their exact architecture/CHPE gate. Outputs remain an uninstalled overlay. No app DLL farm, prefix, Wine source, submodule pin, IPA or signing state was changed.

## Source and tool identity

- Madeira base checkout: `62b0895cb87fda94e6307fa2bdbdbfc32d28d31d` from `https://github.com/Mi-Yomi/Madeira.git`
- Wine: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f` from `https://github.com/willfaust/wine.git`; clean tracked sources, matching the repository gitlink
- Recipe and inventory: the `build/wine-pe` files accompanying this document; exact copies and hashes also accompany the local overlay in `rebuild-inputs/` and `source-inputs.json`
- Host: Debian 13 x86_64, GCC 14.2.0, GNU make 4.4.1, bison 3.8.2, flex 2.6.4 and m4 1.4.19
- Official `llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz`, 82,139,820 bytes, SHA-256 `f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`; downloaded bytes matched the official release asset digest
- Clang 22.1.4, LLVM revision `35990504507d79e0b9deb809c8ee5e1b34ceef20`
- Two compile jobs; each architecture ran under a 2,700-second external timeout

The original target-prefixed compiler override failed ARM64EC by bypassing Wine's own Windows/MSVC target selection. Using the same toolchain's unprefixed clang fixes this without changing Wine. Both final architectures were rebuilt from fresh disposable trees with that corrected recipe.

## Final stripped DLL hashes

Hashes identify these particular outputs; bit-for-bit reproducibility across hosts, paths or build times was not established.

| Architecture | DLL | Bytes | SHA-256 |
|---|---|---:|---|
| aarch64 | `netprofm.dll` | 524288 | `8b9f454bf3628b15be92f7e5e9fbe9cd8eebfaf28365436e2455b01efc5e9629` |
| aarch64 | `sensapi.dll` | 458752 | `0d556b267be19519e0bf7fbcf612c9db9c354574220d651a1866c7b3d6def068` |
| aarch64 | `avifil32.dll` | 786432 | `af428e285d3b900600f53e910b1350acb24a44dc1a9190c4cf73eda2bfbba9b3` |
| aarch64 | `msvfw32.dll` | 524288 | `45e924c79f6312b8c9b4407cfabcafa40b6b4ceb13731b397311150c602bdcf2` |
| aarch64 | `msftedit.dll` | 589824 | `acca9eb3e17fe749657380f92592253b1b3885ebc38235d72d9cb4cf2f8edb21` |
| aarch64 | `riched20.dll` | 1048576 | `054efd72edca212ae7d88bbb386813f5d3532998fc1d9c79bb59531c8ad3430a` |
| arm64ec | `netprofm.dll` | 655360 | `4276d002bf3a535c0617957c69de3f22271e0a34d90524d334627c83da5eddfa` |
| arm64ec | `sensapi.dll` | 589824 | `516193aaf8cb454485855f730c9072ba804b682b2817d0db1b5c37bff8209238` |
| arm64ec | `avifil32.dll` | 917504 | `21568d6d73ab06b154256d7b3b946aeabab64dd019bd446c713bb3134d47684a` |
| arm64ec | `msvfw32.dll` | 655360 | `1ac0b38888abdce70250c3c7d436db6a2c5135890996dd7ffc0804fc0cc36560` |
| arm64ec | `msftedit.dll` | 720896 | `58a0f9bb9457f0a9ea686a7b36515beeb0a2058556321c14643a2b90341dbe52` |
| arm64ec | `riched20.dll` | 1179648 | `7e83ed39c4153baadf7561661abadb4527d91ea24e34de6925e14dddc31d3165` |

## Static import and export audit

- Every output has a complete export-table and normal/delay/forwarder record in the local `<arch>-symbol-audit.json`; independent LLVM `--coff-imports --coff-exports --coff-load-config` dumps accompany it
- aarch64: 464 imported symbols, 156 exports, 7 exported forwarders checked; zero missing direct symbols or forwarder targets
- ARM64EC: 465 imported symbols, 156 exports, 7 exported forwarders checked; zero missing direct symbols or forwarder targets
- The new outputs have no delay imports. Seven `msftedit` exports forward to `riched20`; those exact exports are present
- Resolution used each architecture's own existing farm plus its fresh six-DLL overlay. Existing export forwarders were followed recursively, including name/ordinal targets. The actual farm API-set schema was available; these checked paths did not require an API-set redirect
- Export counts per DLL in either architecture: netprofm 4, sensapi 3, avifil32 79, msvfw32 47, msftedit 14, riched20 9

### DLL dependencies of the new modules

- `netprofm.dll`: `iphlpapi.dll`, `kernel32.dll`, `ntdll.dll`, `ucrtbase.dll`
- `sensapi.dll`: `kernel32.dll`, `ntdll.dll`, `ucrtbase.dll`
- `avifil32.dll`: `advapi32.dll`, `kernel32.dll`, `msacm32.dll`, `msvfw32.dll`, `ntdll.dll`, `ole32.dll`, `rpcrt4.dll`, `ucrtbase.dll`, `user32.dll`, `winmm.dll`
- `msvfw32.dll`: `advapi32.dll`, `comctl32.dll`, `gdi32.dll`, `kernel32.dll`, `ntdll.dll`, `ucrtbase.dll`, `user32.dll`, `winmm.dll`
- `msftedit.dll`: `kernel32.dll`, `riched20.dll` (export forwarder), `ucrtbase.dll`
- `riched20.dll`: `gdi32.dll`, `imm32.dll`, `kernel32.dll`, `ntdll.dll`, `ole32.dll`, `oleaut32.dll`, `ucrtbase.dll`, `user32.dll`

Both architectures have this same DLL dependency set.

### Residual farm gaps

The combined inventories contain 141 aarch64 and 150 ARM64EC PE files. All parse successfully and all six required components are present. The six outputs introduce no new DLL-level closure gap. The pre-existing farm gaps are unchanged:

- aarch64: 14 edges, comprising 12 delayed imports and 2 export-forwarder dependencies
- ARM64EC: 11 edges, comprising 1 normal import (`bthprops.cpl` → `bluetoothapis.dll`), 8 delayed imports and 2 export-forwarder dependencies
- Both have the pre-existing `advapi32` → `cryptsp` and `secur32` → `sspicli` forwarder gaps
- i386 remains empty and was not built by this test

## Source, notices and potential integration

Each final overlay retains its full successful compilation log, `provenance.json`, copied LGPL text, the exact Wine fork notice, and Wine's bundled compiler-rt dual MIT/NCSA notice. The last one follows the real PE link commands, which link `libs/compiler-rt/<arch>-windows/libcompiler-rt.a`. The toolchain's newer LLVM Apache license is not a substitute for that bundled source notice. The official release archive, signed Debian package metadata, prerequisite hashes and complete clean Wine checkout are retained locally.

The source-only patch corrects stale Wine-specific GPL-conversion statements in the top-level `THIRD-PARTY-NOTICES.md` using the exact pinned fork notice. It makes no new licensing decision and changes no upstream copyright/license text. The older bundled `legal/THIRD-PARTY-NOTICES.md` remains stale until an explicit integration updates it.

If these DLLs are later copied into app resources, carry the corrected notices and exact source/rebuild identity with them:

- `legal/THIRD-PARTY-NOTICES.md`: refresh from corrected top-level notices
- `legal/Wine-LGPL-2.1.txt`: copy exact `wine/COPYING.LIB`
- `legal/Wine-LICENSE-MADEIRA.md`: copy exact `wine/LICENSE-MADEIRA.md`
- `legal/Wine-compiler-rt-LICENSE.txt`: copy exact `wine/libs/compiler-rt/LICENSE.TXT`
- Include a source/rebuild notice naming the final committed Madeira recipe revision, exact Wine revision, official toolchain checksum, commands and corresponding-source location

`app/Madeira/legal` already is a folder reference in `PBXResourcesBuildPhase`; these additions do not require separate per-file Xcode references. `app/Madeira/licenses` is also already bundled and contains an LGPL-2.1 text, but not these exact Wine branch/compiler-rt notices. Preserve existing unrelated notices. `build/stage-licenses.sh` currently refreshes only the GPL/Converter Exception copies in `licenses`; it does not refresh the stale `legal` notice. No app resource was mutated during this verification.

For an exact rebuild from these local outputs, follow the `SOURCE-REBUILD.md` retained beside each overlay. It checks out the recorded Madeira base and exact Wine gitlink, overlays the captured recipe inputs, verifies the official archive, and invokes the same recipe. Before redistribution, keep the complete corresponding source and those instructions available, and record the final published recipe commit. This audit alone is not a determination of overall distribution/relinking compliance.

## Verification limits

- Static tables and exported names/ordinals are not runtime loader, ABI, function-implementation or application-compatibility tests
- Not every import of every existing farm DLL was recursively symbol-audited; only the new DLLs' direct imports and required forwarder chains were checked
- Dynamic `LoadLibrary`/`GetProcAddress`, COM activation, SxS, installer/launcher behavior, real DNS/TCP/TLS, Wine Unix calls and iOS device behavior remain untested
- `sensapi!IsNetworkAlive` remains the pinned source's TRUE/LAN stub and does not prove connectivity
- Full-farm strict closure intentionally remains failing; adding the six DLLs is not a complete Wine distribution
- Successful final logs are complete. Early prerequisite/incorrect-target failures were removed by the original disposable-tree cleanup; only their diagnostic tails were retained

Portable PE/bounds, fail-closed staging, wrong-architecture, missing-tool, pin/dirty-source and notice-preservation regressions all passed after the fix.


## Automated evidence publication gate

The follow-on tooling change moves the manual handoff steps above into the
builder itself. Each new build requires the retained official archive via
`--toolchain-archive`; the digest/size and every extracted member are verified
before invoking that cross-toolchain. Host tools are recorded separately.
It captures actual Wine file SHA-256/Git-blob identities and all recipe inputs,
writes the complete source/rebuild record, runs mandatory name/ordinal import
and forwarder resolution plus independent LLVM metadata checks, preserves
original license bytes, and indexes all stage files in `SHA256SUMS`.
Missing evidence or an audit failure prevents publication of the whole stage.
Source and tool identities are rechecked after compilation; Git replacement
objects and ambient Git overrides cannot redefine the pin. Every farm/API-set
input used by the symbol resolver is hashed, compared to inventory, and
rechecked before publication. Hashing, PE audit
and LLVM metadata subprocesses have explicit bounds. No existing final stage
is rewritten by this change; these original hashes remain historical evidence.

The new portable suite `tests/host/check-desktop-build-receipts.py` injects
missing receipts, copied inputs, symbol reports, metadata and notices; changed
notices; unresolved-symbol reports; archive/extracted-tool substitutions; and
source/tool hashing limits. `tests/host/check-desktop-symbol-audit.py` exercises
the independent symbol parser and resolver. These tests complement the original
architecture/pin/strip/second-architecture failure regressions. A generated
receipt is a verified identity and rebuild guide, not proof of cross-host or
bitwise reproducibility, which still requires independently clean matching runs.
