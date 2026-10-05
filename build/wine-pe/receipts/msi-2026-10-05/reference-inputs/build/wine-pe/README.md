# Guest DLL inventory and the desktop overlay

This directory keeps guest PE checks separate from native iOS builds. No command
below packages an IPA, signs, uploads, changes a prefix, or downloads DLLs.
Presence and static imports are **not** evidence that an installer, launcher,
Blender, 1C, or a game works on a device.

## Audit a checkout

```sh
python3 build/wine-pe/guest_inventory.py
python3 build/wine-pe/guest_inventory.py --json > /tmp/guest-inventory.json
python3 build/wine-pe/guest_inventory.py --require-components
python3 build/wine-pe/guest_inventory.py --require-closure
python3 build/wine-pe/guest_inventory.py --profile vc2012 --require-components
python3 tests/host/check-guest-dll-inventory.py
```

The default command reports incompleteness without failing solely for missing
DLLs; corrupt images, case-colliding filenames, symlinks, and wrong architectures
always fail. `--require-components` requires the selected profile in **each**
selected farm (`--arch` may be repeated). `--require-closure` requires a nonempty
farm and all normal, delay-loaded and export-forwarded DLL targets. Delayed
imports are reported separately because they need not block process startup.
The JSON report includes every module's SHA-256, size, machine interpretation and
dependency edges, so a later source rebuild can be compared without guessing.

The checker reads PE structures directly, without executing guest code or
requiring host objdump support for ARM64. ARM64EC executable images may use the
AMD64 (`0x8664`) header; their load-config CHPE metadata distinguishes them from
ordinary x64 images. Existing emulated x64/test/data-only images are permitted
in the ARM64EC farm, but the six rebuilt desktop DLLs must have ARM64EC metadata.
Aarch64 and i386 outputs must match their own architecture; another farm cannot
satisfy a dependency. The actual v6 `apisetschema.dll` resolves API-set imports,
including the hashed contract-version prefix and importer-specific aliases. Unresolved contracts are not silently
ignored. This is a DLL-level audit; it does not resolve every exported symbol,
SxS activation context, dynamic `LoadLibrary`, COM activation or host Unix call.

## Measured baseline, 2026-10-04

The fork's Wine gitlink is `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`.
All 279 existing PE files parsed successfully:

| Farm | PE files | Reported dependency gaps |
| --- | ---: | --- |
| aarch64-windows | 135 | 12 delay + 2 forwarder edges |
| arm64ec-windows | 144 | 1 normal + 8 delay + 2 forwarder edges |
| i386-windows | 0 | Empty farm, not a successful closure result |

125 of the ARM64EC farm's 144 files carry CHPE metadata. The remaining 19 have
x64 headers without that metadata, including test executables and data-only or
forwarder libraries. All 135 aarch64 images have the ARM64 machine type.
The i386 directory in this fork contains only `.gitkeep`, despite community
reports describing fuller release bundles. It needs the existing full
`build/wine-i386/build.sh` chain, not just six extra DLLs.

All six desktop-profile DLLs and both optional VC2012-profile DLLs are absent
from both populated farms. There are also these pre-existing closure gaps:

- Both populated farms: `cryptsp`, `sspicli`, `evr`, `glu32`, `cabinet`,
  `gdiplus`, `shdocvw`, `mlang`, `advpack`
- Aarch64 additionally: `winspool.drv`, `inetcomm`
- ARM64EC additionally: `bthprops.cpl` normally imports `bluetoothapis.dll`

The two forwarder gaps are `advapi32 -> cryptsp` and `secur32 -> sspicli`.
These are measured static dependencies, not a recommendation to ship every
module blindly: e.g. adding `glu32` does not create an OpenGL backend. Rebuild
and assess each relevant component chain, then repeat the audit. Strict closure
is intentionally red on this baseline. The portable regression suite is green
because it tests the checker, and does not hide these gaps.

## Minimal source-backed desktop component closure

The small `desktop` profile in `desktop-components.json` is based on exact
community reports and inspection of the pinned Wine source:

- `netprofm` and `sensapi`: missing connectivity APIs in
  [issue #189](https://github.com/willfaust/Madeira/issues/189#issuecomment-5981910061)
- `avifil32` plus its `msvfw32` dependency: AVI imports from the same report;
  the dependency is explicit in the pinned
  [avifil32 Makefile](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/avifil32/Makefile.in)
- `msftedit` plus `riched20`: installer failure in
  [issue #151](https://github.com/willfaust/Madeira/issues/151); the pinned
  [msftedit Makefile](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/msftedit/Makefile.in)
  links riched20 and its DllMain explicitly loads it to register window classes

`uuid` in those Makefiles is an import/static library, not a missing `uuid.dll`
to invent. The existing prefix template was inspected read-only: both native
and Wow6432Node NetworkListManager/AVIFile COM keys already name `netprofm.dll`
and `avifil32.dll`. No registry rewrite or prefix-template replacement is needed
for that observation.

The final issue #189 follow-up reports actual ARM64EC Wine DLL loading and API
success, but Trackmania still exits `0xDEADC0DE`; it is not game-compatibility
proof. In particular, the pinned
[`sensapi!IsNetworkAlive`](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/sensapi/sensapi.c)
always returns TRUE/LAN. A successful call therefore proves neither Internet
access nor a working VPN route. Verify real DNS/TCP/TLS separately on device.

The `vc2012` inventory profile covers Wine's `msvcr110` and `msvcp110`, from
[the separate report](https://github.com/willfaust/Madeira/issues/189#issuecomment-5975777529).
It is not built by the bounded desktop recipe below. This does not copy
Microsoft redistributables or imply they can be redistributed under Wine's
license.

## Rebuild a fresh, uninstalled overlay

Read `docs/BUILDING.md` for the verified llvm-mingw download/checksum, source
availability and licensing limits. Initialize the exact Wine submodule at
`<Madeira>/wine`; its source includes Madeira's adjacent `build/madeira_cfg.h`.
Have bison 3.0+, flex and GNU make on PATH and the appropriate **host** llvm-mingw
20260421 toolchain available. macOS's system bison 2.3 is insufficient. The
script installs no prerequisite and never accepts license prompts. ARM64EC also
requires the same toolchain's x86_64 companion compiler. Ambient compiler,
configure-cache and make overrides are not inherited: the verified toolchain's
unprefixed `clang`, host `cc`, `-O2` host flags and `-g -O2` cross flags are
explicit and recorded. Wine selects its own `-target <arch>-windows` flags.
Do not replace the unprefixed compiler override with a target-prefixed MinGW
wrapper: at this source pin that suppresses Wine's Windows/MSVC target choice
and breaks ARM64EC on GNU-mode x86 inline assembly.

```sh
# Plan only; works even without Wine/toolchain present.
python3 build/wine-pe/build_desktop.py

# Actual bounded PE compilation when the prerequisites are present.
python3 build/wine-pe/build_desktop.py --build --arch aarch64 --arch arm64ec \
  --jobs 2 --toolchain-archive /path/to/llvm-mingw-20260421-ucrt-macos-universal.tar.xz \
  --output build/wine-pe/out/desktop

# An i386 overlay is useful only alongside a complete WoW64 farm.
python3 build/wine-pe/build_desktop.py --build --arch i386 \
  --toolchain /path/to/verified/llvm-mingw/bin \
  --toolchain-archive /path/to/reviewed-llvm-mingw-archive.tar.xz \
  --output build/wine-pe/out/desktop-i386
```

The output directory must be new. The recipe:

1. Rejects a missing/dirty Wine source tree or any Wine pin different from the
   manifest and repository gitlink; no source patch or submodule update occurs
2. Creates one clean disposable build tree for each selected architecture
3. Builds exact `dlls/<module>/<arch>-windows/<module>.dll` targets, never
   `dlls/<module>/all` (which can invoke unwanted host Unix backends)
4. Preserves upstream's ARM64EC `stdole2.tlb/aarch64-windows` alias and uses
   `--strip-debug`, with no ntdll-style padding
5. Validates every fresh PE and its imports after stripping, then publishes
   the **whole** requested stage only after all architectures succeeded;
   compilation, stripping, missing-file or architecture failure publishes none
6. Before executing the cross-toolchain, checks the original official archive's
   pinned digest and size and compares every extracted file/link and executable
   mode. Only the reviewed 20260421 Linux x86_64 and macOS universal archives
   are accepted; an arbitrary user-supplied checksum is not proof of origin
7. Hashes each actual tracked Wine source file, verifies its Git blob and mode,
   rejects untracked/ignored Wine inputs and replacement-object pin bypasses,
   and captures exact recipe, manifest,
   inventory, symbol-audit helper, tests, rebuild header and notices
8. Audits every new DLL's name/ordinal imports and export-forwarder chains
   against its own farm plus overlay, binds every resolver input to the inventory
   and rechecks farm bytes before publication, writes independent LLVM import/export/
   load-config dumps, and rejects missing symbols or LLVM/parser disagreements
9. Rechecks source/tool identities, preserves the exact upstream notices, and
   publishes only after every required evidence file passes the final seal.
   Missing audits, metadata, captured inputs, logs or notices publish nothing

The stage includes `source-inputs.json`, `toolchain-receipt.json`,
`SOURCE-REBUILD.md`, `rebuild-inputs/`, `licenses/`, per-architecture inventory
and symbol-audit JSON, `readobj/` LLVM dumps, complete build logs and
`provenance.json`. `SHA256SUMS` covers every regular file except itself.
Host compiler/parser/make tools are resolved explicitly and their real paths,
versions (where supported) and streaming hashes recorded separately from the
verified cross-toolchain. Auxiliary host headers/libraries, wrapper data and OS
are not a hermetic image. Source/toolchain hashing has byte/file-count limits;
PE symbol audits and LLVM subprocesses have size/count/time limits. Source and
toolchain verification repeat before publication to catch changed inputs.
Builds remain bounded to at most two compile jobs and fresh all-or-nothing
staging outside app resources. No bitwise reproducibility claim is made.

Run the focused regression suites without a compiler or guest execution:

```sh
python3 tests/host/check-desktop-build-receipts.py
python3 tests/host/check-desktop-symbol-audit.py
```

The standalone symbol helper can re-audit an existing overlay into a **new**
evidence directory; this does not create a source-build receipt retroactively.
Pass its exact `--readobj` path from a verified toolchain. The actual builder
requires `--toolchain-archive` and never falls back to an LLVM tool on PATH.

The allowlisted profile cannot replace the specially padded `ntdll` or the
DXMT/D3D12/FEX-owned DLLs. Nothing is copied into `app/Madeira` automatically.
This overlay does not repair unrelated pre-existing farm gaps; a successful
build is not a successful strict full-farm closure check. Review source and
applicable Wine/toolchain notices before redistributing any staged binary;
keep complete corresponding source and rebuild instructions available.

**Verification status (2026-10-04):** the dry-run, real 279-file baseline
inventory and portable failure-injection regressions passed. On Linux x86_64,
the official checksum-verified llvm-mingw 20260421 host release compiled and
stripped all six DLLs for aarch64 and ARM64EC from the clean exact Wine pin.
The six outputs passed PE architecture/CHPE validation. Their static imported
symbols and export forwarders resolved against their own existing farms plus
the overlay. See `docs/DESKTOP_OVERLAY_BUILD.md` for exact hashes, sizes,
source/rebuild identity, dependency counts and limits. No generated DLL was
installed into app resources by this verification.

Actual import/export behavior inside Wine, installer/COM smokes and iOS device
behavior remain **UNVERIFIED**. Full-farm strict closure remains red on the
pre-existing gaps above; i386 is still empty. This records a source-build and
static audit, not runtime compatibility or complete redistribution compliance.

## Relationship to October 4 upstream work

The recipe incorporates the relevant approach from
[upstream b4bf4198](https://github.com/willfaust/Madeira/commit/b4bf419888233a24b2d992d8bbe0d5f75f553aff)
and its [ownership guard](https://github.com/willfaust/Madeira/commit/5137e8b1ca5c22f4ca73614cbaffd589613bcf3e):
exact PE targets, strip-debug, the typelib alias, and protection for other
providers. The local extension is architecture-specific fresh staging and a
portable completeness gate rather than a generic in-place farm installer.

Upstream [828be772](https://github.com/willfaust/Madeira/commit/828be77229f47d999bdb344a47b36da21e985d42)
adds 18 launcher/installer builtins. That is a useful follow-on source-rebuild
candidate, not a DLL bundle to copy into this older fork. The earlier
[upstream repin](https://github.com/willfaust/Madeira/commit/7b5680047980cb7b018c5b3ecd727ef95769e3d8)
changed Wine to `3a54f56896c85c932870afe6fd91404bbbcb74c8`. The launcher group
also includes `msxml3` with statically linked Wine-bundled libxml2/libxslt,
whose MIT notices upstream correctly added. Any future expansion must inspect
our exact source pin, include those corresponding notices, and address WMI
`wbem` placement separately; filename presence alone is insufficient.
