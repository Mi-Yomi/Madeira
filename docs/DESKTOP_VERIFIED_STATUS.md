# Verified desktop compatibility checkpoints

Updated 2026-10-05. These checkpoints describe the tested commits and scopes.
Neither 1C nor Windows Blender has been run inside Madeira by this work.

## Full iOS app compile and link

Commit [`10a8a2f`](https://github.com/Mi-Yomi/Madeira/commit/10a8a2f18f804470897cbb3e2ad4fb3ca214b431)
passed the [complete app link diagnostic](https://github.com/Mi-Yomi/Madeira/actions/runs/37302715936):

- All 20 native iOS ARM64 archives: 30,356,385 bytes
- All 34 required LLVM archives, Metal AIR decoding and 87 DXMT objects
- Combined DXMT archive: 59,905,080 bytes and 1,057 object members
- Actual iOS 27 Metal shader smoke test, unsigned app compile/link, and final
  bundle validation with 309 tracked guest PE files

The native archive contract also passed eight captured production objects,
strong ownership checks and all six NSI record layouts. Its optional final
native-link/FEXBridge capture was **not** collected; the receipt correctly has
`final_link: null`. The app's successful link does not substitute for that
separate ABI evidence or for device execution.

Packaging, signing and artifact uploads were disabled. No IPA was created and
the temporary unsigned app is not a delivered or durably retained download.
This result establishes compilation and bundle consistency at the stated
commit, not iPhone JIT, Wine processes, input, rendering or application support.
Later provider changes need their own validation.

## Source-owned installer reference

Commit [`83abff90`](https://github.com/Mi-Yomi/Madeira/commit/83abff90c4392a848255563621bc2fab3a3ddd22)
passed the [native Windows MSI reference](https://github.com/Mi-Yomi/Madeira/actions/runs/37310383730)
and [portable/macOS regressions](https://github.com/Mi-Yomi/Madeira/actions/runs/37310383729).
The Windows reference executed its own embedded i386 custom action in two
rounds, checked Unicode/ANSI properties and SID lookups, rejected a missing
export with error 1603 and closed its session successfully. It did not run a
proprietary installer or exercise Wine, FEX or Madeira.

The separate Madeira diagnostic now requires the same live child/image/guest
base after its negative action and an unchanged native-parent base at every
checkpoint. This prevents an early clean child exit from satisfying that
control. Its host tests and cross-compiles passed; its iPhone runtime has not
run. See the [device acceptance contract](../tests/desktop/msi_wow64/DEVICE-ACCEPTANCE.md).
Ordinary i386 app launches remain disabled.

### Dead custom-action child during startup

The reviewed MSI startup change makes the parent wait for either its pipe
connection or child-process termination. A child that dies before connecting
now produces a nonzero failure. Pending connection cancellation is drained
before releasing its event or stack storage; later operations on that pipe use
the matching overlapped-I/O contract. No production installer timeout is added.

The exact three helper bodies passed the
[real Windows API reference](https://github.com/Mi-Yomi/Madeira/actions/runs/37314605300)
at `1769ad970b8292cd70bc766834d0360b6de7ce08`: all eight cases passed, with
64 connection/death races and 256 complete serialized exchanges. Every case
confirmed cleanup, and no outer test watchdog fired. The deterministic
both-signaled case observed process-first selection and the cancellation race.
The separate 64-race case observed 64 successful connections before child exit;
it does not claim both race outcomes occurred in that particular run.

The source-built AArch64/ARM64EC MSI replacements preserve all 296 exports and
add exactly four kernel32 imports. Their 331/332 imports resolve in the current
farms. The [fixed integration record](../build/wine-pe/msi-startup-integration.json)
and [source/rebuild receipt](../build/wine-pe/receipts/msi-startup-2026-10-05/build/README.md)
bind the exact source, toolchain, outputs, predecessor identities and notices.
Historical receipts remain unchanged. The rebuilt i386 provider remains
evidence-only and has no fresh full peer-farm import-resolution result.

This Windows helper result does not establish execution of the rebuilt Wine
DLLs, Madeira or a 1C installer. A live child that never connects, stalled later
action I/O and shutdown retain their existing unbounded waits. Bitwise build
reproducibility across paths/times/hosts is not established. The full app-link
checkpoint above predates this new provider pair; its new app result must be
recorded separately when available.

## Graphics reference and remaining blocker

The source-built Mesa 26.2.4 softpipe
[Windows reference](https://github.com/Mi-Yomi/Madeira/actions/runs/37280616713)
passed real GDI backing pixels and two distinct GL backbuffer/post-swap colors.
It reported OpenGL 3.3 compatibility. The pinned source/configuration cannot
supply the required OpenGL 4.3 GLSL level; this is a source capability result,
not a measurement of the maximum core context. The earlier failed core-context
request remains a failure.

A stricter modern canary is prepared for actual 12-buffer shader operations,
indirect draw parameters and clip-control behavior. It has not passed a capable
Windows renderer. No OpenGL backend was added to Madeira, and Direct3D/Metal
support alone does not provide Blender's OpenGL UI.

The official LLVM 22.1.4 MSVC SDK investigation established an exact selected
closure of 70 static libraries, 203,711,068 bytes and 1,691 object members.
Its additional ATL, DIA and CRT providers require separate validation. The
[final read-only provider inventory](https://github.com/Mi-Yomi/Madeira/actions/runs/37311092068)
is rejected/incomplete: only 18 of the 20 provider libraries completed the
strict archive audit. No C++ ABI probe, MCJIT probe or llvmpipe build passed.

The final member evidence identifies `NoRegCoCreate` in `guidstr.obj` and both
required GUIDs in `dia2_i.obj`. Their recorded symbols/directives contain no
direct dependency on the MD-tagged `stdafx.obj` PCH symbol. This does **not**
prove which members an eventual complete link would select, nor establish an
actual mixed-CRT conflict. The first blocked `libcmt`/`oldnames` members have
machine-neutral headers, one debug section and weak aliases. The current
reader's rejection alone establishes neither corruption nor an incompatible
runtime. Inspecting those first members does not complete either archive audit.

Further SDK runtime retries are deferred pending a complete, reviewed provider
closure and actual link-selection evidence. No provider policy was relaxed,
members stripped, CRT defaults suppressed or vendor metadata rewritten to
obtain a pass. The MSVC x64 SDK is also not a drop-in MinGW, ARM64EC or iOS
library. Even a future native Windows llvmpipe pass would leave Madeira/FEX
execution, UIKit presentation and practical iPhone performance unproved.

See the [Mesa reference](../tests/desktop/mesa_wgl/README.md),
[modern graphics canary](../tests/desktop/mesa_wgl/MODERN.md) and
[provider evidence scope](../tests/desktop/llvm_sdk/PROVIDER_INVENTORY.md).
