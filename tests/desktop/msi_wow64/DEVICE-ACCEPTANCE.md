# Madeira MSI diagnostic: device acceptance

This source-owned fixture is the next narrow runtime check toward the 1C
installer path. It creates temporary MSI/DLL inputs and runs explicit custom
actions; it does not install or register a product. A pass does not establish
1C installation, application startup, UI, licensing or general i386 support.

## Build the diagnostic before collecting its runtime result

Compile the 64-bit canary with `MADEIRA_I386_DIAGNOSTIC=1`, embedding the exact
source-built i386 action. The default `build_msvc.cmd` and Windows-reference
runner omit that flag and retain their native-Windows behavior. Class 1010 is
private to Madeira; the diagnostic mode is not a native-Windows test.

A future diagnostic app may be built once its source/provenance, native link and
isolated launch route are established. A previous device pass is not required
to create that build: obtaining the missing device result is its purpose. The
canary flag alone does not implement that app mode or enable an i386 loader.
Do not copy an i386 farm into ordinary app resources to make this test available.

The app route must use a disposable prefix, a fixed source-built canary, an exact
reviewed PE inventory, and current native archives. Arbitrary launch overrides
must not select another executable or child. Require actual iPhone/iOS/JIT
readiness, ordinary i386 launch still disabled, and a real successful native app
link with FEXBridge capture. An archive/member pass alone is insufficient.
These app/launcher prerequisites are separate work; this directory implements
the canary and transcript checks only.

## Bind one run to exact inputs

Retain one receipt with:

- Device model, iOS version, JIT method/readiness, host architecture, disposable
  prefix identity, start/end times and externally observed process exit status
- Source hashes, native archive/compile receipts, final app/link-map hashes,
  diagnostic launch mode, full PE inventory, canary hash and embedded-action hash
- Complete bounded runtime output, its SHA-256, native loader/binder output and
  the relevant parent/child PIDs; retain failures and timeouts as failures

The current matched MSI set includes the reviewed dead-child startup wait fix.
Its `custom.c` SHA-256 is
`0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f`.
Its provider hashes are:

- aarch64: `6845b17db8b5650fd7637718c2fbcd8467b02060d179354e78ed3037321d2f6e`
- ARM64EC: `6b611ac3a9c9b1200314397ab033e03ce1a5d9e93f6be3337a935ca33f124a9f`
- i386, inactive: `46d3348f16188e5b05a13b3e01564a652b0b3f7af0b6555d23d110e8169bd0e0`

These identify this reviewed MSI set, not a complete device build. The previous
client-fix set used source `9c6db846…`, AArch64 `c04b4aa7…`, ARM64EC `3c69a7be…`
and inactive i386 `1fe60025…`; it is retained as historical evidence and lacks
the startup fix. The older i386 MSI ending `13a7746` also predates the client
property-reply correction. Neither historical set may substitute for these
matched providers. Re-audit any changed provider.

The new static checks preserve the 296-export API and allow exactly four added
`kernel32.dll` imports. Fresh full import resolution was checked for the two
active architectures only; the i386 provider remains inactive evidence. The fix
handles a child that exits before connecting. A live child that never connects,
later stalled action I/O and shutdown remain unbounded. The build and source
model tests do not establish any of the runtime observations below.

## Required observations on an iPhone with working JIT

1. Run the aarch64 host. Both Unicode/ANSI property rounds must pass, proving
   the embedded action executed out of process with 32-bit pointers and MSI
   ordinal imports 144/145. Parent class-1010 base must be zero initially,
   after each round and after the negative action
2. Both rounds must observe the same live SysWOW64 `msiexec.exe`, the same
   retained process handle/PID, and the same nonzero 4-GiB-aligned guest base.
   Correlate its PID/base with native loader/binder logs, including i386 ntdll,
   API-set routing and intended WoW64 syscall/Unix-call tables
3. The missing export must fail without any proof properties; the same child
   must still be live with its unchanged image/base afterward. Session close,
   retained-handle child exit with status zero, temporary-input cleanup, final
   proof and externally observed host exit zero are all required. The 60-second
   watchdog or the 5-second child-exit timeout always means failure
4. Repeat from a fresh session after teardown, then repeat with the x86_64 host
   to exercise the FEX parent route. Inspect native window release/reuse and
   absence of stale prefix state; child exit alone does not prove those facts

Validate each saved canary log with:

    python3 tests/desktop/msi_wow64/madeira_reference.py runtime.log --exit-code 0

Pass the actual observed exit code. The parser enforces a 1-MiB input bound,
exact proof order, identities, stable aligned base, post-negative child
liveness, required controls and exit
proof. A successful parse validates supplied text only; it does not authenticate
the device, build, JIT state, native table binding or memory reclamation.
Correlate the separate native logs and receipt before accepting the run.

After this canary passes, pointer-boundary/syscall/Unix-call probes and the
user's separately authorized real 1C installer/application tests remain. A
successful diagnostic must never automatically enable general i386 launches.
