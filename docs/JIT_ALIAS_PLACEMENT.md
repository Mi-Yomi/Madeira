# JIT RW-alias placement

The debugger-created RX pool keeps its existing accepted-address and
executable-window checks. Its writable alias now requests these hints in order:

1. `0x7000000000`, the existing high-address preference
2. The first address above the RX pool
3. `0`, allowing the kernel to choose

Only `KERN_NO_SPACE` advances to another hint. Setting
`env.MADEIRA_RW_ALIAS_RETRY = 0` retains the single high-hint attempt. All requests
use `VM_FLAGS_ANYWHERE`, never fixed/overwrite mappings, and the returned address
is used rather than assuming the requested hint won. An overflowing above-pool
calculation omits that hint instead of wrapping into a low address.

This is a focused adaptation of upstream
[`184591a9`](https://github.com/willfaust/Madeira/commit/184591a92806214d8009ccee3fd7bdb7da4944b0).
The upstream report describes 63 GiB address maps where the high hint is outside
the map and a no-hint retry can consume a low hole needed by fixed-base x64
images. Trying above RX first reduces that risk; it does not reserve the hole or
guarantee the hint will fit. The final no-hint fallback remains available.

The port preserves the existing RW-overlap diagnostic, RW protection change,
cleanup of the alias after a failed protection change, and non-fatal footprint
exemption. In particular, RW executable-window overlap remains diagnostic-only;
it is not a new rejection rule. Existing RX ownership and failure cleanup are
unchanged.

## Host regression

Run `python3 tests/host/check-jit-alias-placement.py` on a host with `swiftc`.
The test compiles the production Swift ladder, alias/protection/finalization
block and RX-selection loop with inert hooks. Before execution it rejects a
binary with direct unresolved Mach VM calls. The regression exercises:

- Ordered attempts and the actual arguments to each remap
- Early success, disabled retry and terminal errors at each stage
- A returned address different from the hint, plus boundary/overflow arithmetic
- RX accepted-band and executable-window boundaries, null responses and rerolls
- Existing RW-overlap logging, protection failure and single-alias cleanup
- Footprint exemption remaining non-fatal and pool readiness only after success

The asserted remap operation counts are 1 for high-hint success, 2 for
above-RX success, and at most 3 for fallback. The disabled switch makes one
attempt. No real Mach VM operations, JIT execution, account access or iOS device
are involved. These are host control-flow checks, not device performance results
or evidence that a particular game launches.

`--source-only` explicitly limits the test to source integration and the changed
Settings catalog row when Swift is unavailable. It reports the compiled checks
as skipped. Compiled host tests and iOS/device validation remain distinct;
macOS compilation does not validate Darwin VM placement or iOS JIT behavior.
