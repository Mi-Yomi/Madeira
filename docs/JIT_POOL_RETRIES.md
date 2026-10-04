# Safe JIT pool retries

The initial address-space placeholder belongs to Madeira only until its first
release. A later failed-launch retry must not unmap that old address range: the
allocator, Metal or IOSurface may have reused it in the meantime.

This port follows upstream
[`caf5d9ac`](https://github.com/willfaust/Madeira/commit/caf5d9ac84011011ed632715217b5d1810a509a4),
with a synchronized one-shot gate around the actual release attempt. The gate
also records a failed attempt so an uncertain old mapping is never blindly
unmapped again; the error is logged instead of reported as a successful release.
It does not make the rest of pool allocation reentrant or change its placement
rules. Missing/zero-size placeholders do not consume the gate.

Readiness polling now uses the existing quiet `SigningStatus.current.debugged`
query instead of the logging `jit_check_debugged()` query. Readiness still
requires the same CS_DEBUGGED/live-debugger or already-created-pool conditions.

`tests/host/check-jit-pool-release.py` compiles the production gate, release
integration and readiness code with inert hooks. It reproduces two deallocation
calls in the old unguarded retry fragment, then requires exactly one for the
guarded path, including 128 concurrent claims and failed-release retries. Three
hundred not-ready polls must produce zero noisy-query calls. These are operation
counts in a host regression, not an iPhone performance measurement or proof of
JIT/device behavior. macOS CI runs the compiled test; `--source-only` explicitly
limits local checks when Swift is unavailable.

The existing default attach checks, user-facing debugger errors, trap fallback
and guest executable placement rules remain in force.
