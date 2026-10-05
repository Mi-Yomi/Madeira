# Launcher child lifetime

Some desktop launchers create a second process and then exit successfully.
[Upstream issue #189](https://github.com/willfaust/Madeira/issues/189) reports
that pattern with Ubisoft Connect. It is also a useful regression scenario
for installers and application launchers; it does not prove 1C compatibility.

Madeira already has the per-application opt-in `MADEIRA_WAIT_CHILDREN=1`.
It remains off by default. The existing bounded registry tracks up to 32
pseudo-process children. Its helper-name and initial 60-second age filters
are heuristics, not a complete Windows descendant process tree.

## Corrected ownership

Previously a child's slot was released only when its boot pthread returned.
`ExitProcess` from a worker could leave a stale slot and an endless session wait.
Each reservation now has a non-reused generation token and is bound to the
child PEB during server initialization. Common process-exit teardown detaches
the PEB and pins that token until image, socket, descriptor, JIT and window
cleanup completes. Boot-thread fallback cannot release the pin prematurely.
Late cleanup also cannot release a newer child that reused an old slot or PEB.
An owner-scoped finalizer also releases the reservation if teardown aborts via
`pthread_exit`. The iOS exit shim unwinds through that scope before its outer
boot-thread `longjmp`, so it cannot leave a dangling pthread cleanup record.

Failed spawns and early boot returns still release their reservations. No
arbitrary timeout or forced child termination was added: either can discard
unsaved application work. Graceful Quit retains the existing Alt+F4 route.

## Verification and limits

`python3 tests/host/check-child-lifetime.py` compiles the production registry,
common exit wrapper and opt-in wait loop with modeled guest teardown hooks.
The host regression covers normal and worker exits, crashes, launcher handoff,
failed boot, registry saturation, stale generations, 6,000 concurrent reuse
cycles, boot-thread cleanup interleaved at every teardown stage, and owner
termination through both pthread-exit and iOS-exit routes. It runs
with address/undefined-behavior sanitizers by default.

This fixes lifetime bookkeeping. It does not terminate all surviving guest
threads, serialize the pre-existing duplicate resource-teardown paths, establish
safe repeated full app sessions, or guarantee a background child will exit.
Finalizing an aborted teardown does not finish the resource cleanup it skipped.
Real installer/application and iOS device checks remain necessary.
