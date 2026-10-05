# Memory overlay

The wide FPS overlay retains the app's `TASK_VM_INFO.phys_footprint` readout
and adds `avail ~NMB`: the latest system-reported per-app physical-memory
headroom, through the existing `jit_available_memory()` bridge. Both readouts
use binary megabytes (1,048,576 bytes), as the original footprint display did.
The compact overlay and the FPS, pacing, capture, ECO and fence controls retain
their visible behavior.

There is no fixed 4096 MB ceiling. Apple documents that
[`os_proc_available_memory()`](https://developer.apple.com/documentation/os/os_proc_available_memory)
reflects the current app memory limit minus its footprint, that limits may
change during the app lifecycle, and that the value is advisory. It is not
system-wide free RAM, virtual address space, a reservation, or a guarantee
against failed allocation or termination. The independently queried footprint
and headroom are not added to infer a limit or used to control allocations.

- A failed footprint query displays `?MB`, never a fabricated zero
- Positive headroom below one megabyte displays `avail <1MB`
- Zero headroom displays `avail ?` in red: the API can report zero when
  headroom is exhausted or when the caller is not an app. The accessibility
  value explains the ambiguity; no reading yet is neutral/unknown
- The existing 768/384/128 MB color bands now use reported headroom directly.
  They are display heuristics, not system pressure levels or safety boundaries
- The visible wide overlay refreshes footprint and headroom on appearance and
  the existing 250 ms display timer. The compact layout skips both memory
  queries because it has no memory readout. The 100 ms FPS sampler never
  queries memory
- Hiding the overlay pauses its two timers, leaving only the dot. Showing it
  takes a fresh sample and resets the FPS window instead of including hidden
  time. Reappearance invalidates old timers; disappearance stops both. This
  does not disable or change the session's ProMotion/pacing intent

Run `python3 tests/host/check-memory-overlay.py` with `swiftc` (or `SWIFTC`)
for compiled production-policy and deterministic timer-lifecycle tests,
including repeated show/hide, hidden reappearance and compact-mode hook counts. On a
host without Swift, `--source-only` is a limited wiring check and explicitly
skips behavior. Neither test simulates an iOS memory limit, real system API
responses, SwiftUI layout, or on-device termination.
