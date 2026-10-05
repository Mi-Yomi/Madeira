# Checked launch readiness

Wine must not start until the wineserver has actually published readiness.
`build/wineserver/main_ios.c` already publishes it with release ordering after
registry initialization and HID setup. Registry loading changes the whole
process's working directory, so starting Wine while it is still running can
race the game's working-directory setup. This change leaves the native
publication site unchanged.

Previously the frontend polled for at most two seconds, then unconditionally
logged “ready” and launched Wine. The legacy fixed-delay setting never checked
readiness at all. A failed server-thread start was logged but otherwise ignored.

## Frontend behavior

`WineServerLaunchGate` in `ContentView.swift` is the production, Foundation-only
ordering logic:

- A failed server start does not poll, announce readiness, start Wine or join an
  uncreated server thread
- A server observed as stopped wins over a stale ready bit
- A ten-second timeout without readiness fails closed: no ready log or Wine start
- Fast mode starts as soon as readiness is observed. Disabling
  `MADEIRA_FAST_SERVER_START` retains the two-second minimum delay and then
  requires readiness too. If registry initialization takes longer, either mode
  can wait up to the separate ten-second bound instead of rejecting a cold start
- The elapsed-time source is monotonic system uptime. Readiness observed exactly
  at the deadline is sufficient. A delayed wake strictly after it times out
  before accepting readiness, even if the ready bit is now set; elapsed time by
  itself is never sufficient. The clock is checked again after the ready-bit
  read, so a suspension during that observation cannot reuse a pre-deadline
  timestamp. The ready log uses this post-observation timestamp
- The final Wine-start wrapper checks running and ready again, and both wrappers
  propagate their native return values

A failed launch queues main-thread cleanup to restore UI logging, stop its
diagnostic heartbeat and report failure before the worker joins a server it
started. The main thread remains free to run that cleanup during a slow join.
The join still depends on native initialization returning; the frontend does not
claim to have cancelled blocked registry I/O. Launch admission stays reserved until the worker/join returns.
The failure tells the user to close and reopen Madeira before another attempt.
Readiness published later during the join cannot restart the abandoned launch:
there is no pending Wine-start callback, and the worker returns after the join.
The JIT-pool failure branch uses the same UI cleanup.

Admission also covers the interval before any native running flag is set.
Repeated developer launch buttons are rejected before changing process-wide
launch environment. Library starts recheck before applying their profile.
Dock reserves admission while waiting for Steam's account connection to close,
then hands it directly to the full sequence without another suspension. This
prevents a duplicate Dock continuation from deleting another launch's handoff
while cleaning up its own rejection.

Dock's report watcher also has an attempt identity. A new admitted launch
invalidates the previous identity before canceling the old task and before
awaiting account-connection closure. Replacing a watcher does the same. A canceled sleep may
resume, but an old watcher cannot read the new report, overwrite its status,
remove its one-use handoff or release its account hold. The active watcher's
normal report and idle-timeout paths still clean up exactly once. This closes
a pre-existing retry race without enabling repeated Wine sessions or changing
the one-session policy. Preparation failure still uses the launch's existing
cleanup; retiring an observer alone does not release an account hold.

## What this does not change

The native bridge's `fatal_error()` exits its pthread directly, bypassing the
normal thread-function assignment that clears the running flag. Such an abnormal
pre-readiness exit can therefore appear as a timeout rather than an immediate
“stopped” result. It still cannot start Wine without readiness, and the failed
attempt's stop/join clears the running flag. Improving native termination status
is outside this frontend patch.

There is no new startup-cancellation contract. The existing library “Close
session” action records a graceful quit request and posts Alt+F4 to the guest;
there may be no guest yet while startup is pending. Closing Madeira ends the
app. Dismissing a details/setup view or a cloud-save notice does not cancel a
full-sequence background worker that has already started.

A later startup-cancellation change needs an explicit, main-thread-owned attempt
identity/cancellation signal shared with the library, a defined boundary before
Wine creation, and cleanup that cannot affect a newer attempt. It also needs to
respect the existing one-session-per-app-run policy: `LibraryModel.begin()`
counts the attempt before native startup, and JIT/native globals are not reset
merely by returning to the library. Cancellation must not imply that another
Wine session is safe in that same app process. This patch does not modify
`Library.swift`, the native lifecycle or the one-session configuration.

## Verification

Run the production Swift gate and native-start wrapper regressions on a host
with Swift installed (macOS CI uses this command):

```sh
python3 tests/host/check-launch-readiness.py
```

The harness injects a deterministic clock and inert native functions. It checks
immediate/delayed/deadline readiness, cold starts beyond the old two-second
cutoff, fast and legacy timeouts, server start
failure, stopped/stale-ready combinations, stopped-during-wait, Wine start
failure, oversleeps with late readiness in both modes, repeated requests and
all admission-flag combinations.
No app, IPA, JIT, Wine process or device is built or started.

`python3 tests/host/check-dock-watch-lifetime.py` compiles the production report
watcher with real Swift tasks, cancellation and MainActor isolation. The sleep
call is replaced with a controlled suspension, and report/file/account/native
hooks are inert. It covers 100 watcher replacements, cancellation before the
old task starts, early retirement before new preparation, stale identity without cancellation, unchanged progress/status
updates, and the original 150-tick startup and five-tick ended-session cleanup.
It does not exercise Steam sign-in, real handoff files or an iOS UI.

On a host without Swift, the explicit limited check is:

```sh
python3 tests/host/check-launch-readiness.py --source-only
```

That checks production integration and cleanup ordering only; it is not a
compiled Swift pass, an iOS build or device validation.
