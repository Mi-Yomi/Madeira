# Startup reports

Settings → Diagnostics → **Share last startup report** exports a small JSON
summary independent of the live/raw Wine log. It is created at accepted Wine
launch admission, before JIT allocation or native thread creation. JIT enablement
before that admission and library validation before admission are outside its
scope. Opening Madeira again does not erase the report. Starting a new attempt
rotates it; the latest and three preceding attempts are retained under the app's
Documents/startup-diagnostics directory.

This is diagnostic instrumentation, not a Blender/OpenGL fix. It changes no
startup timeout, JIT allocation, renderer, guest executable or DLL.

## Privacy and persistence

Each report has a random per-attempt identifier, UTC Unix start time, a fixed
scope (`initial_process`), bounded events, fixed phase names, monotonic elapsed
milliseconds and numeric codes. It does not collect the program name, arguments,
credentials, environment values, paths or raw guest/Wine output. Existing raw
logs have different privacy properties and are not attached by this export.

Events are written as atomic replacement snapshots, with file data fsynced and
private file permissions. Each snapshot keeps at most 64 events. Before an exit
has been observed, it keeps `attempt_begin` and the newest 63 other events. After
an exit is recorded, it keeps `attempt_begin`, the first `process_exit_reported`
(including its original code and timestamp), and the newest 62 other events.
Repeated close requests while waiting for children cannot evict that first exit.
Other phase events can age out; `dropped_events` counts each event evicted by the
bound. No periodic raw-log copying or network transmission occurs. Sharing happens through
the system share sheet when the user chooses it.

The native exit callback can run during signal-driven teardown, so it only
captures the first observed status and monotonic timestamp with lock-free
atomics and `clock_gettime`. Safe observer/loader code subsequently writes it.
An immediate host kill before that flush can still lose the final exit event.
A missing terminal event is **unknown/incomplete**, never evidence of a timeout,
normal exit, successful initialization, graphics failure or jetsam. This is not
a complete crash reporter or power-loss guarantee.

## Reading phases

- `jit_unavailable` / `jit_pool_failed`: native launch was refused before Wine
- `detach_begin/end` / `network_restore_begin/end`: isolate time spent before
  starting the server
- `server_start_requested`, `server_ready`, `server_start_failed`,
  `server_stopped`, `server_ready_timeout`: actual readiness outcome
- `wine_start_requested`, `socket_failed`, `thread_create_failed`,
  `thread_entered`: native Wine thread admission and execution; socket/thread
  failures carry errno/pthread error numbers
- `arguments_rejected`, `directory_rejected`: explicit pre-loader refusal;
  directory rejection includes errno
- `loader_entered`: immediately before `__wine_main`, with the probed PE machine
  number (zero means unknown). This does not prove the application's entry point,
  window creation or graphics initialization
- `process_exit_reported`: the initial process's first actual reported 32-bit
  exit code, including zero, ordinary nonzero values and NTSTATUS errors. These
  are the codes observed at the native hook: the existing `get_unix_exit_code`
  path can already convert a nonzero Windows status with low byte zero to 1.
  The report does not recover that original value. The
  elapsed timestamp is captured at exit, not at a potentially delayed flush
- `loader_longjmp`: Wine's exit shim returned control to the bridge; its numeric
  code is preserved. `loader_returned` means the loader returned normally to the
  bridge, not that the requested application initialized successfully
- `live_children_observed`: count from the existing live-game-child heuristic at
  initial-process return. It is not a complete process tree, does not identify
  Blender and does not prove any child initialized. Desktop/Dock child-specific
  failures need separate native evidence; the report deliberately declares its
  initial-process scope
- `thread_finished`: normal completion of the bridge's session thread body
- `first_frame_observed`: the UI observed the existing present/surface threshold;
  a splash, dialog or desktop frame can satisfy it
- `close_requested`: the user requested the existing graceful Alt+F4 action
- `observation_settled` / `observation_limit`: why the detach observer stopped
  waiting. Neither terminates the guest or means it exited

Only numeric `code` fields for phases described above are meaningful. The
readiness and observation limit events carry their configured bound in
milliseconds. Other phases currently carry zero. Exit codes are unsigned decimal
in JSON and can be converted to hexadecimal for Windows status lookup. Do not
infer a particular missing DLL or an OpenGL cause from duration alone.

## The reported approximately 116-second failure

At source base `6406b09`, the checked wineserver readiness window is 10 seconds.
The library shows a slow-start indicator after 30 seconds but has no launch
cutoff. The later observation loop has a 1,200-second cap and stops waiting for
detach without killing the process. The network-restoration shortcut separately
waits up to 30 seconds and then continues. The source contains a 120-second HTTP
request timeout in Steam Cloud, but that is not the ordinary executable startup
gate. None establishes the cause of a reported 116-second Blender failure.

The existing front end retained only NTSTATUS values at or above 0xC0000000 and
could miss a process that started and exited between half-second UI polls. This
patch preserves ordinary exit codes and checks that durable in-process status
when the native session has stopped. A recorded zero exit does not become a
generic startup failure if the completion callback wins the race with the UI
poll. It also does not prove that the requested application initialized. Explicit
setup errors and JIT guidance retain priority. No unavailable historical error is
reconstructed; the installed IPA, Blender version and failed launch stage remain
unconfirmed without a report from that attempt.

## Verification

Portable production-C tests:

```
python3 tests/host/check-startup-report.py
ASAN_OPTIONS=detect_leaks=0 CFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all' python3 tests/host/check-startup-report.py
ASAN_OPTIONS=detect_leaks=0 python3 tests/host/check-child-lifetime.py
python3 tests/host/check-frontend.py --c-only
python3 tests/host/check-launch-readiness.py --source-only
python3 tests/host/check-launch-diagnostics.py --source-only
```

The new test covers an exit captured at 116 seconds and flushed at 120 seconds,
zero/nonzero/NTSTATUS exits, duplicate callback handling, capture while the
persistence lock is already held, concurrent writes, retention, first-exit
preservation after 140 late close requests, permissions, fixed-format privacy and
symlink-directory rejection. A failure mutation reinstates oldest-event eviction
and must fail the post-exit retention assertion.
It compiles the real journal and exit-hook code. ASan/UBSan run when requested;
LeakSanitizer is disabled only where the execution host uses ptrace.

Swift source checks are not a Swift compiler or iOS build. Before delivery, run
the existing full Swift/frontend tests and Xcode app build on the Apple executor,
including `python3 tests/host/check-launch-exit-ui.py`, which compiles the
production poll/completion/exit-report methods and rejects the old zero-exit
fallback with a behavioral mutation. Then verify the share sheet on-device
after a failed and interrupted attempt, and
confirm that reopening the app preserves the last report. No device/Blender
runtime success is claimed by host tests.
