# Opt-in JIT crash captures

Normal crashes no longer dump the JIT pool. The existing fault, register,
VM-region and stack diagnostics and exception delivery remain unchanged.
The dump helper adds no file I/O, pool reads, residency queries or log lines
unless explicitly enabled. This does not make every pre-existing crash
handler diagnostic async-signal-safe.

## Why

This is a focused port and hardening of upstream
[bc46c48 (ml1242)](https://github.com/willfaust/Madeira/commit/bc46c48ca364d60b5f21e41344abd9daea70baa4),
“JIT-pool dump only with MADEIRA_JIT_DUMP, and sparse.” The previous two
independent crash paths synchronously wrote the entire RW alias to the same
file. Reading untouched JIT pages can itself commit memory, making a crash
or low-memory situation worse. Upstream reported roughly 600 MB of added
footprint during one dump; that device measurement is not a measurement of
this port. See also [issue #123](https://github.com/willfaust/Madeira/issues/123).

## Requesting a capture

For an explicitly requested debugging session, set these options in
`Documents/madeira.cfg` (also listed under Settings → All settings):

```ini
env.MADEIRA_JIT_DUMP = 1
env.MADEIRA_JIT_DUMP_MAX_MB = 16
```

Then fully restart the host app. The policy and Documents path are captured
once during normal initialization before the signal/Mach handlers are
installed, not parsed in a fault handler. Relaunching only a guest program
does not reset this host-process policy or the one-attempt guard.

- Only the exact value `1` enables capture. Unset, empty, `0`, `off` and other
  values leave it off. This is deliberately stricter than upstream's “set”
  test, which also enabled the dump for `0`
- `MADEIRA_JIT_DUMP_MAX_MB` is a decimal MiB prefix cap, default **16**, range
  **1–1024**. Empty/unset means 16; malformed/out-of-range values disable
  capture. Large caps explicitly permit correspondingly costly crash-time I/O
- The output is `Documents/fex-jit-dump.bin`, using `MADEIRA_DOCS_DIR` or `/tmp`
  if that variable is absent/empty. An overlong path disables capture
- A previous capture is never overwritten. Move or remove it yourself before
  requesting another; an existing file, symlink or FIFO makes the one attempt
  fail. New files are created with owner-only `0600` permissions
- Capture contents may include private guest data. Do not automatically share
  or upload them. This change neither uploads nor deletes any existing dump

The file starts at pool offset zero, retaining the original raw format and
pool-relative offsets. Its logical size never exceeds the requested prefix
cap. Only pages reported resident or paged out by Darwin `mincore` are copied;
untouched pages remain holes. A **capped** capture can omit the faulting code,
especially in tail CodeBuffers. To request the whole pool, explicitly choose
a cap at least as large as that pool (maximum 1024 MiB); larger pools remain
capped. This is a debug capture, not a coherent snapshot of concurrently
changing JIT code.

A single metadata-only log line gives the reason, status, written and logical
bytes, total pool bytes, query/write counts and first I/O error. It never
includes pool contents. Check this status before interpreting a capture:
`complete`, `capped`, `invalid-pool`, `open-failed`, `residency-failed`,
`write-failed`, `write-budget`, `truncate-failed` or `close-failed`.
An I/O failure can leave a partial file; its length is only extended through
pages actually examined, rather than to the advertised full pool size.
There is no `fsync` or crash-durability guarantee.

## Bounds and safety

Both crash paths share one lock-free atomic attempt guard for the entire
host process. A nested signal or another faulting thread returns immediately
instead of waiting or reopening/truncating a file. Failed opens also consume
the attempt. The immutable policy is published with release/acquire ordering.

Let `L = min(pool size, configured cap)` and `P = page size` (supported powers
of two from 4 KiB to 64 KiB). An enabled attempt performs at most:

- `L` payload bytes, and a file logical size of `L`
- `ceil(L / 1 MiB)` residency queries, with a fixed 256-byte stack vector
- `ceil(L / P) + 8` `pwrite` calls, counting partial writes and `EINTR`
- one open, one truncate, one close and one metadata `write` of at most 256 bytes

For the default **enabled** cap, worst-case payload is 16,777,216 bytes:
16 residency queries and at most 4,104 writes on 4 KiB pages, or 1,032 writes
on 16 KiB pages. The normal disabled configuration does **zero** of this work.
For an explicitly requested 1024 MiB cap the maxima are 1,073,741,824 bytes,
1,024 queries and 262,152/65,544 writes respectively. These are operation and
byte bounds, not elapsed-time bounds; filesystem operations can still block.

Short writes advance correctly. Zero writes fail. `EINTR` consumes the same
finite write budget; close is never retried because the descriptor may already
have been recycled. Residency-query errors stop capture without a dense-read
fallback. Kernel `pwrite` copies memory, so a disappearing mapping can return
an I/O error instead of requiring a direct userspace load in this helper.
Residency can still change between a query and its write.

There is no allocation, environment parsing, stdio formatting or locking in
the new fault-path code. Nevertheless, `mincore` is not specified as
async-signal-safe by POSIX, paged-out pages can fault back in, and the
underlying filesystem may block. Captures should remain a deliberate,
temporary diagnostic setting. Disable the setting and restart afterward.

## Verification

Run:

```sh
python3 tests/host/check-jit-dump.py
JIT_DUMP_TSAN=1 python3 tests/host/check-jit-dump.py
```

The tests compile the real helper and extract the actual normal-init/logging
wrapper from `signal_arm64_ios.c`. They exercise disabled and invalid policy,
path/page-size validation, pre-init calls, capped and partial final pages,
paged-out pages, an unreadable untouched page left as a sparse hole, short and
zero writes, finite `EINTR`, ENOSPC, query/open/truncate/close failures,
preserved errno, existing files and symlinks, reentry and 16 competing threads.
Maximum-volume tests use mock writes and a PROT_NONE mapping, not a real GiB
file. The wrapper tests check immutable init-once behavior and the 256-byte
metadata bound. AddressSanitizer and UBSan run by default; LeakSanitizer is
disabled because it is incompatible with the managed executor's ptrace setup.

Host C, ASan/UBSan and optional TSan passed on the Linux executor. Full iOS
compilation, Darwin/APFS sparse-file behavior, actual Mach/SIGILL delivery,
and on-device memory/latency improvements remain **unverified**. No emulator
instruction semantics were changed. No IPA, signing, upload or heavy CI build
is part of this change.

The config catalog change contains only the two generated new option rows.
A full catalog regeneration/check needs the pinned Wine/FEX/DXMT submodules;
regenerating from a partial checkout can incorrectly remove their entries.
