# Software text input

The two UIKit software-keyboard entry points share the same encoder and queue:

- `MetalBackedView.insertText` retains its hardware-keyboard duplicate guard
- `LibraryKeyInput.insertText` retains held accessory modifiers
- Both allow the normal iOS keyboard selector instead of forcing ASCII
- ASCII uses the existing Windows virtual-key/scan-code route so shortcuts,
  Enter, Tab, path punctuation, and temporary Shift retain their behavior
- Everything else is sent as its original UTF-16 code units using
  `KEYEVENTF_UNICODE`, `wVk = 0`, and the full 16-bit `wScan`

Wine's existing `queue_ios.c` converts those packets to `VK_PACKET`, and
`NtUserTranslateMessage` in `message_ios.c` posts `WM_CHAR` (or `WM_SYSCHAR`
with Alt). This does not require installing a Russian Wine keyboard layout for
software text. It does not implement physical-keyboard layout switching, an
IME, or support for applications that ignore text packets and read only raw
keyboard input.

## Queue contract

Each call is admitted completely or rejected without queueing any part. A
software insertion occupies one slot in the existing 256-slot input ring.
The input is capped at 4096 UTF-16 units in Swift, and allocated native text
records are capped at 4096 globally, including partially drained batches.
Each record is four bytes; input payload allocation is therefore at most
16 KiB, plus bounded allocator and queue overhead. A supplementary character
such as an emoji takes two UTF-16 units.

The frontend shows an alert, warning haptic, and accessibility announcement
when an insertion is too large or the queue cannot accept it. The user can
retry after pressure clears or enter smaller sections. No unbounded retry
queue is created. Admission is not a guarantee that the guest application
will accept or display the text.

Each Wine pump processes at most 64 logical records, with at most 256 key
messages for shifted ASCII. An unfinished batch remains at the FIFO head.
Multiple pumps are serialized; reentrant pumps return without blocking.
This preserves down/up pairs, temporary modifiers, and UTF-16 ordering while
letting Wine's event loop process other work between portions of a paste.
Session startup waits for an active bounded drain, cancels all old queued
input, frees partial batches, and restores the text budget.

Text strings, Unicode code-unit values, and VK/scan values are not included
in the bridge's default keyboard diagnostics. Explicit Wine debug channels
may have their own logging, which this change does not alter.

## Host regression checks

Run:

```sh
python3 tests/host/check-unicode-input.py
ASAN_OPTIONS=detect_leaks=0 \
  CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 tests/host/check-unicode-input.py
```

The test compiles the production C queue and Unicode driver bridge with a
mock Wine dispatch. It checks all 65,536 UTF-16 values, Cyrillic, surrogate
pairs, ASCII/Ctrl/Shift ordering, ring and text-capacity limits, allocation
failure, retry, bounded draining, concurrent producers/pumps, reentrancy,
and session reset during an in-flight dispatch. It counts allocations to
verify cleanup even where LeakSanitizer is unavailable.

When `swiftc` is installed, the same test also compiles and executes the
production Swift mapping/encoder against the C API declarations. This covers
Cyrillic, combining characters, emoji, non-ASCII letters whose uppercase
spelling resembles ASCII, held Shift, and the 4096-unit boundary. Without
Swift, that portion is explicitly reported as skipped.

## Required device checks

Host checks do not prove that 1C or Blender launches or that a particular
Windows control accepts Unicode packets. Before calling this feature verified
on iOS:

1. Build Madeira with Xcode and run both keyboard frontends on a device
2. Select the Russian iOS keyboard and enter `Проверка Ёё №1` in a standard
   Wine Unicode edit control and an actual 1C field
3. Enter a Cyrillic database path, mixed ASCII punctuation, an emoji, and a
   combining-accent sequence; check that text is neither lost nor doubled
4. Exercise Ctrl+A/C/V, held Shift, Enter, Tab, and Backspace; verify the next
   key does not inherit a temporary modifier
5. Paste a long value under the limit, then one above it; verify complete
   accepted input and a dismissible rejection alert with no partial insertion
6. Verify the hardware-keyboard duplicate guard, navigation keys, and Blender
   shortcuts continue to behave as before

The legacy raw-key/mouse producer still drops new events when its ring is
full. The atomic text-batch path prevents that existing policy from splitting
new software insertions; this change is not a general raw-input queue rewrite.
