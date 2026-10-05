# Virtual desktop maximum track size

The iOS override of `get_system_metrics` now derives `SM_CXMAXTRACK` and
`SM_CYMAXTRACK` from the current guest virtual monitor, plus 16 guest pixels,
while keeping the previous minimums of 1920 and 1080. Each addition saturates
at `INT_MAX` instead of overflowing. This affects the default maximum size
reported to windowed applications; applications can still supply their own
limits through `WM_GETMINMAXINFO`.

## Provenance

Adapted from [willfaust/Madeira commit bf0d037ea1eb24c9bd5a1a5c1707701395bcfbb5](https://github.com/willfaust/Madeira/commit/bf0d037ea1eb24c9bd5a1a5c1707701395bcfbb5),
“win32u: max track size follows the virtual screen”, authored/signed off by
spitefulowl, with Claude Opus 5.5 credited as co-author, dated 2026-10-04.
The upstream commit explicitly reports build-only verification, without a
device log proving this clamp. This port adds saturation and host regression
coverage. Existing Wine copyright and LGPL notices remain in the C file.

Only the narrow maximum-track behavior is ported here. No resolution picker,
valid session default, saved preference, mode list or preference migration
changes. The separate [session-size validation fix](DISPLAY_SIZE_VALIDATION.md)
rejects malformed/out-of-range strings before native conversion.

## Source and size semantics

- `app/Madeira/Library.swift` already offers 2560×1440; smaller choices such as
  1408×648 and 1280×720 keep the same maximum track values.
- `GuestDisplay.configureSessionDefault` exports selected positive dimensions
  through `MADEIRA_SCREEN_W/H`. Its separate validation fix requires a positive
  `Int32` before publication; valid library profiles keep their existing bounds.
- `ios_screen_size` reads the session default once. Unset, nonnumeric and
  non-positive, malformed or out-of-range dimensions fall back independently
  to 1024 and 768. The shared integer-safe parser comes from the separate
  session-size validation fix. Later environment edits do not change an
  initialized session.
- `ios_virtual_change_display_settings` changes the current values for supported
  modes, and restores the session default on a null mode. The new metrics read
  those current values on every call, including after growth and shrinkage.
- Dimensions and the 16-pixel allowance use the same guest-pixel coordinate
  space as the existing iOS screen/maximized overrides. They are unrelated to
  the phone's Retina scale. `get_system_metrics_for_dpi` has no special cases
  for these indices and delegates them to `get_system_metrics`; this behavior
  is unchanged. The patch does not introduce a DPI-dependent frame calculation.

At the pinned Wine revision `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`,
`dlls/win32u/window.c` seeds `ptMaxTrackSize` from these metrics in
`get_min_max_info`, calls `WM_GETMINMAXINFO`, and uses the resulting values to
clamp eligible window creation sizes. The host checks below verify the metric
and mode callbacks, not this complete window-creation path.

## Compiled host verification

Run from the repository root:

```sh
python3 tests/host/check-max-track-size.py
CFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' python3 tests/host/check-max-track-size.py
```

The test extracts the production iOS branch of `get_system_metrics`,
`ios_screen_size`, the standard mode table, mode-setting policy and
`ios_virtual_change_display_settings` verbatim. It compiles and calls them
with host C. Device-name lookup and server/UI publication are inert hooks;
other Wine metrics are outside the compiled fragment. The unchanged DPI
delegation is checked in source, not through a Wine/Windows DPI runtime.

Coverage includes small/large/portrait/one-axis sizes, the minimum boundaries,
all existing iOS minimum/screen/fullscreen/maximized overrides at ordinary
sizes, actual mode growth/shrink/restore, `CDS_TEST`, `CDS_NORESET`, disabled
mode programming, rejected mode requests, invalid environment fallback and
`INT_MAX - 16` saturation boundaries. The original source fails the same
regression test on 2560×1440. `--source` and `--probe` can compare revisions.

| Virtual monitor | Original max track | Patched max track |
| --- | --- | --- |
| 1408×648 | 1920×1080 | 1920×1080 |
| 1920×1080 | 1920×1080 | 1936×1096 |
| 1728×1200 | 1920×1080 | 1920×1216 |
| 2560×1440 | 1920×1080 | 2576×1456 |
| 3840×2160 | 1920×1080 | 3856×2176 |
| INT_MAX×INT_MAX | 1920×1080 | INT_MAX×INT_MAX |

Extreme sizes test only the new maximum-track arithmetic. They are not
supported rendering sizes: existing maximized-metric arithmetic, mode-area
arithmetic, allocations and downstream UI conversion limits remain outside
this fix. There is no claim that a device can render those extreme sizes.

## Native rebuild and remaining verification

Rebuild `app/Madeira/libwin32u_unix.a` using `build/win32u-unix/build.sh` with
the configured Wine source and iOS SDK, then relink the native app against that
new archive. Reusing the previous archive does not include this source fix.
Host tests do not establish native build, app-link or device behavior.

No app/IPA build, guest execution or device test was performed for this port.
A later device check should create/resize a normal window at a selected large
desktop size, compare the queried maximum-track values, and verify a switch to
a smaller mode. The fix offers no claimed improvement at the usual smaller
desktop sizes on an iPhone 16 Pro Max; iOS 27 behavior remains unverified.
