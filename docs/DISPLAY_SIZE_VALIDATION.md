# Session display-size validation

This change prevents invalid session-size strings from wrapping in native C or
trapping at the Swift-to-C boundary. It does not establish safe rendering sizes
for a GPU, surface allocation, or the other Wine metric/mode calculations.

## Inputs and reachability

- A saved library profile stores `resolution` in `Documents/madeira-library.json`.
  `ContentView.startLibraryEntry` calls `LibraryEntry.validate()` before
  `configureLaunch`; a Steam Dock launch validates its optional profile before
  using its resolution. Those validators already require width 320–4096 and
  height 240–4096. This patch retains those bounds, all presets, and custom
  valid stored sizes. It does not modify settings files or migrate values.
- `GuestDisplay.configureSessionDefault` also accepts a standalone `WxH` knob.
  Previously a positive Swift `Int` above `Int32.max` trapped when passed to
  `winios_display_mode_changed`. The currently validated library launch routes
  exclude that input, so this guard is defense at the helper boundary, not a
  claim that an ordinary preset can cause that crash.
- The existing `desktop-size` config readers for developer/Dock launches have
  their own 640–3840 by 360–2160 bounds. Those paths are unchanged.
- `WineProcessBridge.m` exports global `env.NAME` entries from `madeira.cfg`
  (or legacy `madeira-env.txt`), then per-game `env.NAME` entries, after the
  profile's environment setup. Thus `env.MADEIRA_SCREEN_W/H` reach native
  `ios_screen_size` independently of the library resolution validator. The app
  display shim also reads these variables until a current size is published.

## Behavior

Library validation now requires exactly two nonempty components, both valid
integers, in addition to its existing bounds. Previously `compactMap` discarded
invalid components, so `800xgarbagex600` passed validation but selected the
1280×720 fallback in GuestDisplay. Extra separators such as `800xx600` also
passed. Such malformed profiles now show the existing invalid-profile error
before starting; their saved strings are not rewritten.

The standalone GuestDisplay knob accepts exactly two positive signed-32-bit
values. A malformed or out-of-range knob uses the existing view-derived
fallback, with source `view`, before exporting or publishing dimensions.
Existing whitespace trimming, uppercase `X`, leading `+` and leading zeroes
remain accepted by this standalone helper. Library validation retains its
existing stricter spelling and size policy.

Both native readers use `build/madeira_display_size.h` to parse a whole positive
decimal `int`. Leading `+`, zeroes and surrounding C whitespace are preserved.
Zero, negative values, trailing junk and values above `INT_MAX` fall back per
axis to the existing defaults: 1024 wide and 768 high. A valid other axis is
retained. win32u logs the invalid variable name and fallback once when seeding
the session; it never logs the supplied value. Missing variables use the same
default without an invalid-value warning. The app shim uses the same fallback
parser without adding a per-frame warning.

This deliberately changes malformed numeric-prefix behavior: `1280junk` is
rejected as a whole instead of being accepted as 1280. Before the fix, compiled
production C on the host interpreted `4294967297` as 1 and `-4294964736` as 2560.
Out-of-range `atoi` behavior is not portable; those exact wrapped values are
host evidence, not an iOS runtime claim.

Native session caching and published mode precedence are unchanged. Parsing
`INT_MAX` successfully only means it is representable. In particular, the
existing maximized-metric and mode-area calculations, allocation sizes and
GPU limits still require separate work; these tests do not run them at extreme
sizes or claim that those dimensions can launch/render safely.

## Host verification

```sh
python3 tests/host/check-display-size.py
CFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' python3 tests/host/check-display-size.py --c-only
CFLAGS='-fsanitize=undefined -fno-sanitize-recover=all' python3 tests/host/check-max-track-size.py
python3 tests/host/check-launch-validation.py
python3 tests/host/check-frontend.py
```

The new test compiles the production native readers with a real host pthread
lock and the production GuestDisplay and library validator with inert display
publication/unrelated field stubs. It checks both axes, integer boundaries,
very long values, malformed tokens, all current library presets, custom valid
sizes, the existing profile bounds, selected/exported/published agreement,
the tablet's view-derived fallback, native caching and shim mode precedence.
`--root` can test another source tree; `--c-only` explicitly skips Swift.
`CC`, `CFLAGS` and `SWIFTC` can select installed trusted host compilers.

No UIKit, full Wine, app/IPA, vendor/guest program or device run is involved.
Rebuild `libwin32u_unix.a` and relink/rebuild the native app to include the changed
native parser and shim; source-only checks do not establish native deployment.
