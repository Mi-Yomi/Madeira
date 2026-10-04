# Desktop application compatibility: 1C and Blender

Initial source audit: upstream `6b79d562690c2e64d6908c3ffdc7943e6ae438e5`,
2026-10-04. **Neither Windows Blender nor 1C has been run inside Madeira by
this work.** Host tests below are deliberately separated from device acceptance.

## What Madeira supplies

Madeira combines Wine's ARM64EC/ARM64 Windows implementation, FEX translation
for x86/x64 application code, WoW64 for 32-bit applications, and Metal-backed
Direct3D implementations. Wine's server and guest processes run within an iOS
application. It is not a Windows kernel or a PC virtual machine: installing a
Windows 11 ISO is outside this architecture.

The current repository is game-oriented. A DLL in upstream Wine is not
automatically present in Madeira: it must be built for the appropriate farm,
packaged, registered when necessary, and supported by a compatible Unix side.

## Initial improvements

### Launch arguments

The library editor documented 64 arguments and less than 4 KB of UTF-8, while
`WineProcessBridge.m` silently kept only 16 space-separated tokens/1023 bytes.
Quotes were sent literally and paths containing spaces were broken apart.

`WineLaunchArguments.h` now decodes Windows-style double quotes, escaped
quotes/backslashes, empty arguments and tabs. The bridge honors the editor's
64-argument/4095-byte bounds and rejects overflow without launching a partial
command. The editor's validation uses the same quote rules; it still requires
balanced quotes. The parser copies UTF-8 bytes without recoding them. These
are arguments to an executable, not a shell expansion language.

Examples now covered by host regression tests:

```text
/F "C:\Data Folder\База" /N "Иван Иванов"
/S "server\base"
--background "C:\My Project\scene.blend" --factory-startup
```

The first examples are parser fixtures, not tested 1C connection recipes.
The native bridge also closes its pending client socket and reports an error
when arguments supplied through configuration bypass the editor's limits.
Executable paths now use the editor's 1023-byte limit too; oversized paths
are rejected. The working-directory component buffers now match that bound,
removing the old 512-byte unchecked-copy risk. Filesystem path limits still apply.

### Mouse wheel

The GameController mouse callback previously treated its first axis as
horizontal. iOS's GCMouse convention requires vertical = negative first axis,
horizontal = second axis. The conversion is now applied only at that ingress;
UIKit fallback scrolling and desktop pointer lock retain their existing behavior.
This matches [SDL's iOS implementation](https://github.com/libsdl-org/SDL/blob/main/src/video/uikit/SDL_uikitevents.m)
and addresses the source-level cause reported in
[issue #190](https://github.com/willfaust/Madeira/issues/190).

### Software-keyboard Unicode text

Both software-keyboard paths now retain ASCII virtual keys/shortcuts and
send other characters as full UTF-16 `KEYEVENTF_UNICODE` packets. They allow
the normal iOS language keyboards rather than forcing ASCII. Surrogate pairs
and combining sequences keep their code units and FIFO order.

An insertion occupies one native queue slot and is accepted completely or
rejected. Outstanding text is capped at 4096 UTF-16 records; each event pump
drains at most 64 records. A busy/oversized insertion shows a warning instead
of silently dropping a suffix. Session reset discards pending text safely.
This changes software text entry, not the physical keyboard's US scan layout
or clipboard integration. Win32/1C text widgets and UIKit alerts still require
on-device acceptance tests.

## Second desktop-launch batch

This batch builds on the first published compatibility commit, `b569c5d`.

- **Working folder:** ordinary library entries can now select an existing
  absolute `C:\` folder in Game details. Empty means the executable's folder;
  Steam keeps its own launch configuration. Exact spelling is preferred, with
  unique Unicode case-insensitive matches for typed Windows folders. Ambiguous
  matches are rejected. Spaces/Cyrillic and the root of
  `C:\` are supported. Relative paths, other drives, ambiguous components,
  missing folders and symlink escapes are rejected rather than silently
  launching in another folder. Native validation is repeated immediately
  before Wine starts. This supports relative project/script/data paths; it
  does not create a 1C infobase or install application dependencies.
- **Complete argument limit:** a separate stale front-end check still capped
  library launches at 1023 bytes. It now uses the same 4095-byte limit as the
  production parser and profile validator; regression checks cover the path
  through the front end as well.
- **Launch diagnostics:** common Windows loader/status failures now distinguish
  missing modules/functions, incompatible image formats, failed DLL/assembly
  initialization, unsupported CPU instructions and missing working folders.
  These explain the status without inventing a particular missing dependency.
- **Default log privacy:** the launch bridge no longer prints argument values;
  global/game configuration logging omits values too. This matters for 1C
  credentials and connection strings. It is not a log sanitizer: guest output,
  opted-in Wine tracing, crash dumps and configuration files can still contain
  private data. Review exports before sharing; avoid passwords in saved launch
  profiles where possible.
- **Hidden windows:** the compositor's frame update now requires `WS_VISIBLE`
  as well as nonempty geometry, so moving/resizing a hidden window does not
  itself reveal its layer. Window stacking and child-surface grouping remain
  separate unresolved device-validation work.

Working-folder tests exercise the actual C/Swift normalization and real
filesystem/symlink confinement. Existing library serialization and Steam
launch tests cover default/override/reset behavior. No device acceptance is
implied by these helper tests.

## Blender: backend work remains

Current built-in OpenGL is explicitly absent:

- `build/ntdll-unix/virtual_ios.c`, `ios_gl_stub_unix_call_table`: attach/detach
  are allowed, while real WGL/GL calls return `STATUS_NOT_SUPPORTED`
- `build/win32u-unix/driver_ios.c`: the OpenGL and Vulkan driver entry points
  return `STATUS_NOT_IMPLEMENTED`
- `build/wine-i386/build.sh`: Vulkan is excluded from the 32-bit build

The GL-absent bridge now also writes Wine's required all-ones “unavailable”
result for `wglGetProcAddress`, with distinct native/WoW64 argument layouts.
Previously the untouched zero result could be interpreted as the first entry
in Wine's extension table for any requested extension name. Lifecycle calls
still permit loading `opengl32.dll`, while capability discovery fails safely.
This is an ABI correctness fix, not a graphics backend. The ABI is pinned to
[Wine 4f5b197](https://github.com/willfaust/wine/blob/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f/dlls/opengl32/wgl.c#L1333).

Direct3D-to-Metal support does not implement Blender's OpenGL/Vulkan UI.
Check requirements against the exact Blender version. Current requirements
are published on [Blender's requirements page](https://www.blender.org/download/requirements/).

### A bounded headless probe

`tests/desktop/blender_cpu_smoke.py` is a reusable background-only probe. It
creates disposable data, writes a `.blend` file with spaces/Cyrillic in its
name, reopens it, and optionally renders a 32x32, one-sample Cycles frame using
one CPU thread. It never opens a user project and creates a fresh results
subdirectory on every run. `report.json` is checkpointed after each stage.

Native-host example:

```sh
blender --background --factory-startup --disable-autoexec --python-exit-code 1 \
  --python tests/desktop/blender_cpu_smoke.py -- \
  --output-dir /tmp/madeira-probes --stage render
```

Device procedure, once an official Windows portable Blender build and this
script are present in the test prefix:

1. Record Blender version, executable bitness, device/iOS version and Madeira
   build. Start with `--version`; separately try the Python probe.
2. In the entry for `blender.exe`, use arguments such as:

   ```text
   --background --factory-startup --disable-autoexec --python-exit-code 1 --python "C:\Madeira Tests\blender_cpu_smoke.py" -- --output-dir "C:\Madeira Tests\Results" --stage python
   ```

3. Only after Python/save-reopen passes, change the final stage to `render`.
4. Save the report and relevant log. A crash before the first checkpoint is
   a loader/CPU/runtime failure, not a successful headless test.

Native Linux Blender 4.3.2 passed both stages during development. That proves
the probe can work; it does not exercise Wine, FEX, iOS JIT or Madeira.
Blender documents the relevant [command-line options](https://docs.blender.org/manual/en/latest/advanced/command_line/index.html).

### OpenGL feasibility gates

Two research candidates, neither integrated or validated here:

- **Mesa LLVMpipe/WGL:** Mesa documents application-local Windows
  `opengl32.dll` plus `libgallium_wgl.dll`. This could investigate software
  OpenGL without Apple's missing desktop GL. It still needs Windows GDI/WGL
  presentation, correct bitness, LLVM JIT compatibility with FEX/iOS, and a
  sustainable CPU/memory cost. See [Mesa LLVMpipe](https://docs.mesa3d.org/drivers/llvmpipe.html#using).
- **Mesa D3D12:** Mesa's driver documents OpenGL 3.3 on D3D12. Its calls would
  traverse Madeira's incomplete D3D12 implementation. This is a possible
  older-Blender research path, not evidence that Blender's required API is
  available. See [Mesa D3D12](https://docs.mesa3d.org/drivers/d3d12.html).

Before bundling either, build from an identified official source revision,
preserve licenses, test a minimal WGL context and pixel readback, then test
Blender startup. Record the first unsupported call. Do not advertise OpenGL
support by changing capability strings, and do not replace system DLLs or
download arbitrary prebuilt DLL packs as a shortcut.

## 1C: verify the exact client, not a generic promise

Record the platform build, x86/x64, thin/thick/Designer, file/server mode and
licensing type. A Windows 8.3.x client, a Linux 1C client and an iOS mobile
client are different targets. Begin with a disposable infobase, never the
only copy of accounting data.

Concrete source gaps found:

- Software-keyboard paths originally silently ignored non-ASCII characters;
  the new packet route above is host-tested but awaits device checks.
  Physical keys still use Wine's US scan-code layout
- The tracked `i386-windows` farm contains only `.gitkeep`. Both tracked
  64-bit farms omit modules including MSI, MSXML, RichEdit and WMI. This is an
  inventory observation, not proof that every listed module is required or
  absent from a separately built release IPA
- The 1C administrator guide calls out WMI for software licensing and matching
  bitness for COM/add-ins. Verify requirements for the exact platform version:
  [1C 8.3.27 administrator guide](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_file_mode_8_3_27/)
- Clipboard integration and printing are not established. The i386 build
  excludes `wineps.drv`; there is no CUPS Unix backend
- A launcher which exits after starting a child may end the session. The
  existing `MADEIRA_WAIT_CHILDREN=1` workaround is opt-in because stale child
  slots can leave a session waiting indefinitely

Acceptance sequence:

1. Inspect the exact installer/client imports and actual IPA module manifest
2. Establish direct client startup, then installer and child-launch paths
3. Test Russian/mixed text, punctuation, deletion, shortcuts, dialogs, mouse
   wheel, focus loss and a desktop resolution suitable for 1C
4. Create/save/close/reopen the disposable infobase, including a failed-start
   recovery; validate original data remains intact
5. Test WMI/COM and authorized licensing, server connectivity/TLS, then the
   actual configuration, add-ins and printing as separate gates

Do not synthesize license success or bypass authorization checks.

## Verification boundaries

The Linux host runs portable C tests with AddressSanitizer/UBSan. In ptraced
environments LeakSanitizer needs `ASAN_OPTIONS=detect_leaks=0`; this does not
disable address/undefined-behavior instrumentation, but leak checking is not
claimed. Focused Swift checks require `swiftc`; their `--source-only` mode is
explicitly incomplete.

`.github/workflows/desktop-compatibility.yml` runs focused C checks on Ubuntu
and Swift input/validation checks on macOS. These are helper tests, not an
Xcode app build. A clean iOS build, signing, on-device input and successful
Windows application runs remain separate required acceptance stages.

The broader pre-existing host suite also depends on pinned Wine/DXMT/FEX
submodules, Swift, newer Python compression support and FFmpeg fixtures.
Do not count missing prerequisites as passed tests or treat this focused
workflow as the full suite. See [BUILDING.md](BUILDING.md) for the full build
chain and its still-unverified clean-machine steps.

The next-build audit also found 16 required static archives absent from the
clean checkout, empty native submodule directories and missing cross-toolchains.
An unsigned `xcodebuild` job cannot fix those prerequisites by turning signing
off. Device acceptance targets iPhone 16 Pro Max on iOS 27; these changes'
on-device behavior has not been verified. The bounded clean-bootstrap recipe
and current source availability are recorded in [BUILDING.md](BUILDING.md).
