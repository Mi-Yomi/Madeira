# Source-built Mesa Windows reference

This is a bounded Microsoft Windows reference for the GDI/softpipe WGL path.
Success requires real GDI pixels and two distinct legacy OpenGL clear colors,
verified in both the GL back buffer and the window's GDI backing pixels after
swap. The two loaded DLLs must be the exact application-local outputs built in
this job. Actual renderer and numeric GL version are recorded. No result here
establishes Madeira, Wine/FEX, ARM64EC, iOS display or Blender compatibility.

## Inputs and build

`inputs.lock.json` contains exact official URLs, sizes, SHA-256 hashes and
metadata sources. `host-requirements.txt` is hash-pinned and installed into a
fresh local virtual environment with no index, dependency resolution, pip
cache or fallback download. The standard runner must already provide x64
CPython 3.12.10; a changed runner image fails explicitly.

- Mesa 26.2.4, official release archive, SHA-256
  `bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9`
- Official LLVM-MinGW 20260421 UCRT x86-64 Windows-host archive,
  187,127,002 bytes, SHA-256
  `0c47b9fc1043b68a8d7e8e022b878f11306ed35beacf858864b36b096a0acd95`;
  [official asset metadata](https://api.github.com/repos/mstorsjo/llvm-mingw/releases/assets/401855829)
- Official WinFlexBison 2.5.25, 1,083,989 bytes, SHA-256
  `8d324b62be33604b2c45ad1dd34ab93d722534448f55a16ca7292de32b6ac135`;
  this digest was computed from the exact official release ZIP. The older
  [release metadata](https://api.github.com/repos/lexxmark/winflexbison/releases/tags/v2.5.25)
  does not publish a digest
- Official PyPI wheels: Meson 1.9.1, Ninja 1.13.0, Mako 1.3.10,
  MarkupSafe 3.0.2, packaging 25.0 and PyYAML 6.0.2. Native wheels are
  selected for Windows x64 / CPython 3.12, not the earlier Linux host

The same pinned LLVM-MinGW compiler builds Mesa and the source-owned canary;
no separate MSVC download or system installation is needed. A Windows-to-Windows
Meson cross file keeps target configure probes from running, and pinned Meson
1.9.1's `skip_sanity_check=true` also suppresses native compiler sanity programs.
All real compile/link steps still have to succeed. The command builds only the
WGL DLL target, with at most two jobs. It never runs `meson install` or the
upstream Mesa test or executable targets.

Only softpipe is enabled. LLVM, LLVM draw, Vulkan, D3D12 video, Microsoft CLC,
EGL, GLX, GLES, GBM, GLVND, shader cache, optional compressors, Rusticl and tests
are disabled. `--wrap-mode=nodownload` forbids Meson fallback downloads.
All regular source-file bytes are hashed before and after the build. Upstream
licenses and source headers stay in their original sources/archives. The
WinFlexBison release ZIP omits full license files, so this directory includes
its exact upstream v2.5.25 GPL, Flex BSD and GFDL notices in `licenses/`:

- [project GPL](https://github.com/lexxmark/winflexbison/blob/v2.5.25/COPYING)
- [Flex BSD](https://github.com/lexxmark/winflexbison/blob/v2.5.25/flex/src/COPYING)
- [documentation GFDL](https://github.com/lexxmark/winflexbison/blob/v2.5.25/COPYING.DOC)

## Runtime gates

1. Confirm Windows x64, exact preinstalled Python and the approved repository,
   branch and event. Make a new root strictly below `RUNNER_TEMP` and outside
   the checkout. All build, tool, download, venv and runtime temporary files
   stay there
2. Fetch and verify only locked official inputs, extract safely and build.
   Copy `opengl32.dll` and `libgallium_wgl.dll` from the just-built target paths
   into a new bundle, verify copied hashes, then build the canary
3. Apply the repository's bounds-checked PE reader: require ordinary AMD64,
   exact expected bundle files, canary exports, package-internal symbol
   resolution, GDI `StretchDIBits`, no delayed dependencies and no unexpected
   external runtime/backend DLL. System/API-set dependencies are classified;
   this static classification alone is not an operating-system symbol proof
4. Run only the source-owned target canary: `gdi` and `legacy`, with
   process-local `GALLIUM_DRIVER=softpipe`. Clear inherited
   renderer/capability overrides. Load the application-local DLL by absolute
   path with DLL-directory/System32 dependency search, and verify both actual
   loaded module paths and the actual softpipe/Mesa version
5. Require the full GDI pattern and two different legacy clear colors to pass.
   Require both post-swap backing pixels, not `SwapBuffers` success alone.
   Verify the bundle hashes again after execution

The generic `core43` canary remains available for a future capable backend. It
requests an actual core context, checks numeric version/profile, compiles/links
real GLSL 4.30 and draws/reads a triangle. Allocation, loader, rendering,
cleanup and unclassified context errors remain failures, including error 203.

This exact softpipe reference does not make that impossible request. After all
mandatory runtime proof passes, it verifies three exact Mesa source hashes
and the actual Meson configuration from `intro-buildoptions.json`:

- [sp_screen.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/gallium/drivers/softpipe/sp_screen.c#L306)
  sets both desktop GLSL feature ceilings to 400
- [st_extensions.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/mesa/state_tracker/st_extensions.c#L1206)
  transfers those values to the core/compatibility GL constants
- [version.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/mesa/main/version.c#L357)
  requires GLSL >= 430 for desktop OpenGL 4.3

The receipt therefore reports core43 unavailable by pinned-source capability,
with `context_creation_attempted=false` and `runtime_core_maximum_measured=false`.
It records the actual successful legacy version separately. No compatibility
context version is relabeled as a measured maximum core version. Source hash,
archive, build configuration, actual renderer or capability override changes
invalidate this classification. No version or extension strings are forced.

The first Windows run created actual softpipe 3.3 compatibility contexts and
passed both legacy backbuffer/window colors, then rejected the optional 4.3
request with NULL/error 203. That error is not a trustworthy capability code:
[st_manager.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/mesa/state_tracker/st_manager.c#L1065)
sets `ST_CONTEXT_ERROR_BAD_VERSION`, but
[stw_context.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/gallium/frontends/wgl/stw_context.c#L245)
discards `ctx_err` without setting a Windows error. The
[WGL wrapper](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/gallium/frontends/wgl/stw_ext_context.c#L236)
also performs cleanup before returning NULL.
[os_misc.c](https://gitlab.freedesktop.org/mesa/mesa/-/blob/mesa-26.2.4/src/util/os_misc.c#L218)
uses `GetEnvironmentVariableA` without preserving last error, so a missing
option can leave `ERROR_ENVVAR_NOT_FOUND` (203). The run did not instrument
which internal call last wrote 203; it is not classified as unsupported.
The original failed run remains a failed run.

Even a future real core43 pass is only a generic graphics result. Blender
5.2.2's additional `GL_ARB_shader_draw_parameters`, `GL_ARB_clip_control`, and
at least 12 shader-storage buffer bindings in each vertex, fragment and compute
stage are unvalidated here; Blender itself is never downloaded or started.

Window GDI backing pixels are not proof of DWM/monitor/remote-desktop display,
and are not UIKit compositor proof. A hosted runner without a usable desktop
must fail this reference instead of silently relaxing the presentation gate.
The first native Windows run proved GDI/legacy backing pixels; core4.3 remains unavailable for this pinned source configuration.
Windows-host output hashes may differ from Linux-host output hashes; this
workflow uses its own same-job outputs and makes no cross-host byte-identity
claim.

## Bounds and triggering

The workflow is pinned to standard `windows-2025`, the public
`Mi-Yomi/Madeira` repository and `compatibility/desktop-apps`. It has only a
read-only contents token and disables checkout credential persistence. It is
triggered by explicit dispatch or changes to its own workflow/request file;
ordinary app/source commits do not repeatedly start it.

- Job deadline 25 minutes; runner script deadline 22 minutes; build at most
  15 minutes and two compile jobs; each canary process at most 45 seconds
- Work tree at most 6 GiB, at least 4 GiB free space, input byte/hash bounds,
  source/ZIP expansion limits, logs at most 16 MiB per subprocess and at most
  24,000 bytes of each log printed to the Actions console
- Timeout/resource failure terminates the subprocess tree. The VM is disposed
  by Actions. No cache/artifact upload, persistent installation, paid/larger
  runner, product input, private data, credential, signing, IPA or app build

Detailed local receipts include exact tool versions, inputs, commands, source
commit, produced binary hashes and stage proof. The Actions log receives a
bounded summary, including actual runtime identity/version and pixels. No
20 MB DLL is published merely to move it between jobs.

## Portable review checks

From the repository root:

```
python tests/host/check-mesa-windows-reference.py
python tests/desktop/mesa_wgl/check_canary.py --windows-cc /path/to/x86_64-w64-mingw32-clang --out-dir /temporary/review-output
```

The first tests proof rejection, archive/size/hash controls and workflow
constraints without Windows or downloads. The second exercises the host pixel
oracle under ASan/UBSan and optionally cross-compiles the Windows canary; it
never executes Windows code. Neither substitutes for the future Windows run.

## Prepared strict modern mode

A separate `modern` stage and mandatory acceptance hook are documented in
[MODERN.md](MODERN.md). They exercise actual twelve-block compute and vertex/
fragment storage, indirect draw parameters and clip-control behavior. This does
not alter the existing softpipe workflow or its unavailable core4.3 classification.
Until a separately reviewed llvmpipe job executes and passes the new required
stage, these additional capabilities remain runtime-unvalidated.
