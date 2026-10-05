# Strict modern graphics prerequisite canary

This is source preparation for a future, separately reviewed Windows llvmpipe
reference. It is not a Blender 5.2.2 execution test. The existing `gdi`, `legacy`
and `core43` CLI modes and the softpipe Windows workflow retain their behavior.
No new job is dispatched by this change.

## Required acceptance mode

A future source-build job must build the canary from this same tree and call
`modern_acceptance.accept_modern(runner, bundle, env, audited_binaries,
windows_reference.parse_proof)` after its source provenance and x64 PE import,
export, forwarder and runtime dependency closure audit. The exact bundle contains
only `wgl-canary.exe`, `opengl32.dll`, and `libgallium_wgl.dll`; LLVM and other
non-system runtime dependencies therefore must be static. Dynamic SDK dependencies
require a separate design/review and cannot silently enter this acceptance hook.

The hook invokes:

```
wgl-canary.exe --stage modern --source-built-reference
```

Both `GALLIUM_DRIVER=llvmpipe` and `LP_NUM_THREADS=2` must be set in the process-local
environment. Remove inherited `MESA_*`, `LIBGL_*`, `NIR_*`, `TGSI_*`, `DRAW_*`, `GALLIVM_*` and all
other `GALLIUM_*`/`LP_*` settings. No GL/GLSL/extension override is allowed. No
`--hold-ms` delay is allowed in modern mode. The hook checks exact file sizes and
SHA-256 hashes against the caller's just-built PE audit before and after execution;
the canary checks actual loaded application-local module paths before and after.
The per-file stop guard is 128 MiB, stated in advance; it must not be raised after
failure. A hash dictionary alone is not source or PE provenance.

The caller's `runner.command` must enforce its passed 45-second deadline by
terminating the process tree, bound subprocess logs and total job work/resources,
retain failures and receipts, and run only on the authorized Microsoft Windows
x64 reference job. `windows_reference.Run.command` has that process-tree/log
interface. This hook does not set up the LLVM build, alter that runner's original
softpipe limits/audit, download packages, or create a workflow. It has no standalone
execution entrypoint. A missing 4.3 context, missing capability, code 77,
`UNAVAILABLE`, failed cleanup, incomplete output or bad readback is a required-job
failure, never an optional result or green classification.

## Evidence produced

The original GDI pattern, both legacy clear/swap/window pixels and generic core
shader/swap/window result run first. Modern mode then requires:

- Actual numeric OpenGL >=4.3, core profile, same llvmpipe renderer and Mesa 26.2.4
  identity, real GLSL 430 compile/link logs, and enumerated
  `GL_ARB_shader_draw_parameters` plus `GL_ARB_clip_control`
- At least 12 shader-storage blocks in each vertex, fragment and compute stage,
  at least 12 bindings and 24 combined stage blocks, 16-byte blocks, and queried
  compute workgroup/invocation and framebuffer limits
- Twelve active named std430 blocks, each at its expected distinct binding and
  16-byte layout, with exact vertex/fragment/compute resource-reference flags
- Two single-invocation compute dispatches with different runtime uniform seeds,
  each producing 48 independently expected uint words. Every buffer is mapped and
  checked after shader-storage and buffer-update barriers; successful unmap is
  required. No two shader invocations write the same location
- Two real storage draws using all 12 blocks independently in vertex and fragment
  stages. Two vertex checksums travel through flat integer varyings; two fragment
  checksums are computed separately. All 128 result bits are checked through a
  `RGBA32UI` attachment, avoiding color-only checksum collisions. Distinct odd
  weights ensure any one changed source word changes its full 32-bit checksum
- A separate normalized `RGBA8` attachment encodes the observed checksums. Exact
  GL colors must match, then that attachment alone is blitted to the default
  framebuffer and both post-swap GDI backing pixels must match. Integer-to-default
  framebuffer blits are not used
- One indexed multidraw-indirect call with two 20-byte commands and two instances
  per command. Nonzero distinct first indices 2/6, base vertices 5/9 and base
  instances 7/11 are exercised. The second index triplet is 3/4/5, distinct from
  0/1/2, so reusing either firstIndex cannot pass. Shader builtins determine four
  distinct screen regions and exact integer outputs; a divisor-one integer
  attribute independently checks `baseInstance + instanceID` fetching.
  `baseInstance` never offsets the `gl_InstanceID` builtin
- Eight asymmetric triangle draws test both clip origins, both depth modes and
  clip-space z=-0.5/+0.5. Two distinct framebuffer coordinates check orientation,
  real negative-z clipping and exact integer/color coverage. A 32-bit float depth
  attachment with depth testing enabled checks depths 0.25/0.75, 0.5 or untouched 1,
  with 1e-6 tolerance; NaN cannot pass. Queried origin/depth state is also recorded
- Bounded hex-encoded shader/link logs, elapsed time, all expected uint/pixel/depth
  observations, GL error rejection, object deletion checks, context detachment/
  deletion, module recheck and Windows DC/window/library/class cleanup. The final
  success marker follows successful platform cleanup

All GL workloads are tiny and fixed. The external 45-second process timeout is
still mandatory because a stuck synchronous driver call cannot self-timeout.

## Portable checks and limitations

```
python tests/host/check-mesa-windows-reference.py
python tests/host/check-mesa-modern-canary.py
python tests/desktop/mesa_wgl/check_canary.py --windows-cc /trusted/path/x86_64-w64-mingw32-clang --out-dir /temporary/review-output
```

These verify proof rejection, host expected values and source cross-compilation.
They do not execute the Windows PE. Synthetic transcript tests are parser tests,
not a simulated GPU or a runtime capability result. Runtime shader compilation,
Windows llvmpipe acceptance and performance remain unmeasured until the required
job really passes. Even that future pass would establish only graphics
prerequisites: it does not prove Blender startup/rendering, Madeira PE loading,
ARM64EC/FEX transitions, iOS JIT permission, UIKit/DWM display or useful performance.
