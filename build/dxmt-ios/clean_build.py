#!/usr/bin/env python3
"""Fresh, fail-closed DXMT build and explicit LLVM archive merge for CI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "llvm-ios"))
import common
import generate_shaders
import merge_archives

# Mirrors the reviewed complete build.sh source list, including the required
# D3D12 conversion service. Updating that script requires reviewing this set.
OBJECTS = """
msc_canary madeira_ir_unix madeira_sm5_ia madeira_ags winemetal_unix cache
airconv_context air_type air_signature air_operations dxbc_converter
dxbc_converter_gs dxbc_converter_ts dxbc_converter_basicblock dxbc_converter_cfg
dxbc_instructions dxbc_signature metallib_writer dxso_compile ffp_compile
air_builder dxbc_converter_base lower_16bit_texread
dxbc_BlobContainer dxbc_DXBCUtils dxbc_ShaderBinary
util_env util_string util_bloom util_futex thread com_guid com_private_data
config log sha1_util wsi_monitor_headless wsi_window_madeira wsi_platform_madeira sha1
winemetal_thunks wmt_api_census
dxmt_format dxmt_names dxmt_command_queue dxmt_command dxmt_capture dxmt_info
dxmt_device dxmt_buffer dxmt_texture dxmt_context dxmt_dynamic dxmt_staging
dxmt_hud_state dxmt_allocation dxmt_presenter dxmt_sampler dxmt_resource_initializer
dxmt_mem_census dxmt_bcn dxmt_shader_cache
d3d9 d3d9_buffer d3d9_census d3d9_clear_quad d3d9_cube_texture d3d9_device d3d9_format
d3d9_fvf d3d9_interface d3d9_mem d3d9_query d3d9_shader d3d9_shader_scan
d3d9_state_block d3d9_state_defaults d3d9_surface d3d9_swapchain d3d9_texture
d3d9_validation d3d9_vertex_declaration d3d9_volume d3d9_volume_texture
d3d9_unix d3d9_unix_table d3d9_native_glue
""".split()


def verify_objects(directory):
    expected = {name + ".o" for name in OBJECTS}
    actual = {path.name for path in directory.glob("*.o")}
    if len(OBJECTS) != len(expected) or actual != expected:
        raise ValueError(f"DXMT object set differs: missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
    native = common.native_validator()
    for name in sorted(expected):
        path = common.regular_file(directory / name)
        native.macho_ios_object(path.read_bytes(), name)
    return len(expected)


def main():
    root = common.ROOT
    build_dir = root / "build/dxmt-ios"
    for relative in ("obj", "libdxmt_unix.a", "libdxmt_combined.a", "graphics-build.json"):
        path = build_dir / relative
        if path.exists() or path.is_symlink():
            raise ValueError(f"DXMT clean build refuses existing output: {path}")
    if (root / "app/Madeira/libdxmt_combined.a").exists() or (root / "app/Madeira/libdxmt_combined.a").is_symlink():
        raise ValueError("DXMT clean build refuses an existing staged app archive")
    generate_shaders.validate()
    common.verify_llvm_archives()
    env = common.environment()
    for name in list(env):
        if name.startswith(("MADEIRA_", "MSC_", "DXMT_")):
            del env[name]
    # Use the established source/flag recipe, but disallow all incremental or
    # optional-D3D12 escape hatches and stale object/archive inputs.
    result = subprocess.run(["bash", str(build_dir / "build.sh")], cwd=root, env=env)
    if result.returncode:
        for path in sorted((build_dir / "obj").glob("*.err")):
            if path.stat().st_size:
                print(f"=== {path.name} (bounded final diagnostics) ===", flush=True)
                print(path.read_text(errors="replace")[-12000:], flush=True)
        raise subprocess.CalledProcessError(result.returncode, "DXMT fresh build")
    # The legacy recipe regenerates version.h and may regenerate its command
    # header; require byte-identical content to the pre-build AIR receipt.
    generate_shaders.validate()
    count = verify_objects(build_dir / "obj")
    data = merge_archives.merge(build_dir / "libdxmt_unix.a", count)
    print(json.dumps({"dxmt_object_members": count, "llvm_archives": len(data["llvm_archives"]),
                      "combined_archive": data["combined_archive"]}, sort_keys=True))


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
