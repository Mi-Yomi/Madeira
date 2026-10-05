#!/usr/bin/env python3
"""Compile the canary and exercise its host-side pixel oracle.

This does not execute Windows code. Supplying --windows-cc also builds x64 PE
and audits imports to ensure the GDI-only stage cannot be blocked by an initial
OpenGL DLL import. No toolchains or packages are downloaded by this script.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host-cc", default=os.environ.get("CC", "cc"))
parser.add_argument("--windows-cc")
parser.add_argument("--objdump", default="objdump")
parser.add_argument("--out-dir", type=Path, default=ROOT / "results")
options = parser.parse_args()
options.out_dir.mkdir(parents=True, exist_ok=True)
result = {"host_pixel_oracle": "not-run", "windows_cross_compile": "not-run",
          "windows_execution": "not-run", "madeira_execution": "not-run"}
host = options.out_dir / "check-canary-pixels"
subprocess.run(shlex.split(options.host_cc) + ["-std=c11", "-Wall", "-Wextra", "-Werror",
    "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    str(ROOT / "check_canary_pixels.c"), "-o", str(host)], check=True)
env = os.environ.copy()
env["ASAN_OPTIONS"] = "detect_leaks=0"
subprocess.run([str(host)], check=True, env=env)
result["host_pixel_oracle"] = "passed-asan-ubsan; leak-check-not-run"
modern = options.out_dir / "check-canary-modern"
subprocess.run(shlex.split(options.host_cc) + ["-std=c11", "-Wall", "-Wextra", "-Werror",
    "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    str(ROOT / "check_canary_modern.c"), "-o", str(modern)], check=True)
subprocess.run([str(modern)], check=True, env=env)
result["host_modern_oracle"] = "passed-asan-ubsan; leak-check-not-run"
if options.windows_cc:
    target = options.out_dir / "wgl-canary-x64.exe"
    subprocess.run(shlex.split(options.windows_cc) + ["-std=c11", "-Wall", "-Wextra", "-Werror",
        "-O2", str(ROOT / "wgl_canary.c"), "-o", str(target), "-lgdi32", "-luser32"], check=True)
    data = target.read_bytes()
    assert data[:2] == b"MZ", "missing DOS signature"
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[offset:offset + 4] == b"PE\0\0", "missing PE signature"
    assert struct.unpack_from("<H", data, offset + 4)[0] == 0x8664, "not x64 PE"
    imports = subprocess.run(shlex.split(options.objdump) + ["-p", str(target)],
                             check=True, text=True, capture_output=True).stdout
    dlls = sorted(set(re.findall(r"DLL Name:\s*(\S+)", imports)))
    names = {name.lower() for name in dlls}
    assert {"gdi32.dll", "user32.dll", "kernel32.dll"} <= names
    assert not any("opengl" in name or "gallium" in name for name in names), names
    result["windows_cross_compile"] = "passed; PE-x64; no-static-OpenGL-import"
    result["windows_exe_sha256"] = hashlib.sha256(data).hexdigest()
    result["windows_imports"] = dlls
    print("PASS: Windows x64 cross-compile; GDI and loader imports; no OpenGL startup import")
else:
    print("NOT RUN: Windows cross-compile (supply --windows-cc)")
result["source_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in ("wgl_canary.c", "wgl_canary_pixels.h", "check_canary_pixels.c",
                                        "wgl_canary_modern.h", "wgl_canary_modern_values.h", "check_canary_modern.c")}
(options.out_dir / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
print("NOT RUN: Windows runtime, Wine runtime, FEX, iOS compositor and Blender acceptance")
