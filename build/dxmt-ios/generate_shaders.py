#!/usr/bin/env python3
"""Build all embedded Metal inputs from scratch; AIR compatibility is a required gate."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "llvm-ios"))
import common

AIR_NAMES = ("air_msad", "air_samplepos", "air_tessellation")
METAL_FLAGS = ("-std=metal3.1", "--target=air64-apple-macos14.0")


def source_path(name):
    directory = "dxmt" if name == "dxmt_command" else "airconv/shaders"
    return common.ROOT / "dxmt/src" / directory / (name + ".metal")


def header_names():
    return [*(name + extension for name in AIR_NAMES for extension in (".air", ".h")),
            "dxmt_command.air", "dxmt_command.metallib", "dxmt_command.h", "version.h"]


def validate(directory=None):
    root, spec = common.ROOT, common.manifest()
    directory = directory or root / "build/dxmt-ios/shader-headers"
    common.check_dxmt()
    data = json.loads(common.regular_file(directory / "provenance.json").read_text())
    if (data.get("schema_version") != 1 or data.get("dxmt_revision") != spec["dxmt_revision"] or
            data.get("llvm_revision") != spec["revision"] or data.get("metal_flags") != list(METAL_FLAGS) or
            data.get("llvm_dis_sha256") != common.sha256(common.regular_file(root / "toolchains/llvm-host-build/bin/llvm-dis"))):
        raise ValueError("Shader provenance differs from current pinned inputs/tools")
    if set(data.get("outputs", {})) != set(header_names()):
        raise ValueError("Shader receipt lacks the exact required output set")
    for name in header_names():
        if common.sha256(common.regular_file(directory / name)) != data["outputs"][name]:
            raise ValueError(f"Shader output changed: {name}")
    expected_sources = {str(source_path(name).relative_to(root)) for name in (*AIR_NAMES, "dxmt_command")}
    expected_sources.add("dxmt/version.h.in")
    if set(data.get("sources", {})) != expected_sources:
        raise ValueError("Shader receipt lacks the exact required source set")
    for name, digest in data["sources"].items():
        if common.sha256(common.regular_file(root / name)) != digest:
            raise ValueError(f"Shader source changed: {name}")
    if data.get("llvm_dis_checked") != list(AIR_NAMES):
        raise ValueError("All three AIR modules must pass host LLVM15 bitcode decoding")
    return data


def generate():
    root, spec = common.ROOT, common.manifest()
    common.check_dxmt()
    dis = common.regular_file(root / "toolchains/llvm-host-build/bin/llvm-dis")
    destination = root / "build/dxmt-ios/shader-headers"
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("Shader output must be a regular directory")
    directory = Path(tempfile.mkdtemp(prefix=".shaders-", dir=destination.parent))
    old = None
    try:
        for name in (*AIR_NAMES, "dxmt_command"):
            source = common.regular_file(source_path(name))
            air = directory / (name + ".air")
            common.run(["xcrun", "--sdk", "macosx", "metal", *METAL_FLAGS, "-c", source, "-o", air])
            common.regular_file(air)
            if name in AIR_NAMES:
                # Compile-time compatibility only, not a GPU/device runtime test.
                common.run([dis, air, "-o", os.devnull])
                embedded = air
            else:
                embedded = directory / "dxmt_command.metallib"
                common.run(["xcrun", "--sdk", "macosx", "metallib", "-o", embedded, air])
                common.regular_file(embedded)
            header = directory / (name + ".h")
            common.run(["xxd", "-n", name, "-i", embedded, header])
            common.regular_file(header)
        version_template = common.regular_file(root / "dxmt/version.h.in")
        version = common.output(["git", "-C", root / "dxmt", "describe", "--always"])
        (directory / "version.h").write_text(version_template.read_text().replace("@VCS_TAG@", version))
        sources = [*(source_path(name) for name in (*AIR_NAMES, "dxmt_command")), version_template]
        data = {"schema_version": 1, "dxmt_revision": spec["dxmt_revision"], "llvm_revision": spec["revision"],
                "metal_flags": list(METAL_FLAGS), "llvm_dis_sha256": common.sha256(dis),
                "llvm_dis_checked": list(AIR_NAMES),
                "sources": {str(path.relative_to(root)): common.sha256(path) for path in sources},
                "outputs": {name: common.sha256(common.regular_file(directory / name)) for name in header_names()}}
        common.write_json(directory / "provenance.json", data)
        validate(directory)
        if destination.exists():
            old = Path(tempfile.mkdtemp(prefix=".shaders-old-", dir=destination.parent))
            old.rmdir()
            destination.rename(old)
        try:
            directory.rename(destination)
        except BaseException:
            if old is not None:
                old.rename(destination)
                old = None
            raise
        print(f"Generated and LLVM15-decoded all three AIR modules: {destination}")
    finally:
        if directory.exists(): shutil.rmtree(directory)
        if old is not None and old.exists(): shutil.rmtree(old)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "validate"), nargs="?", default="generate")
    args = parser.parse_args()
    try:
        if args.action == "generate": generate()
        else: validate()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__": main()
