#!/usr/bin/env python3
"""Fresh LLVM 15.0.7 host tools and iOS ARM64 static libraries; no package installs."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

import common


def fetch():
    root, spec = common.ROOT, common.manifest()
    destination = root / "toolchains/llvm-project"
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Source destination must be fresh: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="llvm-source-", dir=destination.parent))
    try:
        common.run(["git", "init", temporary])
        common.run(["git", "-C", temporary, "remote", "add", "origin", spec["repository"]])
        common.run(["git", "-C", temporary, "config", "core.sparseCheckout", "true"])
        common.run(["git", "-C", temporary, "sparse-checkout", "set", "--cone", *spec["sparse_directories"]])
        common.run(["git", "-C", temporary, "fetch", "--filter=blob:none", "--depth=1", "origin", spec["revision"]])
        common.run(["git", "-C", temporary, "checkout", "--detach", "FETCH_HEAD"])
        common.check_revision(temporary, spec["revision"])
        for directory in spec["sparse_directories"]:
            if not (temporary / directory).is_dir():
                raise ValueError(f"Sparse checkout lacks {directory}")
        common.regular_file(temporary / "llvm/LICENSE.TXT")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def definitions():
    # LLVM 15's BLAKE3 assembler selection mishandles explicit OSX architectures.
    # NO_DEAD_STRIP avoids AddLLVM's non-Darwin --gc-sections path on CMAKE_SYSTEM_NAME=iOS.
    return {
        "CMAKE_BUILD_TYPE": "Release", "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "CMAKE_C_FLAGS": "", "CMAKE_CXX_FLAGS": "", "CMAKE_EXE_LINKER_FLAGS": "",
        "CMAKE_MODULE_LINKER_FLAGS": "", "CMAKE_SHARED_LINKER_FLAGS": "",
        "CMAKE_INTERPROCEDURAL_OPTIMIZATION": "OFF", "BUILD_SHARED_LIBS": "OFF",
        "LLVM_TARGETS_TO_BUILD": "", "LLVM_EXPERIMENTAL_TARGETS_TO_BUILD": "",
        "LLVM_ENABLE_PROJECTS": "", "LLVM_ENABLE_RUNTIMES": "", "LLVM_ENABLE_LTO": "OFF",
        "LLVM_BUILD_LLVM_DYLIB": "OFF", "LLVM_LINK_LLVM_DYLIB": "OFF",
        "LLVM_ENABLE_EH": "OFF", "LLVM_ENABLE_RTTI": "OFF", "LLVM_ENABLE_ASSERTIONS": "OFF",
        "LLVM_INCLUDE_TESTS": "OFF", "LLVM_BUILD_TESTS": "OFF",
        "LLVM_INCLUDE_EXAMPLES": "OFF", "LLVM_BUILD_EXAMPLES": "OFF",
        "LLVM_INCLUDE_BENCHMARKS": "OFF", "LLVM_BUILD_BENCHMARKS": "OFF",
        "LLVM_INCLUDE_DOCS": "OFF", "LLVM_ENABLE_DOXYGEN": "OFF", "LLVM_ENABLE_SPHINX": "OFF",
        "LLVM_ENABLE_BINDINGS": "OFF", "LLVM_ENABLE_ZLIB": "OFF", "LLVM_ENABLE_ZSTD": "OFF",
        "LLVM_ENABLE_TERMINFO": "OFF", "LLVM_ENABLE_LIBXML2": "OFF", "LLVM_ENABLE_LIBEDIT": "OFF",
        "LLVM_ENABLE_LIBPFM": "OFF", "LLVM_ENABLE_FFI": "OFF", "LLVM_ENABLE_CURL": "OFF",
        "LLVM_DISABLE_ASSEMBLY_FILES": "ON", "LLVM_NO_DEAD_STRIP": "ON",
        "LLVM_BUILD_UTILS": "OFF", "LLVM_INCLUDE_UTILS": "OFF", "LLVM_BUILD_TOOLS": "OFF",
        "LLVM_PARALLEL_COMPILE_JOBS": "2", "LLVM_PARALLEL_LINK_JOBS": "1",
    }


def build(stage):
    root, spec = common.ROOT, common.manifest()
    source = root / "toolchains/llvm-project"
    common.check_revision(source, spec["revision"])
    build_dir = root / f"toolchains/llvm-{stage}-build"
    if build_dir.exists() or build_dir.is_symlink():
        raise ValueError(f"LLVM {stage} build directory must be fresh: {build_dir}")
    sdk = "macosx" if stage == "host" else "iphoneos"
    sdk_path = common.output(["xcrun", "--sdk", sdk, "--show-sdk-path"])
    compiler = common.output(["xcrun", "--sdk", sdk, "--find", "clang"])
    cxx = common.output(["xcrun", "--sdk", sdk, "--find", "clang++"])
    opts = definitions()
    opts.update({"CMAKE_C_COMPILER": compiler, "CMAKE_CXX_COMPILER": cxx,
                 "CMAKE_OSX_SYSROOT": sdk_path, "CMAKE_OSX_ARCHITECTURES": "arm64"})
    if stage == "host":
        if common.output(["uname", "-m"]) != "arm64":
            raise ValueError("The graphics build requires an arm64 macOS host")
        opts.update({"CMAKE_SYSTEM_NAME": "Darwin", "CMAKE_SYSTEM_PROCESSOR": "arm64",
                     "LLVM_INCLUDE_TOOLS": "ON"})
        targets = ["llvm-tblgen", "llvm-dis"]
    else:
        # AIR was already compiled by Metal and decoded with these exact host tools.
        import sys
        sys.path.insert(0, str(root / "build/dxmt-ios"))
        from generate_shaders import validate
        validate()
        tablegen = common.regular_file(root / "toolchains/llvm-host-build/bin/llvm-tblgen")
        opts.update({"CMAKE_SYSTEM_NAME": "iOS", "CMAKE_SYSTEM_PROCESSOR": "arm64",
                     "CMAKE_OSX_DEPLOYMENT_TARGET": spec["deployment_target"],
                     "LLVM_HOST_TRIPLE": "arm64-apple-ios17.0", "LLVM_DEFAULT_TARGET_TRIPLE": "arm64-apple-ios17.0",
                     "LLVM_TARGET_ARCH": "host", "LLVM_TABLEGEN": str(tablegen.resolve()),
                     "LLVM_INCLUDE_TOOLS": "OFF"})
        targets = ["LLVMBitWriter", "LLVMPasses"]
    # Do not set TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY: link failures must be real failures.
    common.run(["cmake", "-S", source / "llvm", "-B", build_dir, "-G", "Ninja",
                *[f"-D{key}={value}" for key, value in opts.items()]])
    common.run(["cmake", "--build", build_dir, "--parallel", "2", "--target", *targets])
    outputs = ({name: common.sha256(common.regular_file(build_dir / "bin" / name)) for name in targets}
               if stage == "host" else common.verify_llvm_archives())
    if stage == "host":
        for name in targets:
            common.run([build_dir / "bin" / name, "--version"])
    common.write_json(build_dir / "madeira-build.json", {
        "schema_version": 1, "stage": stage, "revision": spec["revision"], "repository": spec["repository"],
        "manifest_sha256": common.sha256(common.MANIFEST_PATH), "definitions": opts,
        "targets": targets, "outputs": outputs,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("fetch", "host", "ios", "validate"))
    args = parser.parse_args()
    try:
        if args.stage == "fetch": fetch()
        elif args.stage == "validate": print(common.verify_llvm_archives())
        else: build(args.stage)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__": main()
