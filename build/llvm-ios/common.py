"""Shared pinned inputs and strict native-object validation for graphics builds."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "build/llvm-ios/manifest.json"
# Deliberately excludes Wine/MinGW toolchain paths inherited by previous stages.
TOOL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
EXPECTED_ARCHIVES = """
LLVMPasses LLVMTarget LLVMObjCARCOpts LLVMCoroutines LLVMipo LLVMInstrumentation
LLVMVectorize LLVMLinker LLVMIRReader LLVMAsmParser LLVMFrontendOpenMP
LLVMScalarOpts LLVMInstCombine LLVMAggressiveInstCombine LLVMTransformUtils
LLVMBitWriter LLVMAnalysis LLVMProfileData LLVMSymbolize LLVMDebugInfoPDB
LLVMDebugInfoMSF LLVMDebugInfoDWARF LLVMObject LLVMTextAPI LLVMMCParser LLVMMC
LLVMDebugInfoCodeView LLVMBitReader LLVMCore LLVMRemarks LLVMBitstreamReader
LLVMBinaryFormat LLVMSupport LLVMDemangle
""".split()


def manifest():
    data = json.loads(MANIFEST_PATH.read_text())
    if (data.get("schema_version") != 1 or
            data.get("repository") != "https://github.com/llvm/llvm-project.git" or
            data.get("revision") != "8dfdcc7b7bf66834a761bd8de445840ef68e4d1a" or
            data.get("dxmt_revision") != "020a848080b861266e04fc0e5f7f6d921614037c" or
            data.get("sparse_directories") != ["llvm", "cmake", "third-party"] or
            data.get("deployment_target") != "17.0"):
        raise ValueError("Unexpected graphics source/build manifest")
    archives = data.get("archives", [])
    if archives != EXPECTED_ARCHIVES:
        raise ValueError("Expected the reviewed 34-member LLVM archive closure")
    return data


def environment():
    env = dict(os.environ)
    for name in list(env):
        if name in {"CC", "CXX", "CPP", "AR", "AS", "LD", "NM", "RANLIB", "STRIP",
                    "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "SDKROOT", "CPATH",
                    "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
                    "MACOSX_DEPLOYMENT_TARGET", "IPHONEOS_DEPLOYMENT_TARGET"} or name.startswith("CMAKE_"):
            del env[name]
    env["PATH"] = TOOL_PATH
    return env


def run(args, **kwargs):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), env=environment(), check=True, **kwargs)


def output(args):
    return run(args, stdout=subprocess.PIPE, text=True).stdout.strip()


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def regular_file(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or not path.stat().st_size:
        raise ValueError(f"Missing, empty or non-regular build input/output: {path}")
    return path


def check_revision(path, expected):
    if output(["git", "-C", path, "rev-parse", "HEAD"]) != expected:
        raise ValueError(f"Wrong source revision: {path}")
    run(["git", "-C", path, "diff", "--exit-code", "HEAD", "--"])


def check_dxmt():
    path = ROOT / "dxmt"
    check_revision(path, manifest()["dxmt_revision"])
    status = run(["git", "-C", path, "submodule", "status", "--recursive"],
                 stdout=subprocess.PIPE, text=True).stdout
    lines = status.splitlines()
    if not lines or any(not re.match(r"^ [0-9a-f]{40} ", line) for line in lines):
        raise ValueError("DXMT nested submodules must be present at exact gitlink revisions")
    if not (path / "include/native/directx").is_dir():
        raise ValueError("DXMT native DirectX headers are missing")


def native_validator():
    spec = importlib.util.spec_from_file_location("graphics_native_artifacts", ROOT / ".github/ci/native-artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_llvm_archives():
    native = native_validator()
    result = {}
    for name in manifest()["archives"]:
        path = ROOT / "toolchains/llvm-ios-build/lib" / f"lib{name}.a"
        result[str(path.relative_to(ROOT))] = native.validate_archive(path)
    return result


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
