#!/usr/bin/env python3
"""Bounded, same-source ThinLTO reproduction; never relax archive acceptance.

Verifies the just-built JitSymbols.cpp iOS Mach-O object, then compiles the same
pinned source and validated explicit device-target flags with ThinLTO. The replay
uses a sanitized environment, disabled default compiler configs and disposable
outputs; dependency-output flags are removed. No recovered object from an earlier
runner is claimed, and no generated code runs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("FEX/FEXCore/Source/Common/JitSymbols.cpp")
OBJECT = Path("FEX/build-ios/FEXCore/Source/CMakeFiles/FEXCore_object.dir/Common/JitSymbols.cpp.o")
DATABASE = Path("FEX/build-ios/compile_commands.json")
EXPECTED_TRIPLE = "arm64-apple-ios17.0.0"
EXPECTED_DEVELOPER_DIR = Path("/Applications/Xcode_27.app/Contents/Developer")
MAX_OUTPUT = 64 * 1024
MAX_FILE = 8 * 1024 * 1024
TOTAL_SECONDS = 120
loader = importlib.util.spec_from_file_location("native_artifacts", ROOT / ".github/ci/native-artifacts.py")
artifacts = importlib.util.module_from_spec(loader)
loader.loader.exec_module(artifacts)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tool_digest(path, deadline):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if time.monotonic() >= deadline:
                raise ValueError("Native object diagnostic exceeded its total timeout while hashing compiler")
            value.update(chunk)
    return value.hexdigest()


def bounded_file(path, root, limit=MAX_FILE):
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Diagnostic input must be a regular file within its expected root")
    if path.stat().st_size > limit:
        raise ValueError("Diagnostic file exceeds size limit")
    return path.read_bytes()


def diagnostic_category(stderr):
    """Classify useful failures without quoting source/IR or arbitrary tool output."""
    text = stderr.lower()
    categories = (
        (("overriding the module target triple",), "module target triple mismatch"),
        (("unknown argument", "unknown warning option", "unsupported option", "unrecognized command-line option"), "unsupported compiler option"),
        (("invalid bitcode", "error reading bitcode", "invalid record", "malformed block", "unknown attribute kind"), "LLVM bitcode reader rejected module"),
        (("unable to create target", "no available targets"), "requested target is unsupported"),
        (("file not found",), "required compilation header missing"),
        (("unable to open output file", "cannot open", "permission denied"), "compiler file access failed"),
        (("error: expected",), "compiler rejected source or IR syntax"),
    )
    for patterns, category in categories:
        if any(pattern in text for pattern in patterns):
            return category
    return "unclassified tool failure"


def run(args, *, cwd=None, deadline, timeout=30, scratch=None):
    """No shell; combined output and process-group lifetime are strictly bounded."""
    end = min(deadline, time.monotonic() + timeout)
    if end <= time.monotonic():
        raise ValueError("Native object diagnostic exceeded its total timeout")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "TZ": "UTC"}
    environment["DEVELOPER_DIR"] = str(EXPECTED_DEVELOPER_DIR)
    if scratch is not None:
        environment.update(HOME=str(scratch), TMPDIR=str(scratch))
    with subprocess.Popen(args, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process, selectors.DefaultSelector() as selector:
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            selector.register(stream, selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Native object diagnostic command timed out")
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if sum(map(len, output.values())) + len(chunk) > MAX_OUTPUT:
                        raise ValueError("Native object diagnostic command output limit exceeded")
                    output[key.data].extend(chunk)
            process.wait(timeout=max(0.01, end - time.monotonic()))
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            if isinstance(error, subprocess.TimeoutExpired):
                raise ValueError("Native object diagnostic command timed out") from error
            raise
    result = subprocess.CompletedProcess(args, process.returncode,
                                         output["stdout"].decode(errors="replace"),
                                         output["stderr"].decode(errors="replace"))
    if result.returncode:
        raise ValueError(f"Native object diagnostic command failed ({result.returncode}); "
                         f"category={diagnostic_category(result.stderr)}; stderr_sha256={digest(output['stderr'])}")
    return result


def compile_entry(root, compiler, sdk):
    build = (root / "FEX/build-ios").resolve()
    cache = bounded_file(build / "CMakeCache.txt", build).decode()
    for name, value in (("ENABLE_LTO", "OFF"), ("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")):
        values = re.findall(rf"^{name}:[^=\n]+=(.*)$", cache, re.M)
        if values != [value]:
            raise ValueError(f"Expected explicit {name}={value}")
    database = bounded_file(root / DATABASE, build)
    entries = json.loads(database)
    if not isinstance(entries, list):
        raise ValueError("Compile database must contain entries")
    matches = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str) or not isinstance(entry.get("directory"), str):
            raise ValueError("Malformed compile database entry")
        directory = Path(entry["directory"])
        if (directory / entry["file"]).resolve() == (root / SOURCE).resolve():
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError("Expected exactly one JitSymbols compile command")
    entry, = matches
    directory = Path(entry["directory"]).resolve()
    # Makefiles records the target's binary directory; Ninja records the root.
    # Accept only these two exact layouts, never arbitrary build subdirectories.
    if directory not in (build, build / "FEXCore/Source"):
        relative = os.path.relpath(directory, build)
        context = json.dumps(relative[:160], ensure_ascii=True)
        if len(context) > 180:
            context = context[:177] + "..."
        raise ValueError("Unexpected FEX compilation working directory: "
                         f"expected build-relative '.' or 'FEXCore/Source'; actual={context}")
    if ("arguments" in entry) == ("command" in entry):
        raise ValueError("Ambiguous compile command representation")
    args = entry.get("arguments") if "arguments" in entry else shlex.split(entry["command"])
    if not isinstance(args, list) or not args or not all(isinstance(arg, str) and arg for arg in args):
        raise ValueError("Malformed compiler arguments")
    if any(arg.startswith("@") or any(ord(char) < 32 for char in arg) for arg in args):
        raise ValueError("Response files or control characters are forbidden")
    if Path(args[0]).resolve() != compiler.resolve():
        raise ValueError("Unexpected compiler; selected Apple clang++ is required")
    # Preserve validated explicit arguments; redirect primary/dependency outputs
    # and disable implicit compiler configs for the diagnostic replay.
    # Unknown options are refused, never silently dropped or passed to plugins.
    keep = [str(compiler), "--no-default-config"]
    arch, sysroot, minimum, target, source, output = [], [], [], [], [], []
    target_flags, defines = [], []
    simple = {"-fPIC", "-fPIE", "-fvisibility=hidden", "-fvisibility-inlines-hidden",
              "-ffunction-sections", "-fdata-sections", "-fwrapv", "-fomit-frame-pointer",
              "-fno-omit-frame-pointer", "-fcolor-diagnostics", "-fdiagnostics-color=always",
              "-stdlib=libc++", "-fno-exceptions", "-fno-rtti"}
    i = 1
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "-MF", "-MT", "-MQ"):
            if i + 1 == len(args):
                raise ValueError("Missing output/dependency operand")
            if arg == "-o":
                output.append((directory / args[i + 1]).resolve())
            i += 2
            continue
        if arg in ("-MD", "-MMD", "-MP"):
            i += 1
            continue
        if arg in ("-arch", "-isysroot", "-target", "--target", "-I", "-isystem", "-D", "-U", "-x", "-c"):
            if i + 1 == len(args):
                raise ValueError("Missing compiler operand")
            value = args[i + 1]
            if arg == "-arch": arch.append(value); target_flags.extend((arg, value))
            elif arg == "-isysroot": sysroot.append(Path(value).resolve()); target_flags.extend((arg, str(Path(value).resolve())))
            elif arg in ("-target", "--target"): target.append(value); target_flags.extend((arg, value))
            elif arg in ("-I", "-isystem"):
                included = (directory / value).resolve()
                if not (included.is_relative_to((root / "FEX").resolve()) or included.is_relative_to(sdk)):
                    raise ValueError("Unexpected include search path")
            elif arg == "-D": defines.append(value)
            elif arg == "-U" and value in ("__APPLE__", "ARCHITECTURE_arm64", "JIT_ARM64"):
                raise ValueError("Native target definitions cannot be undefined")
            elif arg == "-x" and value != "c++": raise ValueError("Unexpected compiler language")
            elif arg == "-c": source.append((directory / value).resolve())
            keep.extend((arg, value))
            i += 2
            continue
        if arg.startswith("--target="):
            target.append(arg.split("=", 1)[1]); target_flags.append(arg)
        elif arg.startswith(("-miphoneos-version-min=", "-mios-version-min=")):
            minimum.append(arg.split("=", 1)[1]); target_flags.append(arg)
        elif arg.startswith("-I"):
            included = (directory / arg[2:]).resolve()
            if not (included.is_relative_to((root / "FEX").resolve()) or included.is_relative_to(sdk)):
                raise ValueError("Unexpected include search path")
        elif arg.startswith("-D"):
            defines.append(arg[2:])
        elif arg.startswith("-U"):
            if arg[2:] in ("__APPLE__", "ARCHITECTURE_arm64", "JIT_ARM64"):
                raise ValueError("Native target definitions cannot be undefined")
        elif arg in simple or re.fullmatch(r"-O(?:[0-3sz])", arg) or re.fullmatch(r"-W[a-zA-Z0-9_=-]+", arg):
            pass
        elif arg in ("-std=gnu++20", "-std=c++20"):
            target_flags.append(arg)
        else:
            raise ValueError(f"Unreviewed compiler option: {arg[:160]}")
        keep.append(arg)
        i += 1
    if source != [(root / SOURCE).resolve()] or output != [(root / OBJECT).resolve()]:
        raise ValueError("Unexpected source or production object output")
    if sysroot != [sdk] or arch not in ([], ["arm64"]) or target not in ([], ["arm64-apple-ios17.0"], [EXPECTED_TRIPLE]):
        raise ValueError("Expected selected iPhoneOS SDK and arm64 iOS target")
    if not arch and not target:
        raise ValueError("Missing arm64 iOS architecture")
    if minimum not in ([], ["17.0"], ["17.0.0"]) or (not minimum and not target):
        raise ValueError("Expected iOS 17.0 deployment target")
    definition_values = {}
    for value in defines:
        name, separator, setting = value.partition("=")
        definition_values.setdefault(name, []).append(setting if separator else "1")
    for name in ("ARCHITECTURE_arm64", "JIT_ARM64"):
        if not definition_values.get(name) or any(value != "1" for value in definition_values[name]):
            raise ValueError("Expected unambiguous native FEX arm64 compiler definitions")
    if any(value != "1" for value in definition_values.get("__APPLE__", [])):
        raise ValueError("Conflicting Apple platform definition")
    if any(value.split("=", 1)[0] in ("_WIN32", "FEX_IOS_HOST", "ARCHITECTURE_arm64ec") for value in defines):
        raise ValueError("PE host definitions are forbidden in native object")
    return keep, directory, digest(database), target_flags


def bitcode_format(data):
    if data[:4] == b"BC\xc0\xde":
        return "LLVM bitcode"
    if data[:4] == b"\xde\xc0\x17\x0b" and len(data) >= 20:
        _, version, offset, size, _ = struct.unpack_from("<5I", data)
        if version == 0 and offset >= 20 and size >= 4 and offset + size <= len(data) and data[offset:offset + 4] == b"BC\xc0\xde":
            return "LLVM bitcode"
    raise ValueError("Fresh ThinLTO object is not recognized LLVM bitcode")


def inspect_native():
    root = ROOT.resolve()
    deadline = time.monotonic() + TOTAL_SECONDS
    developer = EXPECTED_DEVELOPER_DIR.resolve(strict=True)
    override = os.environ.get("DEVELOPER_DIR")
    if override and Path(override).resolve() != developer:
        raise ValueError("DEVELOPER_DIR overrides the audited selected Xcode")
    selected = Path(run(["/usr/bin/xcode-select", "--print-path"], deadline=deadline).stdout.strip()).resolve()
    if selected != developer:
        raise ValueError("Selected Xcode differs from the audited Xcode 27 developer directory")
    compiler = Path(run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--find", "clang++"], deadline=deadline).stdout.strip())
    sdk_path = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"], deadline=deadline).stdout.strip()
    sdk = Path(sdk_path).resolve()
    if not compiler.is_absolute() or not compiler.is_file() or not sdk.is_dir() or not re.fullmatch(r"iPhoneOS[0-9.]*\.sdk", sdk.name):
        raise ValueError("Invalid selected Apple compiler or iPhoneOS SDK")
    trusted_bin = (developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin").resolve()
    trusted_sdks = (developer / "Platforms/iPhoneOS.platform/Developer/SDKs").resolve()
    if compiler.resolve().parent != trusted_bin or compiler.resolve().name not in ("clang", "clang++") or not sdk.is_relative_to(trusted_sdks):
        raise ValueError("Compiler or device SDK escaped the audited Xcode")
    run(["/usr/bin/codesign", "--verify", "--strict", "-R", "=anchor apple", str(compiler.resolve())], deadline=deadline)
    version = run([str(compiler), "--no-default-config", "--version"], deadline=deadline).stdout.strip()
    if not version.startswith("Apple clang version"):
        raise ValueError("Selected compiler is not Apple clang")
    command, directory, database_hash, target_flags = compile_entry(root, compiler, sdk)
    original_source = bounded_file(root / SOURCE, root / "FEX")
    specification = json.loads(bounded_file(root / "build/fex-ios/source-repairs.json", root).decode())
    revision = run(["git", "rev-parse", "HEAD"], cwd=root / "FEX", deadline=deadline).stdout.strip()
    if revision != specification["source_revision"]:
        raise ValueError("FEX source revision does not match its reviewed pin")
    committed = run(["git", "show", "HEAD:" + str(SOURCE.relative_to("FEX"))],
                    cwd=root / "FEX", deadline=deadline).stdout.encode()
    if committed != original_source:
        raise ValueError("JitSymbols source differs from its pinned Git blob")
    production = bounded_file(root / OBJECT, root / "FEX/build-ios")
    artifacts.macho_ios_object(production, "FEX production JitSymbols.cpp.o")
    with tempfile.TemporaryDirectory(prefix="FEX native object diagnostic ") as name:
        temporary = Path(name).resolve()
        probe, ir = temporary / "JitSymbols-thinlto.o", temporary / "JitSymbols.ll"
        run([*command, "-flto=thin", "-o", str(probe)], cwd=directory, deadline=deadline, timeout=45, scratch=temporary)
        bitcode = bounded_file(probe, temporary)
        format_name = bitcode_format(bitcode)
        try:
            artifacts.macho_ios_object(bitcode, "diagnostic-only ThinLTO object")
        except ValueError:
            pass
        else:
            raise ValueError("Strict object validator unexpectedly accepted bitcode")
        reader = run([str(compiler), "--no-default-config", "-S", "-emit-llvm", "-x", "ir", "--target=" + EXPECTED_TRIPLE,
                      "-Werror=override-module", "-Werror=unknown-warning-option", str(probe), "-o", str(ir)],
                     deadline=deadline, timeout=45, scratch=temporary)
        text = bounded_file(ir, temporary).decode()
        triples = re.findall(r'^target triple = "([^"\n]+)"$', text, re.M)
        if triples != [EXPECTED_TRIPLE] or reader.stderr.strip():
            raise ValueError("LLVM reader did not verify the exact original iOS target triple without diagnostics")
        reproduction = {"format": format_name, "magic_hex": bitcode[:4].hex(), "sha256": digest(bitcode),
                        "added_flag": "-flto=thin", "target_triple": triples[0],
                        "override_module_is_error": True, "reader_exit_code": reader.returncode,
                        "strict_validator_rejected": True}
    if bounded_file(root / SOURCE, root / "FEX") != original_source or bounded_file(root / OBJECT, root / "FEX/build-ios") != production:
        raise ValueError("Diagnostic changed a production input or object")
    compiler_hash = tool_digest(compiler, deadline)
    if time.monotonic() >= deadline:
        raise ValueError("Native object diagnostic exceeded its total timeout")
    return {"schema_version": 1, "status": "passed", "evidence_kind": "fresh-same-source-thinlto-reproduction",
            "source": {"path": str(SOURCE), "sha256": digest(original_source)},
            "compiler": {"path": str(compiler), "version": version, "sha256": compiler_hash}, "sdk_path": sdk_path,
            "helper_sha256": artifacts.sha256(Path(__file__)), "native_flags": target_flags,
            "compile_database": {"path": str(DATABASE), "sha256": database_hash},
            "production_object": {"path": str(OBJECT), "sha256": digest(production), "format": "Mach-O arm64 iOS"},
            "native_configuration": {"enable_lto": False, "architecture": "arm64", "deployment_target": "17.0",
                                     "ipo_flags": []},
            "reproduction": reproduction}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink() or args.receipt.parent.is_symlink():
        raise ValueError("Refusing a stale or symlinked native object receipt")
    receipt = inspect_native()
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    # Publish a complete new receipt without replacing a concurrent/stale file.
    with tempfile.NamedTemporaryFile(mode="w", dir=args.receipt.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.link(temporary, args.receipt)
        finally:
            temporary.unlink(missing_ok=True)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"FEX native object diagnostic failed: {error}", file=sys.stderr)
        sys.exit(1)
