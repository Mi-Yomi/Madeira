#!/usr/bin/env python3
"""Source-built Dock receipt for the app gate; no downloads or guest execution.

Only the producer runs the trusted host cross compiler. The consumer verifies
its exact source, official toolchain installation, outputs and same-job receipt.
The intentionally x86-64 host is copied to the arm64ec-windows bundle directory;
it is never added to or exempted from the sealed Wine source farm.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "build/wine-pe"), str(ROOT / "build/llvm-ios")]
import build_receipt
import common
import guest_inventory

SOURCE_REVISION = "3cadfbea700e4da4b04e331dd7ef1ba633dfacef"
SOURCE_REPOSITORY = "https://github.com/willfaust/madeira-dock.git"
SOURCE_URL = "https://github.com/125hz/madeira-dock"
OUTPUT = "build/madeira-dock/generated"
RECEIPT = "provenance.json"
FILES = frozenset(("dockhost.exe", "dock-notices.txt"))
RECIPE_INPUTS = ("build/madeira-dock/build.sh", "build/madeira-dock/verified_build.py",
                 "build/wine-pe/build_receipt.py", "build/wine-pe/guest_inventory.py",
                 "build/llvm-ios/common.py")
RUN_KEYS = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF", "GITHUB_SHA")
TOOLCHAIN = "toolchains/llvm-mingw-20260421-ucrt-macos-universal"
SCOPE = "Source-built x86-64 Dock host and notices; static packaging evidence only, no Steam login or runtime proof"
EXPECTED_IMPORTS = frozenset(("advapi32.dll", "kernel32.dll", *(
    f"api-ms-win-crt-{name}-l1-1-0.dll" for name in
    ("convert", "environment", "heap", "locale", "math", "private", "runtime", "stdio", "string"))))


def require(value, message):
    if not value:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents)
            and path.is_file() and 0 < path.stat().st_size <= 4 * 1024 * 1024,
            f"Missing, unsafe or oversized Dock input: {path}")
    return path


def digest(path):
    return hashlib.sha256(regular(path).read_bytes()).hexdigest()


def git(root, *args):
    return build_receipt.git_output("git", root, *args).decode().strip()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def source_snapshot(root):
    require(git(root, "ls-tree", "HEAD", "madeira-dock").split() ==
            ["160000", "commit", SOURCE_REVISION, "madeira-dock"], "Wrong pinned Dock gitlink")
    require(git(root, "config", "-f", ".gitmodules", "submodule.madeira-dock.url") == SOURCE_REPOSITORY,
            "Wrong Dock source repository")
    source = root / "madeira-dock"
    require(git(source, "rev-parse", "HEAD") == SOURCE_REVISION, "Wrong Dock source revision")
    require(not git(source, "ls-files", "--others", "-z"), "Untracked/ignored Dock source inputs")
    listing = git(source, "ls-tree", "-rz", "--full-tree", "HEAD").split("\0")
    files = {}
    for row in filter(None, listing):
        metadata, name = row.split("\t", 1)
        mode, kind, blob = metadata.split()
        build_receipt.safe_relative(name)
        require(mode in ("100644", "100755") and kind == "blob", "Unexpected Dock source entry")
        path = regular(source / name)
        identity = build_receipt.hash_file(path, git_blob=True)
        require(identity["git_blob"] == blob, "Modified pinned Dock source: " + name)
        files[name] = identity["sha256"]
    require("src/main.c" in files and 0 < len(files) < 1000, "Incomplete Dock source snapshot")
    return {"repository": SOURCE_REPOSITORY, "revision": SOURCE_REVISION,
            "tree": git(source, "rev-parse", "HEAD^{tree}"), "files_sha256": files}


def recipe_snapshot(root):
    result = {}
    for name in RECIPE_INPUTS:
        path = regular(root / name)
        identity = build_receipt.hash_file(path, git_blob=True)
        require(git(root, "rev-parse", "HEAD:" + name) == identity["git_blob"],
                "Dock recipe differs from this source commit: " + name)
        result[name] = identity["sha256"]
    return result


def toolchain_snapshot(toolchain, archive):
    # An archive hash alone cannot establish which compiler or runtime was used.
    # Reuse the bounded validator for every installed regular file and symlink.
    value = build_receipt.verify_toolchain(toolchain, archive)
    members = value.pop("members")
    value["members_sha256"] = hashlib.sha256(canonical(members)).hexdigest()
    value["members_count"] = len(members)
    return value


def expected_notices(root):
    source = root / "madeira-dock"
    content = regular(source / "LICENSE").read_bytes()
    content += f"\nCorresponding source: {SOURCE_URL} (commit {SOURCE_REVISION})\n".encode()
    for label, name in (("LICENSE-EXCEPTION.md (Madeira Converter Exception)", "LICENSE-EXCEPTION.md"),
                        ("COPYING (GNU General Public License, version 3)", "COPYING"),
                        ("MinGW-w64 runtime notice (statically linked runtime)", "notices/MinGW-w64-runtime.txt"),
                        ("LLVM runtime notice", "notices/LLVM.txt")):
        content += f"\n\n==== {label} ====\n\n".encode() + regular(source / name).read_bytes()
    return content


def pe_identity(path):
    data = regular(path).read_bytes()
    pe = guest_inventory.PE(data)
    require(pe.machine == 0x8664 and pe.pe64 and pe.architecture() == "x86_64",
            "Dock host must be x86-64 PE32+ without ARM64EC CHPE metadata")
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    timestamp, symbols, count = struct.unpack_from("<III", data, offset + 8)
    flags = struct.unpack_from("<H", data, offset + 22)[0]
    require(timestamp == symbols == count == 0 and flags & 2 and not flags & 0x2000
            and pe.directory(4) == (0, 0) and pe.directory(6) == (0, 0),
            "Dock host must be a timestamp-free stripped unsigned executable")
    dependencies = [{"dll": name, "kind": kind} for name, kind in pe.dependencies()]
    require({item["dll"] for item in dependencies} == EXPECTED_IMPORTS
            and all(item["kind"] == "import" for item in dependencies),
            "Dock imports differ from the reviewed source-built host")
    return {"machine": "0x8664", "architecture": "x86_64", "format": "PE32+",
            "chpe": False, "dependencies": dependencies}


def input_evidence(root, toolchain, archive):
    commit = git(root, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and os.environ.get("GITHUB_SHA", commit) == commit,
            "Dock source differs from this workflow run")
    return {"schema_version": 1, "source_commit": commit, "source": source_snapshot(root),
            "recipe_sha256": recipe_snapshot(root), "toolchain": toolchain_snapshot(toolchain, archive),
            "run": {key: os.environ.get(key, "") for key in RUN_KEYS}, "scope": SCOPE,
            "host_tests": {"status": "passed", "script": "madeira-dock/tools/check.sh",
                           "suites": ["probe", "validation", "auth", "client_layout"],
                           "sanitizers": ["address", "undefined"], "guest_executed": False}}


def check_source(root, source):
    """Upstream checks create .build/: keep those outputs outside pinned source."""
    env = common.environment()
    # Native bootstrap may have prepended Windows cross tools to PATH. Select
    # the host compiler through the same clean host-tool path as the app gate.
    compiler = os.environ.get("HOST_CC") or shutil.which("clang", path=env["PATH"])
    require(compiler, "Host compiler is required for Dock ASan/UBSan fixtures (set HOST_CC)")
    env["HOST_CC"] = compiler
    with tempfile.TemporaryDirectory(prefix="madeira-dock-check-") as temporary:
        copy = Path(temporary)
        for name, expected in source["files_sha256"].items():
            data = regular(root / "madeira-dock" / name).read_bytes()
            require(hashlib.sha256(data).hexdigest() == expected, "Dock source changed before host checks")
            target = copy / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        subprocess.run(["bash", "tools/check.sh"], cwd=copy, env=env, check=True)


def output_evidence(root, *, receipt=True):
    output = root / OUTPUT
    require(output.is_dir() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents),
            "Missing or unsafe generated Dock directory; run verified_build.py build first")
    require({path.name for path in output.iterdir()} == FILES | ({RECEIPT} if receipt else set()),
            "Generated Dock directory must contain only host, notices and its receipt")
    require(regular(output / "dock-notices.txt").read_bytes() == expected_notices(root),
            "Dock notices differ from pinned source/runtime licences")
    return {"outputs_sha256": {name: digest(output / name) for name in sorted(FILES)},
            "pe": pe_identity(output / "dockhost.exe")}


def validate(root=ROOT):
    root = Path(root)
    record = json.loads(regular(root / OUTPUT / RECEIPT).read_text())
    require(isinstance(record, dict) and isinstance(record.get("toolchain"), dict), "Invalid Dock receipt")
    saved = record["toolchain"]
    expected = input_evidence(root, Path(saved["installation"]) / "bin", Path(saved["archive"]))
    expected.update(output_evidence(root))
    require(record == expected, "Dock receipt differs from same-job source/toolchain/output evidence")
    return expected


def build(root=ROOT, *, toolchain=None, archive=None):
    root = Path(root)
    output = root / OUTPUT
    require(not output.exists() and not output.is_symlink(), "Refusing existing generated Dock output")
    toolchain = Path(toolchain) if toolchain else root / TOOLCHAIN / "bin"
    archive = Path(archive) if archive else root / (TOOLCHAIN + ".tar.xz")
    evidence = input_evidence(root, toolchain, archive)
    check_source(root, evidence["source"])
    env = common.environment()
    env.update({"LLVM_MINGW": str(toolchain.resolve()), "DOCK_OUTPUT_DIR": str(output)})
    subprocess.run(["bash", "build/madeira-dock/build.sh"], cwd=root, env=env, check=True)
    require(evidence == input_evidence(root, toolchain, archive), "Dock inputs changed during compilation")
    evidence.update(output_evidence(root, receipt=False))
    with (output / RECEIPT).open("x") as stream:
        stream.write(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    require(validate(root) == evidence, "Dock producer verification failed")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("mode", choices=("build", "verify"))
    parser.add_argument("--toolchain", type=Path)
    parser.add_argument("--toolchain-archive", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "verify":
            require(args.toolchain is None and args.toolchain_archive is None, "Verify uses recorded toolchain paths")
            value = validate()
        else:
            value = build(toolchain=args.toolchain, archive=args.toolchain_archive)
        print(json.dumps({"status": "passed", "source_commit": value["source_commit"],
                          "source_revision": SOURCE_REVISION, "outputs_sha256": value["outputs_sha256"],
                          "scope": SCOPE}, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
