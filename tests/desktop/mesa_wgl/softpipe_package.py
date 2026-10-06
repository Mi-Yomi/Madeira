#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, bounded packaging for an explicitly activated softpipe request.

This module never builds, executes a PE, accesses the network or uploads files.
The ordinary Windows reference workflow remains unchanged.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import time
import zipfile

import windows_reference as reference

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
REQUEST = "tests/desktop/mesa_wgl/delivery-request.json"
REPOSITORY = "Mi-Yomi/Madeira"
REF = "refs/heads/compatibility/desktop-apps"
ASSETS = ("Madeira-softpipe-test.zip", "Madeira-softpipe-source.zip", "provenance.json", "SHA256SUMS")
BINARIES = {"opengl32.dll", "libgallium_wgl.dll", "wgl-canary.exe"}
MAX_ASSET = 128 * 1024**2
MAX_NOTICE = 24 * 1024**2
MAX_PACKAGE = 256 * 1024**2
LIMITS = {
    "windows_reference": "GDI and legacy softpipe backing pixels only",
    "madeira_execution_tested": False,
    "ios_compositor_display_proven": False,
    "interactive_mode_runtime_tested": False,
    "blender_tested": False,
    "opengl_43_available": False,
    "ipa_included": False,
    "installs_system_dlls": False,
    "automatic_device_log_upload": False,
    "historical_binary_reproducibility_proven": False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


def request_value(value):
    expected = {"schema_version", "enabled", "repository", "source_ref", "source_commit",
                "request_id", "release_id", "target_ipa_sha256", "delivery", "publish"}
    require(isinstance(value, dict) and set(value) == expected, "Unexpected request fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and
            type(value["enabled"]) is bool and value["repository"] == REPOSITORY and
            value["source_ref"] == REF and value["delivery"] == "existing-private-draft" and
            value["publish"] is False, "Unexpected request scope")
    if not value["enabled"]:
        require(all(value[k] is None for k in ("source_commit", "request_id", "release_id", "target_ipa_sha256")),
                "Inactive request must not retain an old destination")
        return value
    require(isinstance(value["source_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]),
            "Exact reviewed source commit is required")
    require(isinstance(value["request_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", value["request_id"]),
            "Invalid request ID")
    require(type(value["release_id"]) is int and value["release_id"] > 0, "Existing draft ID is required")
    require(isinstance(value["target_ipa_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["target_ipa_sha256"]),
            "Bind this canary to the exact previously delivered IPA hash")
    return value


def preflight():
    request = request_value(json.loads((ROOT / REQUEST).read_text()))
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY and os.environ.get("GITHUB_REF") == REF and
            os.environ.get("GITHUB_EVENT_NAME") == "push" and os.environ.get("GITHUB_ACTIONS") == "true",
            "Only the dedicated request-file push on the approved branch is supported")
    head = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", head) and git("rev-parse", "HEAD") == head, "Checkout/run mismatch")
    require(not git("diff", "--name-only", "HEAD", "--"), "Tracked source changed after checkout")
    if not request["enabled"]:
        return {"enabled": False, "status": "inactive"}
    parents = git("rev-list", "--parents", "-n", "1", "HEAD").split()
    require(parents == [head, request["source_commit"]], "Activation must have the reviewed source as its only parent")
    prior = request_value(json.loads(git("show", request["source_commit"] + ":" + REQUEST)))
    require(prior["enabled"] is False, "Reviewed parent must contain the inactive request")
    require(git("diff", "--name-only", request["source_commit"], head, "--").splitlines() == [REQUEST],
            "Activation must change only the dedicated request file")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", os.environ.get(key, "")), "Missing run identity")
    return {**request, "request_commit": head, "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "tag": "softpipe-test-" + request["request_id"] + "-" + request["source_commit"][:12]}


def regular(path, cap=MAX_ASSET, *, allow_empty=False):
    path = Path(path).absolute()
    require(not path.is_symlink() and path.is_file() and
            not any(p.is_symlink() for p in path.parents), "Not a regular file: " + str(path))
    require((0 if allow_empty else 1) <= path.stat().st_size <= cap,
            "File is empty or exceeds its bound: " + str(path))
    return path


def identity(path):
    path = regular(path)
    return {"bytes": path.stat().st_size, "sha256": reference.digest(path)}


def temp_directory(path, *, fresh=False):
    path = Path(path).absolute()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents) and
            path.resolve().is_relative_to(temp) and path.resolve() != temp and
            not path.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(path.resolve()),
            "Output/work directory must be safely below RUNNER_TEMP and outside the checkout")
    require(not path.exists() if fresh else path.is_dir(), "Expected a fresh output or existing work directory")
    return path


def safe_entry(name):
    p = PurePosixPath(name)
    require(name and not p.is_absolute() and ".." not in p.parts and "\\" not in name and
            ":" not in name and "\0" not in name, "Unsafe ZIP entry")
    return name


def write_zip(path, entries, epoch):
    require(len(entries) <= 25000 and sum(len(v) if isinstance(v, bytes) else v.stat().st_size
                                         for v in entries.values()) <= MAX_PACKAGE, "Package size/count bound exceeded")
    timestamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(path, "x") as archive:
        for name, value in sorted(entries.items()):
            info = zipfile.ZipInfo(safe_entry(name), timestamp)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED if name.endswith(".xz") else zipfile.ZIP_DEFLATED
            archive.writestr(info, value if isinstance(value, bytes) else regular(value).read_bytes(), compresslevel=9)
    regular(path)
    verify_zip(path, entries)


def verify_zip(path, entries):
    with zipfile.ZipFile(regular(path)) as archive:
        rows = archive.infolist()
        require(len(rows) == len(entries) and {r.filename for r in rows} == set(entries), "ZIP inventory mismatch")
        for row in rows:
            safe_entry(row.filename)
            require((row.external_attr >> 16) == 0o100644 and not row.flag_bits & 1, "Unexpected ZIP permissions/encryption")
            value = entries[row.filename]
            expected = value if isinstance(value, bytes) else regular(value).read_bytes()
            require(row.file_size == len(expected) and archive.read(row) == expected, "ZIP bytes differ from staged input")


def source_archive_inventory(archive, source):
    expected = {}
    with tarfile.open(archive) as tar:
        for member in tar:
            p = reference.safe_name(member.name)
            require(p.parts[0] == "mesa-26.2.4", "Wrong Mesa source root")
            if member.isfile():
                name = str(PurePosixPath(*p.parts[1:]))
                require(name not in expected, "Duplicate source entry")
                expected[name] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    require(reference.source_hashes(source) == expected, "Mesa source differs from the verified official archive")
    return expected


def notices(source, toolchain_archive):
    result = {"licenses/Mesa/license.rst": regular(source / "docs/license.rst")}
    for p in sorted((source / "licenses").rglob("*")):
        if p.is_file():
            result["licenses/Mesa/" + p.relative_to(source / "licenses").as_posix()] = regular(p)
    require("licenses/Mesa/MIT" in result, "Mesa license inventory is missing")
    # Preserve source attribution/license comments from the entire pinned tree,
    # not just a guessed subset of compiled objects. Full originals travel in
    # the separate, mandatory source archive alongside the runtime.
    comments = []
    pattern = re.compile(r"/\*[\s\S]*?\*/|(?:^[ \t]*#[^\n]*(?:\n|$))+|(?:^[ \t]*//[^\n]*(?:\n|$))+", re.M)
    marker = re.compile(r"copyright|SPDX-License-Identifier|permission is hereby granted|redistribution and use", re.I)
    for p in sorted(source.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if re.search(r"(?i)(license|copying|notice|copyright|authors)", p.name):
            result["licenses/Mesa/source-files/" + p.relative_to(source).as_posix()] = regular(p, MAX_NOTICE)
        if p.stat().st_size > 2 * 1024**2:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue
        blocks = [m.group() for m in pattern.finditer(text) if marker.search(m.group())]
        if blocks:
            comments.append("FILE " + p.relative_to(source).as_posix() + "\n" + "\n".join(blocks))
    attribution = ("Pinned Mesa source copyright/license comments; originals are in Madeira-softpipe-source.zip.\n\n" +
                   "\n\n".join(comments)).encode()
    require(comments and len(attribution) <= MAX_NOTICE, "Mesa attribution output is missing or oversized")
    result["licenses/Mesa/SOURCE-ATTRIBUTION.txt"] = attribution
    # Read these from the hash-verified distribution archive itself, not an
    # extracted toolchain directory that build steps could have changed.
    prefix = "llvm-mingw-20260421-ucrt-x86_64/"
    required = {"LICENSE.TXT", *["x86_64-w64-mingw32/share/mingw32/" + n for n in
                ("COPYING", "COPYING.MinGW-w64-runtime.txt", "COPYING.MinGW-w64.txt", "COPYING.winpthreads.txt")]}
    found = set()
    with zipfile.ZipFile(toolchain_archive) as archive:
        for row in archive.infolist():
            if row.is_dir() or not row.filename.startswith(prefix):
                continue
            name = row.filename[len(prefix):]
            if not re.search(r"(?i)(license|copying|notice|copyright|authors)", PurePosixPath(name).name):
                continue
            safe_entry(name)
            require(0 < row.file_size <= MAX_NOTICE and name not in found, "Invalid toolchain notice")
            result["licenses/LLVM-MinGW/" + name] = archive.read(row)
            found.add(name)
    require(required <= found, "Pinned toolchain omits a required runtime notice")
    result["licenses/Canary-MIT.txt"] = regular(HERE / "Canary-MIT.txt")
    return result


def package(work, output, context):
    require(context.get("enabled") is True, "Delivery request is inactive")
    work = temp_directory(work)
    output = temp_directory(output, fresh=True)
    require(not output.is_relative_to(work) and not work.is_relative_to(output), "Work/output paths overlap")
    receipt_path = regular(work / "reference-receipt.json")
    receipt = json.loads(receipt_path.read_text())
    require(receipt.get("status") == "gdi-and-legacy-reference-passed" and
            receipt.get("source_commit") == context["request_commit"] and receipt.get("source_modified") is False and
            receipt.get("options") == reference.OPTIONS and receipt.get("files_uploaded") is False and
            all(receipt.get(k) is False for k in ("madeira_runtime_tested", "ios_display_tested", "blender_tested")),
            "Not this request's unchanged successful Windows-only reference")
    lock = json.loads((HERE / "inputs.lock.json").read_text())
    require(receipt.get("inputs") == lock, "Reference lockfile changed")
    for item in lock["inputs"]:
        reference.verify_file(regular(work / "downloads" / item["filename"], 256 * 1024**2), item)
    mesa = next(x for x in lock["inputs"] if x["name"] == "Mesa")
    source = work / "mesa-26.2.4"
    archive = work / "downloads" / mesa["filename"]
    source_hashes = source_archive_inventory(archive, source)
    binaries = reference.audit_binaries(work / "bundle", source)
    require(binaries == receipt["binaries"] and set(binaries) == BINARIES, "Runtime bytes/audit differ from receipt")
    proofs = []
    for stage in ("gdi", "legacy"):
        log = regular(work / ("runtime-" + stage + ".log"), reference.MAX_LOG)
        command = [x for x in receipt["commands"] if x["name"] == "runtime-" + stage]
        require(len(command) == 1 and command[0]["exit"] == 0 and
                command[0]["log_sha256"] == reference.digest(log), "Runtime log/command mismatch")
        proofs.append(reference.parse_proof(log.read_text(encoding="utf-8", errors="replace"), 0, stage, work / "bundle"))
    options = {x["name"]: x["value"] for x in json.loads((work / "build/meson-info/intro-buildoptions.json").read_text())}
    proofs.append(reference.source_bound_core43(source_hashes, lock, options, proofs[-1], {"GALLIUM_DRIVER": "softpipe"}))
    require(proofs == receipt["proof"], "Revalidated proof differs")
    runtime = {name: regular(work / "bundle" / name) for name in sorted(BINARIES)}
    toolchain = next(x for x in lock["inputs"] if x["name"] == "LLVM-MinGW")
    runtime.update(notices(source, work / "downloads" / toolchain["filename"]))
    instructions = regular(HERE / "SOFTPIPE-TEST.txt").read_text().replace("{TARGET_IPA_SHA256}", context["target_ipa_sha256"])
    runtime.update({"README.txt": instructions.encode(), "reference-receipt.json": receipt_path,
                    "limits.json": encode(LIMITS)})
    inputs = {"upstream/" + mesa["filename"]: archive,
              "evidence/mesa-source-sha256.json": encode(source_hashes),
              "evidence/reference-receipt.json": receipt_path,
              "evidence/windows-x64.ini": regular(work / "windows-x64.ini"),
              "evidence/intro-buildoptions.json": regular(work / "build/meson-info/intro-buildoptions.json")}
    for command in receipt["commands"]:
        require(re.fullmatch(r"[a-z0-9-]+", command["name"]), "Unsafe command-log name")
        p = regular(work / (command["name"] + ".log"), reference.MAX_LOG, allow_empty=True)
        require(reference.digest(p) == command["log_sha256"], "Command log changed")
        # Successful venv/compiler commands may emit zero bytes. Preserve
        # exactly those verified bytes, including the empty-file checksum.
        inputs["evidence/logs/" + p.name] = p.read_bytes()
    paths = git("ls-files", "--", "tests/desktop/mesa_wgl", "build/wine-pe/symbol_audit.py",
                "build/wine-pe/guest_inventory.py", ".github/workflows/mesa-softpipe-delivery.yml",
                ".github/workflows/mesa-windows-reference.yml", "tests/host/check-mesa-windows-reference.py",
                "tests/host/check-softpipe-delivery.py", "COPYING", "LICENSE-EXCEPTION.md").splitlines()
    for name in paths:
        inputs["recipe/" + safe_entry(name)] = regular(ROOT / name)
    inputs.update({"runtime-notices/" + name: value for name, value in runtime.items() if name.startswith("licenses/")})
    runtime_hashes = {n: hashlib.sha256(v if isinstance(v, bytes) else v.read_bytes()).hexdigest() for n, v in runtime.items()}
    runtime["SHA256SUMS"] = "".join(f"{h}  {n}\n" for n, h in sorted(runtime_hashes.items())).encode()
    output.mkdir(parents=True)
    write_zip(output / ASSETS[0], runtime, lock["source_date_epoch"])
    write_zip(output / ASSETS[1], inputs, lock["source_date_epoch"])
    provenance = {"schema_version": 1, "status": "packaged-after-windows-reference", "context": context,
                  "limits": LIMITS, "assets": {n: identity(output / n) for n in ASSETS[:2]},
                  "runtime_files": runtime_hashes, "source_archive": mesa,
                  "reference_receipt_sha256": reference.digest(receipt_path),
                  "recipe_files": {n: reference.digest(ROOT / n) for n in paths}}
    (output / "provenance.json").write_bytes(encode(provenance))
    sums = "".join(f"{identity(output / n)['sha256']}  {n}\n" for n in ASSETS[:3])
    (output / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
    return verify_delivery(output, context)


def verify_delivery(output, context):
    output = temp_directory(output)
    require({p.name for p in output.iterdir()} == set(ASSETS), "Unexpected delivery inventory")
    provenance = json.loads(regular(output / "provenance.json").read_text())
    require(provenance["context"] == context and provenance["limits"] == LIMITS and
            provenance["status"] == "packaged-after-windows-reference", "Delivery context/limits mismatch")
    assets = {name: identity(output / name) for name in ASSETS}
    require(provenance["assets"] == {name: assets[name] for name in ASSETS[:2]}, "ZIP hash mismatch")
    require((output / "SHA256SUMS").read_text() == "".join(f"{assets[n]['sha256']}  {n}\n" for n in ASSETS[:3]),
            "Checksum manifest mismatch")
    return {"status": "offline-delivery-verified", "context": context, "assets": assets, "limits": LIMITS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("request", "package", "verify"))
    parser.add_argument("--work", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    context = preflight()
    if args.mode == "request":
        require(not args.work and not args.output, "Request takes no artifact paths")
        result = context
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write("enabled=" + str(context["enabled"]).lower() + "\n")
    else:
        require(context["enabled"] and args.output, "Activated request and output are required")
        if args.mode == "package":
            require(args.work, "Reference work directory is required")
            result = package(args.work, args.output, context)
        else:
            require(not args.work, "Verify takes no work directory")
            result = verify_delivery(args.output, context)
        require(preflight() == context, "Request/source changed during packaging")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from exc
