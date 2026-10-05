#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Fixed compile/link-only entry point. No packaging option exists here.

Reuse the app gate's native/graphics provenance and unsigned bundle validation.
Only license staging and the fixed unsigned Xcode build may run through its
command dispatcher. Packaging/ZIP validation is disabled at runtime as well as
at the CLI. Receipts and scans establish this diagnostic's scope, not device,
JIT, rendering, 1C or Blender success. No files are uploaded.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_unsigned as gate

ROOT = Path(__file__).resolve().parents[2]
REQUEST = ROOT / "build/app-ios/link-diagnostic-request.json"
RECEIPT = "link-diagnostic.json"
EXPECTED_REQUEST = {
    "schema_version": 1, "scope": "ios-app-link-diagnostic-no-ipa",
    "desktop_dll_count": 12,
    "desktop_stage_seal_sha256": "a0f56fd773375a2c2cc2bd76d01db0fbf28973ca1d7bf36a7dd6dbd6c9a02023",
    "ipa_creation": False, "runner": "xcode-27", "max_minutes": 45,
    "max_compile_jobs": 2,
}


def request():
    data = gate.document(REQUEST)
    # Strict JSON equality also rejects bool/int substitutions and extra knobs.
    if json.dumps(data, sort_keys=True) != json.dumps(EXPECTED_REQUEST, sort_keys=True):
        raise ValueError("Link-only diagnostic request differs from the reviewed fixed scope")
    return gate.digest(REQUEST)


def outputs(products, intermediates, diagnostics):
    paths = [Path(p).absolute() for p in (products, intermediates, diagnostics)]
    if any(".." in p.parts for p in paths):
        raise ValueError("Diagnostic output paths must not contain traversal")
    paths = [p.parent.resolve() / p.name for p in paths]
    for path in paths:
        if path.name.lower().endswith((".ipa", ".xcarchive")) or path.name.lower() == "payload":
            raise ValueError("Output roots cannot be named as a package or archive stage")
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError("Diagnostic output root must be a non-symlink directory")
        if path.is_relative_to(ROOT.resolve()) or ROOT.resolve().is_relative_to(path):
            raise ValueError("Diagnostic outputs must be outside the source checkout")
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            if path.is_relative_to(other) or other.is_relative_to(path):
                raise ValueError("Diagnostic outputs must be distinct and non-nested")
    return paths


def scan(products, intermediates, diagnostics):
    """Inspect checkout and all diagnostic output names without following links.

    Missing outputs are normal after an earlier failure. This scan is NOT a
    link-pass receipt and never upgrades an incomplete build to success.
    """
    paths = outputs(products, intermediates, diagnostics)
    count = 0
    def inaccessible(error):
        raise error
    for base in (ROOT, *paths):
        if not base.exists():
            continue
        for folder, directories, files in os.walk(base, followlinks=False, onerror=inaccessible):
            if base == ROOT:
                directories[:] = [name for name in directories if name != ".git"]
            for name in (*directories, *files):
                count += 1
                if count > 1000000:
                    raise ValueError("No-IPA scan exceeded its bounded entry count")
                if name.lower().endswith((".ipa", ".xcarchive")) or (base != ROOT and name.lower() == "payload"):
                    raise ValueError("Forbidden IPA/archive/package stage found: " + str(Path(folder) / name))
    return {"status": "passed", "roots": [str(ROOT), *map(str, paths)],
            "entries_checked": count, "ipa_files": 0, "package_stage_directories": 0,
            "stage": "no-ipa-output-scan", "link_status": "not_evaluated"}


def app_receipt(products, intermediates, diagnostics):
    record = gate.document(diagnostics / "provenance.json")
    commit = gate.git("rev-parse", "HEAD")
    if (type(record.get("schema_version")) is not int or record["schema_version"] != 1 or
            record.get("status") != "passed" or
            record.get("source_commit") != commit or os.environ.get("GITHUB_SHA", commit) != commit or
            record.get("scope") != gate.SCOPE or
            json.dumps(record.get("packaging"), sort_keys=True) !=
            json.dumps({"requested": False, "status": "not_requested"}, sort_keys=True) or
            record.get("build_command") != gate.build_command(products, intermediates) or
            any(key.startswith("ipa_") for key in record)):
        raise ValueError("App receipt does not prove this checkout's unsigned link-only build")
    guest = record.get("guest_pe", {})
    desktop = guest.get("source_built_desktop_sha256", {})
    if (guest.get("status") != "tracked-existing-plus-reviewed-source-built-desktop" or
            guest.get("desktop_stage_seal_sha256") != EXPECTED_REQUEST["desktop_stage_seal_sha256"] or
            set(desktop) != gate.verify_desktop_integration.DLLS or len(desktop) != 12):
        raise ValueError("App receipt lacks the twelve reviewed desktop DLLs")
    gate.hashes_match(desktop, products / "Debug-iphoneos/Madeira.app")
    # Independently bind the final check to every app file, not just a status bit.
    actual = gate.tree_files(products / "Debug-iphoneos/Madeira.app")
    if not actual or actual != record.get("app", {}).get("files_sha256"):
        raise ValueError("App files changed after link validation")
    return record


def verify(products, intermediates, diagnostics):
    products, intermediates, diagnostics = outputs(products, intermediates, diagnostics)
    audit = scan(products, intermediates, diagnostics)
    record = app_receipt(products, intermediates, diagnostics)
    receipt = gate.document(diagnostics / RECEIPT)
    expected = {
        "schema_version": 1, "status": "passed", "scope": EXPECTED_REQUEST["scope"],
        "source_commit": record["source_commit"], "request_sha256": request(),
        "app_receipt_sha256": gate.digest(diagnostics / "provenance.json"),
        "commands": [["bash", "build/stage-licenses.sh"], gate.build_command(products, intermediates)],
        "packaging": "disabled", "ipa_created": False, "runtime_tested": False,
    }
    if (json.dumps(receipt, sort_keys=True) != json.dumps(expected, sort_keys=True) or
            {p.name for p in diagnostics.iterdir()} != {"provenance.json", RECEIPT}):
        raise ValueError("Link diagnostic receipt or diagnostic directory changed")
    print(json.dumps({"status": "passed", "scope": EXPECTED_REQUEST["scope"],
                      "source_commit": record["source_commit"], "ipa_created": False,
                      "runtime_tested": False, "scan": audit}, sort_keys=True))
    return receipt


def build(native_receipt, products, intermediates, diagnostics):
    request_hash = request()
    products, intermediates, diagnostics = outputs(products, intermediates, diagnostics)
    scan(products, intermediates, diagnostics)
    expected = [["bash", "build/stage-licenses.sh"], gate.build_command(products, intermediates)]
    commands = []
    original_run, original_zip, original_archive = gate.run, gate.verify_zip, gate.zipfile.ZipFile
    def guarded_run(args):
        command = list(map(str, args))
        if len(commands) >= len(expected) or command != expected[len(commands)]:
            raise ValueError("Command forbidden by fixed link-only diagnostic: " + repr(command))
        commands.append(command)
        return original_run(args)
    def forbidden_zip(*args, **kwargs):
        raise ValueError("ZIP/package validation is disabled in this link-only diagnostic")
    gate.run, gate.verify_zip, gate.zipfile.ZipFile = guarded_run, forbidden_zip, forbidden_zip
    try:
        # Never forwards arbitrary flags or calls the package-capable CLI.
        gate.build(Path(native_receipt), products, intermediates, diagnostics, package=False)
    finally:
        gate.run, gate.verify_zip, gate.zipfile.ZipFile = original_run, original_zip, original_archive
        # Even failed commands must not silently leave an IPA/package stage.
        scan(products, intermediates, diagnostics)
    if commands != expected:
        raise ValueError("Link diagnostic did not execute its exact build command sequence")
    record = app_receipt(products, intermediates, diagnostics)
    receipt = {
        "schema_version": 1, "status": "passed", "scope": EXPECTED_REQUEST["scope"],
        "source_commit": record["source_commit"], "request_sha256": request_hash,
        "app_receipt_sha256": gate.digest(diagnostics / "provenance.json"),
        "commands": commands, "packaging": "disabled", "ipa_created": False,
        "runtime_tested": False,
    }
    # Exclusive creation prevents overwriting an injected/stale success receipt.
    with (diagnostics / RECEIPT).open("x") as stream:
        stream.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return verify(products, intermediates, diagnostics)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("request", allow_abbrev=False)
    for name in ("build", "scan", "verify"):
        command = commands.add_parser(name, allow_abbrev=False)
        if name == "build":
            command.add_argument("--native-receipt", required=True, type=Path)
        for output in ("products", "intermediates", "diagnostics"):
            command.add_argument("--" + output, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "request":
            print(json.dumps({"request_sha256": request(), "scope": EXPECTED_REQUEST["scope"]}))
        elif args.command == "build":
            build(args.native_receipt, args.products, args.intermediates, args.diagnostics)
        elif args.command == "verify":
            verify(args.products, args.intermediates, args.diagnostics)
        else:
            print(json.dumps(scan(args.products, args.intermediates, args.diagnostics), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
