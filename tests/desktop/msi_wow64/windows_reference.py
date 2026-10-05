#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Build and run only the source-owned MSI canary on disposable Windows.

Uses the runner's existing Microsoft C++ compiler/SDK. No installation of a
product, proprietary media, Wine/iOS execution, download, signing or IPA.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
SOURCES = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "build/wine-pe"))
from guest_inventory import PE
from symbol_audit import exports, imports

INPUTS = ("canary_common.h", "canary_host.c", "canary_i386.c",
          "canary_i386_msvc.def", "msi_ordinals_i386.def", "build_msvc.cmd")
MAX_BINARY = 1024 * 1024
MAX_LOG = 1024 * 1024
PREFIX = "MADEIRA-MSI-WOW64: "


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, maximum):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular file: {path.name}")
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError(f"Missing or oversized data: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError(f"Missing or oversized data: {path.name}")
    return data


def embedded_action(pe):
    """Read the single numeric RCDATA/1 language entry with PE bounds checks."""
    base, size = pe.directory(2)
    if not base or size < 16:
        raise ValueError("Host has no resource directory")

    def entries(relative):
        if relative < 0 or relative > size - 16:
            raise ValueError("Resource directory exceeds bounds")
        offset = pe.rva(base + relative, 16)
        named, count = pe.unpack("HH", offset + 12)
        if named or not 1 <= count <= 16 or relative + 16 + count * 8 > size:
            raise ValueError("Unexpected resource directory")
        return [pe.unpack("II", pe.rva(base + relative + 16 + n * 8, 8))
                for n in range(count)]

    def child(relative, wanted):
        selected = [value for name, value in entries(relative) if name == wanted]
        if len(selected) != 1 or not selected[0] & 0x80000000:
            raise ValueError("Missing or duplicate canary resource")
        return selected[0] & 0x7fffffff

    language = entries(child(child(0, 10), 1))
    if len(language) != 1 or language[0][1] & 0x80000000:
        raise ValueError("Unexpected canary resource language/data")
    offset = language[0][1]
    if offset > size - 16:
        raise ValueError("Resource data descriptor exceeds bounds")
    rva, length, _, _ = pe.unpack("IIII", pe.rva(base + offset, 16))
    if not 1 <= length <= MAX_BINARY:
        raise ValueError("Canary resource exceeds bound")
    return pe.read(pe.rva(rva, length), length)


def verify_binaries(directory):
    ca_data = regular(directory / "madeira-msi-probe-i386.dll", MAX_BINARY)
    host_data = regular(directory / "madeira-msi-canary-x86_64.exe", MAX_BINARY)
    ca, host = PE(ca_data), PE(host_data)
    if ca.architecture() != "i386" or host.architecture() != "x86_64":
        raise ValueError("Canary architecture mismatch")
    ca_exports = exports(ca)
    if ([entry["names"] for entry in ca_exports] != [["MadeiraProbe"]]
            or any("forwarder" in entry for entry in ca_exports)):
        raise ValueError("Canary must export only the undecorated action")
    ca_imports, host_imports = imports(ca), imports(host)
    if any(item["kind"] != "import" for item in ca_imports + host_imports):
        raise ValueError("Unexpected delayed canary dependency")
    if {item["module"].lower() for item in ca_imports} != {"kernel32.dll", "advapi32.dll", "msi.dll"}:
        raise ValueError("Unexpected custom-action DLL dependency")
    if {item["module"].lower() for item in host_imports} != {"kernel32.dll", "msi.dll", "ole32.dll"}:
        raise ValueError("Unexpected host dependency")
    symbols = [(item["module"].lower(), symbol.get("name", symbol.get("ordinal")))
               for item in ca_imports for symbol in item["symbols"]]
    if ("msi.dll", 144) not in symbols or ("msi.dll", 145) not in symbols:
        raise ValueError("Required MSI ordinal imports are absent")
    if any(module == "msi.dll" and name in ("MsiSetPropertyA", "MsiSetPropertyW")
           for module, name in symbols):
        raise ValueError("MSI named imports replaced the ordinal test")
    if embedded_action(host) != ca_data:
        raise ValueError("Embedded custom action differs from the audited DLL")
    return {"custom_action": {"architecture": "i386", "bytes": len(ca_data),
                             "sha256": digest(ca_data), "imports": ca_imports},
            "host": {"architecture": "x86_64", "bytes": len(host_data),
                     "sha256": digest(host_data), "imports": host_imports},
            "embedded_action_matches": True, "msi_ordinals": [144, 145]}


def verify_proof(log, returncode):
    if returncode:
        raise ValueError(f"Canary returned {returncode}")
    rows = [line[len(PREFIX):].strip() for line in log.splitlines()
            if line.startswith(PREFIX)]
    if any(row.startswith("FAIL ") for row in rows):
        raise ValueError("Canary reported a failed assertion")

    def values(label):
        found = [row[len(label) + 1:] for row in rows if row.startswith(label + " ")]
        if any(not re.fullmatch(r"[0-9]{1,10}", value) for value in found):
            raise ValueError(f"Malformed proof value: {label}")
        return [int(value) for value in found]

    parent = values("START parent-pid")
    children = values("PASS child-pid")
    negative = values("PASS missing-export-rejected")
    if len(parent) != 1 or not 0 < parent[0] <= 0xffffffff:
        raise ValueError("Missing parent identity")
    if len(children) != 2 or any(not 0 < child <= 0xffffffff or child == parent[0]
                                for child in children):
        raise ValueError("Missing cross-process proof")
    if len(negative) != 1 or not 0 < negative[0] <= 0xffffffff:
        raise ValueError("Missing negative control")
    if values("PASS positive-round") != [1, 2]:
        raise ValueError("Both verified property rounds are required")
    if values("ACTION positive-return") != [0, 0]:
        raise ValueError("Both positive custom actions must have executed successfully")
    if values("PASS session-close") != [0] or values("PASS final") != [0]:
        raise ValueError("Session close and final proof are required")
    return {"parent_pid": parent[0], "child_pids": children,
            "missing_export_error": negative[0], "property_rounds": [1, 2],
            "pointer_bytes": 4, "session_closed": True,
            "child_process_termination_proven": False}


def logged(argv, cwd, env, path, timeout):
    try:
        with path.open("xb") as stream:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Artifacts are not uploaded: retain useful bounded failure diagnostics
        # in the job log even when a compiler or the canary times out.
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - MAX_LOG))
            print(stream.read(MAX_LOG).decode("utf-8", errors="replace"),
                  end="", flush=True)
        raise
    if path.stat().st_size > MAX_LOG:
        raise ValueError("Diagnostic log exceeds bound")
    output = path.read_bytes().decode("utf-8", errors="replace")
    print(output, end="", flush=True)
    return result.returncode, output


def run(work):
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("Real reference execution requires x64 Windows")
    work = work.absolute()
    if work.exists() or work.is_symlink():
        raise ValueError("Reference work directory must be new")
    if work.resolve().is_relative_to(ROOT) or ROOT.is_relative_to(work.resolve()):
        raise ValueError("Reference work directory must be outside the checkout")
    if os.environ.get("RUNNER_TEMP") and not work.resolve().is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        raise ValueError("CI work directory must stay inside RUNNER_TEMP")
    source_hashes = {name: digest(regular(SOURCES / name, 128 * 1024)) for name in INPUTS}
    work.mkdir(parents=True)
    source = work / "source"
    source.mkdir()
    for name in INPUTS:
        shutil.copyfile(SOURCES / name, source / name)
        if digest((source / name).read_bytes()) != source_hashes[name]:
            raise ValueError("Source changed while copying")
    cmd = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/cmd.exe"
    if not cmd.is_file():
        raise ValueError("Windows command processor is unavailable")
    env = dict(os.environ)
    # Do not inherit caller compiler/linker injections into this reference build.
    for key in ("CL", "_CL_", "LINK", "_LINK_"):
        env.pop(key, None)
    started = time.monotonic()
    code, _ = logged([str(cmd), "/d", "/c", str(source / "build_msvc.cmd")],
                     source, env, work / "build.log", 180)
    if code:
        raise ValueError(f"Microsoft compiler build failed: {code}")
    binaries = verify_binaries(source / "msvc-build")
    temp = work / "runtime-temp"
    temp.mkdir()
    env.update(TEMP=str(temp), TMP=str(temp))
    code, output = logged([str(source / "msvc-build/madeira-msi-canary-x86_64.exe")],
                         work, env, work / "runtime.log", 75)
    proof = verify_proof(output, code)
    remaining = sorted(item.name for item in temp.iterdir())
    if any(name.lower().startswith(("mdm", "mdd")) for name in remaining):
        raise ValueError("Canary did not remove its owned input files")
    receipt = {"schema_version": 1, "scope": "Microsoft Windows MSI reference only",
               "status": "passed", "source_commit": os.environ.get("GITHUB_SHA"),
               "source_sha256": source_hashes, "platform": platform.platform(),
               "seconds": round(time.monotonic() - started, 3),
               "binaries": binaries, "proof": proof,
               "runtime_log_sha256": digest((work / "runtime.log").read_bytes()),
               "system_managed_temp_entries": remaining,
               "proprietary_payload_used": False, "product_installed": False,
               "madeira_runtime_tested": False, "ipa_created": False}
    (work / "reference-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.work_root)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Windows reference stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
