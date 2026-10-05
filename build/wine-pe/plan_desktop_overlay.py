#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only, paired-64-bit overlay handoff check. Print a reversible file plan.

Does not install/copy/remove files, edit a prefix, build/package an app, execute
stage tools, or claim compatibility. --expected-seal must come from the reviewed
build handoff, not from an untrusted package alongside its replacement hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import guest_inventory as inventory

ARCHES = ("aarch64", "arm64ec")
MODULES = frozenset(("netprofm", "sensapi", "avifil32", "msvfw32", "msftedit", "riched20"))
NAMES = {name + ".dll" for name in MODULES}
LICENSES = {"COPYING.LIB": "Wine-LGPL-2.1.txt", "LICENSE-MADEIRA.md": "Wine-LICENSE-MADEIRA.md",
            "libs/compiler-rt/LICENSE.TXT": "Wine-compiler-rt-LICENSE.txt"}
MAX_FILE = 64 * 1024 * 1024
MAX_STAGE = 256 * 1024 * 1024
MAX_FILES = 512
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(base, name):
    require(isinstance(name, str) and name and not any(c in name for c in "\\\r\n\0") and
            all(p not in ("", ".", "..") for p in name.split("/")), "unsafe relative path")
    path = base / name
    require(not path.is_absolute() or path.is_relative_to(base), "path leaves its root")
    require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), "symlink path refused")
    return path


def identity(path):
    require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents), "symlink input refused")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_FILE, "nonregular, empty or oversized input")
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            require(count <= before.st_size, "input grew while hashing")
            digest.update(data)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and count == before.st_size,
            "input changed while hashing")
    return {"bytes": count, "sha256": digest.hexdigest()}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def document(base, name):
    path = safe_path(base, name)
    identity(path)
    value = json.loads(path.read_text(), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "expected JSON object")
    return value


def seal(stage, expected):
    require(isinstance(expected, str) and SHA256.fullmatch(expected), "expected seal must be SHA-256")
    require(identity(safe_path(stage, "SHA256SUMS"))["sha256"] == expected, "reviewed stage seal differs")
    listed = {}
    for line in (stage / "SHA256SUMS").read_text().splitlines():
        require(len(line) > 66 and line[64:66] == "  " and SHA256.fullmatch(line[:64]), "malformed checksum index")
        name = line[66:]
        safe_path(stage, name)
        require(name not in listed and name != "SHA256SUMS", "duplicate/self-referential checksum entry")
        listed[name] = line[:64]
        require(len(listed) <= MAX_FILES, "too many checksum entries")
    found, total, pending, entries = {}, 0, [stage], 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_FILES, "stage exceeds entry budget")
                require(not child.is_symlink(), "stage contains a symlink")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    path = Path(child.path)
                    value = identity(path)
                    total += value["bytes"]
                    require(total <= MAX_STAGE, "stage exceeds byte budget")
                    name = path.relative_to(stage).as_posix()
                    if name != "SHA256SUMS":
                        found[name] = value
    require(listed and {n: v["sha256"] for n, v in found.items()} == listed,
            "stage differs from complete checksum index")
    return found


def children(directory, limit):
    with os.scandir(directory) as scan:
        entries = [Path(entry.path) for entry in itertools.islice(scan, limit + 1)]
    require(len(entries) <= limit, "directory exceeds entry budget")
    return entries


def identities(modules):
    return {name: {key: value[key] for key in ("bytes", "sha256", "architecture")}
            for name, value in modules.items()}


def plan(stage, bundle, expected_seal, wine_revision):
    require(hasattr(inventory, "MAX_FARM_FILES") and hasattr(inventory, "read_pe_bytes"),
            "bounded guest inventory prerequisite missing; apply the automated evidence patch first")
    stage, bundle = Path(stage).absolute(), Path(bundle).absolute()
    require(stage.is_dir() and bundle.is_dir(), "stage and target bundle folders must exist")
    require(not stage.is_symlink() and not bundle.is_symlink(), "symlink root refused")
    files = seal(stage, expected_seal)
    source = document(stage, "source-inputs.json")
    provenance = document(stage, "provenance.json")
    reviewed = inventory.manifest()
    require(wine_revision == reviewed["wine_revision"] == source.get("wine_revision") == provenance.get("wine_revision"),
            "target/source/manifest Wine pins differ")
    require(source.get("schema_version") == 1 and source.get("wine_tracked_sources_clean") is True,
            "missing clean source receipt")
    require(provenance.get("staged_only") is True and provenance.get("runtime_tested") is False,
            "unexpected build receipt scope")
    recipe = provenance.get("recipe", {})
    require(recipe.get("profile") == "desktop" and recipe.get("wine_revision") == wine_revision and
            sorted(a.get("arch", "") for a in recipe.get("architectures", [])) == sorted(ARCHES),
            "integration requires the complete aarch64 + ARM64EC desktop pair")
    captured = document(stage, "rebuild-inputs/build/wine-pe/desktop-components.json")
    require(captured == reviewed and set(captured["profiles"]["desktop"]) == MODULES, "unreviewed component manifest")
    require(source.get("recipe_inputs") and source.get("wine_files"), "source identity maps missing")
    for name, value in source["recipe_inputs"].items():
        require(files.get("rebuild-inputs/" + name) == value, f"captured recipe differs: {name}")
    needed = {"toolchain-receipt.json", "SOURCE-REBUILD.md", "rebuild-inputs/build/wine-pe/desktop-components.json"}
    needed.update("licenses/" + n for n in LICENSES.values())
    needed.add("licenses/Madeira-THIRD-PARTY-NOTICES.md")
    for arch in ARCHES:
        needed.update({arch + "-inventory.json", arch + "-symbol-audit.json", arch + "-build.log"})
        needed.update(f"readobj/{arch}-{m}.txt" for m in MODULES)
    require(needed <= files.keys(), "required build/notice/evidence file missing")
    operations, farms, notice_conflicts, unchanged_notices = [], [], [], []
    for arch in ARCHES:
        farm = safe_path(bundle, arch + "-windows")
        overlay = safe_path(stage, arch + "-windows")
        require(farm.is_dir() and overlay.is_dir(), "architecture farm missing")
        require({p.name for p in children(overlay, len(NAMES))} == NAMES, "overlay must contain exactly six reviewed DLLs")
        # Even equal bytes must not hide replacement of a previously owned DLL.
        farm_entries = children(farm, inventory.MAX_FARM_FILES)
        require(not NAMES.intersection(p.name.lower() for p in farm_entries), "target already owns an overlay DLL")
        old = document(stage, arch + "-inventory.json")
        audit = document(stage, arch + "-symbol-audit.json")
        expected_base = {n: v for n, v in old.get("modules", {}).items() if n not in NAMES}
        actual_base = {}
        for path in farm_entries:
            if path.suffix.lower() in inventory.PE_SUFFIXES:
                require(path.name.lower() not in actual_base, "case-colliding target modules")
                actual_base[path.name.lower()] = path
        require(actual_base.keys() == expected_base.keys(), "target module set differs from sealed inventory")
        total = 0
        for name, path in actual_base.items():
            require(not path.is_symlink() and path.is_file() and path.stat().st_size == expected_base[name]["bytes"],
                    "target input is unsafe or differs in size")
            total += path.stat().st_size
            require(total <= inventory.MAX_FARM_BYTES, "target farm exceeds byte budget")
        for name, path in actual_base.items():
            require(identity(path) == {k: expected_base[name][k] for k in ("bytes", "sha256")},
                    "target bytes differ from sealed inventory before PE parsing")
        current = inventory.audit_farm(farm, arch, NAMES, overlay)
        require(not current["errors"] and not current["missing_required"], "invalid same-architecture combined farm")
        require({k: v for k, v in old.items() if k != "folder"} ==
                {k: v for k, v in current.items() if k != "folder"}, "current farm differs from the audited build inputs")
        require(audit.get("architecture") == arch and audit.get("passed") is True and audit.get("issues") == [] and
                set(audit.get("modules", {})) == NAMES and audit.get("input_modules") == identities(current["modules"]),
                "symbol evidence does not bind the same-architecture inputs")
        new_gaps = [gap for gap in current["missing_dependencies"] if gap["module"] in NAMES]
        require(not new_gaps, "new desktop module has an unresolved direct dependency")
        for name in sorted(NAMES):
            value = identities({name: current["modules"][name]})[name]
            require(value["architecture"] == arch and identities({name: audit["modules"][name]})[name] == value,
                    "overlay output differs from its symbol audit")
            relative = arch + "-windows/" + name
            require(files[relative] == {k: value[k] for k in ("bytes", "sha256")}, "overlay hash differs from seal")
            operations.append({"source": relative, "destination": relative, "before": None,
                               "after": files[relative], "rollback": "remove only if bytes still match after"})
        farms.append({"arch": arch, "modules": current["module_count"],
                      "residual_dependencies": current["missing_dependencies"], "new_module_direct_dependency_gaps": new_gaps})
    notices = {"licenses/" + name: "legal/" + name for name in LICENSES.values()}
    notices["licenses/Madeira-THIRD-PARTY-NOTICES.md"] = "legal/THIRD-PARTY-NOTICES.md"
    notices["SOURCE-REBUILD.md"] = "legal/Wine-desktop-SOURCE-REBUILD.md"
    for relative, name in LICENSES.items():
        value = source["wine_files"].get(relative, {})
        require(files["licenses/" + name] == {k: value.get(k) for k in ("bytes", "sha256")}, "Wine notice differs from source")
    require(files["licenses/Madeira-THIRD-PARTY-NOTICES.md"] == source["recipe_inputs"].get("THIRD-PARTY-NOTICES.md"),
            "Madeira notice differs from source receipt")
    for src, dst in notices.items():
        path = safe_path(bundle, dst)
        before = identity(path) if path.exists() else None
        if src == "licenses/Madeira-THIRD-PARTY-NOTICES.md":
            notice_conflicts.append({"source": src, "destination": dst, "current": before,
                                     "candidate": files[src], "action": "adapt source-relative paths and merge preserving target-specific notices"})
        elif before == files[src]:
            unchanged_notices.append(dst)
        elif before is not None:
            # A top-level notice may have source-relative paths, or the target
            # may carry notices for newer components. Never replace it blindly.
            notice_conflicts.append({"source": src, "destination": dst, "current": before,
                                     "candidate": files[src], "action": "review and merge preserving target-specific notices and valid bundle-relative paths"})
        else:
            operations.append({"source": src, "destination": dst, "before": None, "after": files[src],
                               "rollback": "remove only if bytes still match after"})
    # Recheck every sealed file after parsing. This plan remains point-in-time;
    # an authorized installer must revalidate it inside its own transaction.
    require(seal(stage, expected_seal) == files, "stage changed during planning")
    return {"schema_version": 1, "read_only": True, "stage_seal_sha256": expected_seal,
            "wine_revision": wine_revision, "stage": str(stage), "target_bundle": str(bundle),
            "architectures": farms, "proposed_files": operations,
            "blocking_notice_merges": notice_conflicts, "unchanged_notices": unchanged_notices,
            "package_ready": False, "runtime_tested": False,
            "required_next_steps": [
                "Use a fresh disposable integration checkout; recheck stage, farm and destination hashes before any write",
                "Resolve every blocking notice merge while preserving target-only notices and working bundle-relative paths",
                "Back up and hash originals before any separately reviewed notice edit; this plan never replaces existing files",
                "Treat the DLL pair and matching legal/source files as one transaction; publish no partial farm",
                "Update the tracked-resource inventory or add a receipt-bound overlay path; do not weaken the unsigned-app gate",
                "Keep complete corresponding source, exact rebuild inputs and the reviewed checksum seal; record final published recipe revision",
                "Rollback verifies installed hashes before removing additions; restore separately reviewed notice edits from verified backups only",
                "Device-prefix symlinks are outside this file plan; assess stale links when rolling back a packaged build",
                "Run loader, COM/installer and real network/device tests; residual full-farm closure gaps remain",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-seal", required=True)
    args = parser.parse_args()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    pin = subprocess.check_output(["git", "--no-replace-objects", "-C", str(args.root),
                                   "ls-tree", "HEAD", "wine"], env=env, text=True, timeout=15).split()
    require(len(pin) == 4 and pin[:2] == ["160000", "commit"] and pin[3] == "wine", "target has no Wine gitlink")
    print(json.dumps(plan(args.stage, args.root / "app/Madeira", args.expected_seal, pin[2]), indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("overlay handoff refused: " + str(exc), file=sys.stderr)
        sys.exit(1)
