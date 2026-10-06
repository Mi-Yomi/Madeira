#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Verify the reviewed, tracked desktop additions; never install or run them."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import guest_inventory as inventory
import plan_desktop_overlay as planner
import verify_msi_integration as msi
import verify_loader_integration as loader
import verify_msi_client_integration as client
import verify_msi_startup_integration as startup
import verify_fex_integration as fex

ROOT = Path(__file__).resolve().parents[2]
RECORD = "build/wine-pe/desktop-integration.json"
RECEIPT = "build/wine-pe/receipts/desktop-2026-10-05"
REVIEWED_SEAL = "a0f56fd773375a2c2cc2bd76d01db0fbf28973ca1d7bf36a7dd6dbd6c9a02023"
WINE_REVISION = "4f5b19718f4de88ecc5cb0dc08b119497a67ba8f"
DLLS = {f"{arch}-windows/{name}" for arch in planner.ARCHES for name in planner.NAMES}
COPIES = {name: name for name in DLLS}
COPIES.update({"legal/" + name: "licenses/" + name for name in planner.LICENSES.values()})
COPIES["legal/Wine-desktop-SOURCE-REBUILD.md"] = "SOURCE-REBUILD.md"
MERGED_NOTICES = {"legal/THIRD-PARTY-NOTICES.md", "legal/Wine-desktop-INTEGRATION.md"}
REQUIRED_NOTICES = tuple(sorted(set(COPIES) - DLLS | MERGED_NOTICES))


def git_output(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return subprocess.check_output(["git", "--no-replace-objects", *args],
                                   cwd=root, env=env, text=True, timeout=15)


def wine_gitlink(root):
    row = git_output(root, "ls-tree", "HEAD", "wine").split()
    planner.require(row == ["160000", "commit", WINE_REVISION, "wine"],
                    "Current Wine gitlink differs from the reviewed desktop source")


def validate_farms(root, stage, msi_extension=None, loader_extension=None, fex_extension=None):
    """Rebind existing same-architecture inputs before trusting the old audit."""
    counts = {}
    for arch in planner.ARCHES:
        farm = planner.safe_path(root / "app/Madeira", arch + "-windows")
        old = planner.document(stage, arch + "-inventory.json")
        original = old
        required = planner.NAMES
        if msi_extension is not None:
            planner.require(msi.contract(msi_extension["baselines"][arch]) == msi.contract(old),
                            "MSI baseline differs from the original sealed desktop inventory")
            old = msi_extension["combined"][arch]
            required = required | msi.NAMES
        if loader_extension is not None:
            planner.require(msi_extension is not None, "Loader extension requires sealed MSI integration")
            old = loader.bind_reports(loader_extension, original, old, arch)
            required = required | loader.NAMES
        if msi_extension is not None and msi_extension.get("client") is not None:
            planner.require(loader_extension is not None, "MSI client requires sealed loader integration")
            old = client.bind_reports(msi_extension["client"], old, arch)
            if msi_extension["client"].get("startup") is not None:
                old = startup.bind_reports(msi_extension["client"]["startup"], old, arch)
        if fex_extension is not None:
            planner.require(msi_extension and msi_extension.get("client") and
                            msi_extension["client"].get("startup"),
                            "FEX requires all reviewed historical farm layers")
            old = fex.bind_reports(fex_extension, old, arch)
        expected = old["modules"]
        paths = {}
        for path in planner.children(farm, inventory.MAX_FARM_FILES):
            if path.suffix.lower() not in inventory.PE_SUFFIXES:
                continue
            name = path.name.lower()
            planner.require(name not in paths, "Case-colliding desktop farm inputs")
            paths[name] = path
        planner.require(paths.keys() == expected.keys(), "Desktop farm module set differs from sealed audit")
        total = 0
        for name, path in paths.items():
            identity = planner.identity(path)
            total += identity["bytes"]
            planner.require(total <= inventory.MAX_FARM_BYTES and
                            identity == {key: expected[name][key] for key in ("bytes", "sha256")},
                            "Desktop farm bytes differ from sealed audit before PE parsing: " + name)
        current = inventory.audit_farm(farm, arch, required)
        planner.require(not current["errors"] and not current["missing_required"] and
                        {key: value for key, value in current.items() if key != "folder"} ==
                        {key: value for key, value in old.items() if key != "folder"},
                        "Desktop farm dependencies or architecture differ from sealed audit")
        counts[arch] = len(current["missing_dependencies"])
    return counts


def validate(root, resources, tracked):
    """Require the paired reviewed bytes AND ordinary tracked-resource policy.

    `tracked` comes from Git, never from the overlay. `resources` is the app
    gate's already checked resource inventory. The native gate separately binds
    the whole source checkout to its source commit before calling this function.
    This does not certify arbitrary replacement receipts or runtime behavior.
    """
    root, tracked = Path(root), set(tracked)
    wine_gitlink(root)
    if startup.present(root):
        planner.require(msi.present(root) and loader.present(root) and client.present(root),
                        "MSI startup requires every historical integration")
    planner.require(RECORD in tracked, "Desktop integration record must be tracked")
    record = planner.document(root, RECORD)
    planner.require(record.get("schema_version") == 1 and
                    record.get("wine_revision") == WINE_REVISION and
                    record.get("stage_seal_sha256") == REVIEWED_SEAL and
                    record.get("receipt_directory") == RECEIPT and
                    record.get("runtime_tested") is False and
                    record.get("package_ready") is False,
                    "Desktop integration record differs from the reviewed contract")
    commit = record.get("published_recipe_commit")
    planner.require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit),
                    "Desktop integration requires the final published recipe commit")
    files = record.get("files")
    planner.require(isinstance(files, dict) and set(files) == set(COPIES) | MERGED_NOTICES,
                    "Desktop integration lacks the exact paired DLL/legal inventory")
    stage = planner.safe_path(root, RECEIPT)
    sealed = planner.seal(stage, REVIEWED_SEAL)
    planner.require(len(sealed) == 54, "Desktop receipt must retain all 55 reviewed files")
    stage_paths = {RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")}
    planner.require(stage_paths <= tracked, "Desktop receipt contains untracked evidence")
    for name, entry in files.items():
        planner.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256"},
                        "Desktop resource identity must contain size and SHA-256")
        planner.require("app/Madeira/" + name in tracked,
                        "Desktop integration resource must be tracked: " + name)
        actual = planner.identity(planner.safe_path(root / "app/Madeira", name))
        planner.require(actual == entry and resources.get(name) == actual["sha256"],
                        "Desktop integration resource substituted or missing: " + name)
        if name in COPIES:
            planner.require(actual == sealed.get(COPIES[name]),
                            "Desktop integration differs from sealed build: " + name)
        if name in DLLS:
            raw = inventory.read_pe_bytes(planner.safe_path(root / "app/Madeira", name))
            planner.require(hashlib.sha256(raw).hexdigest() == actual["sha256"],
                            "Desktop DLL changed before architecture parsing: " + name)
            pe = inventory.PE(raw)
            planner.require(pe.architecture() == name.split("-windows/")[0],
                            "Wrong architecture in desktop integration: " + name)
    # The desktop seal and its historical baseline remain immutable. A fixed,
    # separately sealed MSI extension must rebind every original input and gap;
    # arbitrary additions still fail the exact combined farm inventory check.
    extension = msi.validate(root, resources, tracked) if msi.present(root) else None
    loader_extension = loader.validate(root, resources, tracked) if loader.present(root) else None
    fex_extension = fex.validate(root, resources, tracked) if fex.present(root) else None
    counts = validate_farms(root, stage, extension, loader_extension, fex_extension)
    planner.require(record.get("residual_dependency_counts") == msi.BASELINE_COUNTS and
                    counts == (msi.RESIDUAL_COUNTS if extension else msi.BASELINE_COUNTS),
                    "Do not silently clear pre-existing full-farm dependency gaps")
    planner.require(planner.seal(stage, REVIEWED_SEAL) == sealed,
                    "Desktop sealed evidence changed during verification")
    return {"stage_seal_sha256": REVIEWED_SEAL, "dll_count": len(DLLS),
            "evidence_files": len(stage_paths), "published_recipe_commit": commit,
            "runtime_tested": False, "package_ready": False,
            "historical_dependency_counts": msi.BASELINE_COUNTS,
            "current_dependency_counts": counts,
            "msi": extension["summary"] if extension else None,
            **({"fex": fex_extension["summary"]} if fex_extension else {}),
            "loader": loader_extension["summary"] if loader_extension else None,
            "msi_client": extension["client"]["summary"] if extension and extension.get("client") else None,
            "msi_startup": extension["client"]["startup"]["summary"]
            if extension and extension.get("client") and extension["client"].get("startup") else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve()
    tracked = git_output(root, "ls-files", "-z", "--").split("\0")
    required = (set(COPIES) | MERGED_NOTICES | (msi.FILES if msi.present(root) else set()) |
                (loader.FILES if loader.present(root) else set()) |
                (client.FILES if client.present(root) else set()) |
                (startup.FILES if startup.present(root) else set()) |
                (fex.FILES if fex.present(root) else set()))
    resources = {name.removeprefix("app/Madeira/"): planner.identity(root / name)["sha256"]
                 for name in tracked if name.startswith("app/Madeira/") and
                 name.removeprefix("app/Madeira/") in required}
    print(json.dumps(validate(root, resources, tracked), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
