#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only, add-only handoff of the exact four reviewed loader providers."""
import argparse
import json
from pathlib import Path

import guest_inventory as inventory
import plan_desktop_overlay as planner
import verify_desktop_integration as desktop
import verify_msi_integration as msi
import verify_loader_integration as loader


def plan(stage, root):
    stage, root = Path(stage).absolute(), Path(root).absolute()
    planner.require(not loader.present(root), "Loader destination already contains an integration or partial copy")
    tracked = desktop.git_output(root, "ls-files", "-z", "--").split("\0")
    required = set(desktop.COPIES) | desktop.MERGED_NOTICES | msi.FILES
    resources = {name.removeprefix("app/Madeira/"): planner.identity(root / name)["sha256"]
                 for name in tracked if name.startswith("app/Madeira/") and
                 name.removeprefix("app/Madeira/") in required}
    desktop.validate(root, resources, tracked)
    planner.require(msi.present(root), "Loader handoff requires reviewed MSI baseline")
    sealed = planner.seal(stage, loader.REVIEWED_SEAL)
    loader.check_source(stage, sealed)
    extension = loader.checked_reports(stage)
    _, baseline = msi.checked_reports(root / msi.RECEIPT)
    originals = {}
    for arch in planner.ARCHES:
        old = planner.document(root / desktop.RECEIPT, f"{arch}-inventory.json")
        expected = loader.bind_reports(extension, old, baseline[arch], arch)
        farm = planner.safe_path(root / "app/Madeira", arch + "-windows")
        prefix = "app/Madeira/" + arch + "-windows/"
        planner.require({prefix + path.name for path in planner.children(farm, inventory.MAX_FARM_FILES)} ==
                        {name for name in tracked if name.startswith(prefix)},
                        "Loader baseline contains untracked farm files")
        originals[arch] = {path.name: planner.identity(path)
                           for path in planner.children(farm, inventory.MAX_FARM_FILES)}
        actual = inventory.audit_farm(farm, arch, planner.NAMES | msi.NAMES | loader.NAMES,
                                     planner.safe_path(stage, f"build/candidate/{arch}-windows"))
        planner.require(msi.contract(actual) == msi.contract(expected),
                        "Loader combined farm differs from sealed dependencies/architecture")
    i386 = root / "app/Madeira/i386-windows"
    planner.require(not i386.is_symlink(), "Symlink i386 resource directory refused")
    if i386.exists():
        planner.require(not any(path.suffix.lower() in inventory.PE_SUFFIXES
                                for path in planner.children(i386, inventory.MAX_FARM_FILES)),
                        "Unverified i386 resources must stay inactive")
    operations, unchanged = [], []
    for destination, source in sorted(loader.COPIES.items()):
        target = planner.safe_path(root / "app/Madeira", destination)
        if target.exists():
            planner.require(destination not in loader.BINARIES and planner.identity(target) == sealed[source],
                            "Loader destination collision: " + destination)
            unchanged.append("app/Madeira/" + destination)
            continue
        operations.append({"source": source, "destination": "app/Madeira/" + destination,
                           "before": None, "after": sealed[source],
                           "rollback": "remove only if current identity still equals after"})
    for source, identity in sorted({**sealed, "SHA256SUMS": planner.identity(stage / "SHA256SUMS")}.items()):
        target = planner.safe_path(root, loader.RECEIPT + "/" + source)
        planner.require(not target.exists(), "Loader receipt destination collision: " + source)
        operations.append({"source": source, "destination": loader.RECEIPT + "/" + source,
                           "before": None, "after": identity,
                           "rollback": "remove only if current identity still equals after"})
    planner.require(planner.seal(stage, loader.REVIEWED_SEAL) == sealed,
                    "Loader receipt changed during planning")
    return {"schema_version": 1, "read_only": True, "source": str(stage), "target": str(root),
            "stage_seal_sha256": loader.REVIEWED_SEAL, "wine_revision": loader.WINE_REVISION,
            "operations": operations, "preserved_notices": unchanged,
            "original_farm_files": originals, "new_app_providers": 4,
            "source_patch_required": True, "i386_activated": False,
            "runtime_tested": False, "package_ready": False,
            "residual_dependency_counts": msi.RESIDUAL_COUNTS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(plan(args.stage, args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
