#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only add-only MSI handoff; no files copied, guests run or app built."""
import argparse
import json
from pathlib import Path

import guest_inventory as inventory
import plan_desktop_overlay as planner
import verify_desktop_integration as desktop
import verify_msi_integration as msi


def plan(stage, root):
    stage, root = Path(stage).absolute(), Path(root).absolute()
    desktop.wine_gitlink(root)
    sealed = planner.seal(stage, msi.REVIEWED_SEAL)
    planner.require(len(sealed) == 108, "MSI receipt requires all 108 indexed files")
    msi.check_source(stage, sealed)
    baselines, combined = msi.checked_reports(stage)
    old_stage = planner.safe_path(root, desktop.RECEIPT)
    old_sealed = planner.seal(old_stage, desktop.REVIEWED_SEAL)
    desktop.validate_farms(root, old_stage)
    originals = planner.document(stage, "evidence/all-original-farm-files.json")
    operations, unchanged = [], []
    for arch in planner.ARCHES:
        old = planner.document(old_stage, f"{arch}-inventory.json")
        planner.require(msi.contract(baselines[arch]) == msi.contract(old),
                        "MSI baseline differs from the sealed desktop inventory")
        farm = planner.safe_path(root / "app/Madeira", arch + "-windows")
        actual = {path.name: planner.identity(path) for path in planner.children(farm, inventory.MAX_FARM_FILES)}
        planner.require(actual == originals[arch]["files"], "Original farm files differ from MSI build inputs")
        report = inventory.audit_farm(farm, arch, msi.NAMES | planner.NAMES,
                                     planner.safe_path(stage, f"candidate/{arch}-windows"))
        planner.require(msi.contract(report) == msi.contract(combined[arch]),
                        "Current combined farm differs from sealed MSI dependencies/architecture")
    # i386 evidence may be retained outside resources; even one i386 PE resource
    # would cross the app gate's intentionally unverified-runtime boundary.
    i386 = root / "app/Madeira/i386-windows"
    planner.require(not i386.is_symlink(), "Symlink i386 resource directory refused")
    if i386.exists():
        planner.require(not any(path.suffix.lower() in inventory.PE_SUFFIXES
                                for path in planner.children(i386, inventory.MAX_FARM_FILES)),
                        "Unverified i386 resources must stay inactive")
    for destination, source in sorted(msi.COPIES.items()):
        target = planner.safe_path(root / "app/Madeira", destination)
        if target.exists():
            planner.require(destination not in msi.BINARIES and planner.identity(target) == sealed[source],
                            "MSI integration destination collision: " + destination)
            unchanged.append("app/Madeira/" + destination)
            continue
        operations.append({"source": source, "destination": "app/Madeira/" + destination,
                           "before": None, "after": sealed[source],
                           "rollback": "remove only if current identity still equals after"})
    # The whole original evidence set is copied without interpreting/executing
    # recipes. Its i386 candidate is never an app resource operation.
    for source, identity in sorted({**sealed, "SHA256SUMS": planner.identity(stage / "SHA256SUMS")}.items()):
        target = planner.safe_path(root, msi.RECEIPT + "/" + source)
        planner.require(not target.exists(), "MSI evidence destination collision: " + source)
        operations.append({"source": source, "destination": msi.RECEIPT + "/" + source,
                           "before": None, "after": identity,
                           "rollback": "remove only if current identity still equals after"})
    planner.require(planner.seal(stage, msi.REVIEWED_SEAL) == sealed and
                    planner.seal(old_stage, desktop.REVIEWED_SEAL) == old_sealed,
                    "Sealed input changed during planning")
    return {"schema_version": 1, "read_only": True, "stage_seal_sha256": msi.REVIEWED_SEAL,
            "wine_revision": msi.WINE_REVISION, "source": str(stage), "target": str(root),
            "operations": operations, "preserved_notices": unchanged,
            "new_app_providers": len(msi.BINARIES), "new_app_notice_copies": len(msi.COPIES) - len(msi.BINARIES) - len(unchanged),
            "source_patch_required": True, "i386_activated": False,
            "residual_dependency_counts": msi.RESIDUAL_COUNTS, "runtime_tested": False, "package_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(plan(args.stage, args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
