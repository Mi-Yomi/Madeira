#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only plan: two fixed MSI replacements and otherwise add-only copies."""
import argparse
import json
from pathlib import Path

import plan_desktop_overlay as planner
import verify_desktop_integration as desktop
import verify_msi_integration as msi
import verify_loader_integration as loader
import verify_msi_client_integration as client
import verify_msi_startup_integration as startup


def plan(stage, root):
    stage, root = Path(stage).absolute(), Path(root).absolute()
    planner.require(not startup.present(root), "MSI startup target already contains an integration or partial copy")
    tracked = desktop.git_output(root, "ls-files", "-z", "--").split("\0")
    required = set(desktop.COPIES) | desktop.MERGED_NOTICES | msi.FILES | loader.FILES | client.FILES
    resources = {name.removeprefix("app/Madeira/"): planner.identity(root / name)["sha256"]
                 for name in tracked if name.startswith("app/Madeira/") and
                 name.removeprefix("app/Madeira/") in required}
    planner.require(msi.present(root) and loader.present(root) and client.present(root), "MSI startup handoff requires all reviewed predecessor integrations")
    desktop.validate(root, resources, tracked)
    sealed = startup.seal(stage)
    startup.check_source(stage, sealed, root)
    extension = {"combined": startup.checked_reports(stage)}
    historical = client.checked_reports(root / client.RECEIPT)
    originals = {}
    for arch in planner.ARCHES:
        expected = startup.bind_reports(extension, historical[arch], arch)
        farm = planner.safe_path(root / "app/Madeira", arch + "-windows")
        prefix = "app/Madeira/" + arch + "-windows/"
        paths = planner.children(farm, desktop.inventory.MAX_FARM_FILES)
        planner.require({prefix + path.name for path in paths} ==
                        {name for name in tracked if name.startswith(prefix)},
                        "MSI startup baseline contains untracked farm files")
        originals[arch] = {path.name: planner.identity(path) for path in paths}
        actual = desktop.inventory.audit_farm(farm, arch, planner.NAMES | msi.NAMES | loader.NAMES,
                                              planner.safe_path(stage, "build/candidate/" + arch + "-windows"))
        planner.require(msi.contract(actual) == msi.contract(expected),
                        "MSI startup planned farm differs from the reviewed combined graph")
    i386 = root / "app/Madeira/i386-windows"
    planner.require(not i386.is_symlink(), "Symlink i386 resource directory refused")
    if i386.exists():
        planner.require(not any(path.suffix.lower() in desktop.inventory.PE_SUFFIXES
                                for path in planner.children(i386, desktop.inventory.MAX_FARM_FILES)),
                        "Unverified i386 resources must stay inactive")
    operations = []
    for destination, source in sorted(startup.COPIES.items()):
        target = planner.safe_path(root / "app/Madeira", destination)
        if destination in startup.BINARIES:
            planner.require(planner.identity(target) == startup.BEFORE[destination],
                            "MSI startup exact replacement precondition failed")
            before = startup.BEFORE[destination]
        else:
            planner.require(not target.exists(), "MSI startup new notice destination collision")
            before = None
        operations.append({"source": source, "destination": "app/Madeira/" + destination,
                           "before": before, "after": sealed[source],
                           "before_mode": "100755" if before and target.stat().st_mode & 0o111 else "100644" if before else None,
                           "after_mode": "100755" if before and target.stat().st_mode & 0o111 else "100644",
                           "rollback_source": client.RECEIPT + "/" + client.COPIES[destination] if before else None,
                           "rollback": "restore before only if current equals after" if before else
                                       "remove only if current identity equals after"})
    for source, identity in sorted({**sealed, "SHA256SUMS": planner.identity(stage / "SHA256SUMS")}.items()):
        target = planner.safe_path(root, startup.RECEIPT + "/" + source)
        planner.require(not target.exists(), "MSI startup receipt destination collision")
        operations.append({"source": source, "destination": startup.RECEIPT + "/" + source,
                           "before": None, "after": identity,
                           "before_mode": None,
                           "after_mode": "100755" if (stage / source).stat().st_mode & 0o111 else "100644",
                           "rollback": "remove only if current identity equals after"})
    planner.require(startup.seal(stage) == sealed, "MSI startup stage changed during planning")
    return {"schema_version": 1, "read_only": True, "source": str(stage), "target": str(root),
            "stage_seal_sha256": startup.REVIEWED_SEAL, "build_seal_sha256": startup.BUILD_SEAL,
            "operations": operations, "original_farm_files": originals,
            "preserved_notices": {name: digest for name, digest in resources.items() if name.startswith("legal/")},
            "replaced_app_providers": 2, "new_app_providers": 0,
            "source_patch_required": True, "i386_activated": False,
            "runtime_tested": False, "package_ready": False,
            "residual_dependency_counts": msi.RESIDUAL_COUNTS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(plan(args.stage, args.root), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
