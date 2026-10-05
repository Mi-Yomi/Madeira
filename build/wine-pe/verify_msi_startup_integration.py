#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""One fixed MSI child-startup replacement, layered over unchanged historical seals.

Only the two reviewed msi.dll identities may change. This is not a caller-
supplied replacement map, a re-sealing facility, or an i386 activation path.
"""
import copy
import hashlib
import json
from pathlib import Path

import guest_inventory as inventory
import plan_desktop_overlay as planner

RECORD = "build/wine-pe/msi-startup-integration.json"
RECEIPT = "build/wine-pe/receipts/msi-startup-2026-10-05"
REVIEWED_SEAL = "98ba33f210fc2a01becb2be20e1f19242a2c8a15e28b0138782778f8ea8cd119"
BUILD_SEAL = "4e2a53480a0ae3650f4ae8d1e273c4aac08e08d4cf611b03c08848f5bc6eebbe"
WINE_REVISION = "4f5b19718f4de88ecc5cb0dc08b119497a67ba8f"
SOURCE_SHA256 = "0feda873cdce7625044f153c10ad05fa3d49939bde94f4fe28fce75b0735669f"
PATCH_SHA256 = "a3c010ea77cf18c3b37ad2bc249692758839d9f83fbe7b081b08312dc8e36bae"
BEFORE = {
    "aarch64-windows/msi.dll": {"bytes": 1572864, "sha256": "c04b4aa74963caa1043229c8d2fbf4b4a09c94a7684107335cddb5fde2b2356a"},
    "arm64ec-windows/msi.dll": {"bytes": 1769472, "sha256": "3c69a7becb0ee31974fb7b0cf9785095b0d3d77551a87dd337257358c37924ae"},
}
CANDIDATES = {
    "aarch64-windows/msi.dll": {"bytes": 1572864, "sha256": "6845b17db8b5650fd7637718c2fbcd8467b02060d179354e78ed3037321d2f6e"},
    "arm64ec-windows/msi.dll": {"bytes": 1769472, "sha256": "6b611ac3a9c9b1200314397ab033e03ce1a5d9e93f6be3337a935ca33f124a9f"},
}
INACTIVE_I386 = {"bytes": 1208320, "sha256": "46d3348f16188e5b05a13b3e01564a652b0b3f7af0b6555d23d110e8169bd0e0"}

BUILD_FILES = 113
STAGE_FILES = 121
IMPORT_ADDITIONS = frozenset((
    ("import", "kernel32.dll", "CancelIoEx"),
    ("import", "kernel32.dll", "CreateEventW"),
    ("import", "kernel32.dll", "GetOverlappedResult"),
    ("import", "kernel32.dll", "WaitForMultipleObjects"),
))
BINARIES = frozenset(CANDIDATES)
COPIES = {name: "build/candidate/" + name for name in BINARIES}
COPIES.update({
    "legal/Wine-MSI-startup-SOURCE-REBUILD.md": "build/SOURCE-REBUILD.md",
    "legal/Wine-MSI-startup.patch": "build/patches/msi-startup-wait.patch",
    "legal/Wine-MSI-startup-MODIFICATIONS.md": "build/licenses/startup-fix/MODIFICATIONS.md",
    "legal/Wine-MSI-startup-INTEGRATION.md": "INTEGRATION.md",
})
FILES = frozenset(COPIES)
REQUIRED_NOTICES = tuple(sorted(FILES - BINARIES))
COUNTS = {arch: {"checked_import_symbols": 331 if arch == "aarch64" else 332,
                 "checked_export_forwarders": 0, "exports": 296} for arch in planner.ARCHES}


def seal(stage, build=False):
    """Retain the strict bounded, complete, nonempty historical seal verifier."""
    return planner.seal(stage, BUILD_SEAL if build else REVIEWED_SEAL)


def present(root):
    root = Path(root)
    paths = [root / RECORD, root / RECEIPT]
    paths.extend(root / "app/Madeira" / name for name in REQUIRED_NOTICES)
    return any(path.exists() or path.is_symlink() for path in paths)


def record_contract(sealed):
    import verify_desktop_integration as desktop
    import verify_msi_integration as msi
    import verify_loader_integration as loader
    import verify_msi_client_integration as client
    return {"schema_version": 1, "wine_revision": WINE_REVISION,
            "receipt_directory": RECEIPT, "stage_seal_sha256": REVIEWED_SEAL,
            "build_seal_sha256": BUILD_SEAL, "source_sha256": SOURCE_SHA256,
            "incremental_patch_sha256": PATCH_SHA256,
            "historical_seals": {"desktop": desktop.REVIEWED_SEAL,
                                 "msi": msi.REVIEWED_SEAL, "loader": loader.REVIEWED_SEAL,
                                 "msi_client": client.REVIEWED_SEAL},
            "replacements": {name: {"before": BEFORE[name], "after": CANDIDATES[name]}
                             for name in sorted(BINARIES)},
            "added_imports": [list(row) for row in sorted(IMPORT_ADDITIONS)],
            "files": {name: sealed[source] for name, source in sorted(COPIES.items())},
            "residual_dependency_counts": msi.RESIDUAL_COUNTS,
            "i386_activated": False, "runtime_tested": False, "package_ready": False}


def check_source(stage, sealed, root):
    import verify_msi_client_integration as client
    import verify_msi_integration as msi
    original = seal(stage / "build", build=True)
    planner.require(len(original) == BUILD_FILES and len(sealed) == STAGE_FILES,
                    "MSI startup receipt must retain the exact build and combined-farm evidence")
    source = planner.document(stage, "build/evidence/source-inputs.json")
    predecessor_source = Path(root) / client.RECEIPT / "build/evidence/source-inputs.json"
    planner.require(planner.identity(predecessor_source) == source.get("source_receipt_identity"),
                    "MSI startup does not bind the historical client source receipt")
    predecessor = planner.document(predecessor_source.parent, predecessor_source.name)
    fields = ("bytes", "sha256", "git_mode", "pinned_git_blob")
    expected_files = {name: {key: item[key] for key in fields}
                      for name, item in predecessor["wine_files"].items()}
    expected_files["dlls/msi/custom.c"].update(original["source/custom.c"])
    planner.require(source.get("wine_pin") == WINE_REVISION and
                    source.get("wine_tree") == "91d4283d3287eda28daf932254db8c6a790a8eb4" and
                    source.get("incremental_baseline_custom_sha256") == client.SOURCE_SHA256 and
                    source.get("incremental_patch") == {"path": "patches/msi-startup-wait.patch",
                        **original["patches/msi-startup-wait.patch"]} and
                    source["incremental_patch"]["sha256"] == PATCH_SHA256 and
                    source.get("only_reviewed_incremental_patch_differs") is True and
                    source.get("all_pinned_git_blobs_and_modes_verified") is True and
                    len(expected_files) == 10958 and source.get("files") == expected_files and
                    original["source/custom.c"]["sha256"] == SOURCE_SHA256 and
                    source.get("patches") == {"msi-combined.patch": original["patches/msi-combined.patch"],
                                              "msi-client-failure.patch": original["patches/msi-client-failure.patch"]} and
                    original["patches/msi-combined.patch"]["sha256"] == msi.PATCH_SHA256 and
                    original["patches/msi-client-failure.patch"]["sha256"] == client.PATCH_SHA256,
                    "MSI startup source differs from the exact incremental reviewed fix")
    planner.require(BEFORE == client.CANDIDATES, "MSI startup predecessor is not the reviewed client pair")
    for name, identity in CANDIDATES.items():
        planner.require(sealed[COPIES[name]] == identity and
                        original["preserved-original/" + name] == BEFORE[name],
                        "MSI startup replacement differs from its fixed before/after identities")
    planner.require(original["candidate/i386-windows/msi.dll"] == INACTIVE_I386 and
                    original["preserved-original/i386-windows/msi.dll"] == client.INACTIVE_I386,
                    "Inactive i386 evidence differs from the reviewed build")
    recipe = planner.document(stage, "build/evidence/rebuild-plan.json")
    planner.require(recipe.get("wine_pin") == WINE_REVISION and
                    recipe.get("source_sha256") == SOURCE_SHA256 and
                    recipe.get("guest_execution") is False and recipe.get("i386_activation") is False and
                    recipe.get("rebuild_script") == original["build_startup.py"] and
                    bool(recipe.get("recipe_helpers")), "MSI startup captured build recipe differs")
    for name, value in recipe["recipe_helpers"].items():
        planner.require(original.get("tools/" + name) == value,
                        "MSI startup captured recipe changed: " + name)


    build_record = planner.document(stage, "build/replacement-identity.json")
    planner.require(build_record.get("wine_pin") == WINE_REVISION and
                    build_record.get("final_source_sha256") == SOURCE_SHA256 and
                    build_record.get("incremental_baseline_sha256") == client.SOURCE_SHA256 and
                    build_record.get("incremental_patch_sha256") == PATCH_SHA256 and
                    build_record.get("runtime_tested") is False and build_record.get("installed") is False and
                    build_record.get("guest_execution") is False and build_record.get("published") is False and
                    build_record.get("bitwise_reproducibility_established") is False and
                    [row.get("architecture") for row in build_record.get("outputs", [])] ==
                    ["aarch64", "arm64ec", "i386"], "MSI startup build provenance differs")
    for row in build_record["outputs"]:
        arch = row["architecture"]
        name = arch + "-windows/msi.dll"
        after = INACTIVE_I386 if arch == "i386" else CANDIDATES[name]
        before = client.INACTIVE_I386 if arch == "i386" else BEFORE[name]
        link = planner.document(stage, "build/evidence/" + arch + "-link-inputs.json")
        planner.require(row.get("identity") == after and row.get("published") == before and
                        row.get("active") is False and row.get("runtime_tested") is False and
                        row.get("architecture_export_contract_equal") is True and
                        row.get("import_delta_verified") is True and row.get("removed_imports") == [] and
                        row.get("added_imports") == [{"kind": kind, "module": module, "symbol": symbol}
                            for kind, module, symbol in sorted(IMPORT_ADDITIONS)] and
                        row.get("full_current_farm_import_resolution") is (arch != "i386") and
                        row.get("custom_object") == original["evidence/compiled-custom/" + arch + "-custom.o"] and
                        link.get("custom_object") == row["custom_object"] and
                        link.get("custom_object_machine_verified") is True and
                        link.get("source") == original["source/custom.c"],
                        "MSI startup compiled source/object/provider chain differs")
        new_raw = inventory.read_pe_bytes(planner.safe_path(stage, "build/candidate/" + name))
        before_raw = inventory.read_pe_bytes(planner.safe_path(stage, "build/preserved-original/" + name))
        planner.require(hashlib.sha256(new_raw).hexdigest() == after["sha256"] and
                        hashlib.sha256(before_raw).hexdigest() == before["sha256"],
                        "MSI startup sealed provider changed before PE parsing")
        check_pe_delta(new_raw, before_raw)
        planner.require(pe_contract(new_raw) == planner.document(stage, "build/evidence/" + arch + "-contract.json"),
                        "MSI startup raw PE differs from captured architecture/API evidence")


def pe_contract(raw):
    import verify_msi_client_integration as client
    return client.pe_contract(raw)


def check_pe_delta(new_raw, before_raw):
    """Exact reviewed additive imports; architecture and exported API unchanged."""
    from collections import Counter
    new, before = pe_contract(new_raw), pe_contract(before_raw)
    planner.require({k: v for k, v in new.items() if k != "imports"} ==
                    {k: v for k, v in before.items() if k != "imports"},
                    "MSI startup architecture/export contract changed")
    def imports(contract):
        return Counter((row["kind"], row["module"], symbol)
                       for row in contract["imports"] for symbol in row["symbols"])
    wanted = imports(before)
    planner.require(not any(wanted[entry] for entry in IMPORT_ADDITIONS),
                    "MSI startup added imports already exist in predecessor")
    wanted.update(IMPORT_ADDITIONS)
    planner.require(imports(new) == wanted,
                    "MSI startup import contract differs from the exact reviewed additions")


def checked_reports(stage):
    reports = {}
    for arch in planner.ARCHES:
        new = planner.document(stage, f"{arch}-inventory.json")
        audit = planner.document(stage, f"{arch}-symbol-audit.json")
        planner.require(not new["errors"] and not new["missing_required"] and
                        audit.get("architecture") == arch and audit.get("passed") is True and
                        audit.get("issues") == [] and audit.get("runtime_tested") is False and
                        audit.get("counts") == COUNTS[arch] and set(audit.get("modules", {})) == {"msi.dll"} and
                        audit.get("input_modules") == planner.identities(new["modules"]) and
                        planner.identities(audit["modules"]) == planner.identities({"msi.dll": new["modules"]["msi.dll"]}),
                        "MSI startup symbol evidence does not bind the exact complete combined farm")
        reports[arch] = new
    return reports


def bind_reports(extension, baseline, arch):
    """Retain every graph/architecture field; change only fixed MSI identities."""
    import verify_msi_integration as msi
    name = arch + "-windows/msi.dll"
    planner.require({k: baseline["modules"]["msi.dll"][k] for k in ("bytes", "sha256")} == BEFORE[name],
                    "MSI startup requires the exact historical MSI precondition")
    expected = copy.deepcopy(baseline)
    expected["modules"]["msi.dll"].update(CANDIDATES[name])
    current = extension["combined"][arch]
    planner.require(msi.contract(current) == msi.contract(expected),
                    "MSI startup changes a module or graph field beyond the fixed replacement")
    return current


def validate(root, resources, tracked):
    import verify_msi_client_integration as client
    root, tracked = Path(root), set(tracked)
    planner.require(RECORD in tracked, "MSI startup integration record must be tracked")
    planner.require(client.present(root), "MSI startup replacement requires reviewed client integration")
    stage = planner.safe_path(root, RECEIPT)
    sealed = seal(stage)
    planner.require({RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")} <= tracked,
                    "MSI startup receipt contains untracked evidence")
    record = planner.document(root, RECORD)
    planner.require(json.dumps(record, sort_keys=True) == json.dumps(record_contract(sealed), sort_keys=True),
                    "MSI startup integration record differs from the exact reviewed replacement")
    check_source(stage, sealed, root)
    for name, source in COPIES.items():
        planner.require("app/Madeira/" + name in tracked, "MSI startup resource must be tracked: " + name)
        path = planner.safe_path(root / "app/Madeira", name)
        actual = planner.identity(path)
        planner.require(actual == sealed[source] and resources.get(name) == actual["sha256"],
                        "MSI startup resource differs from sealed replacement: " + name)
        if name in BINARIES:
            raw = inventory.read_pe_bytes(path)
            planner.require(hashlib.sha256(raw).hexdigest() == actual["sha256"],
                            "MSI startup changed before architecture parsing")
            planner.require(inventory.PE(raw).architecture() == name.split("-windows/")[0],
                            "Wrong architecture in MSI startup replacement")
            old_path = planner.safe_path(root / client.RECEIPT, client.COPIES[name])
            planner.require(planner.identity(old_path) == BEFORE[name],
                            "MSI startup historical provider precondition changed")
            old_raw = inventory.read_pe_bytes(old_path)
            planner.require(hashlib.sha256(old_raw).hexdigest() == BEFORE[name]["sha256"],
                            "MSI startup predecessor changed before PE parsing")
            check_pe_delta(raw, old_raw)
    combined = checked_reports(stage)
    planner.require(seal(stage) == sealed, "MSI startup evidence changed during verification")
    return {"combined": combined, "summary": {"stage_seal_sha256": REVIEWED_SEAL,
            "build_seal_sha256": BUILD_SEAL, "source_sha256": SOURCE_SHA256,
            "replacement_count": 2, "evidence_files": len(sealed) + 1,
            "added_imports": [list(row) for row in sorted(IMPORT_ADDITIONS)],
            "runtime_tested": False, "package_ready": False, "i386_activated": False}}
