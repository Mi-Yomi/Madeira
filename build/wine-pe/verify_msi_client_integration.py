#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""One fixed MSI client replacement, layered over unchanged historical seals.

Only the two reviewed msi.dll identities may change. This is not a caller-
supplied replacement map, a re-sealing facility, or an i386 activation path.
"""
import copy
import hashlib
import json
import os
from pathlib import Path

import guest_inventory as inventory
import plan_desktop_overlay as planner
import symbol_audit

RECORD = "build/wine-pe/msi-client-integration.json"
RECEIPT = "build/wine-pe/receipts/msi-client-2026-10-05"
REVIEWED_SEAL = "98c5adfb9a4e8bee95eadfcf390898eb7cc49059a4c436de86d29c4bfe61cc23"
BUILD_SEAL = "55f90bf94f2a67a1c9c25bf1dbb29311e2277e2d1d996d54a8753b538cae8833"
WINE_REVISION = "4f5b19718f4de88ecc5cb0dc08b119497a67ba8f"
SOURCE_SHA256 = "9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50"
PATCH_SHA256 = "6dc3802f26e98a0cc03462b989e2d3619b74f9374d325784009c1df5a8623ebe"
BEFORE = {
    "aarch64-windows/msi.dll": {"bytes": 1572864, "sha256": "12bbe1e84a6ef12b6775f1e081e69e404736d9be5b118fa322d989d9f1b93221"},
    "arm64ec-windows/msi.dll": {"bytes": 1769472, "sha256": "30fca59166929f1300d7708d45d56b401e680d0318b0ce7d7ff754987177f30d"},
}
CANDIDATES = {
    "aarch64-windows/msi.dll": {"bytes": 1572864, "sha256": "c04b4aa74963caa1043229c8d2fbf4b4a09c94a7684107335cddb5fde2b2356a"},
    "arm64ec-windows/msi.dll": {"bytes": 1769472, "sha256": "3c69a7becb0ee31974fb7b0cf9785095b0d3d77551a87dd337257358c37924ae"},
}
INACTIVE_I386 = {"bytes": 1208320, "sha256": "1fe600254f476fb48e9b9694f7b4e9ef7b7bdc1980358cc5d0727186d9dc2b23"}
BINARIES = frozenset(CANDIDATES)
COPIES = {name: "build/candidate/" + name for name in BINARIES}
COPIES.update({
    "legal/Wine-MSI-client-SOURCE-REBUILD.md": "build/SOURCE-REBUILD.md",
    "legal/Wine-MSI-client.patch": "build/patches/msi-client-failure.patch",
    "legal/Wine-MSI-client-MODIFICATIONS.md": "build/licenses/client-fix/CLIENT-MODIFICATIONS.md",
    "legal/Wine-MSI-client-INTEGRATION.md": "INTEGRATION.md",
})
FILES = frozenset(COPIES)
REQUIRED_NOTICES = tuple(sorted(FILES - BINARIES))
COUNTS = {arch: {"checked_import_symbols": 327 if arch == "aarch64" else 328,
                 "checked_export_forwarders": 0, "exports": 296} for arch in planner.ARCHES}
EMPTY_LOGS = frozenset((
    "evidence/client-baseline/compile.log", "evidence/client-normal/compile.log",
    "evidence/client-sanitized/compile.log", "review-inputs/client-fix/reports/baseline/compile.log",
    "review-inputs/client-fix/reports/cross-compile/aarch64.log",
    "review-inputs/client-fix/reports/cross-compile/arm64ec.log",
    "review-inputs/client-fix/reports/patched/compile.log",
    "review-inputs/client-fix/reports/sanitized/compile.log",
))


def seal(stage, build=False):
    """Verify the fixed new index, including eight legitimately empty logs.

    Historical seals retain the existing stricter nonempty-file verifier.
    Only these exact zero-byte build logs need different handling here.
    """
    expected = BUILD_SEAL if build else REVIEWED_SEAL
    planner.require(planner.identity(planner.safe_path(stage, "SHA256SUMS"))["sha256"] == expected,
                    "MSI client reviewed stage seal differs")
    listed = {}
    for line in (stage / "SHA256SUMS").read_text().splitlines():
        planner.require(len(line) > 66 and line[64:66] == "  " and planner.SHA256.fullmatch(line[:64]),
                        "MSI client malformed checksum index")
        name = line[66:]
        planner.safe_path(stage, name)
        planner.require(name not in listed and name != "SHA256SUMS", "MSI client duplicate checksum entry")
        listed[name] = line[:64]
        planner.require(len(listed) <= planner.MAX_FILES, "MSI client checksum entry budget exceeded")
    empty = EMPTY_LOGS if build else {"build/" + name for name in EMPTY_LOGS}
    found, pending, total, entries = {}, [stage], 0, 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                planner.require(entries <= planner.MAX_FILES and not child.is_symlink(),
                                "MSI client evidence entry budget or symlink violation")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                    continue
                path = Path(child.path)
                name = path.relative_to(stage).as_posix()
                if name in empty:
                    planner.safe_path(stage, name)
                    planner.require(child.is_file(follow_symlinks=False) and path.stat().st_size == 0,
                                    "MSI client empty compiler log changed")
                    value = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
                else:
                    value = planner.identity(path)
                total += value["bytes"]
                planner.require(total <= planner.MAX_STAGE, "MSI client evidence byte budget exceeded")
                if name != "SHA256SUMS":
                    found[name] = value
    planner.require(empty <= found.keys() and listed and
                    {name: value["sha256"] for name, value in found.items()} == listed,
                    "MSI client stage differs from complete checksum index")
    return found


def present(root):
    root = Path(root)
    paths = [root / RECORD, root / RECEIPT]
    paths.extend(root / "app/Madeira" / name for name in REQUIRED_NOTICES)
    return any(path.exists() or path.is_symlink() for path in paths)


def record_contract(sealed):
    import verify_desktop_integration as desktop
    import verify_msi_integration as msi
    import verify_loader_integration as loader
    return {"schema_version": 1, "wine_revision": WINE_REVISION,
            "receipt_directory": RECEIPT, "stage_seal_sha256": REVIEWED_SEAL,
            "build_seal_sha256": BUILD_SEAL, "source_sha256": SOURCE_SHA256,
            "incremental_patch_sha256": PATCH_SHA256,
            "historical_seals": {"desktop": desktop.REVIEWED_SEAL,
                                 "msi": msi.REVIEWED_SEAL, "loader": loader.REVIEWED_SEAL},
            "replacements": {name: {"before": BEFORE[name], "after": CANDIDATES[name]}
                             for name in sorted(BINARIES)},
            "files": {name: sealed[source] for name, source in sorted(COPIES.items())},
            "residual_dependency_counts": msi.RESIDUAL_COUNTS,
            "i386_activated": False, "runtime_tested": False, "package_ready": False}


def check_source(stage, sealed):
    import verify_msi_integration as msi
    original = seal(stage / "build", build=True)
    planner.require(len(original) == 168 and len(sealed) == 176,
                    "MSI client receipt must retain the exact build and combined-farm evidence")
    source = planner.document(stage, "build/evidence/source-inputs.json")
    planner.require(source.get("wine_revision") == WINE_REVISION and
                    source.get("wine_tree") == "91d4283d3287eda28daf932254db8c6a790a8eb4" and
                    source.get("incremental_baseline_sha256") == msi.CUSTOM_AFTER and
                    source.get("incremental_patch_sha256") == PATCH_SHA256 and
                    source.get("patch_sha256") == msi.PATCH_SHA256 and
                    source.get("production_functions_changed_by_incremental_patch") == ["custom_client_thread"] and
                    source.get("only_reviewed_patch_applied") is True and
                    source.get("patched_file") == {"path": "dlls/msi/custom.c",
                        "before_sha256": msi.CUSTOM_BEFORE, "after_sha256": SOURCE_SHA256} and
                    len(source.get("wine_files", {})) == 10958 and
                    [name for name, item in source["wine_files"].items() if item.get("patched")] == ["dlls/msi/custom.c"] and
                    source["wine_files"]["dlls/msi/custom.c"]["sha256"] == SOURCE_SHA256 and
                    original["patches/msi-client-failure.patch"]["sha256"] == PATCH_SHA256 and
                    original["source/custom.c"]["sha256"] == SOURCE_SHA256,
                    "MSI client source differs from the exact incremental reviewed fix")
    for name, identity in CANDIDATES.items():
        planner.require(sealed[COPIES[name]] == identity and
                        original["preserved-original/" + name] == BEFORE[name],
                        "MSI client replacement differs from its fixed before/after identities")
    planner.require(original["candidate/i386-windows/msi.dll"] == INACTIVE_I386,
                    "Inactive i386 evidence differs from the reviewed build")
    for name, value in source["recipe_inputs"].items():
        planner.require(original.get(name) == value, "MSI client captured recipe changed: " + name)


def pe_contract(raw):
    pe = inventory.PE(raw)
    return {"architecture": pe.architecture(), "machine": hex(pe.machine),
            "exports": [{k: v for k, v in row.items() if k != "rva"}
                        for row in symbol_audit.exports(pe)],
            "imports": [{"module": row["module"], "kind": row["kind"],
                         "symbols": [s.get("name", s.get("ordinal")) for s in row["symbols"]]}
                        for row in symbol_audit.imports(pe)]}


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
                        "MSI client symbol evidence does not bind the exact complete combined farm")
        reports[arch] = new
    return reports


def bind_reports(extension, baseline, arch):
    """Retain every graph/architecture field; change only fixed MSI identities."""
    import verify_msi_integration as msi
    name = arch + "-windows/msi.dll"
    planner.require({k: baseline["modules"]["msi.dll"][k] for k in ("bytes", "sha256")} == BEFORE[name],
                    "MSI client requires the exact historical MSI precondition")
    expected = copy.deepcopy(baseline)
    expected["modules"]["msi.dll"].update(CANDIDATES[name])
    current = extension["combined"][arch]
    planner.require(msi.contract(current) == msi.contract(expected),
                    "MSI client changes a module or graph field beyond the fixed replacement")
    return current


def validate(root, resources, tracked):
    import verify_msi_integration as msi
    import verify_loader_integration as loader
    import verify_msi_startup_integration as startup
    root, tracked = Path(root), set(tracked)
    planner.require(RECORD in tracked, "MSI client integration record must be tracked")
    planner.require(loader.present(root), "MSI client replacement requires reviewed loader integration")
    stage = planner.safe_path(root, RECEIPT)
    sealed = seal(stage)
    planner.require({RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")} <= tracked,
                    "MSI client receipt contains untracked evidence")
    record = planner.document(root, RECORD)
    planner.require(json.dumps(record, sort_keys=True) == json.dumps(record_contract(sealed), sort_keys=True),
                    "MSI client integration record differs from the exact reviewed replacement")
    check_source(stage, sealed)
    replacement = startup.validate(root, resources, tracked) if startup.present(root) else None
    for name, source in COPIES.items():
        planner.require("app/Madeira/" + name in tracked, "MSI client resource must be tracked: " + name)
        path = planner.safe_path(root / "app/Madeira", name)
        actual = planner.identity(path)
        expected = startup.CANDIDATES[name] if replacement is not None and name in BINARIES else sealed[source]
        planner.require(actual == expected and resources.get(name) == actual["sha256"],
                        "MSI client resource differs from sealed replacement: " + name)
        if name in BINARIES:
            raw = inventory.read_pe_bytes(path)
            planner.require(hashlib.sha256(raw).hexdigest() == actual["sha256"],
                            "MSI client changed before architecture parsing")
            planner.require(inventory.PE(raw).architecture() == name.split("-windows/")[0],
                            "Wrong architecture in MSI client replacement")
            old_path = planner.safe_path(root / msi.RECEIPT, "candidate/" + name)
            planner.require(planner.identity(old_path) == BEFORE[name],
                            "MSI client historical provider precondition changed")
            old_raw = inventory.read_pe_bytes(old_path)
            historical_raw = raw if replacement is None else inventory.read_pe_bytes(planner.safe_path(stage, source))
            planner.require(hashlib.sha256(historical_raw).hexdigest() == sealed[source]["sha256"] and
                            hashlib.sha256(old_raw).hexdigest() == BEFORE[name]["sha256"] and
                            pe_contract(historical_raw) == pe_contract(old_raw),
                            "MSI client architecture/import/export contract changed")
    combined = checked_reports(stage)
    planner.require(seal(stage) == sealed, "MSI client evidence changed during verification")
    return {"combined": combined, "startup": replacement, "summary": {"stage_seal_sha256": REVIEWED_SEAL,
            "build_seal_sha256": BUILD_SEAL, "source_sha256": SOURCE_SHA256,
            "replacement_count": 2, "evidence_files": len(sealed) + 1,
            "runtime_tested": False, "package_ready": False, "i386_activated": False}}
