#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Bind only the reviewed fourteen MSI providers to their original farm inputs.

Static reads only. The i386 output remains sealed evidence outside app resources.
This is deliberately one fixed extension of the desktop audit, not an arbitrary
overlay allowlist. The app gate still rejects every unverified i386 PE resource.
"""
from pathlib import Path
import hashlib

import guest_inventory as inventory
import plan_desktop_overlay as planner

RECORD = "build/wine-pe/msi-integration.json"
RECEIPT = "build/wine-pe/receipts/msi-2026-10-05"
REVIEWED_SEAL = "3d748dc6f9fa84d386c79acdaf9b4952755719daa79f8ac161f1c07d27fee0fe"
WINE_REVISION = "4f5b19718f4de88ecc5cb0dc08b119497a67ba8f"
PATCH_SHA256 = "3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8"
CUSTOM_BEFORE = "201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25"
CUSTOM_AFTER = "31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5"
NAMES = frozenset(("msi.dll", "msiexec.exe", "cabinet.dll", "sxs.dll",
                   "mspatcha.dll", "odbccp32.dll", "regsvr32.exe"))
BINARIES = {f"{arch}-windows/{name}" for arch in planner.ARCHES for name in NAMES}
COPIES = {name: "candidate/" + name for name in BINARIES}
COPIES.update({"legal/" + name: "licenses/" + name for name in (
    "Wine-LGPL-2.1.txt", "Wine-LICENSE-MADEIRA.md", "Wine-compiler-rt-LICENSE.txt",
    "Wine-MSI-MODIFICATIONS.md", "Wine-zlib-LICENSE.txt", "Wine-zlib-header-with-notice.h")})
COPIES.update({"legal/Wine-MSI-SOURCE-REBUILD.md": "SOURCE-REBUILD.md",
               "legal/Wine-MSI-custom-actions.patch": "patches/msi-combined.patch",
               "legal/Wine-MSI-toolchain-LICENSE.txt": "licenses/llvm-mingw-20260421-LICENSE.TXT"})
INTEGRATION_NOTICE = "legal/Wine-MSI-INTEGRATION.md"
FILES = set(COPIES) | {INTEGRATION_NOTICE}
REQUIRED_NOTICES = tuple(sorted(FILES - BINARIES))
RESIDUAL_COUNTS = {"aarch64": 13, "arm64ec": 10}
BASELINE_COUNTS = {"aarch64": 14, "arm64ec": 11}
CLOSED_EDGE = {"dependency": "cabinet.dll", "kind": "delay", "module": "setupapi.dll",
               "reason": "absent/invalid module", "target": "cabinet.dll"}


def present(root):
    """A partial/untracked integration must activate validation too."""
    root = Path(root)
    paths = [root / RECORD, root / RECEIPT]
    paths.extend(root / "app/Madeira" / name for name in FILES
                 if name not in {"legal/" + value for value in planner.LICENSES.values()})
    return any(path.exists() or path.is_symlink() for path in paths)


def contract(report):
    return {key: value for key, value in report.items() if key != "folder"}


def checked_reports(stage):
    """Check the exact add-only transition and bind the recorded symbol audit."""
    baselines, combined = {}, {}
    for arch in planner.ARCHES:
        old = planner.document(stage, f"evidence/{arch}-baseline-inventory.json")
        new = planner.document(stage, f"evidence/{arch}-inventory.json")
        audit = planner.document(stage, f"evidence/{arch}-symbol-audit.json")
        planner.require(not old["errors"] and not old["missing_required"] and
                        not new["errors"] and not new["missing_required"] and
                        not (set(old["modules"]) & NAMES) and
                        set(new["modules"]) == set(old["modules"]) | NAMES and
                        {name: new["modules"][name] for name in old["modules"]} == old["modules"],
                        "MSI evidence does not describe the exact add-only farm transition")
        planner.require(old["missing_dependencies"].count(CLOSED_EDGE) == 1 and
                        len(old["missing_dependencies"]) == BASELINE_COUNTS[arch] and
                        new["missing_dependencies"] == [gap for gap in old["missing_dependencies"] if gap != CLOSED_EDGE] and
                        len(new["missing_dependencies"]) == RESIDUAL_COUNTS[arch],
                        "MSI evidence changes a dependency gap other than setupapi to cabinet")
        planner.require(audit.get("architecture") == arch and audit.get("passed") is True and
                        audit.get("issues") == [] and set(audit.get("modules", {})) == NAMES and
                        audit.get("input_modules") == planner.identities(new["modules"]) and
                        planner.identities(audit["modules"]) == planner.identities(
                            {name: new["modules"][name] for name in NAMES}),
                        "MSI symbol evidence does not bind the complete same-architecture farm")
        baselines[arch], combined[arch] = old, new
    return baselines, combined


def check_source(stage, sealed):
    source = planner.document(stage, "evidence/source-inputs.json")
    patch = source.get("patched_file", {})
    planner.require(source.get("wine_revision") == WINE_REVISION and
                    source.get("only_reviewed_patch_applied") is True and
                    source.get("patch_sha256") == PATCH_SHA256 and
                    patch == {"path": "dlls/msi/custom.c", "before_sha256": CUSTOM_BEFORE,
                              "after_sha256": CUSTOM_AFTER} and
                    [name for name, entry in source["wine_files"].items() if entry.get("patched")] == ["dlls/msi/custom.c"] and
                    source["wine_files"]["dlls/msi/custom.c"]["sha256"] == CUSTOM_AFTER and
                    sealed["patches/msi-combined.patch"]["sha256"] == PATCH_SHA256,
                    "MSI source evidence lacks the exact reviewed single-file Wine patch")

def validate(root, resources, tracked):
    root, tracked = Path(root), set(tracked)
    planner.require(RECORD in tracked, "MSI integration record must be tracked")
    record = planner.document(root, RECORD)
    planner.require(record.get("schema_version") == 1 and
                    record.get("wine_revision") == WINE_REVISION and
                    record.get("stage_seal_sha256") == REVIEWED_SEAL and
                    record.get("patch_sha256") == PATCH_SHA256 and
                    record.get("patched_custom_c_sha256") == CUSTOM_AFTER and
                    record.get("receipt_directory") == RECEIPT and
                    record.get("runtime_tested") is False and record.get("package_ready") is False and
                    record.get("i386_activated") is False and
                    record.get("residual_dependency_counts") == RESIDUAL_COUNTS,
                    "MSI integration record differs from the reviewed contract")
    files = record.get("files")
    planner.require(isinstance(files, dict) and set(files) == FILES,
                    "MSI integration requires the exact fourteen-provider/legal inventory")
    stage = planner.safe_path(root, RECEIPT)
    sealed = planner.seal(stage, REVIEWED_SEAL)
    planner.require(len(sealed) == 108, "MSI receipt must retain all 108 indexed files plus index")
    planner.require({RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")} <= tracked,
                    "MSI receipt contains untracked evidence")
    check_source(stage, sealed)
    for name, entry in files.items():
        planner.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256"} and
                        "app/Madeira/" + name in tracked, "MSI resource must be tracked with exact identity: " + name)
        path = planner.safe_path(root / "app/Madeira", name)
        actual = planner.identity(path)
        planner.require(actual == entry and resources.get(name) == actual["sha256"],
                        "MSI resource substituted or missing: " + name)
        if name in COPIES:
            planner.require(actual == sealed[COPIES[name]], "MSI resource differs from sealed build: " + name)
        if name in BINARIES:
            raw = inventory.read_pe_bytes(path)
            planner.require(hashlib.sha256(raw).hexdigest() == actual["sha256"],
                            "MSI provider changed before architecture parsing: " + name)
            planner.require(inventory.PE(raw).architecture() == name.split("-windows/")[0],
                            "Wrong architecture in MSI integration: " + name)
    baselines, combined = checked_reports(stage)
    planner.require(planner.seal(stage, REVIEWED_SEAL) == sealed, "MSI evidence changed during verification")
    return {"baselines": baselines, "combined": combined,
            "summary": {"stage_seal_sha256": REVIEWED_SEAL, "provider_count": len(BINARIES),
                        "evidence_files": len(sealed) + 1, "residual_dependency_counts": RESIDUAL_COUNTS,
                        "runtime_tested": False, "package_ready": False, "i386_activated": False}}
