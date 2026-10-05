#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Verify only the sealed AVICAP32/ACTIVEDS additions, without guest execution."""
from pathlib import Path
import hashlib

import guest_inventory as inventory
import plan_desktop_overlay as planner
import verify_msi_integration as msi

RECORD = "build/wine-pe/loader-integration.json"
RECEIPT = "build/wine-pe/receipts/loader-2026-10-05"
REVIEWED_SEAL = "033316ebff397f5988935ecc653171c25f0341aecb856a79a2190abb6b694df5"
BUILD_SEAL = "d3f405e38d8a4749e54ee6aab53fd034400424b8233555500dfde3cbdaca08ae"
WINE_REVISION = "4f5b19718f4de88ecc5cb0dc08b119497a67ba8f"
WINE_TREE = "91d4283d3287eda28daf932254db8c6a790a8eb4"
NAMES = frozenset(("avicap32.dll", "activeds.dll"))
BINARIES = {f"{arch}-windows/{name}" for arch in planner.ARCHES for name in NAMES}
CANDIDATES = {
    "aarch64-windows/activeds.dll": {"bytes": 655360, "sha256": "39c0505d43d773a6173a96b1ca7fca1777785223b944b18c24d17858f919ad63"},
    "aarch64-windows/avicap32.dll": {"bytes": 458752, "sha256": "870e5d818712f751029c47c038c201aa8a846ca7b5d3f5622633dd027d228b2c"},
    "arm64ec-windows/activeds.dll": {"bytes": 851968, "sha256": "407bd4949ae12bf22861d96695a4047af63ff1081364eaebaf623702eafcacad"},
    "arm64ec-windows/avicap32.dll": {"bytes": 589824, "sha256": "f9e500425444a9cb82cb76def929d5591308b68b7d8b4d61b85367616a966ffd"},
}
COPIES = {name: "build/candidate/" + name for name in BINARIES}
COPIES.update({"legal/Wine-LGPL-2.1.txt": "build/licenses/Wine-COPYING.LIB",
               "legal/Wine-LICENSE-MADEIRA.md": "build/licenses/Wine-LICENSE-MADEIRA.md",
               "legal/Wine-compiler-rt-LICENSE.txt": "build/licenses/Wine-LICENSE.TXT",
               "legal/Wine-loader-SOURCE-REBUILD.md": "build/SOURCE-REBUILD.md"})
INTEGRATION_NOTICE = "legal/Wine-loader-INTEGRATION.md"
FILES = set(COPIES) | {INTEGRATION_NOTICE}
REQUIRED_NOTICES = tuple(sorted(FILES - BINARIES))


def present(root):
    root = Path(root)
    unique = BINARIES | {INTEGRATION_NOTICE, "legal/Wine-loader-SOURCE-REBUILD.md"}
    paths = [root / RECORD, root / RECEIPT]
    paths.extend(root / "app/Madeira" / name for name in unique)
    return any(path.exists() or path.is_symlink() for path in paths)


def check_source(stage, sealed):
    original = planner.seal(stage / "build", BUILD_SEAL)
    planner.require(len(original) == 54 and len(sealed) == 59,
                    "Loader receipt must preserve all 54 build entries plus four integration records")
    source = planner.document(stage, "build/evidence/source-inputs.json")
    planner.require(source.get("wine_revision") == WINE_REVISION and
                    source.get("wine_tree") == WINE_TREE and
                    source.get("wine_tracked_sources_clean") is True and
                    len(source.get("wine_files", {})) == 10958,
                    "Loader source must be the complete pristine reviewed Wine pin")
    candidate = planner.document(stage, "build/evidence/candidate-manifest.json")
    expected = [{"path": "candidate/" + name, "architecture": name.split("-windows/")[0],
                 **identity} for name, identity in sorted(CANDIDATES.items())]
    planner.require(candidate == {"wine_revision": WINE_REVISION, "inactive": True,
                                  "runtime_tested": False, "files": expected},
                    "Loader candidate manifest differs from the four reviewed providers")
    for name, identity in CANDIDATES.items():
        planner.require(sealed[COPIES[name]] == identity,
                        "Loader candidate differs from reviewed hash: " + name)


def checked_reports(stage):
    historical, combined = {}, {}
    for arch in planner.ARCHES:
        old = planner.document(stage, f"build/evidence/{arch}-baseline-inventory.json")
        built = planner.document(stage, f"build/evidence/{arch}-inventory.json")
        new = planner.document(stage, f"{arch}-inventory.json")
        audit = planner.document(stage, f"{arch}-symbol-audit.json")
        planner.require(not old["errors"] and not old["missing_required"] and
                        not built["errors"] and not built["missing_required"] and
                        not new["errors"] and not new["missing_required"] and
                        not (set(old["modules"]) & NAMES) and
                        set(built["modules"]) == set(old["modules"]) | NAMES and
                        {name: built["modules"][name] for name in old["modules"]} == old["modules"] and
                        built["missing_dependencies"] == old["missing_dependencies"] and
                        len(old["missing_dependencies"]) == msi.BASELINE_COUNTS[arch],
                        "Loader historical evidence changes the original desktop baseline")
        planner.require(audit.get("architecture") == arch and audit.get("passed") is True and
                        audit.get("issues") == [] and audit.get("runtime_tested") is False and
                        audit.get("counts") == {"checked_import_symbols": 86,
                                                "checked_export_forwarders": 0, "exports": 32} and
                        set(audit.get("modules", {})) == NAMES and
                        audit.get("input_modules") == planner.identities(new["modules"]) and
                        planner.identities(audit["modules"]) == planner.identities(
                            {name: new["modules"][name] for name in NAMES}),
                        "Loader symbol evidence does not bind the complete combined farm")
        historical[arch], combined[arch] = old, new
    return {"historical": historical, "combined": combined}


def bind_reports(extension, desktop, baseline, arch):
    """Preserve both old receipts, all original modules and every residual gap."""
    planner.require(msi.contract(extension["historical"][arch]) == msi.contract(desktop),
                    "Loader build baseline differs from original sealed desktop inventory")
    new = extension["combined"][arch]
    planner.require(not (set(baseline["modules"]) & NAMES) and
                    set(new["modules"]) == set(baseline["modules"]) | NAMES and
                    {name: new["modules"][name] for name in baseline["modules"]} == baseline["modules"] and
                    new["missing_dependencies"] == baseline["missing_dependencies"] and
                    len(new["missing_dependencies"]) == msi.RESIDUAL_COUNTS[arch],
                    "Loader integration changes the sealed MSI baseline or residual gaps")
    return new


def validate(root, resources, tracked):
    root, tracked = Path(root), set(tracked)
    planner.require(RECORD in tracked, "Loader integration record must be tracked")
    record = planner.document(root, RECORD)
    planner.require(record.get("schema_version") == 1 and
                    record.get("wine_revision") == WINE_REVISION and
                    record.get("stage_seal_sha256") == REVIEWED_SEAL and
                    record.get("build_seal_sha256") == BUILD_SEAL and
                    record.get("receipt_directory") == RECEIPT and
                    record.get("runtime_tested") is False and record.get("package_ready") is False and
                    record.get("i386_activated") is False and
                    record.get("residual_dependency_counts") == msi.RESIDUAL_COUNTS,
                    "Loader integration record differs from reviewed contract")
    files = record.get("files")
    planner.require(isinstance(files, dict) and set(files) == FILES,
                    "Loader integration requires the exact four-provider/legal inventory")
    stage = planner.safe_path(root, RECEIPT)
    sealed = planner.seal(stage, REVIEWED_SEAL)
    planner.require({RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")} <= tracked,
                    "Loader receipt contains untracked evidence")
    check_source(stage, sealed)
    for name, entry in files.items():
        planner.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256"} and
                        "app/Madeira/" + name in tracked,
                        "Loader resource must be tracked with exact identity: " + name)
        path = planner.safe_path(root / "app/Madeira", name)
        actual = planner.identity(path)
        planner.require(actual == entry and resources.get(name) == actual["sha256"],
                        "Loader resource substituted or missing: " + name)
        if name in COPIES:
            planner.require(actual == sealed[COPIES[name]],
                            "Loader resource differs from sealed build: " + name)
        if name in BINARIES:
            raw = inventory.read_pe_bytes(path)
            planner.require(hashlib.sha256(raw).hexdigest() == actual["sha256"],
                            "Loader provider changed before architecture parsing: " + name)
            planner.require(inventory.PE(raw).architecture() == name.split("-windows/")[0],
                            "Wrong architecture in loader integration: " + name)
    reports = checked_reports(stage)
    planner.require(planner.seal(stage, REVIEWED_SEAL) == sealed,
                    "Loader evidence changed during verification")
    return {**reports, "summary": {"stage_seal_sha256": REVIEWED_SEAL,
            "build_seal_sha256": BUILD_SEAL, "provider_count": 4,
            "evidence_files": len(sealed) + 1, "runtime_tested": False,
            "package_ready": False, "i386_activated": False}}
