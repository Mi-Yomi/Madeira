#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""One fixed FEX pair layered over immutable historical desktop/MSI seals.

This authenticates a recorded local cross-build and static farm checks. It does
not build, execute, install or certify runtime behavior, or activate i386 PEs.
"""
import copy
import hashlib
import json
from pathlib import Path
import shlex

import guest_inventory as inventory
import plan_desktop_overlay as planner
import verify_msi_client_integration as client

RECORD = "build/wine-pe/fex-integration.json"
RECEIPT = "build/wine-pe/receipts/fex-2026-10-06"
REVIEWED_SEAL = "c492fab63b1af3b3342960c4602cbd29044cb6018e841d2f2978401b13bdade6"
STAGE_FILES = 158  # Filled from the separately reviewed fixed evidence package.
FEX_REVISION = "1adb337a2f2270434ba731346438c072337a5d5f"
BUILD_PARENT = "6406b09801026e7211b9f9e26d4f526327eb8c2b"
REPAIRS_SHA256 = "8ece9467d4bd9a00aa051336f1fc73654f907b15a91ba728ca7cff39226bfd1f"
TOOLCHAIN_SHA256 = "f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121"
BEFORE = {
    "arm64ec-windows/xtajit64.dll": {"bytes": 5435392, "sha256": "38b68f69909aea0dae3ce88934936275e9415accf22fc0823568eda244962b07"},
    "aarch64-windows/xtajit.dll": {"bytes": 4857856, "sha256": "682ed22a3e60aff6f0bca8d5d62ec59bc67a2330dd318b70937174244c5c3cb6"},
}
CANDIDATES = {
    "arm64ec-windows/xtajit64.dll": {"bytes": 5410816, "sha256": "4c508cea3d7fd66cee756ba08098c1df3eb334b275c2b6127c3dc313e81e2fb8"},
    "aarch64-windows/xtajit.dll": {"bytes": 4857856, "sha256": "6c1e397f10c4bfbc7e4abc1eca97f2aba207dbbc301f01df7a089430b1ac830e"},
}
BINARIES = frozenset(CANDIDATES)
COPIES = {name: "candidate/" + name for name in BINARIES}
NOTICE_COPIES = {'legal/FEX-guest/PLAYPORT-LICENSE': 'build/evidence/PLAYPORT-LICENSE',
 'legal/FEX-guest/PLAYPORT-LICENSE-EXCEPTION.md': 'build/evidence/PLAYPORT-LICENSE-EXCEPTION.md',
 'legal/FEX-guest/SOURCE-REBUILD.md': 'SOURCE-REBUILD.md',
 'legal/FEX-guest/licenses/FEX/COPYING.GPL-3.0': 'build/evidence/licenses/FEX/COPYING.GPL-3.0',
 'legal/FEX-guest/licenses/FEX/External/SoftFloat-3e/COPYRIGHT-source-header.txt': 'build/evidence/licenses/FEX/External/SoftFloat-3e/COPYRIGHT-source-header.txt',
 'legal/FEX-guest/licenses/FEX/External/cephes/LICENSE': 'build/evidence/licenses/FEX/External/cephes/LICENSE',
 'legal/FEX-guest/licenses/FEX/External/fmt/LICENSE': 'build/evidence/licenses/FEX/External/fmt/LICENSE',
 'legal/FEX-guest/licenses/FEX/External/range-v3/LICENSE.txt': 'build/evidence/licenses/FEX/External/range-v3/LICENSE.txt',
 'legal/FEX-guest/licenses/FEX/External/rpmalloc/COPYING.GPL-3.0': 'build/evidence/licenses/FEX/External/rpmalloc/COPYING.GPL-3.0',
 'legal/FEX-guest/licenses/FEX/External/rpmalloc/LICENSE': 'build/evidence/licenses/FEX/External/rpmalloc/LICENSE',
 'legal/FEX-guest/licenses/FEX/External/rpmalloc/LICENSE-MADEIRA.md': 'build/evidence/licenses/FEX/External/rpmalloc/LICENSE-MADEIRA.md',
 'legal/FEX-guest/licenses/FEX/External/rpmalloc/UNLICENSE': 'build/evidence/licenses/FEX/External/rpmalloc/UNLICENSE',
 'legal/FEX-guest/licenses/FEX/External/tiny-json/LICENSE': 'build/evidence/licenses/FEX/External/tiny-json/LICENSE',
 'legal/FEX-guest/licenses/FEX/External/unordered_dense/LICENSE': 'build/evidence/licenses/FEX/External/unordered_dense/LICENSE',
 'legal/FEX-guest/licenses/FEX/External/xxhash/LICENSE': 'build/evidence/licenses/FEX/External/xxhash/LICENSE',
 'legal/FEX-guest/licenses/FEX/FEXCore/LICENSE': 'build/evidence/licenses/FEX/FEXCore/LICENSE',
 'legal/FEX-guest/licenses/FEX/LICENSE': 'build/evidence/licenses/FEX/LICENSE',
 'legal/FEX-guest/licenses/FEX/LICENSE-MADEIRA.md': 'build/evidence/licenses/FEX/LICENSE-MADEIRA.md',
 'legal/FEX-guest/licenses/FEX/Source/Common/cpp-optparse/LICENSE': 'build/evidence/licenses/FEX/Source/Common/cpp-optparse/LICENSE',
 'legal/FEX-guest/licenses/llvm-mingw/LICENSE.TXT': 'build/evidence/licenses/llvm-mingw/LICENSE.TXT',
 'legal/FEX-guest/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING': 'build/evidence/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING',
 'legal/FEX-guest/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.MinGW-w64-runtime.txt': 'build/evidence/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.MinGW-w64-runtime.txt',
 'legal/FEX-guest/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.MinGW-w64.txt': 'build/evidence/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.MinGW-w64.txt',
 'legal/FEX-guest/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.winpthreads.txt': 'build/evidence/licenses/llvm-mingw/aarch64-w64-mingw32/share/mingw32/COPYING.winpthreads.txt',
 'legal/FEX-guest/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING': 'build/evidence/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING',
 'legal/FEX-guest/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.MinGW-w64-runtime.txt': 'build/evidence/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.MinGW-w64-runtime.txt',
 'legal/FEX-guest/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.MinGW-w64.txt': 'build/evidence/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.MinGW-w64.txt',
 'legal/FEX-guest/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.winpthreads.txt': 'build/evidence/licenses/llvm-mingw/arm64ec-w64-mingw32/share/mingw32/COPYING.winpthreads.txt'}
COPIES.update(NOTICE_COPIES)
FILES = frozenset(COPIES)
REQUIRED_NOTICES = tuple(sorted(NOTICE_COPIES))
SOURCE_INPUTS = ("build/fex-ios", "build/fex-arm64ec", "build/fex-wow64")
COUNTS = {
    "arm64ec": {"checked_import_symbols": 211, "checked_export_forwarders": 0, "exports": 30},
    "aarch64": {"checked_import_symbols": 216, "checked_export_forwarders": 0, "exports": 24},
}


def present(root):
    root = Path(root)
    return any(path.exists() or path.is_symlink() for path in
               [root / RECORD, root / RECEIPT, root / "app/Madeira/legal/FEX-guest"])


def seal(stage):
    result = planner.seal(stage, REVIEWED_SEAL)
    planner.require(len(result) == STAGE_FILES, "FEX evidence file count differs")
    return result


def record_contract(sealed):
    import verify_desktop_integration as desktop
    import verify_msi_integration as msi
    import verify_loader_integration as loader
    import verify_msi_startup_integration as startup
    return {"schema_version": 1, "receipt_directory": RECEIPT,
            "stage_seal_sha256": REVIEWED_SEAL, "fex_revision": FEX_REVISION,
            "actual_build_parent_revision": BUILD_PARENT,
            "repairs_manifest_sha256": REPAIRS_SHA256,
            "source_integration_binding": sealed["source-integration.json"],
            "historical_seals": {"desktop": desktop.REVIEWED_SEAL, "msi": msi.REVIEWED_SEAL,
                "loader": loader.REVIEWED_SEAL, "msi_client": client.REVIEWED_SEAL,
                "msi_startup": startup.REVIEWED_SEAL},
            "replacements": {name: {"before": BEFORE[name], "after": CANDIDATES[name]}
                             for name in sorted(BINARIES)},
            "files": {name: sealed[source] for name, source in sorted(COPIES.items())},
            "residual_dependency_counts": msi.RESIDUAL_COUNTS,
            "runtime_tested": False, "package_ready": False, "i386_activated": False,
            "rebuilt_at_integration_revision": False}


def check_pe(raw, before, arch, expected):
    """Check raw CHPE-aware architecture plus every named/ordinal import/export."""
    current = client.pe_contract(raw)
    planner.require(current["architecture"] == arch and
                    current["machine"] == ("0x8664" if arch == "arm64ec" else "0xaa64"),
                    "Wrong architecture or missing ARM64EC CHPE metadata in FEX replacement")
    planner.require(current == client.pe_contract(before) == expected,
                    "FEX architecture/import/export contract changed")
    exports = {name for row in current["exports"] for name in row["names"]}
    planner.require(len(current["exports"]) == COUNTS[arch]["exports"] and
                    ("BTCpu64IosAddAliasMapping" if arch == "arm64ec" else "BTCpuIosSetMonoBridge") in exports,
                    "Required iOS FEX exports missing")
    return current


def check_source(root, stage, sealed):
    root = Path(root)
    binding = planner.document(stage, "source-integration.json")
    planner.require(binding.get("actual_build_parent_revision") == BUILD_PARENT and
                    binding.get("rebuilt_at_integration_revision") is False and
                    binding.get("source_patch") == sealed["source-integration.patch"] and
                    binding.get("source_patch_manifest") == sealed["source-integration-original-manifest.json"] and
                    isinstance(binding.get("files"), dict) and binding["files"],
                    "FEX source integration is not bound to the actual earlier build")
    integrated = planner.document(stage, "source-integration-original-manifest.json")
    planner.require(integrated.get("base_revision") == BUILD_PARENT and
                    integrated.get("patch", {}).get("sha256") == binding["source_patch"]["sha256"] and
                    integrated.get("source_repair_manifest_sha256") == REPAIRS_SHA256,
                    "FEX original source integration patch receipt changed")
    for name, identity in binding["files"].items():
        planner.require(planner.identity(planner.safe_path(root, name)) == identity,
                        "FEX integrated source input changed: " + name)
    repairs = planner.document(stage, "build/source-repairs.json")
    planner.require(sealed["build/source-repairs.json"]["sha256"] == REPAIRS_SHA256 and
                    planner.identity(root / "build/fex-ios/source-repairs.json")["sha256"] == REPAIRS_SHA256 and
                    repairs.get("source_revision") == FEX_REVISION and len(repairs.get("repairs", [])) == 5,
                    "FEX pinned five-repair source manifest changed")
    snapshot = planner.document(stage, "build/evidence/patched-source-manifest.json")
    planner.require(snapshot["."]["revision"] == FEX_REVISION and len(snapshot) == 7 and
                    sum(len(item["files_sha256"]) for item in snapshot.values()) == 6871,
                    "FEX compiled source snapshot changed")
    for repair in repairs["repairs"]:
        name = repair["patch"]
        planner.require(planner.identity(planner.safe_path(root, name))["sha256"] == repair["patch_sha256"] ==
                        sealed["build/patches/" + Path(name).name]["sha256"], "FEX source repair patch changed")
        for entry in repair["files"]:
            planner.require(snapshot["."]["files_sha256"][entry["path"]] == entry["patched_sha256"],
                            "FEX compiled source differs from repair result")
    toolchain = planner.document(stage, "build/toolchain-complete.json")
    selected = planner.document(stage, "build/evidence/toolchain-extraction-verification.json")
    planner.require(toolchain.get("sha256") == TOOLCHAIN_SHA256 == selected.get("archive_sha256") and
                    len(toolchain.get("members", {})) == 8282,
                    "FEX complete toolchain provenance changed")
    for name, item in selected["verified_files"].items():
        planner.require(item.get("matches_official_archive") is True and
                        toolchain["members"][name]["sha256"] == item["sha256"],
                        "FEX compiler executable differs from full toolchain receipt")
    summary = planner.document(stage, "build/evidence/BUILD-SUMMARY.json")
    planner.require(summary.get("fex_revision") == FEX_REVISION and summary.get("parent_revision") == BUILD_PARENT and
                    summary.get("proposed_five_repairs_manifest_sha256") == REPAIRS_SHA256 and
                    summary.get("runtime_tested") is False and summary.get("primary_staged") is False,
                    "FEX actual build source provenance changed")
    for arch, kind, target, source_dir in (("arm64ec", "arm64ec", "arm64ecfex", "ARM64EC"),
                                          ("aarch64", "wow64", "wow64fex", "WOW64")):
        name = arch + "-windows/" + ("xtajit64.dll" if arch == "arm64ec" else "xtajit.dll")
        build = planner.document(stage, "build/evidence/" + kind + "-patched-full-build.json")
        probe = planner.document(stage, "build/evidence/" + kind + "-patched-probe.json")
        source_sha = snapshot["."]["files_sha256"]["Source/Windows/" + source_dir + "/Module.cpp"]
        configure = probe["commands"][0]
        flags = {"-DFEX_IOS_HOST_BUILD=ON", "-DCMAKE_C_FLAGS=-DFEX_IOS_HOST",
                 "-DCMAKE_CXX_FLAGS=-DFEX_IOS_HOST", "-DCMAKE_ASM_FLAGS=-DFEX_IOS_HOST",
                 "-DMINGW_TRIPLE=" + arch + "-w64-mingw32",
                 "-DENABLE_GUEST_WINDOW=" + ("OFF" if arch == "arm64ec" else "ON")}
        command = shlex.split(probe["module_compile_command"]["command"])
        planner.require(build.get("exit_code") == 0 and build.get("phase") == "patched" and
                        build.get("module_source_sha256") == source_sha == probe.get("source_sha256") and
                        probe.get("source_revision") == FEX_REVISION and probe.get("crt_ios_selected") is True and
                        all(item.get("exit_code") == 0 for item in probe["commands"]) and
                        configure.get("step") == "configure" and flags <= set(configure["argv"]) and
                        "-DFEX_IOS_HOST" in command and
                        any(x.startswith("-DFEX_GUEST_WINDOW") for x in command) is (arch == "aarch64") and
                        build["argv"][-3:] == ["--target", target, "--verbose"] and
                        {"bytes": build["dll"]["size"], "sha256": build["dll"]["sha256"]} == CANDIDATES[name] and
                        sealed["candidate/" + name] == CANDIDATES[name] and
                        sealed["preserved-original/" + name] == BEFORE[name],
                        "FEX actual configuration/source/output receipt changed")
        current = inventory.read_pe_bytes(planner.safe_path(stage, "candidate/" + name))
        before = inventory.read_pe_bytes(planner.safe_path(stage, "preserved-original/" + name))
        contract = check_pe(current, before, arch, planner.document(stage, arch + "-contract.json"))
        definition = "build/lib" + kind + "fex.def"
        source_definition = "Source/Windows/" + source_dir + "/lib" + kind + "fex.def"
        planner.require(sealed[definition]["sha256"] == snapshot["."]["files_sha256"][source_definition],
                        "FEX export definition differs from compiled source")
        lines = (stage / definition).read_text().split("EXPORTS", 1)[1].splitlines()
        required = {line.split(";", 1)[0].split()[0] for line in lines if line.split(";", 1)[0].strip()}
        if arch == "aarch64":
            required.add("BTCpuIosSetMonoBridge")
        planner.require({name for row in contract["exports"] for name in row["names"]} == required,
                        "FEX exports differ from pinned DEF plus the iOS-only WOW64 export")


def checked_reports(stage):
    reports = {}
    for arch in planner.ARCHES:
        name = "xtajit64.dll" if arch == "arm64ec" else "xtajit.dll"
        report = planner.document(stage, arch + "-inventory.json")
        audit = planner.document(stage, "audit/" + arch + "-symbol-audit.json")
        planner.require(not report["errors"] and not report["missing_required"] and
                        audit.get("architecture") == arch and audit.get("passed") is True and
                        audit.get("runtime_tested") is False and audit.get("issues") == [] and
                        audit.get("counts") == COUNTS[arch] and set(audit.get("modules", {})) == {name} and
                        audit.get("input_modules") == planner.identities(report["modules"]) and
                        planner.identities(audit["modules"]) == planner.identities({name: report["modules"][name]}),
                        "FEX symbol evidence does not bind the exact combined farm")
        reports[arch] = report
    return reports


def bind_reports(extension, baseline, arch):
    import verify_msi_integration as msi
    name = "xtajit64.dll" if arch == "arm64ec" else "xtajit.dll"
    key = arch + "-windows/" + name
    planner.require(planner.identities(baseline["modules"])[name] == {**BEFORE[key], "architecture": arch},
                    "FEX requires the exact historical provider precondition")
    planner.require(msi.contract(extension["baselines"][arch]) == msi.contract(baseline),
                    "FEX baseline is not the reviewed preceding full farm")
    expected = copy.deepcopy(baseline)
    expected["modules"][name].update(CANDIDATES[key])
    current = extension["combined"][arch]
    planner.require(msi.contract(current) == msi.contract(expected),
                    "FEX changes a module or graph beyond the fixed replacement")
    return current


def validate(root, resources, tracked):
    import verify_msi_startup_integration as startup
    root, tracked = Path(root), set(tracked)
    import verify_desktop_integration as desktop
    planner.require(desktop.git_output(root, "ls-tree", "HEAD", "FEX").split() ==
                    ["160000", "commit", FEX_REVISION, "FEX"], "FEX gitlink differs from compiled source pin")
    planner.require(RECORD in tracked and startup.present(root), "FEX requires tracked record and historical startup layer")
    stage = planner.safe_path(root, RECEIPT)
    sealed = seal(stage)
    planner.require({RECEIPT + "/" + name for name in (*sealed, "SHA256SUMS")} <= tracked,
                    "FEX receipt contains untracked evidence")
    planner.require(planner.document(root, RECORD) == record_contract(sealed),
                    "FEX integration record differs from exact reviewed replacement")
    check_source(root, stage, sealed)
    for name, source in COPIES.items():
        planner.require("app/Madeira/" + name in tracked, "FEX resource must be tracked: " + name)
        path = planner.safe_path(root / "app/Madeira", name)
        actual = planner.identity(path)
        planner.require(actual == sealed[source] and resources.get(name) == actual["sha256"],
                        "FEX resource differs from sealed replacement: " + name)
    combined = checked_reports(stage)
    planner.require(seal(stage) == sealed, "FEX evidence changed during verification")
    return {"combined": combined,
            "baselines": {arch: planner.document(stage, arch + "-baseline-inventory.json") for arch in planner.ARCHES},
            "summary": {"stage_seal_sha256": REVIEWED_SEAL, "fex_revision": FEX_REVISION,
                "repairs_manifest_sha256": REPAIRS_SHA256, "source_integration_binding": sealed["source-integration.json"],
                "replacement_count": 2, "evidence_files": len(sealed) + 1,
                "runtime_tested": False, "package_ready": False, "i386_activated": False}}
