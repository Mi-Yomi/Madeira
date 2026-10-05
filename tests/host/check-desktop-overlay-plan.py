#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only handoff regressions with synthetic PE bytes; no guest/tool execution."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import plan_desktop_overlay as planner


def pe(arch, imports=(), forwards=()):
    data = bytearray(0x2200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0xaa64 if arch == "aarch64" else 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 240)
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<Q", data, 0x98 + 24, 0x180000000)
    struct.pack_into("<I", data, 0x98 + 60, 0x200)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<8sIIII", data, 0x98 + 240, b".rdata", 0x2000, 0x1000, 0x2000, 0x200)
    def rva(offset):
        return offset + 0xe00
    if imports:
        struct.pack_into("<II", data, 0x98 + 112 + 8, rva(0x300), (len(imports) + 1) * 20)
        cursor = 0x500
        for i, name in enumerate(imports):
            struct.pack_into("<I", data, 0x300 + i * 20 + 12, rva(cursor))
            encoded = name.encode() + b"\0"
            data[cursor:cursor + len(encoded)] = encoded
            cursor += len(encoded)
    if forwards:
        struct.pack_into("<II", data, 0x98 + 112, rva(0x700), 0x200)
        struct.pack_into("<I", data, 0x700 + 20, len(forwards))
        struct.pack_into("<I", data, 0x700 + 28, rva(0x740))
        cursor = 0x780
        for i, name in enumerate(forwards):
            struct.pack_into("<I", data, 0x740 + i * 4, rva(cursor))
            encoded = name.encode() + b"\0"
            data[cursor:cursor + len(encoded)] = encoded
            cursor += len(encoded)
    if arch == "arm64ec":
        struct.pack_into("<II", data, 0x98 + 112 + 10 * 8, rva(0xa00), 208)
        struct.pack_into("<I", data, 0xa00, 208)
        struct.pack_into("<Q", data, 0xa00 + 200, 0x180000000 + rva(0xb00))
        struct.pack_into("<I", data, 0xb00, 2)
    return bytes(data)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else value.encode())


def write_json(path, value):
    write(path, json.dumps(value, sort_keys=True) + "\n")


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


class OverlayPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="madeira-overlay-plan-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage, self.bundle = self.root / "stage", self.root / "bundle"
        self.manifest = planner.inventory.manifest()
        self.pin = self.manifest["wine_revision"]
        write_json(self.stage / "rebuild-inputs/build/wine-pe/desktop-components.json", self.manifest)
        write(self.stage / "rebuild-inputs/THIRD-PARTY-NOTICES.md", "corrected Wine branch notice")
        source = {"schema_version": 1, "wine_revision": self.pin, "wine_tracked_sources_clean": True,
                  "recipe_inputs": {}, "wine_files": {}}
        for name in ("THIRD-PARTY-NOTICES.md", "build/wine-pe/desktop-components.json"):
            source["recipe_inputs"][name] = planner.identity(self.stage / "rebuild-inputs" / name)
        for original, destination in planner.LICENSES.items():
            write(self.stage / "licenses" / destination, "exact source notice " + original)
            source["wine_files"][original] = planner.identity(self.stage / "licenses" / destination)
        write(self.stage / "licenses/Madeira-THIRD-PARTY-NOTICES.md", "corrected Wine branch notice")
        write_json(self.stage / "source-inputs.json", source)
        write_json(self.stage / "toolchain-receipt.json", {"fixture": True})
        write(self.stage / "SOURCE-REBUILD.md", "Keep corresponding source and exact rebuild inputs")
        self.provenance = {"wine_revision": self.pin, "staged_only": True, "runtime_tested": False,
                           "recipe": {"profile": "desktop", "wine_revision": self.pin,
                                      "architectures": [{"arch": arch} for arch in planner.ARCHES]}}
        write_json(self.stage / "provenance.json", self.provenance)
        for arch in planner.ARCHES:
            write(self.bundle / (arch + "-windows/kernel32.dll"), pe(arch))
            # A pre-existing unresolved forwarder must remain visible, not be
            # mistaken for a new overlay gap or hidden by a blanket success.
            write(self.bundle / (arch + "-windows/old.dll"), pe(arch, forwards=("preexisting.Func",)))
            for name in sorted(planner.NAMES):
                imports = ("kernel32.dll", "msvfw32.dll") if name == "avifil32.dll" else ("kernel32.dll",)
                forwards = ("riched20.RichEdit10ANSIWndProc",) if name == "msftedit.dll" else ()
                write(self.stage / (arch + "-windows") / name, pe(arch, imports, forwards))
                write(self.stage / f"readobj/{arch}-{name[:-4]}.txt", "synthetic evidence; never executed")
            write(self.stage / (arch + "-build.log"), "synthetic build log")
            self.record_farm(arch)
        write(self.bundle / "legal/THIRD-PARTY-NOTICES.md", "original stale notice preserved")
        write(self.bundle / "legal/UNRELATED.txt", "unrelated original remains unchanged")
        self.reseal()

    def record_farm(self, arch):
        report = planner.inventory.audit_farm(self.bundle / (arch + "-windows"), arch, planner.NAMES,
                                              self.stage / (arch + "-windows"))
        write_json(self.stage / (arch + "-inventory.json"), report)
        symbols = {"architecture": arch, "passed": True, "issues": [],
                   "input_modules": planner.identities(report["modules"]),
                   "modules": {n: report["modules"][n] for n in planner.NAMES if n in report["modules"]}}
        write_json(self.stage / (arch + "-symbol-audit.json"), symbols)

    def reseal(self):
        hashes = tree_hashes(self.stage)
        hashes.pop("SHA256SUMS", None)
        write(self.stage / "SHA256SUMS", "".join(f"{value}  {name}\n" for name, value in sorted(hashes.items())))
        self.expected = planner.identity(self.stage / "SHA256SUMS")["sha256"]

    def run_plan(self):
        return planner.plan(self.stage, self.bundle, self.expected, self.pin)

    def refused(self):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            self.run_plan()

    def test_read_only_pair_and_rollback_plan(self):
        before = tree_hashes(self.root)
        value = self.run_plan()
        self.assertEqual(tree_hashes(self.root), before)
        self.assertTrue(value["read_only"])
        self.assertFalse(value["package_ready"])
        self.assertEqual(len(value["proposed_files"]), 16)
        self.assertEqual(sum(p["before"] is None for p in value["proposed_files"]), 16)
        self.assertEqual(len(value["blocking_notice_merges"]), 1)
        self.assertEqual([len(a["residual_dependencies"]) for a in value["architectures"]], [1, 1])
        self.assertTrue(all(not a["new_module_direct_dependency_gaps"] for a in value["architectures"]))

    def test_changed_seal(self):
        self.expected = "0" * 64
        self.refused()

    def test_tampered_dll_without_reseal(self):
        write(self.stage / "aarch64-windows/sensapi.dll", pe("x86_64"))
        self.refused()

    def test_unlisted_stage_file(self):
        write(self.stage / "extra.txt", "not listed")
        self.refused()

    def test_duplicate_checksum_entry(self):
        index = self.stage / "SHA256SUMS"
        write(index, index.read_text() + index.read_text().splitlines()[0] + "\n")
        self.expected = planner.identity(index)["sha256"]
        self.refused()

    def test_path_traversal_index(self):
        write(self.stage / "SHA256SUMS", "0" * 64 + "  ../outside\n")
        self.expected = planner.identity(self.stage / "SHA256SUMS")["sha256"]
        self.refused()

    def test_symlink_stage_directory(self):
        (self.stage / "alias").symlink_to(self.stage / "licenses", target_is_directory=True)
        self.refused()

    def test_foreign_architecture(self):
        write(self.stage / "aarch64-windows/sensapi.dll", pe("arm64ec"))
        self.reseal()
        self.refused()

    def test_arm64ec_requires_chpe_not_plain_x64(self):
        write(self.stage / "arm64ec-windows/sensapi.dll", pe("x86_64"))
        self.reseal()
        self.refused()

    def test_peer_architecture_cannot_fill_missing_component(self):
        (self.stage / "aarch64-windows/riched20.dll").unlink()
        self.reseal()
        self.refused()

    def test_protected_extra_dll(self):
        write(self.stage / "aarch64-windows/ntdll.dll", pe("aarch64"))
        self.reseal()
        self.refused()

    def test_changed_same_arch_dependency(self):
        write(self.bundle / "aarch64-windows/kernel32.dll", pe("aarch64", imports=("new.dll",)))
        self.refused()

    def test_changed_base_rejected_before_pe_parser(self):
        path = self.bundle / "aarch64-windows/kernel32.dll"
        data = bytearray(path.read_bytes()); data[-1] = 1; write(path, bytes(data))
        with mock.patch.object(planner.inventory, "audit_farm", side_effect=AssertionError("must not parse changed bytes")):
            self.refused()

    def test_scandir_budget_does_not_call_eager_listdir(self):
        with mock.patch.object(planner.os, "listdir", side_effect=AssertionError("eager listdir")):
            with self.assertRaisesRegex(ValueError, "entry budget"):
                planner.children(self.bundle / "aarch64-windows", 1)

    def test_missing_same_arch_dependency_not_filled_by_peer(self):
        (self.bundle / "aarch64-windows/kernel32.dll").unlink()
        self.refused()

    def test_existing_casefold_collision_requires_review(self):
        write(self.bundle / "aarch64-windows/SENSAPI.DLL", pe("aarch64"))
        self.refused()

    def test_farm_root_symlink(self):
        farm = self.bundle / "aarch64-windows"
        farm.rename(self.bundle / "real-farm")
        farm.symlink_to(self.bundle / "real-farm", target_is_directory=True)
        self.refused()

    def test_wrong_gitlink_pin(self):
        self.pin = "0" * 40
        self.refused()

    def test_single_architecture_receipt(self):
        self.provenance["recipe"]["architectures"].pop()
        write_json(self.stage / "provenance.json", self.provenance)
        self.reseal()
        self.refused()

    def test_reverse_build_order_still_pairs_exact_architectures(self):
        self.provenance["recipe"]["architectures"].reverse()
        write_json(self.stage / "provenance.json", self.provenance)
        self.reseal()
        self.assertEqual(len(self.run_plan()["proposed_files"]), 16)

    def test_duplicate_architecture_receipt(self):
        self.provenance["recipe"]["architectures"] = [{"arch": "aarch64"}] * 2
        write_json(self.stage / "provenance.json", self.provenance)
        self.reseal()
        self.refused()

    def test_unreviewed_manifest_expansion(self):
        self.manifest["profiles"]["desktop"].append("ntdll")
        write_json(self.stage / "rebuild-inputs/build/wine-pe/desktop-components.json", self.manifest)
        self.reseal()
        self.refused()

    def test_new_dependency_gap_even_when_recorded(self):
        write(self.stage / "aarch64-windows/sensapi.dll", pe("aarch64", imports=("new-missing.dll",)))
        self.record_farm("aarch64")
        self.reseal()
        self.refused()

    def test_failed_symbol_report(self):
        path = self.stage / "arm64ec-symbol-audit.json"
        audit = json.loads(path.read_text()); audit["passed"] = False
        write_json(path, audit); self.reseal(); self.refused()

    def test_symbol_inputs_disagree_with_inventory(self):
        path = self.stage / "arm64ec-symbol-audit.json"
        audit = json.loads(path.read_text()); audit["input_modules"]["kernel32.dll"]["sha256"] = "0" * 64
        write_json(path, audit); self.reseal(); self.refused()

    def test_missing_llvm_evidence(self):
        (self.stage / "readobj/aarch64-sensapi.txt").unlink()
        self.reseal(); self.refused()

    def test_missing_source_notice(self):
        (self.stage / "licenses/Wine-compiler-rt-LICENSE.txt").unlink()
        self.reseal(); self.refused()

    def test_notice_bytes_do_not_match_source_receipt(self):
        write(self.stage / "licenses/Wine-compiler-rt-LICENSE.txt", "substituted newer LLVM license")
        self.reseal(); self.refused()

    def test_target_specific_notices_cannot_be_replaced(self):
        path = self.bundle / "legal/THIRD-PARTY-NOTICES.md"
        write(path, path.read_text() + "\nNew target component notice and bundle-local link")
        result = self.run_plan()
        self.assertEqual(result["blocking_notice_merges"][0]["current"], planner.identity(path))
        self.assertFalse(any(p["destination"] == "legal/THIRD-PARTY-NOTICES.md" for p in result["proposed_files"]))

    def test_absent_bundle_notice_still_requires_path_adaptation(self):
        (self.bundle / "legal/THIRD-PARTY-NOTICES.md").unlink()
        result = self.run_plan()
        self.assertIsNone(result["blocking_notice_merges"][0]["current"])
        self.assertFalse(any(p["destination"] == "legal/THIRD-PARTY-NOTICES.md" for p in result["proposed_files"]))

    def test_source_identical_bundle_notice_still_needs_path_review(self):
        write(self.bundle / "legal/THIRD-PARTY-NOTICES.md", (self.stage / "licenses/Madeira-THIRD-PARTY-NOTICES.md").read_bytes())
        self.assertEqual(len(self.run_plan()["blocking_notice_merges"]), 1)

    def test_identical_existing_notice_is_preserved_as_noop(self):
        path = self.bundle / "legal/Wine-LGPL-2.1.txt"
        write(path, (self.stage / "licenses/Wine-LGPL-2.1.txt").read_bytes())
        result = self.run_plan()
        self.assertIn("legal/Wine-LGPL-2.1.txt", result["unchanged_notices"])
        self.assertFalse(any(p["destination"] == "legal/Wine-LGPL-2.1.txt" for p in result["proposed_files"]))

    def test_destination_notice_symlink(self):
        target = self.bundle / "legal/THIRD-PARTY-NOTICES.md"
        target.unlink(); target.symlink_to(self.bundle / "legal/UNRELATED.txt")
        self.refused()

    def test_duplicate_json_key(self):
        write(self.stage / "source-inputs.json", '{"schema_version": 1, "schema_version": 1}')
        self.reseal(); self.refused()

    def test_stage_budget(self):
        with mock.patch.object(planner, "MAX_FILES", 3):
            self.refused()

    def test_farm_enumeration_budget(self):
        with mock.patch.object(planner.inventory, "MAX_FARM_FILES", 1):
            self.refused()

    def test_no_stage_tool_execution(self):
        with mock.patch.object(planner.subprocess, "check_output", side_effect=AssertionError("unexpected process")):
            self.run_plan()


if __name__ == "__main__":
    unittest.main(verbosity=2)
