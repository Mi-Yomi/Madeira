#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Actual local FEX pair, historical farms, and fail-closed mutation regressions."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import plan_desktop_overlay as planner
import verify_fex_integration as fex
import verify_desktop_integration as desktop
import verify_msi_integration as msi
import verify_loader_integration as loader
import verify_msi_client_integration as client
import verify_msi_startup_integration as startup
spec = importlib.util.spec_from_file_location("fex_app_gate", ROOT / "build/app-ios/build_unsigned.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FexReplacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="madeira-fex-replacement-")
        cls.root = Path(cls.tmp.name)
        subprocess.check_call(["git", "init", "-q"], cwd=cls.root)
        subprocess.check_call(["git", "update-index", "--add", "--cacheinfo", "160000," + fex.FEX_REVISION + ",FEX"], cwd=cls.root)
        subprocess.check_call(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "Pinned FEX fixture"], cwd=cls.root)
        for folder in (*gate.RESOURCE_DIRS, "x86_64-vcruntime"):
            (cls.root / "app/Madeira" / folder).mkdir(parents=True, exist_ok=True)
        cls.tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=True).split("\0")
        # One isolated real-file fixture; each mutation below restores its bytes.
        needed = [name for name in cls.tracked if name.startswith(("app/Madeira/", "build/wine-pe/receipts/"))
                  or name in (desktop.RECORD, msi.RECORD, loader.RECORD, client.RECORD, startup.RECORD, fex.RECORD)]
        binding = planner.document(ROOT / fex.RECEIPT, "source-integration.json")
        needed += list(binding["files"])
        for name in set(needed):
            src, dst = ROOT / name, cls.root / name
            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(src, dst)
        for target, source in gate.GENERATED_LICENSES.items():
            dst = cls.root / source; dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, dst)
            dst = cls.root / "app/Madeira" / target; dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source, dst)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def resources(self):
        return {name: planner.identity(self.root / "app/Madeira" / name)["sha256"]
                for name in fex.FILES if (self.root / "app/Madeira" / name).exists()}

    def check(self):
        return fex.validate(self.root, self.resources(), self.tracked)

    @contextlib.contextmanager
    def changed(self, name, data):
        path = self.root / name
        original = path.read_bytes() if path.exists() else None
        if data is None:
            path.unlink()
        else:
            path.write_bytes(data)
        try:
            yield path
        finally:
            if original is None: path.unlink(missing_ok=True)
            else: path.write_bytes(original)

    def test_complete_corresponding_source_archive_matches_every_manifest_file(self):
        stage = self.root / fex.RECEIPT
        snapshot = planner.document(stage, "build/evidence/patched-source-manifest.json")
        expected = {(Path(sub) / name).as_posix(): sha for sub, item in snapshot.items()
                    for name, sha in item["files_sha256"].items()}
        found = {}
        with tarfile.open(stage / "build/corresponding-source.tar.gz", "r:gz") as tar:
            for item in tar:
                self.assertTrue(item.isfile())
                self.assertNotIn(item.name, found)
                self.assertEqual((item.uid, item.gid, item.mtime), (0, 0, 0))
                found[item.name] = hashlib.sha256(tar.extractfile(item).read()).hexdigest()
        self.assertEqual(len(found), 6871)
        self.assertEqual(found, expected)

    def test_wrong_current_fex_source_pin_is_refused(self):
        with mock.patch.object(desktop, "git_output", return_value="160000 commit " + "0" * 40 + " FEX"):
            with self.assertRaisesRegex(ValueError, "FEX gitlink differs"):
                self.check()

    def test_actual_full_combined_farms_and_unchanged_historical_seals(self):
        ext = self.check()
        for module in (desktop, msi, loader, client, startup):
            if module is client:
                client.seal(self.root / module.RECEIPT)
            else:
                planner.seal(self.root / module.RECEIPT, module.REVIEWED_SEAL)
        resources = {name.removeprefix("app/Madeira/"): hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                     for name in self.tracked if name.startswith("app/Madeira/") and (self.root / name).is_file()}
        with mock.patch.object(desktop, "wine_gitlink"):
            result = desktop.validate(self.root, resources, self.tracked)
        self.assertEqual(result["current_dependency_counts"], {"aarch64": 13, "arm64ec": 10})
        self.assertEqual(result["fex"], ext["summary"])
        self.assertFalse(result["runtime_tested"])

    def test_both_copied_outputs_and_every_supplement_required(self):
        for name in sorted(fex.FILES):
            with self.subTest(name=name), self.changed("app/Madeira/" + name, None):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.check()

    def test_byte_tamper_in_each_copied_dll_is_refused(self):
        for name in fex.BINARIES:
            p = self.root / "app/Madeira" / name
            with self.subTest(name=name), self.changed("app/Madeira/" + name, p.read_bytes() + b"X"):
                with self.assertRaisesRegex(ValueError, "FEX resource differs"):
                    self.check()

    def test_manifest_unknown_replacement_and_source_relabel_refused(self):
        original = planner.document(self.root, fex.RECORD)
        mutations = [lambda d: d["replacements"].update({"aarch64-windows/kernel32.dll": {}}),
                     lambda d: d.update(actual_build_parent_revision="0" * 40),
                     lambda d: d.update(rebuilt_at_integration_revision=True),
                     lambda d: d.update(runtime_tested=True),
                     lambda d: d.update(i386_activated=True),
                     lambda d: d.update(stage_seal_sha256="0" * 64)]
        for mutate in mutations:
            record = copy.deepcopy(original); mutate(record)
            with self.changed(fex.RECORD, json.dumps(record).encode()):
                with self.assertRaisesRegex(ValueError, "exact reviewed replacement"):
                    self.check()

    def test_missing_or_untracked_receipt_and_output_refused(self):
        for name in (fex.RECORD, fex.RECEIPT + "/build/corresponding-source.tar.gz",
                     "app/Madeira/arm64ec-windows/xtajit64.dll"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "tracked|untracked"):
                    fex.validate(self.root, self.resources(), set(self.tracked) - {name})

    def test_pinned_source_manifest_patch_and_integrated_recipe_tamper(self):
        binding = planner.document(self.root / fex.RECEIPT, "source-integration.json")
        selected = ["build/fex-ios/source-repairs.json", "build/fex-ios/patches/0005-wow64-smc-write-fault-only.patch",
                    "build/fex-arm64ec/build.sh", "build/fex-wow64/build.sh"]
        self.assertTrue(set(selected) <= binding["files"].keys())
        for name in selected:
            with self.subTest(name=name), self.changed(name, (self.root / name).read_bytes() + b"\n"):
                with self.assertRaisesRegex(ValueError, "source input changed"):
                    self.check()

    def test_evidence_tamper_and_self_reseal_cannot_change_trust_anchor(self):
        name = fex.RECEIPT + "/build/evidence/BUILD-SUMMARY.json"
        with self.changed(name, (self.root / name).read_bytes() + b"\n"):
            with self.assertRaisesRegex(ValueError, "checksum index"):
                self.check()
            seal_name = fex.RECEIPT + "/SHA256SUMS"
            sums = (self.root / seal_name).read_text()
            old = planner.document(ROOT / fex.RECEIPT, "build/evidence/BUILD-SUMMARY.json")
            del old  # The seal, not a mutable success field, anchors the receipt.
            original_hash = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            changed_hash = planner.identity(self.root / name)["sha256"]
            with self.changed(seal_name, sums.replace(original_hash, changed_hash).encode()):
                with self.assertRaisesRegex(ValueError, "reviewed stage seal"):
                    self.check()

    def test_wrong_architecture_chpe_import_and_export_changes_refused(self):
        stage = self.root / fex.RECEIPT
        for arch, name in (("arm64ec", "xtajit64.dll"), ("aarch64", "xtajit.dll")):
            raw = (stage / "candidate" / (arch + "-windows") / name).read_bytes()
            before = (stage / "preserved-original" / (arch + "-windows") / name).read_bytes()
            expected = planner.document(stage, arch + "-contract.json")
            fex.check_pe(raw, before, arch, expected)
            bad = bytearray(raw); offset = struct.unpack_from("<I", raw, 0x3c)[0]
            struct.pack_into("<H", bad, offset + 4, 0x14c)
            with self.assertRaisesRegex(ValueError, "Wrong architecture"):
                fex.check_pe(bytes(bad), before, arch, expected)
            if arch == "arm64ec":
                pe = fex.inventory.PE(raw); lc, _ = pe.directory(10)
                bad = bytearray(raw); struct.pack_into("<Q", bad, pe.rva(lc, 208) + 200, 0)
                with self.assertRaisesRegex(ValueError, "Wrong architecture"):
                    fex.check_pe(bytes(bad), before, arch, expected)
            for old in (b"NtAllocateVirtualMemory\0", b"BTCpu64IosAddAliasMapping\0" if arch == "arm64ec" else b"BTCpuIosSetMonoBridge\0"):
                self.assertIn(old, raw)
                bad = raw.replace(old, b"X" + old[1:])
                with self.assertRaisesRegex(ValueError, "import/export contract"):
                    fex.check_pe(bad, before, arch, expected)

    def test_unknown_farm_replacement_and_graph_edit_refused(self):
        ext = self.check()
        baseline = ext["baselines"]["aarch64"]
        fex.bind_reports(ext, baseline, "aarch64")
        for name in ("kernel32.dll", "xtajit.dll"):
            changed = copy.deepcopy(ext)
            changed["combined"]["aarch64"]["modules"][name]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "beyond the fixed replacement"):
                fex.bind_reports(changed, baseline, "aarch64")
        changed = copy.deepcopy(ext); changed["combined"]["aarch64"]["missing_dependencies"] = []
        with self.assertRaisesRegex(ValueError, "beyond the fixed replacement"):
            fex.bind_reports(changed, baseline, "aarch64")

    def test_symbol_audit_bound_to_every_actual_farm_input(self):
        stage = self.root / fex.RECEIPT
        name = fex.RECEIPT + "/audit/aarch64-symbol-audit.json"
        report = planner.document(stage, "audit/aarch64-symbol-audit.json")
        report["input_modules"]["kernel32.dll"]["sha256"] = "0" * 64
        with self.changed(name, json.dumps(report).encode()):
            with self.assertRaisesRegex(ValueError, "exact combined farm"):
                fex.checked_reports(stage)

    def test_app_receipt_explicit_fex_and_i386_refusal(self):
        with mock.patch.object(gate, "ROOT", self.root), mock.patch.object(gate, "git", return_value="\0".join(self.tracked)), mock.patch.object(desktop, "wine_gitlink"):
            resources, pe = gate.resource_inputs()
            receipt = gate.guest_pe_evidence(pe)
            self.assertEqual(receipt["fex"]["stage_seal_sha256"], fex.REVIEWED_SEAL)
            self.assertEqual(receipt["fex"]["source_built_sha256"], {n: v["sha256"] for n, v in fex.CANDIDATES.items()})
            self.assertFalse(receipt["fex"]["rebuilt_at_integration_revision"])
            self.assertTrue(set(fex.REQUIRED_NOTICES) <= resources.keys())
            path = "app/Madeira/i386-windows/unapproved.dll"
            (self.root / path).parent.mkdir(exist_ok=True)
            with self.changed(path, (self.root / "app/Madeira/aarch64-windows/xtajit.dll").read_bytes()), mock.patch.object(gate, "git", return_value="\0".join([*self.tracked, path])):
                with self.assertRaisesRegex(ValueError, "unverified 32-bit runtime"):
                    gate.resource_inputs()


if __name__ == "__main__":
    unittest.main()
