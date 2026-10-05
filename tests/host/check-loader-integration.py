#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Host-only fixed loader integration mutations. No guests or app builds."""
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import plan_desktop_overlay as planner
import verify_desktop_integration as desktop
import verify_msi_integration as msi
import verify_loader_integration as loader
import plan_loader_integration as handoff

spec = importlib.util.spec_from_file_location("loader_msi_fixtures", ROOT / "tests/host/check-msi-integration.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
gate = fixtures.gate


class LoaderIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.MsiIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.app = self.fixture.root, self.fixture.app
        self.git, self.commit = self.fixture.git, self.fixture.commit
        shutil.copytree(ROOT / loader.RECEIPT, self.root / loader.RECEIPT)
        for name, source in loader.COPIES.items():
            shutil.copyfile(self.root / loader.RECEIPT / source, self.app / name)
        shutil.copyfile(ROOT / "app/Madeira" / loader.INTEGRATION_NOTICE, self.app / loader.INTEGRATION_NOTICE)
        shutil.copyfile(ROOT / loader.RECORD, self.root / loader.RECORD)
        self.record = planner.document(self.root, loader.RECORD)
        self.commit()

    def full_farms(self):
        self.fixture.full_farms()
        for name in loader.BINARIES:
            shutil.copyfile(self.root / loader.RECEIPT / loader.COPIES[name], self.app / name)
        self.commit()

    def check(self, full=False):
        return self.fixture.check(full=full)

    def refused(self, pattern=".+", full=False):
        with self.assertRaisesRegex(ValueError, pattern):
            self.check(full)

    def write_record(self):
        (self.root / loader.RECORD).write_text(json.dumps(self.record, sort_keys=True) + "\n")

    def reseal(self):
        stage = self.root / loader.RECEIPT
        index = stage / "SHA256SUMS"
        index.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(stage).as_posix()}\n"
                                 for p in sorted(stage.rglob("*")) if p.is_file() and p != index))
        seal = hashlib.sha256(index.read_bytes()).hexdigest()
        self.record["stage_seal_sha256"] = seal
        self.write_record(); self.commit()
        return seal

    def test_complete_pair_preserves_both_original_seals_and_farms(self):
        self.full_farms()
        before = fixtures.pe_tests.tree_hashes(self.app)
        resources, binaries = self.check(full=True)
        self.assertTrue(loader.BINARIES <= binaries.keys())
        self.assertTrue(set(loader.REQUIRED_NOTICES) <= resources.keys())
        self.assertFalse(any(n.startswith("i386-windows/") for n in binaries))
        self.assertEqual(before, fixtures.pe_tests.tree_hashes(self.app))
        for module, count in ((desktop, 54), (msi, 108), (loader, 59)):
            self.assertEqual(len(planner.seal(self.root / module.RECEIPT, module.REVIEWED_SEAL)), count)
        self.assertEqual(len(planner.seal(self.root / loader.RECEIPT / "build", loader.BUILD_SEAL)), 54)

    def test_every_unique_resource_required_even_after_index_removal(self):
        for name in sorted(loader.FILES - msi.FILES - set(desktop.COPIES)):
            with self.subTest(name=name):
                path = self.app / name; raw = path.read_bytes()
                self.git("rm", "--cached", "--", "app/Madeira/" + name); path.unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.check()
                path.write_bytes(raw); self.git("add", "--", "app/Madeira/" + name)

    def test_manifest_cannot_authorize_substituted_provider(self):
        name = "aarch64-windows/avicap32.dll"
        path = self.app / name; raw = bytearray(path.read_bytes()); raw[-1] ^= 1; path.write_bytes(raw)
        self.record["files"][name] = planner.identity(path)
        self.write_record(); self.commit(); self.refused("differs from sealed build")

    def test_untracked_provider_record_or_source_evidence_refused(self):
        for name in ["app/Madeira/arm64ec-windows/activeds.dll", loader.RECORD,
                     loader.RECEIPT + "/build/evidence/source-inputs.json",
                     loader.RECEIPT + "/aarch64-symbol-audit.json"]:
            with self.subTest(name=name):
                self.git("rm", "--cached", "--", name); self.refused()
                self.git("add", "--", name)

    def test_changed_or_extra_receipt_content_refused(self):
        stage = self.root / loader.RECEIPT
        path = stage / "build/SOURCE-REBUILD.md"
        raw = path.read_bytes(); path.write_bytes(raw + b"changed\n")
        self.commit(); self.refused("checksum index")
        path.write_bytes(raw); (stage / "unexpected.txt").write_text("unchecked")
        self.commit(); self.refused("checksum index")

    def test_wrong_architecture_beyond_hash_validation(self):
        # This adversarial fixture bypasses only the fixed source/hash anchor
        # to exercise the separate PE architecture gate. Production never does.
        for arch, wrong in (("aarch64", "arm64ec"), ("arm64ec", "x86_64")):
            with self.subTest(arch=arch):
                name = arch + "-windows/avicap32.dll"
                target, staged = self.app / name, self.root / loader.RECEIPT / loader.COPIES[name]
                raw = target.read_bytes(); target.write_bytes(fixtures.pe_tests.pe(wrong))
                staged.write_bytes(target.read_bytes()); self.record["files"][name] = planner.identity(target)
                seal = self.reseal()
                with mock.patch.object(loader, "REVIEWED_SEAL", seal), mock.patch.object(loader, "check_source"):
                    self.refused("Wrong architecture")
                target.write_bytes(raw); staged.write_bytes(raw)
                self.record["files"][name] = planner.identity(target)

    def test_read_substitution_refused_before_pe_parser(self):
        resources = {name: planner.identity(self.app / name)["sha256"] for name in loader.FILES}
        tracked = self.git("ls-files", "-z").split("\0")
        with mock.patch.object(loader.inventory, "read_pe_bytes", return_value=b"MZ substitution"), \
                mock.patch.object(loader.inventory, "PE") as parser:
            with self.assertRaisesRegex(ValueError, "changed before architecture parsing"):
                loader.validate(self.root, resources, tracked)
            parser.assert_not_called()

    def test_i386_resources_stay_rejected(self):
        for name in ("AVICAP32.DLL", "ACTIVEDS.DlL", "DRIVER.SYS"):
            path = self.app / "i386-windows" / name
            path.write_bytes((self.app / "aarch64-windows/avicap32.dll").read_bytes())
            self.commit(); self.refused("unverified 32-bit runtime")
            path.unlink(); self.commit()

    def test_arbitrary_addition_case_collision_and_core_change_refused(self):
        self.full_farms()
        for name in ("arbitrary.dll", "AVICAP32.DLL"):
            path = self.app / "aarch64-windows" / name
            path.write_bytes((self.app / "aarch64-windows/avicap32.dll").read_bytes())
            self.commit(); self.refused("Case-colliding|module set differs", full=True)
            path.unlink(); self.commit()
        target = self.app / "arm64ec-windows/kernel32.dll"
        raw = bytearray(target.read_bytes()); raw[-1] ^= 1; target.write_bytes(raw)
        self.commit(); self.refused("before PE parsing", full=True)

    def test_combined_audit_requires_all_input_modules_and_counts(self):
        stage = self.root / loader.RECEIPT
        for relative, mutate in [
            ("aarch64-symbol-audit.json", lambda d: d["input_modules"].pop("ntdll.dll")),
            ("aarch64-symbol-audit.json", lambda d: d["counts"].update(checked_import_symbols=85)),
            ("aarch64-symbol-audit.json", lambda d: d.update(passed=False)),
            ("build/evidence/aarch64-inventory.json", lambda d: d["missing_dependencies"].pop())]:
            with self.subTest(path=relative):
                path = stage / relative; raw = path.read_bytes(); data = json.loads(raw)
                mutate(data); path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): loader.checked_reports(stage)
                path.write_bytes(raw)

    def test_both_historical_and_msi_baselines_are_bound(self):
        extension = loader.checked_reports(self.root / loader.RECEIPT)
        original = planner.document(self.root / desktop.RECEIPT, "aarch64-inventory.json")
        _, baselines = msi.checked_reports(self.root / msi.RECEIPT)
        baseline = baselines["aarch64"]
        self.assertEqual(loader.bind_reports(extension, original, baseline, "aarch64"), extension["combined"]["aarch64"])
        for field in ("historical", "combined"):
            modified = json.loads(json.dumps(extension)); modified[field]["aarch64"]["modules"]["kernel32.dll"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError): loader.bind_reports(modified, original, baseline, "aarch64")
        modified = json.loads(json.dumps(extension)); modified["combined"]["aarch64"]["missing_dependencies"].pop()
        with self.assertRaises(ValueError): loader.bind_reports(modified, original, baseline, "aarch64")

    def test_partial_integration_cannot_disable_detection(self):
        self.git("rm", "--cached", "--", loader.RECORD); (self.root / loader.RECORD).unlink()
        self.assertTrue(loader.present(self.root)); self.refused("record must be tracked")

    def test_symlink_provider_and_notice_refused(self):
        for name in ("aarch64-windows/activeds.dll", "legal/Wine-loader-SOURCE-REBUILD.md"):
            path = self.app / name; raw = path.read_bytes(); path.unlink()
            path.symlink_to(self.root / loader.RECEIPT / loader.COPIES[name]); self.refused("special file|unsafe|symlink")
            path.unlink(); path.write_bytes(raw)

    def test_source_and_pin_contract_cannot_be_changed(self):
        stage = self.root / loader.RECEIPT
        path = stage / "build/evidence/source-inputs.json"; data = json.loads(path.read_text())
        data["wine_revision"] = "0" * 40; path.write_text(json.dumps(data))
        self.refused("checksum index")
        self.git("update-index", "--cacheinfo", "160000," + "1" * 40 + ",wine")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-q", "-m", "Wrong pin")
        self.refused("Wine gitlink")

    def planning_target(self):
        self.fixture.full_farms()
        for name in loader.FILES - msi.FILES - set(desktop.COPIES):
            (self.app / name).unlink(missing_ok=True)
        shutil.rmtree(self.root / loader.RECEIPT); (self.root / loader.RECORD).unlink()
        self.commit()
        return self.root

    def test_plan_is_read_only_exact_and_add_only(self):
        target = self.planning_target(); before = fixtures.pe_tests.tree_hashes(target / "app")
        plan = handoff.plan(ROOT / loader.RECEIPT, target)
        self.assertEqual(before, fixtures.pe_tests.tree_hashes(target / "app"))
        self.assertEqual(len(plan["operations"]), 65)
        self.assertEqual(len(plan["preserved_notices"]), 3)
        self.assertTrue(all(op["before"] is None for op in plan["operations"]))
        self.assertEqual(plan["new_app_providers"], 4)
        self.assertFalse(any(op["destination"].startswith("app/Madeira/i386-windows/") for op in plan["operations"]))

    def test_plan_refuses_partial_copy_untracked_nonpe_and_notice_change(self):
        target = self.planning_target()
        for relative, content in [("aarch64-windows/avicap32.dll", b"occupied"),
                                  ("aarch64-windows/unreviewed.txt", b"untracked"),
                                  ("legal/Wine-LGPL-2.1.txt", b"notice replacement")]:
            with self.subTest(path=relative):
                path = self.app / relative; raw = path.read_bytes() if path.exists() else None
                path.write_bytes(content)
                with self.assertRaises(ValueError): handoff.plan(ROOT / loader.RECEIPT, target)
                if raw is None: path.unlink()
                else: path.write_bytes(raw)


class CheckoutTests(unittest.TestCase):
    def test_autocrlf_preserves_original_and_combined_receipts(self):
        with tempfile.TemporaryDirectory(prefix="madeira-loader-checkout-") as tmp:
            seed, checkout = Path(tmp) / "seed", Path(tmp) / "checkout"; seed.mkdir()
            def git(root, *args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT)
            git(seed, "init", "-q"); git(seed, "config", "core.autocrlf", "true")
            shutil.copyfile(ROOT / ".gitattributes", seed / ".gitattributes")
            shutil.copytree(ROOT / loader.RECEIPT, seed / loader.RECEIPT)
            for name in loader.REQUIRED_NOTICES:
                target = seed / "app/Madeira" / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / "app/Madeira" / name, target)
            (seed / "control.txt").write_bytes(b"one\ntwo\n")
            git(seed, "add", "-A"); git(seed, "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-q", "-m", "Fixture")
            git(seed, "clone", "--no-hardlinks", "--no-checkout", str(seed), str(checkout))
            git(checkout, "config", "core.autocrlf", "true"); git(checkout, "checkout", "--force", "HEAD")
            self.assertEqual((checkout / "control.txt").read_bytes(), b"one\r\ntwo\r\n")
            self.assertEqual(len(planner.seal(checkout / loader.RECEIPT, loader.REVIEWED_SEAL)), 59)
            self.assertEqual(len(planner.seal(checkout / loader.RECEIPT / "build", loader.BUILD_SEAL)), 54)
            for name in loader.REQUIRED_NOTICES:
                self.assertEqual((checkout / "app/Madeira" / name).read_bytes(), (ROOT / "app/Madeira" / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
