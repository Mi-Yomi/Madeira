#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Static MSI resource/evidence mutations; no guest, installer, Xcode or IPA."""
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
import verify_desktop_integration as desktop
import verify_msi_integration as msi
import plan_msi_integration as handoff


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app_tests = load("msi_app_fixtures", "tests/host/check-app-bootstrap.py")
pe_tests = load("msi_pe_fixtures", "tests/host/check-desktop-overlay-plan.py")
gate = app_tests.gate


class MsiIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="madeira-msi-integration-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.app = self.root / "app/Madeira"
        app_tests.fixture(self.app, include_dock=False)  # Generated Dock is never a source-farm input.
        for module in (desktop, msi):
            shutil.copytree(ROOT / module.RECEIPT, self.root / module.RECEIPT)
            for name, source in module.COPIES.items():
                target = self.app / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.root / module.RECEIPT / source, target)
            for name in (module.MERGED_NOTICES if module is desktop else [msi.INTEGRATION_NOTICE]):
                shutil.copyfile(ROOT / "app/Madeira" / name, self.app / name)
            target = self.root / module.RECORD
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / module.RECORD, target)
        for target, source in gate.GENERATED_LICENSES.items():
            app_tests.put(self.root / source, (self.app / target).read_bytes())
        self.record = json.loads((self.root / msi.RECORD).read_text())
        self.git("init", "-q")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.STDOUT).decode()

    def commit(self):
        self.git("add", "-A")
        self.git("rm", "--cached", "--ignore-unmatch", "--", *[
            "app/Madeira/" + name for name in gate.GENERATED_LICENSES])
        self.git("update-index", "--add", "--cacheinfo", "160000," + msi.WINE_REVISION + ",wine")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
                 "commit", "-q", "--allow-empty", "-m", "Static integration fixture")

    def full_farms(self):
        for arch in desktop.planner.ARCHES:
            folder = arch + "-windows"
            shutil.copytree(ROOT / "app/Madeira" / folder, self.app / folder, dirs_exist_ok=True)
            # This fixture tests the historical MSI stage even when the checkout
            # has the separately reviewed client replacement installed.
            shutil.copyfile(self.root / msi.RECEIPT / "candidate" / folder / "msi.dll",
                            self.app / folder / "msi.dll")
            for name in desktop.loader.NAMES:
                (self.app / folder / name).unlink(missing_ok=True)
        (self.app / "aarch64-windows/example.dll").unlink()
        (self.app / "arm64ec-windows/example.exe").unlink()
        self.commit()

    def check(self, full=False):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "ROOT", self.root))
            stack.enter_context(mock.patch.object(gate, "run", side_effect=AssertionError("No app/guest execution")))
            if not full:
                stack.enter_context(mock.patch.object(desktop, "validate_farms", return_value=msi.RESIDUAL_COUNTS))
            return gate.resource_inputs()

    def refused(self, pattern=None, full=False):
        with self.assertRaisesRegex(ValueError, pattern or ".+"):
            self.check(full)

    def write_record(self):
        (self.root / msi.RECORD).write_text(json.dumps(self.record, sort_keys=True) + "\n")

    def reseal(self):
        stage = self.root / msi.RECEIPT
        index = stage / "SHA256SUMS"
        entries = {p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in stage.rglob("*") if p.is_file() and p != index}
        index.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items())))
        seal = hashlib.sha256(index.read_bytes()).hexdigest()
        self.record["stage_seal_sha256"] = seal
        self.write_record()
        self.commit()
        return seal

    def test_complete_pair_rebinds_real_farms_and_preserves_original_desktop_seal(self):
        self.full_farms()
        before = pe_tests.tree_hashes(self.app)
        resources, binaries = self.check(full=True)
        self.assertTrue(msi.BINARIES <= binaries.keys())
        self.assertTrue(set(msi.REQUIRED_NOTICES) <= resources.keys())
        self.assertFalse(any(name.startswith("i386-windows/") for name in binaries))
        self.assertEqual(before, pe_tests.tree_hashes(self.app))
        self.assertEqual(len(desktop.planner.seal(self.root / desktop.RECEIPT, desktop.REVIEWED_SEAL)), 54)

    def test_every_new_resource_is_required_even_after_index_removal(self):
        old_notices = set(desktop.REQUIRED_NOTICES)
        for name in sorted(msi.FILES - old_notices):
            with self.subTest(name=name):
                target = self.app / name
                original = target.read_bytes()
                self.git("rm", "--cached", "--", "app/Madeira/" + name)
                target.unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.check()
                target.write_bytes(original)
                self.git("add", "--", "app/Madeira/" + name)

    def test_changed_binary_cannot_be_authorized_by_editing_resource_manifest(self):
        name = "aarch64-windows/msi.dll"
        target = self.app / name
        raw = bytearray(target.read_bytes()); raw[-1] ^= 1; target.write_bytes(raw)
        self.record["files"][name] = desktop.planner.identity(target)
        self.write_record(); self.commit()
        self.refused("differs from sealed build")

    def test_untracked_provider_or_record_or_evidence_rejected(self):
        for name in ["app/Madeira/arm64ec-windows/msiexec.exe", msi.RECORD,
                     msi.RECEIPT + "/patches/msi-combined.patch", msi.RECEIPT + "/candidate/i386-windows/msi.dll"]:
            with self.subTest(name=name):
                self.git("rm", "--cached", "--", name)
                self.refused()
                self.git("add", "--", name)

    def test_extra_or_mutated_evidence_rejected(self):
        stage = self.root / msi.RECEIPT
        path = stage / "evidence/aarch64-build.log"
        original = path.read_bytes(); path.write_bytes(original + b"substitution\n")
        self.commit(); self.refused("checksum index")
        path.write_bytes(original)
        (stage / "unexpected.txt").write_text("unreviewed")
        self.commit(); self.refused("checksum index")

    def test_wrong_architecture_even_with_matching_fixture_hashes(self):
        # The test alone replaces the trust anchor to exercise architecture
        # validation beyond hashes; production always pins the original seal.
        for arch, wrong in (("aarch64", "arm64ec"), ("arm64ec", "x86_64")):
            with self.subTest(arch=arch):
                name = arch + "-windows/msiexec.exe"
                target, staged = self.app / name, self.root / msi.RECEIPT / msi.COPIES[name]
                original = target.read_bytes()
                target.write_bytes(pe_tests.pe(wrong)); staged.write_bytes(target.read_bytes())
                self.record["files"][name] = desktop.planner.identity(target)
                seal = self.reseal()
                with mock.patch.object(msi, "REVIEWED_SEAL", seal):
                    self.refused("Wrong architecture")
                target.write_bytes(original); staged.write_bytes(original)
                self.record["files"][name] = desktop.planner.identity(target)

    def test_read_substitution_rejected_before_msi_architecture_parser(self):
        resources = {name: desktop.planner.identity(self.app / name)["sha256"] for name in msi.FILES}
        tracked = self.git("ls-files", "-z").split("\0")
        with mock.patch.object(msi.inventory, "read_pe_bytes", return_value=b"MZ substituted"), \
                mock.patch.object(msi.inventory, "PE") as parser:
            with self.assertRaisesRegex(ValueError, "changed before architecture parsing"):
                msi.validate(self.root, resources, tracked)
            parser.assert_not_called()

    def test_i386_ntdll_and_patched_msi_remain_rejected(self):
        for name in ("ntdll.dll", "msi.dll"):
            path = self.app / "i386-windows" / name
            path.write_bytes((self.root / msi.RECEIPT / "candidate/i386-windows/msi.dll").read_bytes())
            self.commit(); self.refused("unverified 32-bit runtime")
            path.unlink(); self.commit()

    def test_tracked_i386_pe_suffixes_and_case_variants_cannot_bypass_guard(self):
        self.full_farms()
        self.check(full=True)
        raw = (self.root / msi.RECEIPT / "candidate/i386-windows/msi.dll").read_bytes()
        names = {"msi.dll", "MSI.DLL", "msi.DlL", "NTDLL.DLL", "INSTALLER.EXE"}
        for suffix in desktop.inventory.PE_SUFFIXES:
            names.update(("payload" + suffix, "PAYLOAD" + suffix.upper(),
                          "mixed" + suffix[:2].upper() + suffix[2:]))
        for name in sorted(names):
            with self.subTest(name=name):
                path = self.app / "i386-windows" / name
                path.write_bytes(raw)
                self.commit()
                self.assertIn("app/Madeira/i386-windows/" + name, self.git("ls-files", "-z").split("\0"))
                self.refused("unverified 32-bit runtime", full=True)
                path.unlink(); self.commit()

    def test_uppercase_64bit_payload_additions_reach_exact_farm_inventory(self):
        self.full_farms()
        for name in ("MSI.DLL", "ARBITRARY.EXE", "DRIVER.SYS"):
            with self.subTest(name=name):
                path = self.app / "aarch64-windows" / name
                path.write_bytes((self.app / "aarch64-windows/msi.dll").read_bytes())
                self.commit()
                self.refused("Case-colliding|module set differs", full=True)
                path.unlink(); self.commit()

    def test_all_existing_pe_suffixes_are_in_guest_hash_receipt(self):
        self.full_farms()
        resources, binaries = self.check(full=True)
        expected = {name: digest for name, digest in resources.items()
                    if Path(name).suffix.lower() in desktop.inventory.PE_SUFFIXES}
        self.assertEqual(binaries, expected)
        extra_suffixes = {Path(name).suffix.lower() for name in binaries} - {".dll", ".exe"}
        self.assertTrue(extra_suffixes, "Real farms must exercise existing non-DLL/EXE PE resources")

    def test_arbitrary_tracked_addition_and_original_substitution_rejected(self):
        self.full_farms()
        extra = self.app / "arm64ec-windows/arbitrary.dll"
        extra.write_bytes(pe_tests.pe("arm64ec")); self.commit()
        self.refused("module set differs", full=True)
        extra.unlink(); self.commit()
        target = self.app / "aarch64-windows/kernel32.dll"
        original = target.read_bytes(); target.write_bytes(b"MZ" + bytes(len(original)-2)); self.commit()
        self.refused("before PE parsing", full=True)

    def test_baseline_and_residual_edge_mutations_rejected(self):
        stage = self.root / msi.RECEIPT
        for relative, mutate in [
            ("evidence/aarch64-inventory.json", lambda d: d["missing_dependencies"].pop()),
            ("evidence/aarch64-inventory.json", lambda d: d["modules"]["kernel32.dll"].update(sha256="0" * 64)),
            ("evidence/aarch64-symbol-audit.json", lambda d: d["input_modules"].pop("ntdll.dll")),
            ("evidence/source-inputs.json", lambda d: d["patched_file"].update(after_sha256="0" * 64))]:
            with self.subTest(path=relative):
                path = stage / relative; original = path.read_bytes()
                data = json.loads(original); mutate(data); path.write_text(json.dumps(data))
                seal = self.reseal()
                with mock.patch.object(msi, "REVIEWED_SEAL", seal):
                    self.refused()
                path.write_bytes(original)

    def test_original_desktop_baseline_cannot_be_replaced_by_a_different_one(self):
        self.full_farms()
        baselines, combined = msi.checked_reports(self.root / msi.RECEIPT)
        baselines["aarch64"]["modules"]["kernel32.dll"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "original sealed desktop inventory"):
            desktop.validate_farms(self.root, self.root / desktop.RECEIPT,
                                   {"baselines": baselines, "combined": combined})

    def test_symlink_provider_and_notice_rejected(self):
        for name in ("aarch64-windows/msi.dll", "legal/Wine-MSI-MODIFICATIONS.md"):
            path = self.app / name; raw = path.read_bytes(); path.unlink()
            path.symlink_to(self.root / msi.RECEIPT / msi.COPIES[name])
            self.refused("special file|unsafe|symlink")
            path.unlink(); path.write_bytes(raw)

    def test_partial_pair_cannot_disable_extension_by_removing_record(self):
        self.git("rm", "--cached", "--", msi.RECORD)
        (self.root / msi.RECORD).unlink()
        self.assertTrue(msi.present(self.root))
        self.refused("record must be tracked")

    def test_original_i386_guard_and_msi_resource_manifest_wiring(self):
        text = (ROOT / "build/app-ios/build_unsigned.py").read_text()
        self.assertIn('if any(name.startswith("i386-windows/") for name in pe):', text)
        self.assertIn('"msi_stage_seal_sha256"', text)
        self.assertIn('"source_built_msi_sha256"', text)
        self.assertIn("verify_msi_integration.RECORD, verify_msi_integration.RECEIPT", text)

    def planning_target(self):
        target = self.root / "untouched-target"
        target.mkdir()
        for arch in desktop.planner.ARCHES:
            farm = target / "app/Madeira" / (arch + "-windows")
            shutil.copytree(ROOT / "app/Madeira" / (arch + "-windows"), farm)
            for name in msi.NAMES | desktop.loader.NAMES:
                (farm / name).unlink(missing_ok=True)
        shutil.copytree(ROOT / "app/Madeira/legal", target / "app/Madeira/legal")
        for name in desktop.client.REQUIRED_NOTICES:
            (target / "app/Madeira" / name).unlink(missing_ok=True)
        for name in (desktop.loader.INTEGRATION_NOTICE, "legal/Wine-loader-SOURCE-REBUILD.md"):
            (target / "app/Madeira" / name).unlink(missing_ok=True)
        for name in msi.REQUIRED_NOTICES:
            if name not in desktop.REQUIRED_NOTICES:
                (target / "app/Madeira" / name).unlink(missing_ok=True)
        shutil.copytree(ROOT / desktop.RECEIPT, target / desktop.RECEIPT)
        subprocess.check_output(["git", "init", "-q"], cwd=target)
        subprocess.check_output(["git", "update-index", "--add", "--cacheinfo",
                                 "160000," + msi.WINE_REVISION + ",wine"], cwd=target)
        subprocess.check_output(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
                                 "commit", "-q", "-m", "Pinned Wine fixture"], cwd=target)
        return target

    def test_plan_is_read_only_exact_and_keeps_i386_only_in_evidence(self):
        target = self.planning_target()
        before = pe_tests.tree_hashes(target / "app")
        plan = handoff.plan(self.root / msi.RECEIPT, target)
        self.assertEqual(before, pe_tests.tree_hashes(target / "app"))
        self.assertEqual(len(plan["operations"]), 129)
        self.assertEqual(plan["new_app_providers"], 14)
        self.assertEqual(plan["new_app_notice_copies"], 6)
        self.assertFalse(any(op["destination"].startswith("app/Madeira/i386-windows/")
                             for op in plan["operations"]))
        self.assertTrue(all(op["before"] is None for op in plan["operations"]))
        self.assertEqual(len(plan["preserved_notices"]), 3)

    def test_plan_refuses_provider_collision_non_pe_addition_and_notice_replacement(self):
        target = self.planning_target()
        for relative, content in [
            ("aarch64-windows/msi.dll", (self.app / "aarch64-windows/msi.dll").read_bytes()),
            ("aarch64-windows/unreviewed.txt", b"not an original farm file"),
            ("legal/Wine-zlib-LICENSE.txt", b"conflicting notice")]:
            with self.subTest(path=relative):
                path = target / "app/Madeira" / relative; path.write_bytes(content)
                with self.assertRaisesRegex(ValueError, "module set differs|Original farm files differ|destination collision"):
                    handoff.plan(self.root / msi.RECEIPT, target)
                path.unlink()


class MsiCheckoutTests(unittest.TestCase):
    def test_autocrlf_preserves_new_evidence_and_notice_bytes(self):
        with tempfile.TemporaryDirectory(prefix="madeira-msi-checkout-") as temporary:
            seed, checkout = Path(temporary).resolve() / "seed", Path(temporary).resolve() / "checkout"
            seed.mkdir()
            def git(root, *args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT)
            git(seed, "init", "-q"); git(seed, "config", "core.autocrlf", "true")
            shutil.copyfile(ROOT / ".gitattributes", seed / ".gitattributes")
            shutil.copytree(ROOT / msi.RECEIPT, seed / msi.RECEIPT)
            for name in msi.REQUIRED_NOTICES:
                target = seed / "app/Madeira" / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / "app/Madeira" / name, target)
            (seed / "control.txt").write_bytes(b"one\ntwo\n")
            git(seed, "add", "-A")
            git(seed, "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-q", "-m", "Fixture")
            git(seed, "clone", "--no-hardlinks", "--no-checkout", str(seed), str(checkout))
            git(checkout, "config", "core.autocrlf", "true"); git(checkout, "checkout", "--force", "HEAD")
            self.assertEqual((checkout / "control.txt").read_bytes(), b"one\r\ntwo\r\n")
            self.assertEqual(len(desktop.planner.seal(checkout / msi.RECEIPT, msi.REVIEWED_SEAL)), 108)
            for name in msi.REQUIRED_NOTICES:
                self.assertEqual((checkout / "app/Madeira" / name).read_bytes(),
                                 (ROOT / "app/Madeira" / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
