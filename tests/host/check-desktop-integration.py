#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Committed-resource overlay regressions; static PE reads only, never Xcode."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import verify_desktop_integration as integration


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


app_tests = load("app_fixtures", "tests/host/check-app-bootstrap.py")
gate = app_tests.gate
pe_tests = load("pe_fixtures", "tests/host/check-desktop-overlay-plan.py")


class IntegratedDesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="madeira-tracked-desktop-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "app/Madeira"
        self.stage = self.root / integration.RECEIPT
        app_tests.fixture(self.app)
        # Keep the existing app-gate fixtures synthetic. The complete reviewed
        # evidence is copied but no captured recipe/tool/guest is executed.
        shutil.copytree(ROOT / integration.RECEIPT, self.stage)
        self.record = json.loads((ROOT / integration.RECORD).read_text())
        self.record["published_recipe_commit"] = "a" * 40  # isolated fixture only
        for name, source in integration.COPIES.items():
            target = self.app / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.stage / source, target)
        for name in integration.MERGED_NOTICES:
            shutil.copyfile(ROOT / "app/Madeira" / name, self.app / name)
        for target, source in gate.GENERATED_LICENSES.items():
            app_tests.put(self.root / source, (self.app / target).read_bytes())
        self.write_record()
        self.git("init", "-q")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.STDOUT).decode()

    def commit(self):
        self.git("add", "-A")
        # These are the same two intentionally generated resource exceptions as
        # production. Neither a DLL nor an overlay notice gets an exception.
        self.git("rm", "--cached", "--ignore-unmatch", "--", *[
            "app/Madeira/" + name for name in gate.GENERATED_LICENSES])
        self.git("update-index", "--add", "--cacheinfo", "160000," + integration.WINE_REVISION + ",wine")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
                 "commit", "-q", "--allow-empty", "-m", "Commit fixture input")

    def write_record(self):
        path = self.root / integration.RECORD
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.record, sort_keys=True) + "\n")

    def gate(self, full_farms=False):
        # Most adversarial fixtures focus on the additions/evidence. Dedicated
        # real-farm tests below exercise the old-farm rebind without this stub.
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "ROOT", self.root))
            if not full_farms:
                stack.enter_context(mock.patch.object(integration, "validate_farms",
                                                     return_value={"aarch64": 14, "arm64ec": 11}))
            return gate.resource_inputs()

    def refused(self):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            self.gate()

    def reseal_fixture(self):
        # Only the adversarial architecture test changes its isolated trust
        # fixture. Production always pins the independently reviewed seal.
        index = self.stage / "SHA256SUMS"
        entries = {p.relative_to(self.stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in self.stage.rglob("*") if p.is_file() and p != index}
        index.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items())))
        seal = hashlib.sha256(index.read_bytes()).hexdigest()
        self.record["stage_seal_sha256"] = seal
        return seal

    def test_recognizes_complete_reviewed_committed_additions(self):
        for arch in integration.planner.ARCHES:
            folder = arch + "-windows"
            shutil.copytree(ROOT / "app/Madeira" / folder, self.app / folder, dirs_exist_ok=True)
        (self.app / "aarch64-windows/example.dll").unlink()
        (self.app / "arm64ec-windows/example.exe").unlink()
        self.commit()
        before = pe_tests.tree_hashes(self.app)
        with mock.patch.object(gate, "run", side_effect=AssertionError("No build or guest execution")):
            resources, binaries = self.gate(full_farms=True)
        self.assertTrue(integration.DLLS <= set(binaries))
        self.assertTrue(set(integration.REQUIRED_NOTICES) <= set(resources))
        self.assertEqual(before, pe_tests.tree_hashes(self.app))
        self.assertEqual(len(list(self.stage.rglob("SHA256SUMS"))), 1)

    def test_committed_missing_or_substituted_dlls_are_rejected(self):
        target = self.app / "aarch64-windows/sensapi.dll"
        target.write_bytes((self.app / "aarch64-windows/netprofm.dll").read_bytes())
        self.commit()
        self.refused()
        target.unlink()
        self.commit()
        self.refused()

    def test_every_dll_and_required_notice_is_required_even_after_index_removal(self):
        for name in sorted(set(integration.COPIES) | integration.MERGED_NOTICES):
            with self.subTest(name=name):
                target = self.app / name
                original = target.read_bytes()
                target.unlink()
                self.git("rm", "--cached", "--", "app/Madeira/" + name)
                self.refused()
                target.write_bytes(original)
                self.git("add", "--", "app/Madeira/" + name)

    def test_every_notice_rejects_substitution_even_when_committed(self):
        for name in integration.REQUIRED_NOTICES:
            with self.subTest(name=name):
                target = self.app / name
                original = target.read_bytes()
                target.write_bytes(b"substituted notice\n")
                self.commit()
                self.refused()
                target.write_bytes(original)
                self.commit()

    def test_untracked_extra_dll_does_not_get_an_overlay_exception(self):
        app_tests.put(self.app / "arm64ec-windows/arbitrary.dll", pe_tests.pe("arm64ec"))
        self.refused()

    def test_dll_read_substitution_is_rejected_before_architecture_parser(self):
        with mock.patch.object(integration.inventory, "read_pe_bytes", return_value=pe_tests.pe("aarch64")), \
                mock.patch.object(integration.inventory, "PE") as parser:
            with self.assertRaisesRegex(ValueError, "changed before architecture parsing"):
                self.gate()
            parser.assert_not_called()

    def test_untracked_reviewed_dll_is_also_rejected(self):
        self.git("rm", "--cached", "--", "app/Madeira/arm64ec-windows/sensapi.dll")
        self.refused()

    def test_missing_or_untracked_evidence_rejected(self):
        name = "aarch64-build.log"
        self.git("rm", "--cached", "--", integration.RECEIPT + "/" + name)
        self.refused()
        self.git("add", "--", integration.RECEIPT + "/" + name)
        (self.stage / name).unlink()
        self.refused()

    def test_substituted_or_extra_evidence_rejected(self):
        original = (self.stage / "aarch64-build.log").read_bytes()
        (self.stage / "aarch64-build.log").write_text("changed\n")
        self.commit()
        self.refused()
        (self.stage / "aarch64-build.log").write_bytes(original)
        self.commit()
        app_tests.put(self.stage / "unlisted-evidence.txt")
        self.refused()

    def test_untracked_record_rejected(self):
        self.git("rm", "--cached", "--", integration.RECORD)
        self.refused()

    def test_committed_wrong_wine_gitlink_rejected(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + "b" * 40 + ",wine")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
                 "commit", "-q", "-m", "Change fixture Wine gitlink")
        self.refused()

    def test_record_requires_final_tooling_reference(self):
        self.record["published_recipe_commit"] = "PENDING_FINAL_PUBLISHED_TOOLING_COMMIT"
        self.write_record()
        self.commit()
        self.refused()

    def test_manifest_cannot_omit_module_or_accept_different_seal(self):
        original = self.record["files"].pop("aarch64-windows/sensapi.dll")
        self.write_record()
        self.refused()
        self.record["files"]["aarch64-windows/sensapi.dll"] = original
        self.record["stage_seal_sha256"] = "0" * 64
        self.write_record()
        self.refused()

    def test_wrong_architecture_rejected_even_with_matching_fixture_hashes(self):
        for arch, wrong in (("aarch64", "arm64ec"), ("arm64ec", "x86_64")):
            with self.subTest(arch=arch, wrong=wrong):
                name = arch + "-windows/sensapi.dll"
                raw = pe_tests.pe(wrong)
                (self.app / name).write_bytes(raw)
                (self.stage / name).write_bytes(raw)
                self.record["files"][name] = integration.planner.identity(self.app / name)
                seal = self.reseal_fixture()
                self.write_record()
                self.commit()
                with mock.patch.object(integration, "REVIEWED_SEAL", seal):
                    with self.assertRaisesRegex(ValueError, "Wrong architecture"):
                        self.gate()
                # Restore for the next architecture so the first cannot mask it.
                shutil.copyfile(ROOT / "app/Madeira" / name, self.app / name)
                shutil.copyfile(ROOT / integration.RECEIPT / name, self.stage / name)
                self.record["files"][name] = integration.planner.identity(self.app / name)

    def test_symlink_dll_or_notice_rejected(self):
        for name in ("aarch64-windows/sensapi.dll", "legal/Wine-LGPL-2.1.txt"):
            with self.subTest(name=name):
                target = self.app / name
                original = target.read_bytes()
                target.unlink()
                target.symlink_to(ROOT / "app/Madeira" / name)
                self.refused()
                target.unlink()
                target.write_bytes(original)


class ReviewedSourceTests(unittest.TestCase):
    def test_autocrlf_checkout_preserves_seal_and_hash_bound_notices(self):
        with tempfile.TemporaryDirectory(prefix="madeira-exact-checkout-") as directory:
            seed = Path(directory) / "seed"
            checkout = Path(directory) / "checkout"
            seed.mkdir()

            def git(root, *args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT)

            git(seed, "init", "-q")
            git(seed, "config", "--local", "core.autocrlf", "true")
            shutil.copyfile(ROOT / ".gitattributes", seed / ".gitattributes")
            shutil.copytree(ROOT / integration.RECEIPT, seed / integration.RECEIPT)
            record = json.loads((ROOT / integration.RECORD).read_text())
            for name in record["files"]:
                target = seed / "app/Madeira" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / "app/Madeira" / name, target)
            # This unprotected LF control must actually become CRLF, proving
            # the test performs a fresh autocrlf checkout rather than just
            # inspecting the original files already present in a worktree.
            (seed / "normal-text.txt").write_bytes(b"line one\nline two\n")
            git(seed, "add", "-A")
            git(seed, "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid",
                "commit", "-q", "-m", "Track exact sealed fixture")
            git(seed, "clone", "--no-hardlinks", "--no-checkout", str(seed), str(checkout))
            git(checkout, "config", "--local", "core.autocrlf", "true")
            git(checkout, "checkout", "--force", "HEAD")
            self.assertEqual((checkout / "normal-text.txt").read_bytes(), b"line one\r\nline two\r\n")
            self.assertEqual(git(checkout, "config", "--local", "--get", "core.autocrlf").strip(), b"true")
            sealed = integration.planner.seal(checkout / integration.RECEIPT, integration.REVIEWED_SEAL)
            self.assertEqual(sealed, integration.planner.seal(ROOT / integration.RECEIPT,
                                                             integration.REVIEWED_SEAL))
            self.assertEqual(len(sealed), 54)
            for name, expected in record["files"].items():
                with self.subTest(name=name):
                    self.assertEqual(integration.planner.identity(checkout / "app/Madeira" / name), expected)

    def test_git_queries_ignore_ambient_override_and_replacement(self):
        for function in (lambda: integration.git_output(ROOT, "ls-files", "-z"),
                         lambda: gate.git("ls-files", "-z")):
            with mock.patch.dict(os.environ, {"GIT_DIR": "/untrusted", "GIT_INDEX_FILE": "/untrusted-index",
                                              "GIT_CONFIG_COUNT": "1"}), \
                    mock.patch.object(subprocess, "check_output", return_value="") as query:
                function()
            args, kwargs = query.call_args
            self.assertEqual(args[0][:2], ["git", "--no-replace-objects"])
            self.assertEqual({key for key in kwargs["env"] if key.startswith("GIT_")}, {"GIT_NO_REPLACE_OBJECTS"})
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(kwargs["timeout"], 15)

    def test_preserved_target_specific_notice_references_and_wine_notices(self):
        text = (ROOT / "app/Madeira/legal/THIRD-PARTY-NOTICES.md").read_text()
        for prefix, names in (("| **StikJIT**", ("LICENSE-StikJIT-MPL-2.0.txt", "LICENSE-idevice-MIT.txt")),
                              ("| **On-device pairing**", ("LICENSES-rppairing-crates.txt", "LICENSE-idevice-MIT.txt"))):
            line = next(line for line in text.splitlines() if line.startswith(prefix))
            self.assertNotIn("`LICENSES/", line)
            for name in names:
                self.assertIn("`" + name + "`", line)
                self.assertTrue((ROOT / "app/Madeira/legal" / name).is_file())
        self.assertIn("| **Wine** | LGPL-2.1-or-later | **LGPL-2.1-or-later** |", text)
        self.assertIn("`Wine-compiler-rt-LICENSE.txt`", text)
        self.assertNotIn("Fork relicensed under LGPL-2.1 §3", text)

    def test_complete_sealed_pair_remains_byte_exact(self):
        sealed = integration.planner.seal(ROOT / integration.RECEIPT, integration.REVIEWED_SEAL)
        self.assertEqual(len(sealed), 54)
        for destination, source in integration.COPIES.items():
            self.assertEqual(integration.planner.identity(ROOT / "app/Madeira" / destination), sealed[source])

    def test_farm_identities_and_residual_gaps_still_match_reviewed_build(self):
        for arch in integration.planner.ARCHES:
            report = integration.inventory.audit_farm(ROOT / "app/Madeira" / (arch + "-windows"),
                                                       arch, integration.planner.NAMES)
            original = json.loads((ROOT / integration.RECEIPT / (arch + "-inventory.json")).read_text())
            self.assertEqual(integration.planner.identities(report["modules"]),
                             integration.planner.identities(original["modules"]))
            self.assertEqual(report["missing_dependencies"], original["missing_dependencies"])
            self.assertEqual(len(report["missing_dependencies"]), 14 if arch == "aarch64" else 11)

    def test_existing_farm_substitution_rejected_before_parser(self):
        with tempfile.TemporaryDirectory(prefix="madeira-old-farm-") as directory:
            root = Path(directory)
            farm = root / "app/Madeira/aarch64-windows"
            shutil.copytree(ROOT / "app/Madeira/aarch64-windows", farm)
            target = farm / "kernel32.dll"
            original = target.read_bytes()
            target.write_bytes(b"MZ" + bytes(len(original) - 2))
            with mock.patch.object(integration.inventory, "audit_farm") as parser:
                with self.assertRaisesRegex(ValueError, "before PE parsing"):
                    integration.validate_farms(root, ROOT / integration.RECEIPT)
                parser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
