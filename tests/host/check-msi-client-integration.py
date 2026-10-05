#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Host-only exact MSI replacement, app receipt and reversible handoff checks."""
import contextlib
import copy
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
import verify_msi_client_integration as client
import plan_msi_client_integration as handoff

spec = importlib.util.spec_from_file_location("client_loader_fixtures", ROOT / "tests/host/check-loader-integration.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
gate = fixtures.gate


class ClientIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LoaderIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.app = self.fixture.root, self.fixture.app
        self.git, self.commit = self.fixture.git, self.fixture.commit
        shutil.copytree(ROOT / client.RECEIPT, self.root / client.RECEIPT)
        for name, source in client.COPIES.items():
            shutil.copyfile(self.root / client.RECEIPT / source, self.app / name)
        shutil.copyfile(ROOT / client.RECORD, self.root / client.RECORD)
        self.record = planner.document(self.root, client.RECORD)
        self.commit()

    def full_farms(self):
        self.fixture.full_farms()
        for name in client.BINARIES:
            shutil.copyfile(self.root / client.RECEIPT / client.COPIES[name], self.app / name)
        self.commit()

    def check(self, full=False):
        return self.fixture.check(full=full)

    def refused(self, pattern=".+", full=False):
        with self.assertRaisesRegex(ValueError, pattern):
            self.check(full)

    def write_record(self):
        (self.root / client.RECORD).write_text(json.dumps(self.record, sort_keys=True) + "\n")

    def planning_target(self):
        self.fixture.full_farms()
        for name in client.REQUIRED_NOTICES:
            (self.app / name).unlink()
        shutil.rmtree(self.root / client.RECEIPT)
        (self.root / client.RECORD).unlink()
        self.commit()
        return self.root

    def test_complete_pair_retains_historical_seals_and_app_receipt(self):
        self.full_farms()
        before = fixtures.fixtures.pe_tests.tree_hashes(self.app)
        resources, pe = self.check(full=True)
        self.assertEqual(before, fixtures.fixtures.pe_tests.tree_hashes(self.app))
        for module, count in ((desktop, 54), (msi, 108), (loader, 59)):
            self.assertEqual(len(planner.seal(self.root / module.RECEIPT, module.REVIEWED_SEAL)), count)
        self.assertEqual(len(client.seal(self.root / client.RECEIPT)), 176)
        self.assertEqual(len(client.seal(self.root / client.RECEIPT / "build", build=True)), 168)
        evidence = gate.guest_pe_evidence(pe)
        self.assertEqual(evidence["msi_client_stage_seal_sha256"], client.REVIEWED_SEAL)
        self.assertEqual(evidence["msi_client_source_sha256"], client.SOURCE_SHA256)
        self.assertEqual(evidence["source_built_msi_client_sha256"], {n: v["sha256"] for n, v in client.CANDIDATES.items()})
        self.assertEqual(evidence["msi_client_before_sha256"], {n: v["sha256"] for n, v in client.BEFORE.items()})
        self.assertEqual(len(evidence["source_built_msi_sha256"]), 14)
        self.assertEqual(len(evidence["source_built_loader_sha256"]), 4)
        self.assertFalse(any(n.startswith("i386-windows/") for n in pe))
        self.assertTrue(set(client.REQUIRED_NOTICES) <= resources.keys())

    def test_record_cannot_expand_or_redefine_replacement_scope(self):
        original = copy.deepcopy(self.record)
        mutations = [lambda d: d["replacements"].update({"aarch64-windows/kernel32.dll": next(iter(d["replacements"].values()))}),
                     lambda d: d["replacements"]["aarch64-windows/msi.dll"]["before"].update(sha256="0" * 64),
                     lambda d: d["replacements"]["arm64ec-windows/msi.dll"]["after"].update(sha256="1" * 64),
                     lambda d: d.update(schema_version=True), lambda d: d.update(i386_activated=True),
                     lambda d: d.update(runtime_tested=True), lambda d: d.update(package_ready=True),
                     lambda d: d["historical_seals"].update(loader="2" * 64),
                     lambda d: d.update(source_sha256="3" * 64), lambda d: d.update(extra="unreviewed")]
        for mutate in mutations:
            self.record = copy.deepcopy(original); mutate(self.record); self.write_record()
            self.refused("exact reviewed replacement")
        self.record = original; self.write_record()

    def test_substituted_candidate_or_half_rollback_fails(self):
        for name in sorted(client.BINARIES):
            path = self.app / name; raw = path.read_bytes()
            old = self.root / msi.RECEIPT / "candidate" / name
            for replacement in (old.read_bytes(), raw[:-1] + bytes([raw[-1] ^ 1])):
                path.write_bytes(replacement)
                self.refused("differs from sealed replacement")
            path.write_bytes(raw)

    def test_editing_old_record_cannot_rewrite_history(self):
        path = self.root / msi.RECORD; original = path.read_bytes(); data = json.loads(original)
        data["files"].update(client.CANDIDATES); path.write_text(json.dumps(data))
        self.refused("differs from sealed build")
        path.write_bytes(original)
        old = self.root / msi.RECEIPT / "candidate/aarch64-windows/msi.dll"
        old.write_bytes((self.app / "aarch64-windows/msi.dll").read_bytes())
        self.refused("checksum index")

    def test_each_unique_resource_stays_required_when_untracked(self):
        for name in client.FILES:
            path = self.app / name; raw = path.read_bytes()
            self.git("rm", "--cached", "--", "app/Madeira/" + name); path.unlink()
            with self.assertRaises((ValueError, OSError)): self.check()
            path.write_bytes(raw); self.git("add", "--", "app/Madeira/" + name)

    def test_receipt_and_source_must_be_tracked(self):
        for name in (client.RECORD, client.RECEIPT + "/build/source/custom.c",
                     client.RECEIPT + "/build/candidate/i386-windows/msi.dll",
                     client.RECEIPT + "/aarch64-symbol-audit.json"):
            self.git("rm", "--cached", "--", name); self.refused("must be tracked|untracked evidence")
            self.git("add", "--", name)

    def test_partial_layer_cannot_hide_by_removing_record(self):
        self.git("rm", "--cached", "--", client.RECORD); (self.root / client.RECORD).unlink()
        self.assertTrue(client.present(self.root)); self.refused("record must be tracked")

    def test_changed_extra_empty_or_symlink_evidence_fails(self):
        stage = self.root / client.RECEIPT
        for name in ("build/source/custom.c", "build/evidence/client-normal/compile.log", "aarch64-inventory.json"):
            path = stage / name; raw = path.read_bytes(); path.write_bytes(raw + b"changed")
            self.refused("checksum index|compiler log changed"); path.write_bytes(raw)
        extra = stage / "extra.txt"; extra.write_text("unchecked")
        self.refused("checksum index"); extra.unlink()
        path = stage / "build/evidence/client-normal/compile.log"; path.unlink(); path.symlink_to("/dev/null")
        self.refused("symlink")

    def test_symlink_candidate_and_notice_fails(self):
        for name in ("aarch64-windows/msi.dll", client.REQUIRED_NOTICES[0]):
            path = self.app / name; raw = path.read_bytes(); path.unlink()
            path.symlink_to(self.root / client.RECEIPT / client.COPIES[name]); self.refused("symlink|unsafe")
            path.unlink(); path.write_bytes(raw)

    def test_read_substitution_fails_before_architecture_parser(self):
        resources = {name: planner.identity(self.app / name)["sha256"] for name in client.FILES}
        tracked = self.git("ls-files", "-z").split("\0")
        with mock.patch.object(client.inventory, "read_pe_bytes", return_value=b"MZ swapped"), \
                mock.patch.object(client.inventory, "PE") as parser:
            with self.assertRaisesRegex(ValueError, "changed before architecture parsing"):
                client.validate(self.root, resources, tracked)
            parser.assert_not_called()

    def test_current_graph_and_original_preconditions_are_bound(self):
        extension = {"combined": client.checked_reports(self.root / client.RECEIPT)}
        original = loader.checked_reports(self.root / loader.RECEIPT)["combined"]["aarch64"]
        self.assertEqual(client.bind_reports(extension, original, "aarch64"), extension["combined"]["aarch64"])
        for mutate in (lambda d: d["modules"]["msi.dll"]["dependencies"].pop(),
                       lambda d: d["modules"]["kernel32.dll"].update(sha256="0" * 64),
                       lambda d: d["modules"]["msi.dll"].update(architecture="x86_64"),
                       lambda d: d["modules"].pop("activeds.dll"),
                       lambda d: d["missing_dependencies"].pop()):
            changed = copy.deepcopy(extension); mutate(changed["combined"]["aarch64"])
            with self.assertRaisesRegex(ValueError, "beyond the fixed replacement"):
                client.bind_reports(changed, original, "aarch64")
        original["modules"]["msi.dll"]["sha256"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "historical MSI precondition"):
            client.bind_reports(extension, original, "aarch64")

    def test_combined_symbol_audit_binds_every_resolver_input(self):
        stage = self.root / client.RECEIPT; path = stage / "arm64ec-symbol-audit.json"; raw = path.read_bytes()
        for mutate in (lambda d: d["input_modules"].pop("avicap32.dll"),
                       lambda d: d["counts"].update(checked_import_symbols=327),
                       lambda d: d.update(passed=False), lambda d: d.update(runtime_tested=True)):
            data = json.loads(raw); mutate(data); path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "complete combined farm"): client.checked_reports(stage)
        path.write_bytes(raw)

    def test_i386_case_variants_remain_inactive(self):
        raw = (self.root / client.RECEIPT / "build/candidate/i386-windows/msi.dll").read_bytes()
        for name in ("msi.dll", "MSI.DLL", "PAYLOAD.SYS", "INSTALLER.EXE"):
            path = self.app / "i386-windows" / name; path.write_bytes(raw); self.commit()
            self.refused("unverified 32-bit runtime"); path.unlink(); self.commit()

    def test_core_addition_and_case_collision_rejected_by_full_farm(self):
        self.full_farms()
        for name in ("arbitrary.dll", "MSI.DLL"):
            path = self.app / "aarch64-windows" / name
            path.write_bytes((self.app / "aarch64-windows/msi.dll").read_bytes()); self.commit()
            self.refused("Case-colliding|module set differs", full=True); path.unlink(); self.commit()
        path = self.app / "arm64ec-windows/kernel32.dll"; raw = bytearray(path.read_bytes()); raw[-1] ^= 1; path.write_bytes(raw)
        self.commit(); self.refused("before PE parsing", full=True)

    def test_plan_is_read_only_exact_two_replacements_and_additions(self):
        target = self.planning_target(); before = fixtures.fixtures.pe_tests.tree_hashes(self.app)
        plan = handoff.plan(ROOT / client.RECEIPT, target)
        self.assertEqual(before, fixtures.fixtures.pe_tests.tree_hashes(self.app))
        self.assertEqual(len(plan["operations"]), 183)
        replacements = [op for op in plan["operations"] if op["before"] is not None]
        self.assertEqual({op["destination"] for op in replacements}, {"app/Madeira/" + n for n in client.BINARIES})
        for op in replacements:
            self.assertEqual(planner.identity(target / op["rollback_source"]), op["before"])
        self.assertFalse(any(op["destination"].startswith("app/Madeira/i386-windows/") for op in plan["operations"]))
        self.assertEqual(plan["new_app_providers"], 0)

    def test_plan_refuses_changed_precondition_partial_layer_and_untracked_farm(self):
        target = self.planning_target()
        for relative, content in (("aarch64-windows/msi.dll", b"MZ changed"),
                                  ("aarch64-windows/unreviewed.txt", b"untracked"),
                                  (client.REQUIRED_NOTICES[0], b"partial")):
            path = self.app / relative; raw = path.read_bytes() if path.exists() else None
            path.write_bytes(content)
            with self.assertRaises(ValueError): handoff.plan(ROOT / client.RECEIPT, target)
            if raw is None: path.unlink()
            else: path.write_bytes(raw)

    def test_forward_plan_and_guarded_rollback_restore_exact_legacy_resources(self):
        target = self.planning_target(); before = fixtures.fixtures.pe_tests.tree_hashes(self.app)
        plan = handoff.plan(ROOT / client.RECEIPT, target)
        for op in plan["operations"]:
            path = target / op["destination"]; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / client.RECEIPT / op["source"], path)
            path.chmod(0o755 if op["after_mode"] == "100755" else 0o644)
        shutil.copyfile(ROOT / client.RECORD, target / client.RECORD); self.commit(); self.check(full=True)
        for op in reversed(plan["operations"]):
            path = target / op["destination"]
            self.assertEqual({"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, op["after"])
            if op["before"] is None: path.unlink()
            else:
                shutil.copyfile(target / op["rollback_source"], path)
                path.chmod(0o755 if op["before_mode"] == "100755" else 0o644)
        shutil.rmtree(target / client.RECEIPT); (target / client.RECORD).unlink(); self.commit()
        self.assertEqual(before, fixtures.fixtures.pe_tests.tree_hashes(self.app)); self.check(full=True)


class CheckoutTests(unittest.TestCase):
    def test_autocrlf_preserves_entire_nested_seal_and_notices(self):
        with tempfile.TemporaryDirectory(prefix="madeira-client-eol-") as temporary:
            seed, clone = Path(temporary) / "seed", Path(temporary) / "clone"; seed.mkdir()
            def git(root, *args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT)
            git(seed, "init", "-q"); git(seed, "config", "core.autocrlf", "true")
            shutil.copyfile(ROOT / ".gitattributes", seed / ".gitattributes")
            shutil.copytree(ROOT / client.RECEIPT, seed / client.RECEIPT)
            for name in client.REQUIRED_NOTICES:
                path = seed / "app/Madeira" / name; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / "app/Madeira" / name, path)
            (seed / "control.txt").write_bytes(b"one\ntwo\n")
            git(seed, "add", "-A"); git(seed, "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "commit", "-qm", "Fixture")
            git(seed, "clone", "--no-hardlinks", "--no-checkout", str(seed), str(clone))
            git(clone, "config", "core.autocrlf", "true"); git(clone, "checkout", "--force", "HEAD")
            self.assertEqual((clone / "control.txt").read_bytes(), b"one\r\ntwo\r\n")
            self.assertEqual(len(client.seal(clone / client.RECEIPT)), 176)
            for name in client.REQUIRED_NOTICES:
                self.assertEqual((clone / "app/Madeira" / name).read_bytes(), (ROOT / "app/Madeira" / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
