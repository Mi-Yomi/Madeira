#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline negative controls; no build, target execution, or network calls."""
import copy
import importlib.util
import json
import io
import os
from pathlib import Path
import sys
import tempfile
import tarfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "tests/desktop/mesa_wgl"
sys.path.insert(0, str(HERE))
import softpipe_package as package
import softpipe_release as release


class DeliveryControls(unittest.TestCase):
    def setUp(self):
        self.inactive = {"schema_version": 1, "enabled": False, "repository": package.REPOSITORY,
                         "source_ref": package.REF, "source_commit": None, "request_id": None,
                         "release_id": None, "target_ipa_sha256": None,
                         "delivery": "existing-private-draft", "publish": False}
        self.active = {**self.inactive, "enabled": True, "source_commit": "a" * 40,
                       "request_id": "review-1", "release_id": 123, "target_ipa_sha256": "b" * 64}
        self.context = {**self.active, "request_commit": "c" * 40,
                        "tag": "softpipe-test-review-1-" + "a" * 12,
                        "run_id": "1", "run_attempt": "1"}

    def test_inactive_default(self):
        self.assertFalse(package.request_value(self.inactive)["enabled"])
        for key in ("source_commit", "request_id", "release_id", "target_ipa_sha256"):
            bad = {**self.inactive, key: self.active[key]}
            with self.assertRaises(ValueError): package.request_value(bad)

    def test_checked_in_request_is_well_formed(self):
        # The same test suite runs after authorized activation; do not require
        # the live request to stay false while validating that activated run.
        package.request_value(json.loads((HERE / "delivery-request.json").read_text()))

    def test_request_only_activation_and_clean_parent(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": package.REPOSITORY,
               "GITHUB_REF": package.REF, "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "c" * 40,
               "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
        calls = {("rev-parse", "HEAD"): "c" * 40, ("diff", "--name-only", "HEAD", "--"): "",
                 ("rev-list", "--parents", "-n", "1", "HEAD"): "c" * 40 + " " + "a" * 40,
                 ("show", "a" * 40 + ":" + package.REQUEST): json.dumps(self.inactive),
                 ("diff", "--name-only", "a" * 40, "c" * 40, "--"): package.REQUEST}
        with patch.dict(os.environ, env), patch.object(Path, "read_text", return_value=json.dumps(self.active)), \
             patch.object(package, "git", side_effect=lambda *args: calls[args]):
            self.assertEqual(package.preflight(), self.context)
            key = ("diff", "--name-only", "a" * 40, "c" * 40, "--")
            calls[key] += "\napp/other-file.c"
            with self.assertRaises(ValueError): package.preflight()
            calls[key] = package.REQUEST
            calls[("show", "a" * 40 + ":" + package.REQUEST)] = json.dumps(self.active)
            with self.assertRaises(ValueError): package.preflight()
            calls[("show", "a" * 40 + ":" + package.REQUEST)] = json.dumps(self.inactive)
            calls[("diff", "--name-only", "HEAD", "--")] = "changed.py"
            with self.assertRaises(ValueError): package.preflight()

    def test_request_rejects_unsafe_destination(self):
        self.assertTrue(package.request_value(self.active)["enabled"])
        for key, value in [("publish", True), ("release_id", True), ("release_id", 0),
                           ("repository", "other/repo"), ("source_ref", "refs/heads/main"),
                           ("source_commit", "main"), ("request_id", "../bad"),
                           ("target_ipa_sha256", "unknown"), ("enabled", "true")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                package.request_value({**self.active, key: value})

    def test_zip_roundtrip_and_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entries = {"README.txt": b"example\n", "licenses/MIT": b"notice\n"}
            package.write_zip(root / "one.zip", entries, 1790865593)
            package.write_zip(root / "two.zip", entries, 1790865593)
            self.assertEqual((root / "one.zip").read_bytes(), (root / "two.zip").read_bytes())
            with self.assertRaises(ValueError): package.verify_zip(root / "one.zip", {"README.txt": b"changed"})
            for name in ("../escape", "/absolute", "C:/absolute", "a\\b", "a\0b"):
                with self.subTest(name=name), self.assertRaises(ValueError): package.safe_entry(name)

    def test_source_bytes_must_match_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "mesa-26.2.4"
            source.mkdir()
            (source / "file.c").write_bytes(b"/* SPDX-License-Identifier: MIT */\n")
            archive = root / "mesa.tar"
            with tarfile.open(archive, "w") as out:
                data = (source / "file.c").read_bytes()
                info = tarfile.TarInfo("mesa-26.2.4/file.c")
                info.size = len(data)
                out.addfile(info, io.BytesIO(data))
            self.assertIn("file.c", package.source_archive_inventory(archive, source))
            (source / "file.c").write_bytes(b"modified source\n")
            with self.assertRaises(ValueError): package.source_archive_inventory(archive, source)

    def test_empty_evidence_log_is_preserved_without_allowing_empty_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "venv.log"
            log.write_bytes(b"")
            with self.assertRaises(ValueError): package.regular(log)
            verified = package.regular(log, allow_empty=True)
            self.assertEqual(package.reference.digest(verified), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            package.write_zip(root / "logs.zip", {"evidence/logs/venv.log": verified.read_bytes()}, 1790865593)
            with zipfile.ZipFile(root / "logs.zip") as archive:
                self.assertEqual(archive.read("evidence/logs/venv.log"), b"")

    def test_notices_come_from_archive_and_missing_runtime_notice_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "source/docs").mkdir(parents=True)
            (root / "source/licenses").mkdir()
            (root / "source/docs/license.rst").write_text("upstream license description\n")
            (root / "source/licenses/MIT").write_text("MIT license text fixture\n")
            (root / "source/file.c").write_text("/* Copyright fixture author. SPDX-License-Identifier: MIT */\n")
            prefix = "llvm-mingw-20260421-ucrt-x86_64/"
            names = ["LICENSE.TXT", *["x86_64-w64-mingw32/share/mingw32/" + n for n in
                     ("COPYING", "COPYING.MinGW-w64-runtime.txt", "COPYING.MinGW-w64.txt", "COPYING.winpthreads.txt")]]
            for complete in (True, False):
                archive = root / ("complete.zip" if complete else "missing.zip")
                with zipfile.ZipFile(archive, "w") as out:
                    for name in names if complete else names[:-1]:
                        out.writestr(prefix + name, "exact notice fixture " + name)
                if complete:
                    result = package.notices(root / "source", archive)
                    self.assertIn(b"Copyright fixture author", result["licenses/Mesa/SOURCE-ATTRIBUTION.txt"])
                    self.assertEqual(result["licenses/LLVM-MinGW/LICENSE.TXT"], b"exact notice fixture LICENSE.TXT")
                else:
                    with self.assertRaises(ValueError): package.notices(root / "source", archive)

    def test_checksum_tamper(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            out = Path(tmp) / "delivery"
            out.mkdir()
            for name in package.ASSETS[:2]:
                package.write_zip(out / name, {"evidence": b"fixture only"}, 1790865593)
            data = {"context": self.context, "limits": package.LIMITS,
                    "status": "packaged-after-windows-reference",
                    "assets": {n: package.identity(out / n) for n in package.ASSETS[:2]}}
            (out / "provenance.json").write_bytes(package.encode(data))
            (out / "SHA256SUMS").write_text("".join(package.identity(out / n)["sha256"] + "  " + n + "\n"
                                                    for n in package.ASSETS[:3]))
            package.verify_delivery(out, self.context)
            with (out / package.ASSETS[0]).open("ab") as stream: stream.write(b"tamper")
            with self.assertRaises(ValueError): package.verify_delivery(out, self.context)

    def test_release_cannot_be_retargeted_or_published(self):
        good = {"id": 123, "draft": True, "prerelease": True, "published_at": None,
                "tag_name": self.context["tag"], "target_commitish": self.context["source_commit"],
                "body": release.body(self.context), "html_url": "https://github.com/Mi-Yomi/Madeira/releases/tag/example"}
        release.check_release_value(good, self.context)
        for key, value in [("id", 124), ("draft", False), ("prerelease", False),
                           ("published_at", "2026-10-06"), ("tag_name", "another"),
                           ("target_commitish", "main"), ("body", "different"), ("html_url", "https://evil.invalid/")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.check_release_value({**good, key: value}, self.context)

    def test_nonempty_or_changed_asset_inventory(self):
        expected = {"Madeira-softpipe-test.zip": {"bytes": 10, "sha256": "d" * 64}}
        row = {"id": 5, "name": "Madeira-softpipe-test.zip", "size": 10, "state": "uploaded", "digest": "sha256:" + "d" * 64}
        self.assertEqual(release.asset_inventory([row], expected), {row["name"]: 5})
        with self.assertRaises(ValueError): release.asset_inventory([row], {})
        with self.assertRaises(ValueError): release.asset_inventory([row, row], expected)
        with self.assertRaises(ValueError): release.asset_inventory([{**row, "digest": "sha256:" + "e" * 64}], expected)
        with self.assertRaises(ValueError): release.asset_inventory([row], expected, {row["name"]: 6})

    def test_existing_tag_or_moved_branch_blocks_destination(self):
        values = {"": {"full_name": package.REPOSITORY, "private": False},
                  "git/ref/heads/compatibility/desktop-apps": {"ref": package.REF, "object": {"type": "commit", "sha": "c" * 40}},
                  "git/matching-refs/tags/" + self.context["tag"]: [],
                  "releases/123": {"id": 123, "draft": True, "prerelease": True, "published_at": None,
                     "tag_name": self.context["tag"], "target_commitish": self.context["source_commit"],
                     "body": release.body(self.context), "html_url": "https://github.com/Mi-Yomi/Madeira/releases/tag/example"}}
        class FakeGitHub:
            def get(self, key): return values[key]
        release.check_destination(FakeGitHub(), self.context)
        key = "git/matching-refs/tags/" + self.context["tag"]
        values[key] = [{"ref": "refs/tags/" + self.context["tag"], "object": {"type": "commit", "sha": "e" * 40}}]
        with self.assertRaises(ValueError): release.check_destination(FakeGitHub(), self.context)
        values[key] = []
        values["git/ref/heads/compatibility/desktop-apps"]["object"]["sha"] = "d" * 40
        with self.assertRaises(ValueError): release.check_destination(FakeGitHub(), self.context)

    def test_workflow_and_touch_flow_scope(self):
        workflow = (ROOT / ".github/workflows/mesa-softpipe-delivery.yml").read_text()
        self.assertIn("paths:\n      - tests/desktop/mesa_wgl/delivery-request.json", workflow)
        self.assertIn("if: needs.request.outputs.enabled == 'true'", workflow)
        for forbidden in ("workflow_dispatch", "pull_request", "schedule:", "upload-artifact@", "actions/cache@", "secrets.", "xcode-"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("runs-on: windows-2025", workflow)
        ordinary = (ROOT / ".github/workflows/mesa-windows-reference.yml").read_text()
        self.assertNotIn("softpipe_release", ordinary)
        self.assertNotIn("upload-artifact", ordinary)
        source = (HERE / "wgl_canary.c").read_text()
        for text in ("interactive = argc == 1", "CREATE_NEW", "ShowWindow(console, SW_HIDE)",
                     '"frame=GL1 rgb=64,128,191"', '"frame=GL2 rgb=191,64,128"',
                     "GetConsoleProcessList(processes, 2) == 1", "processes[0] == GetCurrentProcessId()",
                     "restore_owned_console();", "pump_for(7000)", "compositor_display_proven=false", "MessageBoxW(NULL, summary"):
            self.assertIn(text, source)
        self.assertNotIn("WinHttp", source)
        self.assertNotIn("InternetOpen", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
