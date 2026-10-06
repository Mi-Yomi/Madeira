#!/usr/bin/env python3
"""Portable failure injection for draft-only IPA delivery; no GitHub/Xcode calls."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/app-ios"))
import deliver_unsigned as delivery
gate = delivery.gate
spec = importlib.util.spec_from_file_location("app_fixtures", ROOT / "tests/host/check-app-bootstrap.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
SHA = "b" * 40
ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": delivery.REPOSITORY,
       "GITHUB_REF": delivery.SOURCE_REF, "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "1234",
       "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "push"}


class PackageFixture:
    def __enter__(self):
        self.stack = contextlib.ExitStack()
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.root = self.temp / "source"
        self.stage = self.temp / "stage"
        self.destination = self.temp / "delivery"
        self.app = self.stage / "Payload/Madeira.app"
        self.resources, framework, converter = fixtures.fixture(self.app)
        layers = (gate.verify_desktop_integration.DLLS, gate.verify_msi_integration.BINARIES,
                  gate.verify_loader_integration.BINARIES)
        for name in set().union(*layers):
            fixtures.put(self.app / name, b"MZ synthetic MSI-layer fixture")
            self.resources[name] = gate.digest(self.app / name)
        self.pe = {name: value for name, value in self.resources.items()
                   if Path(name).suffix.lower() in gate.verify_desktop_integration.inventory.PE_SUFFIXES}
        candidates = {name: {"bytes": (self.app / name).stat().st_size, "sha256": self.pe[name]}
                      for name in gate.verify_msi_startup_integration.BINARIES}
        self.stack.enter_context(mock.patch.object(gate.verify_msi_startup_integration, "CANDIDATES", candidates))
        self.stack.enter_context(mock.patch.object(gate, "CONVERTER_SHA256", converter))
        self.stack.enter_context(mock.patch.object(gate, "ROOT", self.root))
        self.stack.enter_context(mock.patch.object(delivery, "ROOT", self.root))
        self.stack.enter_context(mock.patch.dict(os.environ, ENV, clear=True))
        for name in self.resources:
            fixtures.put(self.root / "app/Madeira" / name, (self.app / name).read_bytes())
        fixtures.put(self.root / gate.FRAMEWORK_SOURCE, (self.app / "Frameworks/StikJIT.framework/StikJIT").read_bytes())
        fixtures.put(self.root / delivery.REQUEST_PATH, delivery.json_bytes(delivery.expected_request()))
        self.native = fixtures.put(self.temp / "native/provenance.json", b'{"synthetic":true}\n')
        self.sources = {p.relative_to(self.root).as_posix(): gate.digest(p)
                        for p in sorted(self.root.rglob("*")) if p.is_file()}
        self.git_mock = self.stack.enter_context(mock.patch.object(gate, "git", side_effect=self.git))
        self.prerequisite = {"source_commit": SHA, "native_receipt_sha256": gate.digest(self.native),
            "graphics_receipt_sha256": {"fixture": "a" * 64},
            "prerequisite_sha256": {gate.FRAMEWORK_SOURCE: framework}, "scope": gate.SCOPE}
        self.prereq_mock = self.stack.enter_context(mock.patch.object(gate, "prerequisites", return_value=self.prerequisite))
        self.resource_mock = self.stack.enter_context(mock.patch.object(gate, "resource_inputs", return_value=(self.resources, self.pe)))
        self.receipt = {**self.prerequisite, "schema_version": 1, "status": "passed",
            "app_source_sha256": self.sources, "resources_sha256": self.resources,
            "guest_pe": gate.guest_pe_evidence(self.pe), "app": gate.validate_app(self.app, self.resources, framework),
            "build_command": gate.build_command(self.temp / "products", self.temp / "intermediates"),
            "scope": gate.PACKAGE_SCOPE, "packaging": {"requested": True, "status": "passed"}, "signing": delivery.SIGNING}
        self.zip()
        self.receipt.update({"ipa_sha256": gate.digest(self.stage / delivery.ASSETS[0]),
                             "ipa_bytes": (self.stage / delivery.ASSETS[0]).stat().st_size})
        self.write_receipt()
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def git(self, *args):
        if args[:1] == ("rev-parse",): return SHA
        if args[:1] == ("merge-base",): return delivery.BASE_CODE_COMMIT
        if args[:1] == ("diff",):
            return "\0".join(sorted(delivery.ALLOWED_CHANGES)) if "--no-renames" in args else ""
        if args[:1] == ("ls-files",): return "\0".join(self.sources)
        raise AssertionError(args)

    def zip(self):
        fixtures.zip_payload(self.stage / delivery.ASSETS[0], self.stage / "Payload")

    def write_receipt(self):
        (self.stage / "provenance.json").write_bytes(delivery.json_bytes(self.receipt))

    def verify(self):
        return delivery.verify_package(self.stage, self.native)

    def prepare(self):
        return delivery.prepare(self.stage, self.native, self.destination)


class FakeGitHub:
    def __init__(self, fixture, *, mutation=None, digest=True):
        self.fixture, self.mutation, self.digest = fixture, mutation, digest
        self.context, package = fixture.verify()
        self.assets, _ = delivery.delivery_metadata(self.context, package)
        self.release = {"id": 42, "draft": True, "prerelease": True, "published_at": None,
            "tag_name": self.context["tag"], "target_commitish": SHA, "body": delivery.release_notes(SHA),
            "html_url": "https://github.com/Mi-Yomi/Madeira/releases/tag/fixture"}
        self.rows, self.calls, self.downloads, self.writes = [], [], [], []
        self.pages = None
        for key, value in {"published": ("draft", False), "non-prerelease": ("prerelease", False),
            "wrong-target": ("target_commitish", "c" * 40), "wrong-tag": ("tag_name", "v1"),
            "wrong-id": ("id", 8), "wrong-url": ("html_url", "https://example.com/"),
            "wrong-body": ("body", "Unapproved or stale draft text")}.items():
            if mutation == key: self.release[value[0]] = value[1]
        if mutation == "existing-assets": self.rows = [{"name": "previous.ipa"}]

    def __enter__(self): return self
    def __exit__(self, *_): pass

    def api(self, endpoint, *, method="GET", data=None):
        assert method == "GET" and data is None, "Release metadata must remain read-only"
        self.calls.append((endpoint, method, data))
        if endpoint == "":
            return {"full_name": delivery.REPOSITORY, "private": self.mutation == "private-repo",
                    "visibility": "public"}
        if endpoint.startswith("git/ref/"):
            return {"ref": delivery.SOURCE_REF, "object": {"type": "commit",
                    "sha": "c" * 40 if self.mutation == "remote-moved" else SHA}}
        if endpoint.startswith("releases?per_page=100&page="):
            page = int(endpoint.rsplit("=", 1)[1])
            pages = self.pages if self.pages is not None else [[self.release]]
            return copy.deepcopy(pages[page - 1] if page <= len(pages) else [])
        if endpoint.endswith("/assets?per_page=100"):
            rows = copy.deepcopy(self.rows)
            if self.downloads:
                for row in rows: row["download_count"] = 1
                if self.mutation == "asset-replaced": rows[0]["id"] += 10
            return rows
        if endpoint == "releases/42":
            checks = sum(path == endpoint and verb == "GET" for path, verb, _ in self.calls)
            if checks == 1 and self.mutation == "changed-before-upload":
                (self.fixture.destination / "Madeira-unsigned.ipa").write_bytes(b"changed")
            if checks == 2:
                if self.mutation == "published-before-first-asset": self.release["draft"] = False
                if self.mutation == "retargeted-before-first-asset": self.release["target_commitish"] = "c" * 40
                if self.mutation == "body-changed-before-first-asset": self.release["body"] = "changed"
            return copy.deepcopy(self.release)
        raise AssertionError(endpoint)

    def run(self, *args, **kwargs):
        raise AssertionError("Uploads must use the verified release ID, never resolve a tag")

    def upload_asset(self, release_id, path, expected):
        assert release_id == 42 and path.name in delivery.ASSETS
        self.writes.append(("upload-asset", release_id, str(path)))
        if self.mutation == "upload-error": raise ValueError("Synthetic upload failure; no retry")
        row = {"id": 100 + delivery.ASSETS.index(path.name), "name": path.name,
               "state": "uploaded", "size": expected["bytes"],
               "digest": "sha256:" + expected["sha256"] if self.digest else None}
        self.rows.append(row)
        if self.mutation == "missing-asset": self.rows.pop()
        if self.mutation == "extra-asset": self.rows.append({"id": 111, "name": "Payload"})
        if self.mutation == "wrong-size": row["size"] += 1
        if self.mutation == "wrong-digest": row["digest"] = "sha256:" + "f" * 64
        if self.mutation == "not-uploaded": row["state"] = "starter"
        if self.mutation == "duplicate-id": row["id"] = 100
        if self.mutation == "published-after-upload": self.release["draft"] = False
        if self.mutation == "body-changed-after-upload": self.release["body"] = "changed"
        return copy.deepcopy(row)

    def download(self, asset_id, destination):
        self.downloads.append(asset_id)
        name = next(row["name"] for row in self.rows if row["id"] == asset_id)
        data = (self.fixture.destination / name).read_bytes()
        destination.write_bytes(b"corrupt" if self.mutation == "corrupt-download" else data)


class RequestTests(unittest.TestCase):
    def test_tag_is_deterministic_across_runs_and_attempts(self):
        with PackageFixture():
            first = delivery.preflight()
            with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "5678", "GITHUB_RUN_ATTEMPT": "3"}):
                second = delivery.preflight()
            self.assertEqual(first["tag"], "unsigned-ipa-20261005-" + SHA[:12])
            self.assertEqual(first["tag"], second["tag"])
            self.assertNotEqual(first["run_id"], second["run_id"])

    def test_real_git_diff_limits_request_to_reviewed_code(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
            git("init", "--quiet")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "user.name", "Fixture")
            fixtures.put(root / "app/Madeira/source.swift", b"reviewed source")
            git("add", ".")
            git("commit", "--quiet", "-m", "Reviewed app baseline")
            base = git("rev-parse", "HEAD")
            with mock.patch.object(delivery, "BASE_CODE_COMMIT", base), mock.patch.object(delivery, "ROOT", root), \
                    mock.patch.object(gate, "ROOT", root):
                fixtures.put(root / delivery.REQUEST_PATH, delivery.json_bytes(delivery.expected_request()))
                git("add", ".")
                git("commit", "--quiet", "-m", "Request unsigned draft delivery")
                sha = git("rev-parse", "HEAD")
                with mock.patch.dict(os.environ, {**ENV, "GITHUB_SHA": sha}, clear=True):
                    self.assertEqual(delivery.preflight(clean=True)["source_commit"], sha)
                fixtures.put(root / "app/Madeira/source.swift", b"unreviewed feature change")
                git("add", ".")
                git("commit", "--quiet", "-m", "Forbidden app change")
                with mock.patch.dict(os.environ, {**ENV, "GITHUB_SHA": git("rev-parse", "HEAD")}, clear=True), \
                        self.assertRaisesRegex(ValueError, "five-file allowlist"):
                    delivery.preflight(clean=True)

    def test_exact_request_accepts_push_and_dispatch_offline(self):
        with PackageFixture(), mock.patch.object(delivery, "GitHub") as gh:
            for event in ("push", "workflow_dispatch"):
                with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": event}):
                    self.assertEqual(delivery.preflight(clean=True)["source_commit"], SHA)
            gh.assert_not_called()

    def test_wrong_context_rejected(self):
        mutations = {"GITHUB_ACTIONS": "false", "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "0",
            "GITHUB_RUN_ATTEMPT": "", "GITHUB_EVENT_NAME": "pull_request"}
        with PackageFixture():
            for key, value in mutations.items():
                with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}), self.assertRaises(ValueError):
                    delivery.preflight()

    def test_request_mutations_rejected(self):
        with PackageFixture() as fx:
            for key, value in {"publish": True, "package_unsigned": False, "delivery": "release",
                               "schema_version": True, "required_msi_layers": ["desktop"], "extra": "private"}.items():
                request = delivery.expected_request()
                request[key] = value
                (fx.root / delivery.REQUEST_PATH).write_bytes(delivery.json_bytes(request))
                with self.subTest(key=key), self.assertRaises(ValueError): delivery.preflight()

    def test_code_diff_ancestor_and_dirty_checkout_rejected(self):
        for mutation in ("source-diff", "empty-diff", "missing-request", "ancestor", "dirty"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                original = fx.git
                def changed(*args):
                    if args[0] == "merge-base" and mutation == "ancestor": return "c" * 40
                    if args[0] == "diff" and "--no-renames" in args:
                        if mutation == "source-diff": return delivery.REQUEST_PATH + "\0app/Madeira/Changed.swift"
                        if mutation == "empty-diff": return ""
                        if mutation == "missing-request": return "build/app-ios/deliver_unsigned.py"
                    if args[0] == "diff" and "--no-renames" not in args and mutation == "dirty": return "app/Changed.swift"
                    return original(*args)
                fx.git_mock.side_effect = changed
                with self.assertRaises(ValueError): delivery.preflight(clean=True)


class PackageTests(unittest.TestCase):
    def test_real_app_zip_verifiers_and_exact_offline_outputs(self):
        with PackageFixture() as fx, mock.patch.object(delivery, "GitHub") as gh, \
                mock.patch.object(gate, "validate_app", wraps=gate.validate_app) as app, \
                mock.patch.object(gate, "verify_zip", wraps=gate.verify_zip) as ipa:
            result = fx.prepare()
            self.assertEqual(result["status"], "verified-offline")
            self.assertEqual({p.name for p in fx.destination.iterdir()}, delivery.OUTPUTS)
            self.assertEqual((fx.destination / "provenance.json").read_bytes(), (fx.stage / "provenance.json").read_bytes())
            self.assertEqual(app.call_count, 2)
            self.assertEqual(ipa.call_count, 2)
            gh.assert_not_called()
            notes = (fx.destination / "release-notes.md").read_text()
            for phrase in ("does not sign", "draft", "COPYING", "Wine-MSI-startup-SOURCE-REBUILD.md",
                           "development signing", "get-task-allow", "MadeiraJITHelper", "docs/JIT.md", SHA):
                self.assertIn(phrase, notes)
            self.assertNotIn("draft status unchanged", notes)
            self.assertIn(f"/tree/{SHA}\n", notes)
            self.assertIn(f"/blob/{SHA}/docs/JIT.md", notes)

    def test_checksum_comments_work_with_available_real_verifiers(self):
        commands = [(tool, executable) for tool in ("sha256sum", "shasum")
                    if (executable := shutil.which(tool))]
        self.assertTrue(commands, "A real checksum verifier is required for this portability test")
        with PackageFixture() as fx:
            fx.prepare()
            sums = (fx.destination / "SHA256SUMS").read_text()
            self.assertIn(f"# Source commit: {SHA}\n", sums)
            self.assertIn("/actions/runs/1234/attempts/2\n", sums)
            self.assertEqual(len([line for line in sums.splitlines() if not line.startswith("#")]), 2)
            for tool, executable in commands:
                args = [executable, *(["-a", "256"] if tool == "shasum" else []), "--check", "SHA256SUMS"]
                with self.subTest(tool=tool):
                    result = subprocess.run(args, cwd=fx.destination, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("WARNING", result.stderr)

    def test_packaging_receipt_mutations_rejected(self):
        mutations = {"status": "failed", "source_commit": "c" * 40,
            "packaging": {"requested": False, "status": "not_requested"}, "ipa_sha256": "f" * 64,
            "ipa_bytes": 1, "schema_version": True, "signing": "signed", "scope": gate.SCOPE,
            "app_source_sha256": {}, "resources_sha256": {}, "guest_pe": {}, "private_data": "must never upload",
            "graphics_receipt_sha256": {}, "app": {}}
        for key, value in mutations.items():
            with self.subTest(key=key), PackageFixture() as fx:
                fx.receipt[key] = value
                fx.write_receipt()
                with self.assertRaises(ValueError): fx.verify()

    def test_unrequested_or_signed_command_rejected(self):
        for mutation in ("archive", "signed", "relative"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                if mutation == "archive": fx.receipt["build_command"][-1] = "archive"
                if mutation == "signed": fx.receipt["build_command"].append("CODE_SIGNING_ALLOWED=YES")
                if mutation == "relative": fx.receipt["build_command"][14] = "SYMROOT=relative"
                fx.write_receipt()
                with self.assertRaises(ValueError): fx.verify()

    def test_missing_msi_layer_rejected_even_with_self_consistent_receipt(self):
        with PackageFixture() as fx:
            expected = copy.deepcopy(fx.receipt["guest_pe"])
            expected["msi_startup_stage_seal_sha256"] = None
            fx.receipt["guest_pe"] = expected
            fx.write_receipt()
            with mock.patch.object(gate, "guest_pe_evidence", return_value=expected), self.assertRaises(ValueError): fx.verify()

    def test_stage_source_and_payload_mutations_rejected(self):
        for mutation in ("private-stage-file", "stage-link", "ipa-link", "modified-source", "native-receipt",
                         "changed-app", "missing-placeholder", "extra-payload"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                if mutation == "private-stage-file": fixtures.put(fx.stage / "private.txt")
                if mutation == "stage-link":
                    actual = fx.temp / "actual-stage"
                    fx.stage.rename(actual)
                    fx.stage.symlink_to(actual, target_is_directory=True)
                if mutation == "ipa-link":
                    target = fx.temp / "real.ipa"
                    (fx.stage / delivery.ASSETS[0]).rename(target)
                    (fx.stage / delivery.ASSETS[0]).symlink_to(target)
                if mutation == "modified-source": (fx.root / "app/Madeira/cacert.pem").write_bytes(b"changed")
                if mutation == "native-receipt": fx.native.write_bytes(b"changed")
                if mutation == "changed-app": (fx.app / "cacert.pem").write_bytes(b"changed")
                if mutation == "missing-placeholder": (fx.app / "x86_64-vcruntime").rmdir()
                if mutation == "extra-payload": fixtures.put(fx.stage / "Payload/secret")
                with self.assertRaises((ValueError, OSError)): fx.verify()

    def test_zip_rewrite_fails_even_if_outer_hash_receipt_was_updated(self):
        with PackageFixture() as fx:
            with zipfile.ZipFile(fx.stage / delivery.ASSETS[0], "a") as archive:
                archive.writestr("Payload/Madeira.app/private", b"unapproved")
            fx.receipt.update({"ipa_sha256": gate.digest(fx.stage / delivery.ASSETS[0]),
                "ipa_bytes": (fx.stage / delivery.ASSETS[0]).stat().st_size})
            fx.write_receipt()
            with self.assertRaises(ValueError): fx.verify()

    def test_asset_size_limit_is_exclusive_before_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / "asset"
            for size in (0, 2 * 1024 ** 3):
                with path.open("wb") as stream: stream.truncate(size)
                with mock.patch.object(gate, "digest") as digest, self.assertRaises(ValueError): delivery.identity(path)
                digest.assert_not_called()

    def test_fresh_delivery_and_metadata_integrity(self):
        with PackageFixture() as fx:
            fx.prepare()
            with self.assertRaises(ValueError): fx.prepare()
            context, package = fx.verify()
            for name in delivery.OUTPUTS:
                path = fx.destination / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.subTest(name=name), self.assertRaises(ValueError): delivery.check_delivery(fx.destination, context, package)
                path.write_bytes(original)


class DraftCheckTests(unittest.TestCase):
    def test_body_accepts_only_crlf_normalization_and_no_other_text_changes(self):
        with PackageFixture() as fx:
            gh = FakeGitHub(fx)
            original = gh.release["body"]
            gh.release["body"] = original.replace("\n", "\r\n")
            with mock.patch.object(delivery, "GitHub", return_value=gh):
                self.assertEqual(delivery.draft_check()["release_id"], 42)
            for changed in (original.replace("\n", "\r", 1), original[:-1], original + " ",
                            original.replace("Reserved", "Completed", 1), None):
                gh.release["body"] = changed
                with self.subTest(body=repr(changed)[:60]), mock.patch.object(delivery, "GitHub", return_value=gh), \
                        self.assertRaises(ValueError):
                    delivery.draft_check()
            self.assertFalse(gh.writes)

    def test_offline_draft_body_needs_only_sha_and_claims_no_completed_build(self):
        args = ["deliver_unsigned.py", "--mode", "draft-body", "--source-commit", SHA]
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "argv", args), \
                mock.patch.object(delivery, "preflight") as preflight, mock.patch.object(delivery, "GitHub") as gh, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            delivery.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result["body"], delivery.release_notes(SHA))
        self.assertEqual(result["tag"], "unsigned-ipa-20261005-" + SHA[:12])
        self.assertEqual(result["target_commitish"], SHA)
        self.assertIn("may be empty or incomplete", result["body"])
        self.assertIn("After upload, SHA256SUMS records the actual Actions run/attempt", result["body"])
        self.assertNotIn("integrity passed", result["body"])
        self.assertNotIn("/actions/runs/", result["body"])
        preflight.assert_not_called()
        gh.assert_not_called()
        for invalid in (None, "", "b" * 39, "b" * 41, "B" * 40, "g" * 40, SHA + "\n", 12):
            with self.subTest(sha=invalid), self.assertRaises(ValueError): delivery.draft_body(invalid)

    def test_body_depends_only_on_source_not_run_or_asset_identities(self):
        with PackageFixture() as fx:
            context, assets = fx.verify()
            _, first = delivery.delivery_metadata(context, assets)
            other_context = {**context, "run_id": "5678", "run_attempt": "3"}
            other_assets = {name: {"bytes": 1, "sha256": "f" * 64} for name in assets}
            _, second = delivery.delivery_metadata(other_context, other_assets)
            self.assertEqual(first["release-notes.md"], second["release-notes.md"])
            self.assertNotEqual(first["SHA256SUMS"], second["SHA256SUMS"])
            self.assertNotEqual(delivery.release_notes(SHA), delivery.release_notes("c" * 40))

    def test_paginated_empty_draft_discovery_uses_only_get_and_no_build_proof(self):
        with PackageFixture() as fx:
            gh = FakeGitHub(fx)
            gh.pages = [[{"id": 1000 + index, "tag_name": f"unrelated-{index}"} for index in range(100)],
                        [gh.release]]
            with mock.patch.object(delivery, "GitHub", return_value=gh), \
                    mock.patch.object(gate, "prerequisites") as native, \
                    mock.patch.object(gate, "resource_inputs") as resources:
                result = delivery.draft_check()
            self.assertEqual(result["release_id"], 42)
            self.assertEqual(result["status"], "empty-draft-verified")
            self.assertEqual(result["tag"], "unsigned-ipa-20261005-" + SHA[:12])
            self.assertTrue(all(method == "GET" and data is None for _, method, data in gh.calls))
            self.assertEqual(sum(endpoint.startswith("releases?") for endpoint, _, _ in gh.calls), 2)
            self.assertFalse(gh.writes)
            self.assertFalse(gh.downloads)
            native.assert_not_called()
            resources.assert_not_called()

    def test_absent_ambiguous_incomplete_or_unstable_list_fails_closed(self):
        for mutation in ("absent", "ambiguous", "incomplete", "duplicate-id", "invalid-list", "invalid-row"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                gh = FakeGitHub(fx)
                if mutation == "absent": gh.pages = [[]]
                if mutation == "ambiguous": gh.pages = [[gh.release, {**gh.release, "id": 43}]]
                if mutation == "incomplete":
                    gh.pages = [[{"id": 1000 + page * 100 + index, "tag_name": f"other-{page}-{index}"}
                                 for index in range(100)] for page in range(delivery.MAX_RELEASE_PAGES)]
                if mutation == "duplicate-id": gh.pages = [[gh.release, gh.release]]
                if mutation == "invalid-list": gh.pages = [{"unexpected": "object"}]
                if mutation == "invalid-row": gh.pages = [[{"id": True, "tag_name": gh.context["tag"]}]]
                with mock.patch.object(delivery, "GitHub", return_value=gh), self.assertRaises(ValueError):
                    delivery.draft_check()
                self.assertFalse(gh.writes)
                self.assertLessEqual(sum(endpoint.startswith("releases?") for endpoint, _, _ in gh.calls),
                                     delivery.MAX_RELEASE_PAGES)

    def test_mismatched_nonempty_or_published_release_fails_without_writes(self):
        for mutation in ("published", "non-prerelease", "wrong-target", "wrong-tag", "wrong-id", "wrong-url",
                         "existing-assets", "private-repo", "remote-moved", "wrong-body"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                gh = FakeGitHub(fx, mutation=mutation)
                if mutation == "wrong-id": gh.pages = [[{**gh.release, "id": 42}]]
                with mock.patch.object(delivery, "GitHub", return_value=gh), \
                        self.assertRaises(ValueError):
                    delivery.draft_check()
                self.assertFalse(gh.writes)

    def test_cli_routes_draft_check_without_artifact_arguments(self):
        with mock.patch.object(sys, "argv", ["deliver_unsigned.py", "--mode", "draft-check"]), \
                mock.patch.object(delivery, "draft_check", return_value={"release_id": 42}) as check, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            delivery.main()
        check.assert_called_once_with()
        self.assertEqual(json.loads(output.getvalue()), {"release_id": 42})
        for extra in (("--release-id", "42"), ("--stage", "/tmp/stage")):
            with mock.patch.object(sys, "argv", ["deliver_unsigned.py", "--mode", "draft-check", *extra]), \
                    mock.patch.object(delivery, "draft_check") as check, self.assertRaises(ValueError):
                delivery.main()
            check.assert_not_called()


class UploadTests(unittest.TestCase):
    def test_success_always_downloads_all_three_even_with_api_digests(self):
        for digest in (True, False):
            with self.subTest(digest=digest), PackageFixture() as fx:
                fx.prepare()
                gh = FakeGitHub(fx, digest=digest)
                if digest: gh.release["body"] = gh.release["body"].replace("\n", "\r\n")
                with mock.patch.object(delivery, "GitHub", return_value=gh):
                    result = delivery.upload(fx.stage, fx.native, fx.destination, 42)
                self.assertEqual(result["status"], "draft-delivered-and-downloaded-verified")
                self.assertEqual(len(gh.downloads), 3)
                self.assertTrue(result["draft"])
                self.assertFalse(result["runtime_tested"])
                uploads = [row for row in gh.writes if row[0] == "upload-asset"]
                self.assertEqual(uploads, [("upload-asset", 42, str(fx.destination / name)) for name in delivery.ASSETS])
                self.assertTrue(all(method == "GET" and data is None for _, method, data in gh.calls))

    def test_invalid_remote_fails_before_any_mutation(self):
        for mutation in ("published", "non-prerelease", "wrong-target", "wrong-tag", "wrong-id", "wrong-url",
                         "existing-assets", "private-repo", "remote-moved", "wrong-body"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                fx.prepare()
                gh = FakeGitHub(fx, mutation=mutation)
                with mock.patch.object(delivery, "GitHub", return_value=gh), self.assertRaises(ValueError):
                    delivery.upload(fx.stage, fx.native, fx.destination, 42)
                self.assertFalse(gh.writes)

    def test_upload_failure_injections_never_retry_publish_or_replace(self):
        for mutation in ("upload-error", "missing-asset", "extra-asset", "wrong-size", "wrong-digest",
                         "not-uploaded", "duplicate-id", "corrupt-download", "asset-replaced",
                         "published-after-upload", "changed-before-upload", "body-changed-after-upload"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                fx.prepare()
                gh = FakeGitHub(fx, mutation=mutation)
                with mock.patch.object(delivery, "GitHub", return_value=gh), self.assertRaises(ValueError):
                    delivery.upload(fx.stage, fx.native, fx.destination, 42)
                uploads = [row for row in gh.writes if row[0] == "upload-asset"]
                self.assertEqual(len(uploads), len({row[2] for row in uploads}))
                if mutation in ("published-after-upload", "body-changed-after-upload"): self.assertEqual(len(uploads), 1)
                self.assertTrue(all(method == "GET" and data is None for _, method, data in gh.calls))

    def test_direct_upload_binds_fixed_host_id_and_raw_bytes_without_tag_lookup(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(os.environ, {"GH_TOKEN": "synthetic-token"}, clear=True), \
                mock.patch.object(shutil, "which", return_value="/usr/bin/gh"), \
                mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b'{"id":100}', b"")) as run:
            path = fixtures.put(Path(temp).resolve() / "Madeira-unsigned.ipa", b"synthetic IPA")
            expected = delivery.identity(path)
            with delivery.GitHub() as gh:
                self.assertEqual(gh.upload_asset(42, path, expected), {"id": 100})
                args = run.call_args.args[0]
                self.assertEqual(args[0:2], ["/usr/bin/gh", "api"])
                self.assertEqual(args[-1], "https://uploads.github.com/repos/Mi-Yomi/Madeira/releases/42/assets?name=Madeira-unsigned.ipa")
                self.assertEqual(args[args.index("--input") + 1], str(path))
                self.assertIn("Content-Type: application/octet-stream", args)
                self.assertIn(f"Content-Length: {expected['bytes']}", args)
                self.assertNotIn("synthetic-token", repr(args))
                self.assertNotIn("release", args)
                run.reset_mock()
                for release_id, filename in ((0, path.name), (True, path.name), (42, "private.txt")):
                    with self.assertRaises(ValueError): gh.upload_asset(release_id, path.parent / filename, expected)
                run.assert_not_called()

    def test_draft_or_target_change_at_final_preupload_check_sends_no_asset(self):
        for mutation in ("published-before-first-asset", "retargeted-before-first-asset", "body-changed-before-first-asset"):
            with self.subTest(mutation=mutation), PackageFixture() as fx:
                fx.prepare()
                gh = FakeGitHub(fx, mutation=mutation)
                with mock.patch.object(delivery, "GitHub", return_value=gh), self.assertRaises(ValueError):
                    delivery.upload(fx.stage, fx.native, fx.destination, 42)
                self.assertFalse(any(row[0] == "upload-asset" for row in gh.writes))

    def test_metadata_api_rejects_all_mutation_methods_and_payloads(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": "synthetic"}, clear=True), \
                mock.patch.object(shutil, "which", return_value="/usr/bin/gh"), \
                mock.patch.object(subprocess, "run") as run:
            with delivery.GitHub() as gh:
                for method in ("POST", "PATCH", "DELETE", "PUT"):
                    with self.subTest(method=method), self.assertRaises(TypeError):
                        gh.api("releases/42", method=method)
                with self.assertRaises(TypeError): gh.api("releases/42", data={"draft": False})
                run.assert_not_called()

    def test_modified_or_extra_local_output_fails_before_github_access(self):
        for name in (*delivery.ASSETS, "release-notes.md", "verification.json", "private.txt"):
            with self.subTest(name=name), PackageFixture() as fx:
                fx.prepare()
                fixtures.put(fx.destination / name, b"private or changed")
                with mock.patch.object(delivery, "GitHub") as gh, self.assertRaises(ValueError):
                    delivery.upload(fx.stage, fx.native, fx.destination, 42)
                gh.assert_not_called()

    def test_gh_uses_only_explicit_token_isolated_config_and_fixed_host(self):
        env = {"GH_TOKEN": "synthetic-ephemeral-token", "GITHUB_TOKEN": "ignored-token", "GH_HOST": "evil.example",
               "GH_DEBUG": "api", "GH_CONFIG_DIR": "/untrusted", "PATH": os.environ.get("PATH", "")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(shutil, "which", return_value="/usr/bin/gh"), \
                mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")) as run:
            with delivery.GitHub() as gh:
                self.assertEqual(gh.api("releases/42"), {})
                self.assertEqual(gh.env["GH_TOKEN"], env["GH_TOKEN"])
                self.assertNotIn("GITHUB_TOKEN", gh.env)
                self.assertNotIn("GH_DEBUG", gh.env)
                self.assertEqual(gh.env["GH_HOST"], "github.com")
                config = Path(gh.env["GH_CONFIG_DIR"])
                self.assertEqual(list(config.iterdir()), [])
            self.assertFalse(config.exists())
            self.assertNotIn(env["GH_TOKEN"], repr(run.call_args.args))
            self.assertIn("github.com", run.call_args.args[0])

    def test_missing_token_and_cli_failure_are_closed_without_retry(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            with delivery.GitHub(): pass
        with mock.patch.dict(os.environ, {"GH_TOKEN": "synthetic"}, clear=True), \
                mock.patch.object(shutil, "which", return_value="/usr/bin/gh"), \
                mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"secret detail")) as run:
            with delivery.GitHub() as gh, self.assertRaisesRegex(ValueError, "no retry"):
                gh.api("releases/42")
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
