#!/usr/bin/env python3
"""Portable link-only CLI, command, failure, receipt and no-IPA fixtures."""
import contextlib
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/app-ios"))
import link_diagnostic as link

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

fixtures = load("app_link_fixtures", ROOT / "tests/host/check-app-bootstrap.py")
put = fixtures.put


class LinkTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, failure=False, extension="desktop"):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            base = Path(temporary).resolve()
            root = base / "source"
            products, objects, diagnostics = (base / n for n in ("products", "objects", "diagnostics"))
            seed = base / "fixture/Madeira.app"
            resources, framework, converter = fixtures.fixture(seed)
            for name in link.gate.verify_desktop_integration.DLLS:
                resources[name] = link.gate.digest(put(seed / name, b"MZ reviewed desktop fixture"))
            if extension in ("msi", "loader"):
                for name in link.gate.verify_msi_integration.BINARIES:
                    resources[name] = link.gate.digest(put(seed / name, b"MZ reviewed MSI fixture"))
            if extension == "loader":
                for name in link.gate.verify_loader_integration.BINARIES:
                    resources[name] = link.gate.digest(put(seed / name, b"MZ reviewed loader fixture"))
            put(root / "app/Madeira/source.c")
            put(root / link.gate.FRAMEWORK_SOURCE, (seed / "Frameworks/StikJIT.framework/StikJIT").read_bytes())
            native = put(base / "native/provenance.json", b"native fixture")
            request = put(root / "build/app-ios/link-diagnostic-request.json",
                          json.dumps(link.EXPECTED_REQUEST).encode())
            evidence = {"source_commit": "a" * 40, "native_receipt_sha256": link.gate.digest(native),
                        "prerequisite_sha256": {link.gate.FRAMEWORK_SOURCE: framework}, "scope": link.gate.SCOPE}
            pe = {name: value for name, value in resources.items() if name.endswith((".dll", ".exe"))}
            executed = []
            def fake_run(args):
                command = list(map(str, args))
                executed.append(command)
                if command[0] == "bash":
                    self.assertEqual(command, ["bash", "build/stage-licenses.sh"])
                elif command[0] == "xcodebuild":
                    self.assertIn("CODE_SIGNING_ALLOWED=NO", command)
                    self.assertIn("CODE_SIGNING_REQUIRED=NO", command)
                    self.assertEqual(command[command.index("-jobs") + 1], "2")
                    if failure:
                        raise subprocess.CalledProcessError(65, command)
                    shutil.copytree(seed, products / "Debug-iphoneos/Madeira.app")
                else:
                    self.fail("Forbidden executable launched: " + repr(command))
            def fake_git(*args):
                if args == ("rev-parse", "--show-toplevel"): return str(root)
                if args == ("rev-parse", "HEAD"): return "a" * 40
                if args[0] == "ls-files": return "app/Madeira/source.c\0"
                self.fail(repr(args))
            def fake_output(args, **kwargs):
                if args == ["xcodebuild", "-version"]: return "Xcode 27.0\nBuild version fixture\n"
                if args == ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"]: return "27.0\n"
                if args == ["uname", "-m"]: return "arm64\n"
                self.fail(repr(args))
            for module, name, value in ((link, "ROOT", root), (link, "REQUEST", request),
                    (link.gate, "ROOT", root), (link.gate, "CONVERTER_SHA256", converter),
                    (link.gate.sys, "platform", "darwin")):
                stack.enter_context(mock.patch.object(module, name, value))
            stack.enter_context(mock.patch.object(link.gate, "prerequisites", return_value=evidence))
            stack.enter_context(mock.patch.object(link.gate, "resource_inputs", return_value=(resources, pe)))
            stack.enter_context(mock.patch.object(link.gate, "git", side_effect=fake_git))
            stack.enter_context(mock.patch.object(link.gate.subprocess, "check_output", side_effect=fake_output))
            stack.enter_context(mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "PACKAGE": "true", "CREATE_IPA": "1"}))
            runner = stack.enter_context(mock.patch.object(link.gate, "run", side_effect=fake_run))
            zipper = stack.enter_context(mock.patch.object(link.gate.zipfile, "ZipFile", side_effect=AssertionError("ZIP invoked")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            yield native, products, objects, diagnostics, executed, runner, zipper

    def test_actual_app_driver_links_without_package_stage_ditto_or_zip(self):
        with self.fixture() as (native, products, objects, diagnostics, executed, runner, zipper):
            result = link.build(native, products, objects, diagnostics)
            self.assertFalse(result["ipa_created"])
            self.assertFalse(result["runtime_tested"])
            self.assertEqual(result["commands"], executed)
            self.assertEqual([cmd[0] for cmd in executed], ["bash", "xcodebuild"])
            self.assertIs(link.gate.run, runner)
            zipper.assert_not_called()
            self.assertEqual({p.name for p in diagnostics.iterdir()}, {"provenance.json", link.RECEIPT})
            self.assertFalse(list(products.parent.rglob("*.ipa")))
            self.assertFalse((diagnostics / "Payload").exists())
            self.assertEqual(link.verify(products, objects, diagnostics), result)

    def test_failed_link_produces_no_pass_receipt_and_never_packages(self):
        with self.fixture(failure=True) as (native, products, objects, diagnostics, executed, runner, zipper):
            with self.assertRaises(subprocess.CalledProcessError):
                link.build(native, products, objects, diagnostics)
            self.assertFalse(diagnostics.exists())
            self.assertIs(link.gate.run, runner)
            zipper.assert_not_called()
            self.assertEqual(link.scan(products, objects, diagnostics)["ipa_files"], 0)
            with self.assertRaises(ValueError):
                link.verify(products, objects, diagnostics)

    def test_legacy_msi_and_loader_receipts_use_exact_resource_contracts(self):
        statuses = {"desktop": "tracked-existing-plus-reviewed-source-built-desktop",
                    "msi": "tracked-existing-plus-reviewed-desktop-and-msi",
                    "loader": "tracked-existing-plus-reviewed-desktop-msi-and-loader"}
        for extension, status in statuses.items():
            with self.subTest(extension=extension), self.fixture(extension=extension) as args:
                native, products, objects, diagnostics, *_ = args
                result = link.build(native, products, objects, diagnostics)
                self.assertEqual(link.verify(products, objects, diagnostics), result)
                guest = json.loads((diagnostics / "provenance.json").read_text())["guest_pe"]
                self.assertEqual(guest["status"], status)
                self.assertEqual(len(guest["source_built_desktop_sha256"]), 12)
                self.assertEqual(len(guest["source_built_msi_sha256"]), 0 if extension == "desktop" else 14)
                self.assertEqual(len(guest["source_built_loader_sha256"]), 4 if extension == "loader" else 0)

    def test_extension_seals_hashes_status_and_final_resources_are_rechecked(self):
        for field in ("status", "msi_stage_seal_sha256", "loader_stage_seal_sha256",
                      "source_built_msi_sha256", "source_built_loader_sha256", "sha256"):
            with self.subTest(field=field), self.fixture(extension="loader") as args:
                native, products, objects, diagnostics, *_ = args
                link.build(native, products, objects, diagnostics)
                path = diagnostics / "provenance.json"; data = json.loads(path.read_text())
                if isinstance(data["guest_pe"][field], dict):
                    data["guest_pe"][field].pop(next(iter(data["guest_pe"][field])))
                else:
                    data["guest_pe"][field] = "unreviewed"
                path.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, "resource contract"):
                    link.verify(products, objects, diagnostics)
        with self.fixture(extension="loader") as args:
            native, products, objects, diagnostics, *_ = args
            link.build(native, products, objects, diagnostics)
            with mock.patch.object(link.gate, "resource_inputs", side_effect=ValueError("source resource changed")):
                with self.assertRaisesRegex(ValueError, "source resource changed"):
                    link.verify(products, objects, diagnostics)

    def test_runtime_guard_blocks_unexpected_commands_and_zip_entry(self):
        for bad in (["ditto", "-c", "-k"], ["zip", "bad.ipa"], ["codesign", "app"],
                    ["xcodebuild", "archive"], ["bash", "-c", "ditto"], "zip-function", "zip-api"):
            with self.subTest(bad=bad), self.fixture() as (native, products, objects, diagnostics, executed, runner, zipper):
                def bad_build(*args, **kwargs):
                    self.assertIs(kwargs["package"], False)
                    if bad == "zip-function": link.gate.verify_zip(None, None)
                    elif bad == "zip-api": link.gate.zipfile.ZipFile("bad.ipa", "w")
                    else: link.gate.run(bad)
                with mock.patch.object(link.gate, "build", side_effect=bad_build), self.assertRaises(ValueError):
                    link.build(native, products, objects, diagnostics)
                self.assertEqual(executed, [])
                self.assertIs(link.gate.run, runner)
                zipper.assert_not_called()
                self.assertFalse((diagnostics / link.RECEIPT).exists())

    def test_failure_finally_scan_catches_package_stage_even_without_commands(self):
        with self.fixture() as (native, products, objects, diagnostics, *_):
            def bad_build(*args, **kwargs):
                (diagnostics / "Payload").mkdir(parents=True)
                raise subprocess.CalledProcessError(65, "fixture")
            with mock.patch.object(link.gate, "build", side_effect=bad_build), self.assertRaisesRegex(ValueError, "package stage"):
                link.build(native, products, objects, diagnostics)
            self.assertFalse((diagnostics / link.RECEIPT).exists())

    def test_receipt_and_app_mutations_fail_independent_verification(self):
        cases = ("package", "ipa-field", "commit", "command", "guest", "app", "request", "diagnostic", "extra-file", "receipt-missing")
        for mutation in cases:
            with self.subTest(mutation=mutation), self.fixture() as (native, products, objects, diagnostics, *_):
                link.build(native, products, objects, diagnostics)
                path = diagnostics / "provenance.json"
                data = json.loads(path.read_text())
                if mutation == "package": data["packaging"]["requested"] = True
                elif mutation == "ipa-field": data["ipa_sha256"] = "0" * 64
                elif mutation == "commit": data["source_commit"] = "b" * 40
                elif mutation == "command": data["build_command"][-1] = "archive"
                elif mutation == "guest": data["guest_pe"]["source_built_desktop_sha256"].pop(next(iter(link.gate.verify_desktop_integration.DLLS)))
                elif mutation == "app": (products / "Debug-iphoneos/Madeira.app/Madeira").write_bytes(b"changed")
                elif mutation == "request": link.REQUEST.write_text('{}')
                elif mutation == "diagnostic": (diagnostics / link.RECEIPT).write_text('{}')
                elif mutation == "extra-file": put(diagnostics / "extra.json")
                elif mutation == "receipt-missing": (diagnostics / link.RECEIPT).unlink()
                if mutation in {"package", "ipa-field", "commit", "command", "guest"}:
                    path.write_text(json.dumps(data))
                with self.assertRaises(ValueError): link.verify(products, objects, diagnostics)

    def test_scan_catches_case_variants_hidden_outputs_and_checkout_ipa(self):
        for location in ("products/.hidden/Forbidden.IPA", "objects/old.xcarchive", "diagnostics/Payload", "source/bad.ipa"):
            with self.subTest(location=location), self.fixture() as (native, products, objects, diagnostics, *_):
                path = products.parent / location
                if location.endswith(("Payload", "xcarchive")): path.mkdir(parents=True)
                else: put(path)
                with self.assertRaisesRegex(ValueError, "Forbidden IPA"):
                    link.scan(products, objects, diagnostics)

    def test_reject_unsafe_or_reused_output_paths(self):
        with self.fixture() as (native, products, objects, diagnostics, *_):
            for invalid in (link.ROOT / "nested", link.ROOT.parent, objects, objects / "nested", products.parent / "x/../products",
                            products.parent / "bad.IPA", products.parent / "Payload"):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    link.outputs(invalid, objects, diagnostics)
            products.symlink_to(objects)
            with self.assertRaises(ValueError): link.outputs(products, objects, diagnostics)
            products.unlink()
            products.mkdir()
            with self.assertRaises(ValueError): link.build(native, products, objects, diagnostics)

    def test_fixed_request_has_no_mutable_runner_packaging_or_budget_knobs(self):
        with self.fixture():
            for field, value in (("ipa_creation", True), ("ipa_creation", 0), ("max_compile_jobs", 3),
                                 ("max_minutes", 46), ("runner", "xcode-27-large"), ("desktop_dll_count", 11),
                                 ("desktop_stage_seal_sha256", "0" * 64), ("extra", True)):
                with self.subTest(field=field, value=value):
                    data = dict(link.EXPECTED_REQUEST, **{field: value})
                    link.REQUEST.write_text(json.dumps(data))
                    with self.assertRaises(ValueError): link.request()

    def test_cli_cannot_receive_package_stage_or_passthrough_flags(self):
        base = ["build", "--native-receipt", "native.json", "--products", "products",
                "--intermediates", "objects", "--diagnostics", "diagnostics"]
        for extra in (["--package"], ["--pack"], ["--package=false"], ["--", "--package"],
                      ["--stage", "Payload"], ["CODE_SIGNING_ALLOWED=YES"], ["--jobs", "3"]):
            with self.subTest(extra=extra), mock.patch.object(link, "build") as build, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error: link.main(base + extra)
                self.assertEqual(error.exception.code, 2)
                build.assert_not_called()
        with mock.patch.object(link, "build") as build:
            link.main(base)
            build.assert_called_once_with(Path("native.json"), Path("products"), Path("objects"), Path("diagnostics"))


if __name__ == "__main__":
    unittest.main()
