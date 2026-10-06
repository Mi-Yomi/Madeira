#!/usr/bin/env python3
"""Portable fail-closed unsigned-app and packaging fixtures; never runs Xcode."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("app_gate", ROOT / "build/app-ios/build_unsigned.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
PROJECT = ROOT / "app/Madeira.xcodeproj/project.pbxproj"
DOCK_RESOURCES = ("arm64ec-windows/dockhost.exe", "arm64ec-windows/dock-notices.txt")


def object_text(identifier):
    text = PROJECT.read_text()
    start = re.search(r"\t\t" + identifier + r"(?: /\*[^\n]*?\*/)? = \{", text).end()
    line_end = text.index("\n", start)
    end = text.index("};", start) if "};" in text[start:line_end] else text.index("\n\t\t};", start)
    return text[start:end]


def shell_phase(identifier):
    encoded = re.search(r'shellScript = ("(?:[^"\\]|\\.)*");', object_text(identifier)).group(1)
    return json.loads(encoded)


def macho(kind=2, platform=2, cpu=0x0100000C):
    command = struct.pack("<6I", 0x32, 24, platform, 0x110000, 0x1B0000, 0)
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, kind, 1, 24, 0, 0) + command


def archive():
    data = macho(kind=1)
    header = f"{'native.o/':<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
    return b"!<arch>\n" + header + data


def put(path, data=b"fixture resource\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def fixture(app, *, include_dock=True):
    resources = {}
    for directory in gate.RESOURCE_DIRS:
        put(app / directory / "fixture.txt")
    for name in (*gate.RESOURCE_FILES, *gate.REQUIRED_NOTICES):
        put(app / name)
    for name in ("aarch64-windows/example.dll", "arm64ec-windows/example.exe"):
        put(app / name, b"MZ fixture tracked PE")
    if include_dock:
        put(app / DOCK_RESOURCES[0], b"MZ fixture source-built Dock PE")
        put(app / DOCK_RESOURCES[1], b"fixture source-built Dock notices\n")
    (app / "x86_64-vcruntime").mkdir()
    put(app / "Assets.car")
    put(app / "default.metallib", b"MTLB fixture app shaders")
    for relative, executable, kind in (("", "Madeira", "APPL"),
            ("PlugIns/MadeiraJITHelper.appex", "MadeiraJITHelper", "XPC!"),
            ("Frameworks/StikJIT.framework", "StikJIT", "FMWK")):
        folder = app / relative
        put(folder / "Info.plist", plistlib.dumps({"CFBundleExecutable": executable,
            "CFBundlePackageType": kind, "CFBundleIdentifier": "fixture.Madeira" + {"APPL": "", "XPC!": ".JITHelper", "FMWK": ".StikJIT"}[kind],
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.ar.viewer"},
            "CFBundleSupportedPlatforms": ["iPhoneOS"]}))
        put(folder / executable, macho(kind=6 if kind == "FMWK" else 2)).chmod(0o755)
    put(app / gate.CONVERTER, macho(kind=6)).chmod(0o755)
    for directory in gate.RESOURCE_DIRS:
        resources.update({directory + "/" + name: value for name, value in gate.tree_files(app / directory).items()})
    resources.update({name: gate.digest(app / name) for name in gate.RESOURCE_FILES})
    return resources, gate.digest(app / "Frameworks/StikJIT.framework/StikJIT"), gate.digest(app / gate.CONVERTER)


def farm_resources(resources):
    """Generated Dock outputs are part of the final app, never the tracked farm."""
    return {name: value for name, value in resources.items() if name not in DOCK_RESOURCES}


def dock_evidence(resources):
    # Generic app suites mock the source-build validator. The dedicated Dock
    # suite exercises actual source, PE, receipt and copy validation.
    return {"schema_version": 1, "source_commit": "a" * 40,
            "source": {}, "recipe_sha256": {}, "toolchain": {}, "run": {},
            "outputs_sha256": {Path(name).name: resources[name] for name in DOCK_RESOURCES},
            "pe": {}, "scope": "synthetic Dock build fixture"}


def zip_payload(path, payload):
    with zipfile.ZipFile(path, "w") as archive:
        archive.write(payload, "Payload/")
        for member in sorted(payload.rglob("*")):
            archive.write(member, "Payload/" + member.relative_to(payload).as_posix())


class ProjectTests(unittest.TestCase):
    def test_all_archive_references_resolve_from_madeira_group(self):
        group = object_text("A4000004")
        self.assertRegex(group, r"path = Madeira;")
        self.assertIn('sourceTree = "<group>";', group)
        archives = set()
        references = re.findall(r"\b([AB][0-9A-F]{7}) /\*[^\n]*?\*/", group)
        for identifier in references:
            body = object_text(identifier)
            if "lastKnownFileType = archive.ar;" not in body:
                continue
            self.assertIn('sourceTree = "<group>"', body)
            path = re.search(r'\bpath = ("[^"]+"|[^;]+);', body).group(1).strip('"')
            resolved = (ROOT / "app/Madeira" / path).resolve()
            self.assertTrue(resolved.is_relative_to(ROOT))
            archives.add(resolved.relative_to(ROOT).as_posix())
        expected = set(gate.common.native_validator().EXPECTED_ARCHIVES)
        expected.remove("build/freetype-ios/build/libfreetype.a")  # folded into win32u; not an Xcode reference
        expected.add("app/Madeira/libdxmt_combined.a")
        self.assertEqual(archives, expected)

    def test_sdk_and_source_root_references_do_not_inherit_group_path(self):
        framework = object_text("B2000030")
        self.assertIn("sourceTree = SOURCE_ROOT", framework)
        self.assertIn("path = Frameworks/StikJIT.xcframework", framework)
        for identifier in ("A2000016", "A2000035", "A2000042", "A2000052", "A2000053", "A2000054"):
            self.assertIn("sourceTree = SDKROOT", object_text(identifier))

    def test_helper_dependency_embed_and_deployment_targets_preserved(self):
        app = object_text("A5000001")
        self.assertIn("B3000006 /* PBXTargetDependency */", app)
        self.assertIn("B3000003 /* Embed JIT Helper */", app)
        self.assertIn("B3000007 /* Embed StikJIT */", app)
        self.assertIn("target = B5000001 /* MadeiraJITHelper */;", object_text("B3000006"))
        self.assertIn('productType = "com.apple.product-type.app-extension";', object_text("B5000001"))
        self.assertIn("dstSubfolderSpec = 13;", object_text("B3000003"))
        for config in ("B8000001", "B8000002"):
            self.assertIn("IPHONEOS_DEPLOYMENT_TARGET = 26.0;", object_text(config))
            self.assertIn('"@executable_path/../../Frameworks"', object_text(config))
        self.assertIn('[ "$CODE_SIGNING_ALLOWED" != "NO" ]', shell_phase("B3000007"))

    def test_unsigned_shell_never_signs_and_still_validates_licenses(self):
        for identity in ("", "fixture identity"):
            for mutation in (None, "missing", "stale", "missing-source"):
                with self.subTest(identity=identity, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    app = root / "product/Madeira.app"
                    (root / "app").mkdir()
                    for dst, src in gate.GENERATED_LICENSES.items():
                        put(root / src, src.encode())
                        put(app / dst, src.encode())
                    target = app / next(iter(gate.GENERATED_LICENSES))
                    if mutation == "missing": target.unlink()
                    elif mutation == "stale": target.write_text("stale")
                    elif mutation == "missing-source": (root / "COPYING").unlink()
                    put(app / gate.CONVERTER)
                    marker = root / "codesign-called"
                    mock_sign = put(root / "bin/codesign", f'#!/bin/sh\ntouch "{marker}"\nexit 99\n'.encode())
                    mock_sign.chmod(0o755)
                    result = subprocess.run(["/bin/sh", "-c", shell_phase("A30000D1")], capture_output=True, text=True,
                        env={**os.environ, "PATH": str(mock_sign.parent) + ":/usr/bin:/bin", "SRCROOT": str(root / "app"),
                             "CODESIGNING_FOLDER_PATH": str(app), "CODE_SIGNING_ALLOWED": "NO",
                             "EXPANDED_CODE_SIGN_IDENTITY": identity})
                    self.assertEqual(result.returncode == 0, mutation is None, result.stderr + result.stdout)
                    self.assertFalse(marker.exists())


class SafetyTests(unittest.TestCase):
    def test_fresh_outputs_reject_existing_nested_and_symlink_leaves(self):
        for mutation in ("directory", "file", "link", "nested", "same", "parent-traversal"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                paths = [root / name for name in ("products", "intermediates", "stage")]
                if mutation == "directory": paths[0].mkdir()
                elif mutation == "file": paths[0].write_text("old")
                elif mutation == "link": paths[0].symlink_to(root / "absent")
                elif mutation == "nested": paths[2] = paths[0] / "nested"
                elif mutation == "same": paths[2] = paths[0]
                elif mutation == "parent-traversal": paths[0] = root / "unused/../products"
                with self.assertRaises(ValueError): gate.fresh_outputs(*paths)

    def test_output_parent_alias_canonicalized_but_leaf_never_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "real").mkdir()
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            result = gate.fresh_outputs(*(root / "alias" / name for name in ("products", "intermediates", "stage")))
            self.assertEqual(result, [root / "real" / name for name in ("products", "intermediates", "stage")])

    def test_build_flags_are_exact_and_do_not_select_scheme_or_signing(self):
        command = gate.build_command(Path("/fresh/products"), Path("/fresh/intermediates"))
        self.assertEqual(command, ["xcodebuild", "-project", "app/Madeira.xcodeproj", "-target", "Madeira", "-configuration", "Debug",
            "-sdk", "iphoneos", "-arch", "arm64", "-jobs", "2", "-hideShellScriptEnvironment", "SYMROOT=/fresh/products",
            "OBJROOT=/fresh/intermediates", "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO", "CODE_SIGN_IDENTITY=",
            "DEVELOPMENT_TEAM=", "PROVISIONING_PROFILE_SPECIFIER=", "build"])
        source = (ROOT / "build/app-ios/build_unsigned.py").read_text()
        for forbidden in ("-allowProvisioningUpdates", "-allowProvisioningDeviceRegistration", "-exportArchive", "-archivePath",
                          "actions/cache", "actions/upload-artifact", "-scheme", "IPHONEOS_DEPLOYMENT_TARGET=", 'run(["codesign"'):
            self.assertNotIn(forbidden, source)

    def test_stale_output_stops_before_receipts_or_xcode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "products").mkdir()
            with mock.patch.object(gate, "prerequisites") as preflight, mock.patch.object(gate, "run") as run:
                with self.assertRaises(ValueError): gate.build(root / "receipt", root / "products", root / "obj", root / "stage")
            preflight.assert_not_called()
            run.assert_not_called()

    def test_archive_hashes_and_exact_sets(self):
        native = gate.common.native_validator()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            put(root / "first.a", archive())
            expected = {"first.a": native.validate_archive(root / "first.a")}
            with mock.patch.object(gate, "ROOT", root):
                gate.verify_archives(native, expected, ["first.a"])
                for mutation in (None, {}, {**expected, "extra.a": expected["first.a"]}, {"first.a": {**expected["first.a"], "sha256": "0" * 64}}):
                    with self.assertRaises(ValueError): gate.verify_archives(native, mutation, ["first.a"])
                (root / "first.a").unlink()
                with self.assertRaises(ValueError): gate.verify_archives(native, expected, ["first.a"])

    def test_resource_inputs_reject_untracked_missing_notices_and_extra_runtimes(self):
        for mutation in (None, "untracked", "missing-notice", "missing-pe", "invalid-pe", "32-bit", "vc-runtime"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                app = root / "app/Madeira"
                resources, _, _ = fixture(app)
                # Source inventory contains resources, not built app products.
                for name in DOCK_RESOURCES:
                    (app / name).unlink()
                resources = farm_resources(resources)
                for target, source in gate.GENERATED_LICENSES.items():
                    put(root / source, (app / target).read_bytes())
                names = ["app/Madeira/" + name for name in resources if name not in gate.GENERATED_LICENSES]
                if mutation == "untracked": put(app / "arm64ec-windows/untracked.dll", b"MZ")
                elif mutation == "missing-notice":
                    name = "d3d12/NOTICE.txt"
                    names.remove("app/Madeira/" + name)
                    (app / name).unlink()
                elif mutation == "missing-pe":
                    names.remove("app/Madeira/aarch64-windows/example.dll")
                    (app / "aarch64-windows/example.dll").unlink()
                elif mutation == "invalid-pe": (app / "aarch64-windows/example.dll").write_bytes(b"not PE")
                elif mutation == "32-bit":
                    names.append("app/Madeira/i386-windows/new.dll")
                    put(app / "i386-windows/new.dll", b"MZ")
                elif mutation == "vc-runtime": put(app / "x86_64-vcruntime/new.dll", b"MZ")
                # The paired source-built overlay has its own end-to-end suite;
                # these fixtures isolate the existing base-resource policy.
                with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate, "git", return_value="\0".join(names) + "\0"), \
                        mock.patch.object(gate.verify_desktop_integration, "validate"):
                    if mutation is None:
                        actual, pe = gate.resource_inputs()
                        self.assertEqual(actual, resources)
                        self.assertEqual(len(pe), 2)
                    else:
                        with self.assertRaises(ValueError): gate.resource_inputs()

    def test_receipt_paths_cannot_escape_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            put(root / "file")
            (root / "link").symlink_to(root / "file")
            for path in ("../file", "/file", "dir/../file", "dir//file", "dir\\file", "link"):
                with self.subTest(path=path), self.assertRaises(ValueError): gate.relative_file(root, path)


class BuildModeTests(unittest.TestCase):
    def exercise_build(self, root, mode, mutation=None):
        """Synthetic Mach-O/ZIP fixtures only: never launches Xcode or ditto."""
        seed = root / "synthetic/Madeira.app"
        resources, framework, converter = fixture(seed)
        dock_build = dock_evidence(resources)
        source_resources = farm_resources(resources)
        put(root / "app/Madeira/source.c", b"fixture source")
        put(root / gate.FRAMEWORK_SOURCE, (seed / "Frameworks/StikJIT.framework/StikJIT").read_bytes())
        receipt = put(root / "native/provenance.json", b"fixture native receipt")
        products, intermediates, stage = (root / name for name in ("products", "objects", "diagnostics"))
        evidence = {"source_commit": "a" * 40, "native_receipt_sha256": gate.digest(receipt),
                    "prerequisite_sha256": {gate.FRAMEWORK_SOURCE: framework}, "scope": gate.SCOPE}
        pe = {name: value for name, value in source_resources.items() if name.endswith((".dll", ".exe"))}
        calls = []
        def fake_run(args):
            calls.append(list(map(str, args)))
            if args[0] == "bash":
                self.assertEqual(args, ["bash", "build/stage-licenses.sh"])
            elif args[0] == "xcodebuild":
                shutil.copytree(seed, products / "Debug-iphoneos/Madeira.app")
            elif args[0] == "ditto" and args[1] == "--norsrc":
                shutil.copytree(args[2], args[3])
                if mutation == "staged-app": (Path(args[3]) / "Madeira").write_bytes(macho(platform=1))
            elif args[0] == "ditto" and args[1] == "-c":
                zip_payload(args[-1], args[-2])
                if mutation == "zip": Path(args[-1]).write_bytes(b"invalid synthetic ZIP")
            else:
                raise AssertionError(args)
        def fake_git(*args):
            if args == ("rev-parse", "--show-toplevel"): return str(root)
            if args == ("rev-parse", "HEAD"): return "a" * 40
            if args[0] == "ls-files": return "app/Madeira/source.c\0"
            raise AssertionError(args)
        def fake_output(args, **kwargs):
            if args == ["xcodebuild", "-version"]: return "Xcode 27.0\nBuild version fixture\n"
            if args == ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"]: return "27.0\n"
            if args == ["uname", "-m"]: return "arm64\n"
            raise AssertionError(args)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "ROOT", root))
            stack.enter_context(mock.patch.object(gate, "CONVERTER_SHA256", converter))
            stack.enter_context(mock.patch.object(gate.sys, "platform", "darwin"))
            stack.enter_context(mock.patch.object(gate, "prerequisites", return_value=evidence))
            stack.enter_context(mock.patch.object(gate, "resource_inputs", return_value=(source_resources, pe)))
            dock_validation = stack.enter_context(mock.patch.object(gate, "dock_inputs", return_value=dock_build))
            dock_staging = stack.enter_context(mock.patch.object(gate, "stage_dock"))
            stack.enter_context(mock.patch.object(gate, "git", side_effect=fake_git))
            stack.enter_context(mock.patch.object(gate.subprocess, "check_output", side_effect=fake_output))
            stack.enter_context(mock.patch.object(gate, "run", side_effect=fake_run))
            app_validation = stack.enter_context(mock.patch.object(gate, "validate_app", wraps=gate.validate_app))
            zip_validation = stack.enter_context(mock.patch.object(gate, "verify_zip", wraps=gate.verify_zip))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            # No keyword is passed in the ordinary mode, exercising the actual
            # function default, not only an explicit False test configuration.
            options = {} if mode == "default" else {"package": True}
            if mutation:
                with self.assertRaises((ValueError, zipfile.BadZipFile)):
                    gate.build(receipt, products, intermediates, stage, **options)
                self.assertFalse((stage / "provenance.json").exists())
                if mutation == "staged-app":
                    self.assertFalse((stage / "Madeira-unsigned.ipa").exists())
                    zip_validation.assert_not_called()
                else:
                    zip_validation.assert_called_once()
                return
            gate.build(receipt, products, intermediates, stage, **options)
            result = json.loads((stage / "provenance.json").read_text())
            summary = json.loads(output.getvalue())
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["dock_build"], dock_build)
            self.assertEqual(result["resources_sha256"], resources)
            self.assertEqual(dock_validation.call_count, 2)
            dock_staging.assert_called_once_with(products / "Debug-iphoneos/Madeira.app", dock_build)
            self.assertIn("CODE_SIGNING_ALLOWED=NO", result["build_command"])
            self.assertIn("CODE_SIGNING_REQUIRED=NO", result["build_command"])
            if mode == "default":
                self.assertEqual({path.name for path in stage.iterdir()}, {"provenance.json"})
                self.assertFalse(list(root.rglob("*.ipa")))
                self.assertFalse(any(call[0] == "ditto" for call in calls))
                self.assertEqual(app_validation.call_count, 1)
                zip_validation.assert_not_called()
                self.assertEqual(result["packaging"], {"requested": False, "status": "not_requested"})
                self.assertEqual(result["scope"], gate.SCOPE)
                self.assertEqual(summary["packaging"], "not_requested")
                self.assertNotIn("ipa_sha256", result)
                self.assertNotIn("ipa_bytes", summary)
            else:
                self.assertEqual(app_validation.call_count, 2)
                zip_validation.assert_called_once_with(stage / "Madeira-unsigned.ipa", stage / "Payload")
                self.assertEqual(len([call for call in calls if call[0] == "ditto"]), 2)
                self.assertEqual(result["packaging"], {"requested": True, "status": "passed"})
                self.assertEqual(result["ipa_sha256"], gate.digest(stage / "Madeira-unsigned.ipa"))
                self.assertEqual(result["scope"], gate.PACKAGE_SCOPE)
                self.assertEqual(summary["packaging"], "passed")

    def test_default_links_validates_and_writes_diagnostics_without_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            self.exercise_build(Path(directory).resolve(), "default")

    def test_explicit_package_opt_in_revalidates_app_and_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            self.exercise_build(Path(directory).resolve(), "package")

    def test_opt_in_cannot_bypass_package_validation(self):
        for mutation in ("staged-app", "zip"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                self.exercise_build(Path(directory).resolve(), "package", mutation)

    def test_cli_requires_explicit_package_flag(self):
        for extra, expected in (([], False), (["--package"], True)):
            args = ["build_unsigned.py", "--native-receipt", "native.json", "--products", "products",
                    "--intermediates", "objects", "--stage", "diagnostics", *extra]
            with self.subTest(extra=extra), mock.patch.object(gate.sys, "argv", args), mock.patch.object(gate, "build") as build:
                gate.main()
                build.assert_called_once_with(Path("native.json"), Path("products"), Path("objects"), Path("diagnostics"), package=expected)


class PreflightTests(unittest.TestCase):
    def make_receipts(self, root, native):
        """Match native-artifacts.collect and graphics receipt schemas exactly."""
        commit = "a" * 40
        native_archives = {}
        for name in native.EXPECTED_ARCHIVES:
            native_archives[name] = native.validate_archive(put(root / name, archive()))
        data = {"schema": 1, "stage": "native-dependencies-only", "dependencies_ready": True,
                "source_commit": commit, "source_repository": "https://github.com/Mi-Yomi/Madeira",
                "source_url": f"https://github.com/Mi-Yomi/Madeira/tree/{commit}", "submodules": [],
                "source_repairs": {"fixture": "reviewed"}, "fex_native_build": {"fixture": "native"},
                "archives": native_archives, "run": {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF": "refs/heads/compatibility/desktop-apps"}}
        for field, name in (("input_sha256", "build/native-input.sh"), ("notice_sha256", "app/Madeira/legal/notice.txt"),
                            ("generated_inputs_sha256", "wine/build-arm64ec/include/config.h")):
            put(root / name)
            data[field] = {name: gate.digest(root / name)}
        for name in ("ConfigValues.inl", "ConfigOptions.inl"):
            put(root / "FEX/build-ios/include/FEXCore/Config" / name)
        spec = gate.common.manifest()
        common_data = {"schema_version": 1, "revision": spec["revision"], "repository": spec["repository"],
                       "manifest_sha256": gate.digest(gate.common.MANIFEST_PATH)}
        host = dict(common_data, stage="host", outputs={})
        for name in ("llvm-dis", "llvm-tblgen"):
            host["outputs"][name] = gate.digest(put(root / "toolchains/llvm-host-build/bin" / name))
        ios = dict(common_data, stage="ios", outputs={})
        for name in spec["archives"]:
            path = f"toolchains/llvm-ios-build/lib/lib{name}.a"
            ios["outputs"][path] = native.validate_archive(put(root / path, archive()))
        combined_data = b"!<arch>\n" + archive()[8:] * 35
        unix = native.validate_archive(put(root / "build/dxmt-ios/libdxmt_unix.a", archive()))
        combined = native.validate_archive(put(root / "build/dxmt-ios/libdxmt_combined.a", combined_data))
        put(root / "app/Madeira/libdxmt_combined.a", combined_data)
        graphics = {"schema_version": 1, "manifest_sha256": common_data["manifest_sha256"],
                    "dxmt_revision": spec["dxmt_revision"], "llvm_revision": spec["revision"],
                    "unix_archive": unix, "combined_archive": combined, "llvm_archives": ios["outputs"], "input_object_members": 35}
        for name, document in zip(gate.GRAPHICS_RECEIPTS, (host, ios, {"fixture": "validated separately"}, graphics)):
            put(root / name, json.dumps(document).encode())
        put(root / "app/Madeira.xcodeproj/project.pbxproj")
        put(root / gate.FRAMEWORK_SOURCE, macho(kind=6))
        converter = put(root / "app/Madeira" / gate.CONVERTER, macho(kind=6))
        receipt = put(root / "native/provenance.json", json.dumps(data).encode())
        return data, receipt, gate.digest(converter)

    def test_complete_preflight_and_fail_closed_mutations(self):
        native = gate.common.native_validator()
        cases = (None, "missing-receipt", "source-commit", "repository", "source-url", "submodules", "not-ready", "archive-missing",
                 "archive-hash", "input-hash", "generated-hash", "notice-hash", "headers-missing", "config-options-missing",
                 "native-build-evidence", "host-receipt-missing", "host-hash", "llvm-receipt-missing", "llvm-output-hash",
                 "graphics-hash", "graphics-members", "shader-rejected", "converter", "changed-source", "changed-native-archive",
                 "changed-notice", "old-run", "old-attempt")
        for mutation in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
                root = Path(temporary).resolve()
                data, receipt, converter = self.make_receipts(root, native)
                if mutation == "source-commit": data["source_commit"] = "b" * 40
                elif mutation == "repository": data["source_repository"] = "https://github.com/other/Madeira"
                elif mutation == "source-url": data["source_url"] = "https://example.invalid"
                elif mutation == "submodules": data["submodules"] = [{"path": "wrong"}]
                elif mutation == "not-ready": data["dependencies_ready"] = False
                elif mutation == "archive-missing": del data["archives"][native.EXPECTED_ARCHIVES[0]]
                elif mutation == "archive-hash": data["archives"][native.EXPECTED_ARCHIVES[0]]["sha256"] = "0" * 64
                elif mutation in ("input-hash", "generated-hash", "notice-hash"):
                    field = {"input-hash": "input_sha256", "generated-hash": "generated_inputs_sha256", "notice-hash": "notice_sha256"}[mutation]
                    data[field][next(iter(data[field]))] = "0" * 64
                elif mutation == "headers-missing": shutil.rmtree(root / "FEX/build-ios/include")
                elif mutation == "config-options-missing": (root / "FEX/build-ios/include/FEXCore/Config/ConfigOptions.inl").unlink()
                elif mutation == "native-build-evidence": data["fex_native_build"] = {}
                elif mutation in ("host-receipt-missing", "llvm-receipt-missing"):
                    (root / gate.GRAPHICS_RECEIPTS[0 if mutation.startswith("host") else 1]).unlink()
                elif mutation in ("host-hash", "llvm-output-hash", "graphics-hash", "graphics-members"):
                    name = gate.GRAPHICS_RECEIPTS[0 if mutation == "host-hash" else 1 if mutation == "llvm-output-hash" else 3]
                    changed = json.loads((root / name).read_text())
                    if mutation == "host-hash": changed["outputs"]["llvm-dis"] = "0" * 64
                    elif mutation == "llvm-output-hash": changed["outputs"][next(iter(changed["outputs"]))]["sha256"] = "0" * 64
                    elif mutation == "graphics-hash": changed["combined_archive"]["sha256"] = "0" * 64
                    else: changed["input_object_members"] = 34
                    (root / name).write_text(json.dumps(changed))
                elif mutation == "converter": converter = "0" * 64
                elif mutation == "old-run": data["run"]["GITHUB_RUN_ID"] = "122"
                elif mutation == "old-attempt": data["run"]["GITHUB_RUN_ATTEMPT"] = "0"
                receipt.write_text(json.dumps(data))
                if mutation == "missing-receipt": receipt.unlink()
                changed = {"changed-source": "app/Madeira/ContentView.swift", "changed-native-archive": "app/Madeira/libgmp.a",
                           "changed-notice": "app/Madeira/legal/notice.txt"}.get(mutation, "")
                def git(*args):
                    if args == ("rev-parse", "HEAD"): return "a" * 40
                    if args[0] == "diff": return changed
                    raise AssertionError(args)
                for target, name, value in ((gate, "ROOT", root), (gate, "CONVERTER_SHA256", converter),
                                            (native, "source_modules", mock.Mock(return_value=[])),
                                            (native, "verified_fex_repairs", mock.Mock(return_value={"fixture": "reviewed"})),
                                            (native, "verified_fex_native_build", mock.Mock(return_value={"fixture": "native"}))):
                    stack.enter_context(mock.patch.object(target, name, value))
                stack.enter_context(mock.patch.object(gate, "git", side_effect=git))
                stack.enter_context(mock.patch.object(gate.common, "native_validator", return_value=native))
                stack.enter_context(mock.patch.object(gate.common, "check_dxmt"))
                stack.enter_context(mock.patch.object(gate.common, "check_revision"))
                stack.enter_context(mock.patch.object(gate.generate_shaders, "validate", side_effect=ValueError("stale shader") if mutation == "shader-rejected" else None))
                stack.enter_context(mock.patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                                                               "GITHUB_REF": "refs/heads/compatibility/desktop-apps"}))
                if mutation in (None, "changed-native-archive", "changed-notice"):
                    result = gate.prerequisites(receipt)
                    self.assertEqual(result["source_commit"], "a" * 40)
                    self.assertIn("FEX/build-ios/include/FEXCore/Config/ConfigValues.inl", result["prerequisite_sha256"])
                else:
                    with self.assertRaises((ValueError, FileNotFoundError)): gate.prerequisites(receipt)


class PackageTests(unittest.TestCase):
    def test_synthetic_valid_app_and_zip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            app = root / "Payload/Madeira.app"
            resources, framework, converter = fixture(app)
            with mock.patch.object(gate, "CONVERTER_SHA256", converter):
                result = gate.validate_app(app, resources, framework)
                self.assertEqual(len(result["images_sha256"]), 4)
            zip_payload(root / "test.ipa", root / "Payload")
            self.assertEqual(gate.verify_zip(root / "test.ipa", root / "Payload"), gate.digest(root / "test.ipa"))

    def test_rejects_missing_invalid_macho_bundles_and_resources(self):
        cases = ("app", "helper", "framework", "converter", "notice", "notices-evidence", "stale-license", "assets", "metallib", "bad-metallib", "helper-plist",
                 "app-plist", "framework-plist", "wrong-cpu", "simulator", "host", "object", "truncated", "bitcode", "converter-hash",
                 "framework-hash", "mode", "symlink", "signed", "profile", "extra-pe", "vc-runtime", "32-bit")
        for mutation in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                app = root / "Payload/Madeira.app"
                resources, framework, converter = fixture(app)
                main = app / "Madeira"
                if mutation in ("app", "helper", "framework", "converter", "notice", "assets", "metallib"):
                    name = {"app": "Madeira", "helper": "PlugIns/MadeiraJITHelper.appex/MadeiraJITHelper",
                            "framework": "Frameworks/StikJIT.framework/StikJIT", "converter": gate.CONVERTER,
                            "notice": gate.REQUIRED_NOTICES[0], "assets": "Assets.car", "metallib": "default.metallib"}[mutation]
                    (app / name).unlink()
                elif mutation == "notices-evidence": del resources[gate.REQUIRED_NOTICES[0]]
                elif mutation == "stale-license": (app / gate.REQUIRED_NOTICES[0]).write_text("stale")
                elif mutation == "bad-metallib": (app / "default.metallib").write_bytes(b"not a Metal library")
                elif mutation.endswith("-plist"):
                    name = {"helper-plist": "PlugIns/MadeiraJITHelper.appex", "framework-plist": "Frameworks/StikJIT.framework", "app-plist": ""}[mutation]
                    (app / name / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "wrong"}))
                elif mutation in ("wrong-cpu", "simulator", "host", "object", "truncated", "bitcode"):
                    main.write_bytes({"wrong-cpu": macho(cpu=0x01000007), "simulator": macho(platform=7), "host": macho(platform=1),
                                      "object": macho(kind=1), "truncated": macho()[:-1], "bitcode": b"BC\xc0\xde" + bytes(100)}[mutation])
                elif mutation == "converter-hash": converter = "0" * 64
                elif mutation == "framework-hash": framework = "0" * 64
                elif mutation == "mode": main.chmod(0o644)
                elif mutation == "symlink": (app / "unsafe").symlink_to(main)
                elif mutation == "signed": put(app / "_CodeSignature/CodeResources")
                elif mutation == "profile": put(app / "embedded.mobileprovision")
                elif mutation == "extra-pe": put(app / "arm64ec-windows/untracked.exe", b"MZ")
                elif mutation == "vc-runtime": put(app / "x86_64-vcruntime/unverified.dll", b"MZ")
                elif mutation == "32-bit": put(app / "Frameworks/host.dylib", macho(cpu=12))
                with mock.patch.object(gate, "CONVERTER_SHA256", converter), self.assertRaises((ValueError, FileNotFoundError)):
                    gate.validate_app(app, resources, framework)

    def test_zip_preserves_executable_bits_and_empty_runtime_placeholder(self):
        for mutation in ("mode", "missing-empty-dir"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                payload = root / "Payload"
                fixture(payload / "Madeira.app")
                path = root / "test.ipa"
                with zipfile.ZipFile(path, "w") as output:
                    output.write(payload, "Payload/")
                    for member in sorted(payload.rglob("*")):
                        if mutation == "missing-empty-dir" and member.name == "x86_64-vcruntime": continue
                        info = zipfile.ZipInfo.from_file(member, "Payload/" + member.relative_to(payload).as_posix())
                        if mutation == "mode" and member.name == "Madeira": info.external_attr = 0o100644 << 16
                        output.writestr(info, b"" if member.is_dir() else member.read_bytes())
                with self.assertRaises(ValueError): gate.verify_zip(path, payload)

    def test_zip_rejects_missing_payload_file_tamper_duplicate_and_unsafe(self):
        for mutation in ("missing-payload", "missing-helper", "changed", "extra", "duplicate", "traversal", "symlink", "extra-dir", "extra-payload"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                payload = root / "Payload"
                fixture(payload / "Madeira.app")
                path = root / "test.ipa"
                if mutation == "missing-payload":
                    with zipfile.ZipFile(path, "w") as output: output.writestr("Madeira.app/Madeira", b"wrong root")
                elif mutation in ("missing-helper", "changed"):
                    with zipfile.ZipFile(path, "w") as output:
                        for member in payload.rglob("*"):
                            if member.is_file():
                                if mutation == "missing-helper" and member.name == "MadeiraJITHelper": continue
                                name = "Payload/" + member.relative_to(payload).as_posix()
                                output.writestr(name, b"changed" if mutation == "changed" and member.name == "Madeira" else member.read_bytes())
                else:
                    zip_payload(path, payload)
                    with zipfile.ZipFile(path, "a") as output:
                        name = {"extra": "Payload/Madeira.app/extra", "duplicate": "Payload/Madeira.app/Madeira", "traversal": "Payload/../outside",
                                "symlink": "Payload/Madeira.app/link", "extra-dir": "Payload/unexpected/", "extra-payload": "Payload/Other.app/file"}[mutation]
                        if mutation == "symlink":
                            item = zipfile.ZipInfo(name); item.external_attr = 0o120777 << 16
                            output.writestr(item, "Madeira")
                        else:
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore", UserWarning)
                                output.writestr(name, "unverified")
                with self.assertRaises(ValueError): gate.verify_zip(path, payload)


if __name__ == "__main__":
    unittest.main()
