#!/usr/bin/env python3
"""Portable failure fixtures for the bounded LLVM/AIR/DXMT graphics gate."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "build/llvm-ios"), str(ROOT / "build/dxmt-ios")]
import common
import build_llvm
import clean_build
import generate_shaders
import merge_archives


def macho(platform=2):
    command = struct.pack("<6I", 0x32, 24, platform, 0x110000, 0x1B0000, 0)
    return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 1, 1, 24, 0, 0) + command


class GraphicsTests(unittest.TestCase):
    def test_manifest_is_pinned_and_explicit(self):
        data = common.manifest()
        self.assertEqual(len(data["archives"]), 34)
        self.assertEqual(data["version"], "llvmorg-15.0.7")
        self.assertIn("LLVMBitWriter", data["archives"])
        self.assertIn("LLVMPasses", data["archives"])

    def test_rejects_changed_pin_and_duplicate_library(self):
        for field, value in (("revision", "a" * 40), ("archives", ["LLVMCore"] * 34),
                             ("archives", ["LLVMAnything", *common.EXPECTED_ARCHIVES[1:]])):
            data = common.manifest()
            data[field] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "manifest.json"
                path.write_text(json.dumps(data))
                with mock.patch.object(common, "MANIFEST_PATH", path), self.assertRaises(ValueError):
                    common.manifest()

    def test_disables_lto_assembly_and_optional_dependencies(self):
        opts = build_llvm.definitions()
        for key in ("LLVM_ENABLE_LTO", "CMAKE_INTERPROCEDURAL_OPTIMIZATION", "LLVM_ENABLE_ZSTD", "LLVM_ENABLE_ZLIB"):
            self.assertEqual(opts[key], "OFF")
        self.assertEqual(opts["LLVM_DISABLE_ASSEMBLY_FILES"], "ON")
        self.assertEqual(opts["LLVM_PARALLEL_COMPILE_JOBS"], "2")

    def test_environment_drops_cross_compiler_injection(self):
        with mock.patch.dict(os.environ, {"CC": "mingw", "CXXFLAGS": "-flto", "CMAKE_TOOLCHAIN_FILE": "evil", "SDKROOT": "macos"}):
            env = common.environment()
        for name in ("CC", "CXXFLAGS", "CMAKE_TOOLCHAIN_FILE", "SDKROOT"):
            self.assertNotIn(name, env)
        self.assertNotIn("mingw", env["PATH"])

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_text("source")
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(ValueError): common.regular_file(root / "link")

    def test_dxmt_nested_gitlinks_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dxmt/include/native/directx").mkdir(parents=True)
            for prefix in ("-", "+", "U", ""):
                status = (prefix + "a" * 40 + " include/native/directx\n") if prefix else ""
                with mock.patch.object(common, "ROOT", root), mock.patch.object(common, "check_revision"), \
                     mock.patch.object(common, "run", return_value=subprocess.CompletedProcess([], 0, status)), self.assertRaises(ValueError):
                    common.check_dxmt()
            with mock.patch.object(common, "ROOT", root), mock.patch.object(common, "check_revision"), \
                 mock.patch.object(common, "run", return_value=subprocess.CompletedProcess([], 0, " " + "a" * 40 + " include/native/directx\n")):
                common.check_dxmt()

    def test_exact_fresh_dxmt_objects_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in clean_build.OBJECTS: (root / (name + ".o")).write_bytes(macho())
            self.assertEqual(clean_build.verify_objects(root), 87)
            (root / "stale.o").write_bytes(macho())
            with self.assertRaises(ValueError): clean_build.verify_objects(root)
            (root / "stale.o").unlink()
            (root / "msc_canary.o").unlink()
            with self.assertRaises(ValueError): clean_build.verify_objects(root)

    def test_host_and_bitcode_dxmt_objects_rejected(self):
        for payload in (macho(1), b"BC\xc0\xde" + bytes(100)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in clean_build.OBJECTS: (root / (name + ".o")).write_bytes(macho())
                (root / "msc_canary.o").write_bytes(payload)
                with self.assertRaises(ValueError): clean_build.verify_objects(root)

    def test_existing_output_stops_before_any_build(self):
        for name in ("obj", "libdxmt_unix.a", "libdxmt_combined.a", "graphics-build.json"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "build/dxmt-ios" / name
                path.parent.mkdir(parents=True)
                path.write_text("old")
                with mock.patch.object(common, "ROOT", root), mock.patch.object(generate_shaders, "validate") as shader, self.assertRaises(ValueError):
                    clean_build.main()
                shader.assert_not_called()

    def test_stage_rolls_back_all_prior_replacements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {}
            for name in ("a", "b"):
                (root / (name + ".new")).write_text("new " + name)
                (root / name).write_text("old " + name)
                sources[root / name] = root / (name + ".new")
            original = os.replace
            count = 0
            def replace(source, destination):
                nonlocal count
                count += 1
                if count == 2: raise OSError("injected replacement failure")
                return original(source, destination)
            with mock.patch.object(merge_archives.os, "replace", side_effect=replace), self.assertRaises(OSError):
                merge_archives.stage_files(sources)
            self.assertEqual((root / "a").read_text(), "old a")
            self.assertEqual((root / "b").read_text(), "old b")
            self.assertEqual(len(list(root.iterdir())), 4)

    def test_stage_all_outputs_and_reject_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").write_text("new data")
            merge_archives.stage_files({root / "output": root / "source"})
            self.assertEqual((root / "output").read_text(), "new data")
            (root / "link").symlink_to(root / "output")
            with self.assertRaises(ValueError): merge_archives.stage_files({root / "link": root / "source"})

    def test_failed_rollback_preserves_backup_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {}
            for name in ("a", "b", "c"):
                (root / (name + ".new")).write_text("new " + name)
                (root / name).write_text("old " + name)
                sources[root / name] = root / (name + ".new")
            original = os.replace
            count = 0
            def replace(source, destination):
                nonlocal count
                count += 1
                if count in (3, 4): raise OSError("injected replacement/rollback failure")
                return original(source, destination)
            with mock.patch.object(merge_archives.os, "replace", side_effect=replace), self.assertRaisesRegex(OSError, "recovery backups retained"):
                merge_archives.stage_files(sources)
            self.assertEqual((root / "a").read_text(), "old a")
            self.assertEqual((root / "b").read_text(), "new b")
            self.assertEqual((root / "c").read_text(), "old c")
            backups = list(root.glob(".b.old-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), "old b")

    def test_merge_rejects_lost_duplicate_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build/dxmt-ios").mkdir(parents=True)
            validator = mock.Mock()
            validator.validate_archive.side_effect = [{"object_members": 2}, {"object_members": 3}]
            with mock.patch.object(common, "ROOT", root), mock.patch.object(common, "native_validator", return_value=validator), \
                 mock.patch.object(common, "verify_llvm_archives", return_value={"llvm.a": {"object_members": 2}}), \
                 mock.patch.object(common, "run"), mock.patch.object(merge_archives, "stage_files") as stage, self.assertRaises(ValueError):
                merge_archives.merge(root / "unix.a", 2)
            stage.assert_not_called()

    def test_failed_air_decoder_never_stages_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build/dxmt-ios").mkdir(parents=True)
            tool = root / "toolchains/llvm-host-build/bin/llvm-dis"
            tool.parent.mkdir(parents=True)
            tool.write_text("fixture")
            source = root / "dxmt/src/airconv/shaders/air_msad.metal"
            source.parent.mkdir(parents=True)
            source.write_text("fixture shader")
            def run(args, **kwargs):
                if args[0] == "xcrun":
                    Path(args[-1]).write_bytes(b"fixture AIR")
                    return subprocess.CompletedProcess(args, 0)
                raise subprocess.CalledProcessError(1, args)
            with mock.patch.object(common, "ROOT", root), mock.patch.object(common, "check_dxmt"), \
                 mock.patch.object(common, "run", side_effect=run), self.assertRaises(subprocess.CalledProcessError):
                generate_shaders.generate()
            self.assertFalse((root / "build/dxmt-ios/shader-headers").exists())
            self.assertEqual(list((root / "build/dxmt-ios").iterdir()), [])

    def test_shader_receipt_rejects_missing_extra_and_changed_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            headers = root / "build/dxmt-ios/shader-headers"
            headers.mkdir(parents=True)
            tool = root / "toolchains/llvm-host-build/bin/llvm-dis"
            tool.parent.mkdir(parents=True)
            tool.write_text("fixture llvm-dis")
            with mock.patch.object(common, "ROOT", root), mock.patch.object(common, "check_dxmt"), \
                 mock.patch.object(generate_shaders, "TESS_ORIGINAL_SHA256", hashlib.sha256(b"fixture source").hexdigest()), \
                 mock.patch.object(generate_shaders, "TESS_PATCHED_SHA256", hashlib.sha256(b"fixture output").hexdigest()):
                sources = [*(generate_shaders.source_path(name) for name in (*generate_shaders.AIR_NAMES, "dxmt_command")), root / "dxmt/version.h.in"]
                for source in sources:
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text("fixture source")
                for name in generate_shaders.header_names(): (headers / name).write_text("fixture output")
                spec = common.manifest()
                receipt = {"schema_version": 1, "dxmt_revision": spec["dxmt_revision"], "llvm_revision": spec["revision"],
                           "metal_flags": list(generate_shaders.METAL_FLAGS), "llvm_dis_sha256": common.sha256(tool),
                           "llvm_dis_checked": list(generate_shaders.AIR_NAMES),
                           "shader_adjustment": generate_shaders.shader_adjustments(),
                           "sources": {str(path.relative_to(root)): common.sha256(path) for path in sources},
                           "outputs": {name: common.sha256(headers / name) for name in generate_shaders.header_names()}}
                common.write_json(headers / "provenance.json", receipt)
                generate_shaders.validate()
                for kind in ("missing", "extra", "changed", "unread", "repair"):
                    data = json.loads(json.dumps(receipt))
                    if kind == "missing": del data["outputs"]["air_msad.h"]
                    elif kind == "extra": data["outputs"]["unexpected.h"] = "0" * 64
                    elif kind == "changed": data["outputs"]["air_msad.h"] = "0" * 64
                    elif kind == "unread": data["llvm_dis_checked"] = list(generate_shaders.AIR_NAMES[:-1])
                    else: data["shader_adjustment"]["compiled_source_sha256"] = "0" * 64
                    common.write_json(headers / "provenance.json", data)
                    with self.assertRaises(ValueError): generate_shaders.validate()

    def test_tessellation_adjustment_is_exact_and_keeps_checkout_clean(self):
        data = b"int fixture() { " + generate_shaders.TESS_OLD + b" }\n"
        adjusted = data.replace(generate_shaders.TESS_OLD, generate_shaders.TESS_NEW)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.metal"
            source.write_bytes(data)
            with mock.patch.object(generate_shaders, "source_path", return_value=source), \
                 mock.patch.object(generate_shaders, "TESS_ORIGINAL_SHA256", hashlib.sha256(data).hexdigest()), \
                 mock.patch.object(generate_shaders, "TESS_PATCHED_SHA256", hashlib.sha256(adjusted).hexdigest()):
                result = generate_shaders.prepare_source("air_tessellation", root)
                self.assertEqual(result.read_bytes(), adjusted)
                self.assertEqual(source.read_bytes(), data)
                source.write_bytes(data + b"unexpected edit")
                with self.assertRaises(ValueError): generate_shaders.prepare_source("air_tessellation", root)

    def test_workflow_is_bounded_and_air_precedes_ios(self):
        text = (ROOT / ".github/workflows/graphics-bootstrap.yml").read_text()
        self.assertIn("runs-on: xcode-27", text)
        self.assertIn("timeout-minutes: 45", text)
        self.assertIn("branches: [compatibility/desktop-apps]", text)
        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("github.event.repository.private == false", text)
        for forbidden in ("actions/cache", "actions/upload-artifact", "-large", "secrets.", "continue-on-error", "-license accept", "-runFirstLaunch"):
            self.assertNotIn(forbidden, text)
        self.assertLess(text.index("run: bash build/dxmt-ios/generate-shaders.sh preflight"), text.index("run: bash build/llvm-ios/build.sh host"))
        self.assertLess(text.index("run: bash build/llvm-ios/build.sh host"), text.index("run: bash build/dxmt-ios/generate-shaders.sh\n"))
        self.assertLess(text.index("run: bash build/dxmt-ios/generate-shaders.sh\n"), text.index("run: bash build/llvm-ios/build.sh ios"))
        self.assertLess(text.index("run: bash build/llvm-ios/build.sh ios"), text.index("run: python3 build/dxmt-ios/clean_build.py"))


if __name__ == "__main__": unittest.main()
