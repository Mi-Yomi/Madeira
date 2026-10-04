#!/usr/bin/env python3
"""Portable diagnostic safety fixtures; no Apple compiler execution is claimed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("fex_native_object", ROOT / "build/fex-ios/check-native-object.py")
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)


def macho(platform=2, cpu=0x0100000C):
    command = struct.pack("<6I", 0x32, 24, platform, 0x110000, 0x1B0000, 0)
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, 1, 1, len(command), 0, 0) + command


class NativeObjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="native object fixture ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / module.SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_text("int pinned_fixture(int x) { return x + 1; }\n")
        self.committed = self.source.read_text()
        self.production = self.root / module.OBJECT
        self.production.parent.mkdir(parents=True)
        self.production.write_bytes(macho())
        self.build = self.root / "FEX/build-ios"
        self.cache = self.build / "CMakeCache.txt"
        self.cache.write_text("ENABLE_LTO:BOOL=OFF\nCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON\n")
        self.compiler = self.root / "Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++"
        self.compiler.parent.mkdir(parents=True)
        self.compiler.write_text("test fixture, never executed\n")
        self.sdk = self.root / "Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.sdk"
        self.sdk.mkdir(parents=True)
        self.args = [str(self.compiler), "-DARCHITECTURE_arm64=1", "-DJIT_ARM64", "-DNDEBUG",
                     "-I" + str(self.source.parent), "-O3", "-std=gnu++20", "-arch", "arm64",
                     "-isysroot", str(self.sdk), "-miphoneos-version-min=17.0", "-fPIC", "-Wall",
                     "-MD", "-MT", "production.o", "-MF", "production.d", "-o", str(self.production), "-c", str(self.source)]
        self.database = self.root / module.DATABASE
        self.entry = {"directory": str(self.build), "file": str(self.source), "arguments": self.args}
        self.save_database()
        specification = self.root / "build/fex-ios/source-repairs.json"
        specification.parent.mkdir(parents=True)
        specification.write_text(json.dumps({"source_revision": "a" * 40}))
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(module, "ROOT", self.root).start()
        mock.patch.object(module, "EXPECTED_DEVELOPER_DIR", self.root / "Xcode.app/Contents/Developer").start()
        mock.patch.dict(os.environ, DEVELOPER_DIR=str(module.EXPECTED_DEVELOPER_DIR)).start()
        self.commands, self.temporary_paths = [], []
        self.bitcode = b"BC\xc0\xde" + b"fixture"
        self.triple = module.EXPECTED_TRIPLE
        self.reader_stderr = ""

    def save_database(self, entries=None):
        self.database.write_text(json.dumps(entries if entries is not None else [self.entry]))

    def fake_run(self, args, **kwargs):
        self.commands.append((args, kwargs))
        output = ""
        if args[:1] == ["/usr/bin/xcode-select"]:
            output = str(module.EXPECTED_DEVELOPER_DIR) + "\n"
        elif args[:1] == ["/usr/bin/codesign"]:
            self.assertEqual(args[1:5], ["--verify", "--strict", "-R", "=anchor apple"])
        elif args[:1] == ["/usr/bin/xcrun"]:
            output = str(self.compiler if "--find" in args else self.sdk) + "\n"
        elif "--version" in args:
            output = "Apple clang version 21.0.0\n"
        elif args[:2] == ["git", "rev-parse"]:
            output = "a" * 40 + "\n"
        elif args[:2] == ["git", "show"]:
            output = self.committed
        elif "-flto=thin" in args:
            path = Path(args[args.index("-o") + 1])
            self.temporary_paths.append(path.parent)
            self.assertEqual(kwargs["scratch"], path.parent)
            self.assertEqual(kwargs["timeout"], 45)
            self.assertIn("--no-default-config", args)
            for flag in ("-MD", "-MMD", "-MF", "-MT", "-MQ", "-MP"):
                self.assertNotIn(flag, args)
            self.assertEqual(args.count("-o"), 1)
            path.write_bytes(self.bitcode)
        elif "-emit-llvm" in args:
            path = Path(args[args.index("-o") + 1])
            self.assertIn("--no-default-config", args)
            self.assertIn("-Werror=override-module", args)
            self.assertIn("-Werror=unknown-warning-option", args)
            self.assertIn("--target=" + module.EXPECTED_TRIPLE, args)
            self.assertEqual(kwargs["scratch"], path.parent)
            path.write_text('target triple = "' + self.triple + '"\n; private fixture IR, never logged\n')
            return subprocess.CompletedProcess(args, 0, "", self.reader_stderr)
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(args, 0, output, "")

    def inspect(self):
        with mock.patch.object(module, "run", side_effect=self.fake_run):
            return module.inspect_native()

    def check_command(self):
        return module.compile_entry(self.root, self.compiler, self.sdk)

    def test_same_source_replay_receipt_and_cleanup(self):
        before = self.production.read_bytes()
        receipt = self.inspect()
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["evidence_kind"], "fresh-same-source-thinlto-reproduction")
        self.assertEqual(receipt["production_object"]["sha256"], module.digest(before))
        self.assertEqual(receipt["source"]["sha256"], module.digest(self.source.read_bytes()))
        self.assertEqual(receipt["reproduction"]["target_triple"], module.EXPECTED_TRIPLE)
        self.assertTrue(receipt["reproduction"]["strict_validator_rejected"])
        self.assertEqual(receipt["native_configuration"], {"enable_lto": False, "architecture": "arm64", "deployment_target": "17.0", "ipo_flags": []})
        self.assertEqual(self.production.read_bytes(), before)
        self.assertTrue(self.temporary_paths)
        self.assertTrue(all(not path.exists() for path in self.temporary_paths))
        self.assertNotIn("private fixture IR", json.dumps(receipt))
        self.assertIn("sha256", receipt["compiler"])

    def test_actual_helper_receipt_passes_current_provenance_verifier(self):
        for name in module.artifacts.FEX_NATIVE_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        document = {
            "input_sha256": {name: module.artifacts.sha256(self.root / name) for name in module.artifacts.FEX_NATIVE_INPUTS},
            "tool_versions": {"iphoneos_sdk_path": str(self.sdk)},
        }
        receipt_path = self.root / "fex-native-object.json"
        with mock.patch.object(module, "run", side_effect=self.fake_run), \
                mock.patch.object(sys, "argv", ["check-native-object.py", "--receipt", str(receipt_path)]), \
                mock.patch("builtins.print"):
            module.main()
        with mock.patch.object(module.artifacts, "ROOT", self.root):
            verified = module.artifacts.verified_fex_native_object(document, receipt_path)
        self.assertEqual(verified["reproduction"]["target_triple"], module.EXPECTED_TRIPLE)

    def test_stale_or_symlink_parent_receipt_is_rejected(self):
        parent = self.root / "receipt-parent"
        parent.mkdir()
        alias = self.root / "receipt-alias"
        alias.symlink_to(parent, target_is_directory=True)
        for receipt in (parent / "old.json", alias / "new.json"):
            if receipt.parent == parent:
                receipt.write_text("old receipt\n")
            with mock.patch.object(sys, "argv", ["helper", "--receipt", str(receipt)]), \
                    mock.patch.object(module, "inspect_native") as inspect:
                with self.assertRaisesRegex(ValueError, "stale or symlinked"):
                    module.main()
                inspect.assert_not_called()
        self.assertFalse((parent / "new.json").exists())

    def test_shell_string_preserves_quoted_paths_without_using_shell(self):
        self.entry.pop("arguments")
        self.entry["command"] = shlex.join(self.args)
        self.save_database()
        self.assertEqual(self.inspect()["status"], "passed")

    def test_explicit_target_without_arch_and_minimum(self):
        self.args[self.args.index("-arch"):self.args.index("-arch") + 2] = ["--target=" + module.EXPECTED_TRIPLE]
        self.args.remove("-miphoneos-version-min=17.0")
        self.save_database()
        self.assertEqual(self.inspect()["status"], "passed")

    def test_makefiles_target_directory_and_relative_paths(self):
        directory = self.build / "FEXCore/Source"
        self.entry["directory"] = str(directory)
        self.entry["file"] = os.path.relpath(self.source, directory)
        self.args[self.args.index("-o") + 1] = "CMakeFiles/FEXCore_object.dir/Common/JitSymbols.cpp.o"
        self.args[self.args.index("-c") + 1] = os.path.relpath(self.source, directory)
        include = "-I" + str(self.source.parent)
        self.args[self.args.index(include)] = "-I" + os.path.relpath(self.source.parent, directory)
        self.save_database()
        command, actual, _, _ = self.check_command()
        self.assertEqual(actual, directory)
        self.assertEqual(command[command.index("-c") + 1], os.path.relpath(self.source, directory))
        self.assertEqual(self.inspect()["status"], "passed")

    def test_ninja_root_directory_with_prefixed_relative_output(self):
        self.args[self.args.index("-o") + 1] = "FEXCore/Source/CMakeFiles/FEXCore_object.dir/Common/JitSymbols.cpp.o"
        self.save_database()
        self.assertEqual(self.check_command()[1], self.build)

    def test_other_working_directories_rejected_with_bounded_relative_context(self):
        for directory in (self.build / "FEXCore", self.build / "other", self.root / "outside",
                          self.build / ("x" * 200 + "\ncontrol"), self.build / ("😀" * 40)):
            with self.subTest(directory=directory):
                self.entry["directory"] = str(directory)
                self.save_database()
                with self.assertRaisesRegex(ValueError, "expected build-relative") as error:
                    self.check_command()
                self.assertIn("actual=", str(error.exception))
                self.assertNotIn(str(self.root), str(error.exception))
                self.assertNotIn("\n", str(error.exception))
                self.assertLess(len(str(error.exception)), 300)

    def test_makefiles_target_directory_symlink_escape_is_rejected(self):
        original = self.build / "FEXCore"
        original.rename(self.build / "saved-target-directory")
        outside = self.root / "outside-target"
        (outside / "Source").mkdir(parents=True)
        original.symlink_to(outside, target_is_directory=True)
        self.entry["directory"] = str(original / "Source")
        self.save_database()
        with self.assertRaisesRegex(ValueError, "expected build-relative"):
            self.check_command()

    def test_makefiles_layout_keeps_output_and_include_containment(self):
        directory = self.build / "FEXCore/Source"
        self.entry["directory"] = str(directory)
        self.args[self.args.index("-o") + 1] = "../../../../outside.o"
        self.save_database()
        with self.assertRaisesRegex(ValueError, "source or production object output"):
            self.check_command()
        self.args[self.args.index("-o") + 1] = "CMakeFiles/FEXCore_object.dir/Common/JitSymbols.cpp.o"
        self.entry["arguments"] = [*self.args, "-I../../../../outside"]
        self.save_database()
        with self.assertRaisesRegex(ValueError, "include search path"):
            self.check_command()

    def test_wrapped_bitcode(self):
        self.bitcode = struct.pack("<5I", 0x0B17C0DE, 0, 20, 8, 0) + b"BC\xc0\xde1234"
        self.assertEqual(self.inspect()["reproduction"]["magic_hex"], "dec0170b")

    def test_unknown_compiler_option_and_side_effects_rejected(self):
        for extra in (["@hidden.rsp"], ["-Xclang", "-load", "plugin.dylib"], ["-fplugin=plugin.dylib"],
                      ["-save-temps"], ["-MJ", "outside.json"], ["--config=outside.cfg"], ["-include", "header.h"],
                      ["-flto=thin"], ["-Wl,-o,outside"], ["-Wa,-a=outside"], ["-Wp,-MD,outside"]):
            with self.subTest(extra=extra):
                self.entry["arguments"] = [*self.args, *extra]
                self.save_database()
                with self.assertRaises(ValueError): self.check_command()

    def test_wrapper_and_unexpected_compiler_rejected(self):
        for compiler in ("ccache", "/usr/bin/clang++", "/tmp/untrusted-clang++"):
            with self.subTest(compiler=compiler):
                self.entry["arguments"] = [compiler, *self.args[1:]]
                self.save_database()
                with self.assertRaisesRegex(ValueError, "Unexpected compiler"): self.check_command()

    def test_ambiguous_missing_and_malformed_commands_rejected(self):
        for entries in ([], [self.entry, self.entry], [{"file": str(self.source)}], [{**self.entry, "command": "ambiguous"}]):
            with self.subTest(entries=entries):
                self.save_database(entries)
                with self.assertRaises(ValueError): self.check_command()

    def test_conflicting_host_and_simulator_targets_rejected(self):
        cases = [self.args + ["-arch", "x86_64"], self.args + ["--target=arm64-apple-macosx17.0"],
                 self.args + ["--target=arm64-apple-ios17.0-simulator"],
                 self.args + ["-miphoneos-version-min=18.0"], self.args + ["-isysroot", "/fake/iPhoneSimulator.sdk"],
                 self.args + ["-DFEX_IOS_HOST"], self.args + ["-DARCHITECTURE_arm64ec=1"],
                 self.args + ["-UARCHITECTURE_arm64"], self.args + ["-U", "JIT_ARM64"],
                 self.args + ["-DARCHITECTURE_arm64=0"], self.args + ["-DJIT_ARM64=0"],
                 self.args + ["-D__APPLE__=0"]]
        for args in cases:
            with self.subTest(args=args):
                self.entry["arguments"] = args
                self.save_database()
                with self.assertRaises(ValueError): self.check_command()

    def test_wrong_source_output_and_external_include_rejected(self):
        for flag, replacement in (("-o", "/tmp/other.o"), ("-c", "/tmp/other.cpp"), ("-isysroot", "/other/iPhoneOS.sdk")):
            with self.subTest(flag=flag):
                args = self.args[:];args[args.index(flag) + 1] = replacement
                self.entry["arguments"] = args;self.save_database()
                with self.assertRaises(ValueError): self.check_command()
        self.entry["arguments"] = [*self.args, "-I/opt/homebrew/include"];self.save_database()
        with self.assertRaises(ValueError): self.check_command()

    def test_cache_requires_explicit_native_lto_off(self):
        for content in ("", "ENABLE_LTO:BOOL=ON\nCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON\n",
                        "ENABLE_LTO:BOOL=OFF\nENABLE_LTO:BOOL=ON\nCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON\n"):
            self.cache.write_text(content)
            with self.assertRaises(ValueError): self.check_command()

    def test_host_simulator_and_malformed_production_objects_rejected(self):
        for data in (macho(1), macho(7), macho(cpu=0x01000007), b"BC\xc0\xde", b"garbage"):
            with self.subTest(data=data):
                self.production.write_bytes(data)
                with self.assertRaises(ValueError): self.inspect()
        self.assertFalse(self.temporary_paths)

    def test_malformed_bitcode_rejected_and_deleted(self):
        for data in (b"garbage", b"\xde\xc0\x17\x0b", struct.pack("<5I", 0x0B17C0DE, 0, 20, 1000, 0) + b"BC\xc0\xde"):
            with self.subTest(data=data):
                self.bitcode = data
                with self.assertRaisesRegex(ValueError, "not recognized LLVM bitcode"): self.inspect()
                self.assertTrue(all(not path.exists() for path in self.temporary_paths))

    def test_wrong_triple_or_reader_diagnostic_never_passes(self):
        for triple in ("arm64-apple-macosx17.0.0", "arm64-apple-ios17.0.0-simulator", "aarch64-unknown-linux-gnu"):
            self.triple = triple
            with self.assertRaisesRegex(ValueError, "exact original iOS target"): self.inspect()
        self.triple = module.EXPECTED_TRIPLE
        self.reader_stderr = "warning: overriding the module target triple\n"
        with self.assertRaisesRegex(ValueError, "exact original iOS target"): self.inspect()
        self.assertTrue(all(not path.exists() for path in self.temporary_paths))

    def test_reader_failure_and_timeout_delete_scratch(self):
        for message in ("reader failed", "reader timed out"):
            def fail_reader(args, **kwargs):
                if "-emit-llvm" in args: raise ValueError(message)
                return self.fake_run(args, **kwargs)
            with mock.patch.object(module, "run", side_effect=fail_reader):
                with self.assertRaisesRegex(ValueError, message): module.inspect_native()
        self.assertTrue(all(not path.exists() for path in self.temporary_paths))

    def test_conflicting_developer_override_rejected_before_tools(self):
        with mock.patch.dict(os.environ, DEVELOPER_DIR="/untrusted/Xcode"), \
                mock.patch.object(module, "run") as runner:
            with self.assertRaisesRegex(ValueError, "overrides the audited"):
                module.inspect_native()
            runner.assert_not_called()

    def test_untrusted_selected_compiler_or_sdk_is_not_executed(self):
        original_compiler, original_sdk = self.compiler, self.sdk
        outside_compiler = self.root / "untrusted/clang++"
        outside_compiler.parent.mkdir()
        outside_compiler.write_text("never execute\n")
        outside_sdk = self.root / "outside/iPhoneOS27.0.sdk"
        outside_sdk.mkdir(parents=True)
        for compiler, sdk in ((outside_compiler, original_sdk), (original_compiler, outside_sdk)):
            self.compiler, self.sdk = compiler, sdk
            self.commands.clear()
            with self.assertRaisesRegex(ValueError, "escaped the audited Xcode"):
                self.inspect()
            self.assertFalse(any("--version" in args or "-flto=thin" in args for args, _ in self.commands))
        self.compiler, self.sdk = original_compiler, original_sdk

    def test_apple_signature_failure_prevents_compiler_execution(self):
        def reject_signature(args, **kwargs):
            if args[0] == "/usr/bin/codesign": raise ValueError("Apple signature rejected")
            return self.fake_run(args, **kwargs)
        with mock.patch.object(module, "run", side_effect=reject_signature):
            with self.assertRaisesRegex(ValueError, "signature rejected"):
                module.inspect_native()
        self.assertFalse(any("--version" in args or "-flto=thin" in args for args, _ in self.commands))

    def test_modified_pinned_source_rejected(self):
        self.source.write_text("unexpected local source edit\n")
        with self.assertRaisesRegex(ValueError, "pinned Git blob"): self.inspect()

    def test_missing_or_symlinked_inputs_rejected(self):
        outside = self.root / "outside-object"
        outside.write_bytes(self.production.read_bytes())
        self.production.unlink();self.production.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular file within"): self.inspect()
        self.production.unlink()
        with self.assertRaisesRegex(ValueError, "regular file within"): self.inspect()

    def test_no_receipt_is_written_on_failure(self):
        receipt = self.root / "receipt.json"
        with mock.patch.object(sys, "argv", ["check-native-object.py", "--receipt", str(receipt)]), \
                mock.patch.object(module, "inspect_native", side_effect=ValueError("diagnostic failed")):
            with self.assertRaises(ValueError): module.main()
        self.assertFalse(receipt.exists())


class BoundedRunnerTests(unittest.TestCase):
    def test_real_command_timeout(self):
        with self.assertRaisesRegex(ValueError, "timed out"):
            module.run([sys.executable, "-c", "import time; time.sleep(30)"], deadline=time.monotonic() + 1, timeout=0.05)

    def test_expired_total_deadline_never_starts_command(self):
        with mock.patch.object(module.subprocess, "Popen") as start:
            with self.assertRaisesRegex(ValueError, "total timeout"):
                module.run(["not-started"], deadline=time.monotonic() - 1)
            start.assert_not_called()

    def test_real_command_output_is_bounded(self):
        with mock.patch.object(module, "MAX_OUTPUT", 1024):
            with self.assertRaisesRegex(ValueError, "output limit"):
                module.run([sys.executable, "-c", "print('x' * 100000)"], deadline=time.monotonic() + 5)

    def test_failure_does_not_expose_ir_diagnostics(self):
        with self.assertRaises(ValueError) as error:
            module.run([sys.executable, "-c", "import sys;sys.stderr.write('private IR line\\n');sys.exit(7)"], deadline=time.monotonic() + 5)
        self.assertNotIn("private IR", str(error.exception))
        self.assertIn("stderr_sha256=", str(error.exception))
        self.assertIn("(7)", str(error.exception))

    def test_allowlisted_failure_categories_exclude_raw_diagnostics(self):
        cases = {
            "error: overriding the module target triple with secret_ir": "module target triple mismatch",
            "error: unknown argument: secret_ir": "unsupported compiler option",
            "error: Invalid bitcode signature secret_ir": "LLVM bitcode reader rejected module",
            "fatal error: 'secret_ir' file not found": "required compilation header missing",
            "secret_ir arbitrary diagnostic": "unclassified tool failure",
        }
        for diagnostic, category in cases.items():
            self.assertEqual(module.diagnostic_category(diagnostic), category)
            self.assertNotIn("secret_ir", module.diagnostic_category(diagnostic))

    def test_compiler_hash_is_streaming_and_deadline_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large-compiler"
            path.write_bytes(b"x" * (module.MAX_FILE + 1))
            self.assertEqual(module.tool_digest(path, time.monotonic() + 5), module.artifacts.sha256(path))
            with self.assertRaisesRegex(ValueError, "total timeout while hashing compiler"):
                module.tool_digest(path, time.monotonic() - 1)

    def test_override_environment_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, CCC_OVERRIDE_OPTIONS="malicious", CPATH="/bad", SDKROOT="/bad", CPLUS_INCLUDE_PATH="/bad"):
            result = module.run([sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))"], deadline=time.monotonic() + 5, scratch=Path(directory))
            environment = json.loads(result.stdout)
            for name in ("CCC_OVERRIDE_OPTIONS", "CPATH", "SDKROOT", "CPLUS_INCLUDE_PATH"):
                self.assertNotIn(name, environment)
            self.assertEqual(environment["TMPDIR"], directory)
            self.assertEqual(environment["HOME"], directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
