#!/usr/bin/env python3
"""Portable PE cache/command rejection and build failure/staging boundaries.

Synthetic CMake records and shell tools exercise orchestration only. These
tests never compile a PE DLL and do not replace a real PE build receipt.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("fex_pe_configuration", ROOT / "build/fex-ios/check-pe-configuration.py")
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)


class PEConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="FEX PE config ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source, self.build = self.root / "FEX", self.root / "build"
        self.compilers = self.root / "toolchain/bin"
        self.compilers.mkdir(parents=True)
        for triple in ("arm64ec-w64-mingw32", "aarch64-w64-mingw32"):
            for suffix in ("-clang", "-clang++"):
                path = self.compilers / (triple + suffix)
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(module, "ROOT", self.root).start()
        mock.patch.dict(os.environ, {"PATH": str(self.compilers) + os.pathsep + os.environ["PATH"]}).start()

    def fixture(self, architecture="arm64ec"):
        triple = "arm64ec-w64-mingw32" if architecture == "arm64ec" else "aarch64-w64-mingw32"
        self.values = {"MINGW_TRIPLE": triple, "CMAKE_GENERATOR": "Ninja",
                       "CMAKE_HOME_DIRECTORY": str(self.source),
                       "CMAKE_TOOLCHAIN_FILE": str(self.source / "Data/CMake/toolchain_mingw.cmake"),
                       "FEX_IOS_HOST_BUILD": "ON", "ENABLE_GUEST_WINDOW": "OFF" if architecture == "arm64ec" else "ON",
                       "ENABLE_LTO": "OFF", "ENABLE_JEMALLOC_GLIBC_ALLOC": "OFF"}
        compiler_dir = self.build / "CMakeFiles/3.31.6"
        compiler_dir.mkdir(parents=True, exist_ok=True)
        for language, suffix in (("C", "-clang"), ("CXX", "-clang++"), ("ASM", "-clang")):
            compiler = str(self.compilers / (triple + suffix))
            self.values[f"CMAKE_{language}_FLAGS"] = "-DFEX_IOS_HOST"
            (compiler_dir / f"CMake{language}Compiler.cmake").write_text(f'set(CMAKE_{language}_COMPILER "{compiler}")\n')
        self.arguments = [str(self.compilers / (triple + "-clang++")), "-DFEX_IOS_HOST"]
        self.arguments.append("-DARCHITECTURE_arm64ec=1" if architecture == "arm64ec" else "-DFEX_GUEST_WINDOW=1")
        self.commands = [{"directory": str(self.build), "file": str(self.source / "Source/Windows" /
                          ("ARM64EC" if architecture == "arm64ec" else "WOW64") / "Module.cpp"),
                          "arguments": self.arguments},
                         {"file": str(self.source / "Source/Windows/Common/CRT/CRT_iOS.cpp")}]
        self.write()

    def write(self):
        (self.build / "CMakeCache.txt").write_text("\n".join(f"{k}:STRING={v}" for k, v in self.values.items()) + "\n")
        (self.build / "compile_commands.json").write_text(json.dumps(self.commands))

    def test_empty_directory_and_both_complete_configurations(self):
        module.verify(self.build, "arm64ec")
        for architecture in ("arm64ec", "wow64"):
            self.fixture(architecture)
            module.verify(self.build, architecture)
            module.verify(self.build, architecture, after=True)

    def test_populated_directory_without_cache_is_rejected(self):
        self.build.mkdir()
        (self.build / "old-object.obj").write_bytes(b"unverified")
        with self.assertRaisesRegex(ValueError, "without a CMake cache"):
            module.verify(self.build, "arm64ec")

    def test_wrong_generator_triple_source_and_toolchain_are_rejected_before_configure(self):
        self.fixture()
        for key, invalid in (("CMAKE_GENERATOR", "Unix Makefiles"), ("MINGW_TRIPLE", "aarch64-w64-mingw32"),
                             ("CMAKE_HOME_DIRECTORY", "/another/source"), ("CMAKE_TOOLCHAIN_FILE", "/another/toolchain")):
            with self.subTest(key=key):
                original = self.values[key]
                self.values[key] = invalid
                self.write()
                with self.assertRaisesRegex(ValueError, "Incompatible PE cache"):
                    module.verify(self.build, "arm64ec")
                self.values[key] = original

    def test_changed_compiler_identity_is_rejected(self):
        self.fixture()
        for language in ("C", "CXX", "ASM"):
            with self.subTest(language=language):
                path = self.build / f"CMakeFiles/3.31.6/CMake{language}Compiler.cmake"
                original = path.read_bytes()
                path.write_text(f'set(CMAKE_{language}_COMPILER "/different/clang")\n')
                with self.assertRaisesRegex(ValueError, "Incompatible PE .* compiler"):
                    module.verify(self.build, "arm64ec")
                path.write_bytes(original)

    def test_wrong_ios_option_and_missing_language_define_are_rejected(self):
        self.fixture()
        for key in ("FEX_IOS_HOST_BUILD", "ENABLE_GUEST_WINDOW", "ENABLE_LTO", "ENABLE_JEMALLOC_GLIBC_ALLOC",
                    "CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS", "CMAKE_ASM_FLAGS"):
            with self.subTest(key=key):
                original = self.values[key]
                self.values[key] = "OFF" if original == "ON" else "ON"
                self.write()
                with self.assertRaises(ValueError):
                    module.verify(self.build, "arm64ec", after=True)
                self.values[key] = original

    def test_effective_module_flags_and_ios_crt_are_required(self):
        for architecture in ("arm64ec", "wow64"):
            self.fixture(architecture)
            for flag in list(self.arguments[1:]):
                with self.subTest(architecture=architecture, flag=flag):
                    self.arguments.remove(flag)
                    self.write()
                    with self.assertRaises(ValueError):
                        module.verify(self.build, architecture, after=True)
                    self.arguments.append(flag)
            self.arguments.append("-DFEX_GUEST_WINDOW=1" if architecture == "arm64ec" else "-DARCHITECTURE_arm64ec=1")
            self.write()
            with self.assertRaises(ValueError):
                module.verify(self.build, architecture, after=True)
            self.arguments.pop()
            self.commands.pop()
            self.write()
            with self.assertRaisesRegex(ValueError, "iOS CRT"):
                module.verify(self.build, architecture, after=True)

    def test_no_or_duplicate_module_commands_are_rejected(self):
        self.fixture()
        self.commands.append(self.commands[0])
        self.write()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            module.verify(self.build, "arm64ec", after=True)
        self.commands = self.commands[1:2]
        self.write()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            module.verify(self.build, "arm64ec", after=True)

    def test_overridden_macros_targets_and_hidden_flags_are_rejected(self):
        for architecture in ("arm64ec", "wow64"):
            self.fixture(architecture)
            good = self.arguments[:]
            invalid = [
                ["-UFEX_IOS_HOST"], ["-U", "FEX_IOS_HOST"], ["-DFEX_IOS_HOST=0"],
                ["-D", "FEX_IOS_HOST=0"], ["-DFEX_IOS_HOST="], ["-UARCHITECTURE_arm64ec"],
                ["-UFEX_GUEST_WINDOW"], ["-DFEX_GUEST_WINDOW=0"],
                ["--target=x86_64-w64-mingw32"], ["--target", "x86_64-w64-mingw32"],
                ["-target", "x86_64-w64-mingw32"], ["-target=x86_64-w64-mingw32"],
                ["-Wp,-UFEX_IOS_HOST"], ["-Xpreprocessor", "-UFEX_IOS_HOST"],
                ["-Xclang", "-triple", "-Xclang", "x86_64-w64-mingw32"],
                ["@hidden-flags.rsp"], ["--config=hidden-flags.cfg"],
            ]
            for extra in invalid:
                with self.subTest(architecture=architecture, flags=extra):
                    self.arguments[:] = good + extra
                    self.write()
                    with self.assertRaises(ValueError):
                        module.verify(self.build, architecture, after=True)
            self.arguments[:] = good + ["-D", "FEX_IOS_HOST=1", "--target", self.values["MINGW_TRIPLE"]]
            self.write()
            module.verify(self.build, architecture, after=True)


class PEBuildScriptTests(unittest.TestCase):
    def test_scripts_reconfigure_and_never_stage_after_an_earlier_failure(self):
        for architecture, target, destination in (("arm64ec", "arm64ecfex", "arm64ec-windows/xtajit64.dll"),
                                                   ("wow64", "wow64fex", "aarch64-windows/xtajit.dll")):
            with self.subTest(architecture=architecture), tempfile.TemporaryDirectory(prefix="FEX PE orchestration ") as temp:
                root = Path(temp)
                script = root / f"build/fex-{architecture}/build.sh"
                script.parent.mkdir(parents=True)
                shutil.copyfile(ROOT / script.relative_to(root), script)
                helpers = root / "build/fex-ios"
                helpers.mkdir()
                helper = '''import os,sys
from pathlib import Path
step = sys.argv[1] if len(sys.argv) > 1 else "repairs"
with Path(os.environ["TEST_LOG"]).open("a") as out: out.write(step + "\\n")
raise SystemExit(7 if os.environ.get("FAIL_STEP") == step else 0)
'''
                for name in ("apply-source-repairs.py", "check-pe-configuration.py"):
                    (helpers / name).write_text(helper)
                bin_dir = root / "tools/bin"
                bin_dir.mkdir(parents=True)
                cmake = bin_dir / "cmake"
                cmake.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
step = "build" if sys.argv[1] == "--build" else "configure"
with Path(os.environ["TEST_LOG"]).open("a") as out: out.write(step + "\\n")
if os.environ.get("FAIL_STEP") == step: raise SystemExit(7)
if step == "build":
    path = Path(sys.argv[2]) / "Bin" / ("lib" + sys.argv[sys.argv.index("--target") + 1] + ".dll")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic linked fixture")
''')
                cmake.chmod(0o755)
                staged = root / "app/Madeira" / destination
                staged.parent.mkdir(parents=True)
                log = root / "steps.log"
                env = dict(os.environ, LLVM_MINGW_ROOT=str(bin_dir.parent), TEST_LOG=str(log))
                steps = ["before", "repairs", "configure", "after", "build"]
                for failure in steps:
                    with self.subTest(failure=failure):
                        log.write_text("")
                        staged.write_bytes(b"existing tracked DLL")
                        result = subprocess.run(["bash", str(script)], env=dict(env, FAIL_STEP=failure), capture_output=True)
                        self.assertEqual(result.returncode, 7, result.stderr)
                        self.assertEqual(log.read_text().splitlines(), steps[:steps.index(failure) + 1])
                        self.assertEqual(staged.read_bytes(), b"existing tracked DLL")
                for _ in range(2):
                    log.write_text("")
                    subprocess.run(["bash", str(script)], env=dict(env, FEX_PE_STAGE="0"), check=True)
                    self.assertEqual(log.read_text().splitlines(), steps)
                    self.assertEqual(staged.read_bytes(), b"existing tracked DLL")
                subprocess.run(["bash", str(script)], env=env, check=True)
                self.assertEqual(staged.read_bytes(), b"synthetic linked fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
