#!/usr/bin/env python3
"""Exercise actual CMake Makefiles/Ninja compile-database layouts, configure only.

An ordinary host CXX compiler is detected before synthetic device flags are
added to a never-built OBJECT target. No Apple SDK, cross compilation, install,
download, or generated target execution is involved. Missing tools fail loudly.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("fex_native_object_layout", ROOT / "build/fex-ios/check-native-object.py")
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)


class CMakeLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = shutil.which("cmake")
        cls.ninja = shutil.which("ninja")
        cls.make = shutil.which("make")
        cls.compiler = shutil.which("c++")
        missing = [name for name, path in (("cmake", cls.cmake), ("ninja", cls.ninja),
                                           ("make", cls.make), ("c++", cls.compiler)) if not path]
        if missing:
            raise RuntimeError("Real CMake layout checks require installed tools: " + ", ".join(missing)
                               + "; no installation or silent skip is performed")
        cls.compiler = Path(cls.compiler).resolve()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="FEX real CMake layout ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.fex = self.root / "FEX"
        self.source = self.root / module.SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_text("int madeira_layout_probe(int value) { return value + 1; }\n")
        self.sdk = self.root / "Synthetic Apple SDK/iPhoneOS27.0.sdk"
        self.sdk.mkdir(parents=True)
        (self.fex / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
project(FEXLayoutProbe LANGUAGES CXX)
# project() above performs normal host compiler detection. The device flags
# below belong only to our fixture target; that target is never compiled.
option(ENABLE_LTO "Fixture native configuration" OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ${ENABLE_LTO})
set(CMAKE_CXX_STANDARD 20)
add_subdirectory(FEXCore/Source)
''')
        (self.source.parent.parent / "CMakeLists.txt").write_text('''add_library(FEXCore_object OBJECT Common/JitSymbols.cpp)
target_compile_definitions(FEXCore_object PRIVATE ARCHITECTURE_arm64=1 JIT_ARM64)
target_include_directories(FEXCore_object PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(FEXCore_object PRIVATE -arch arm64 -isysroot "${FIXTURE_IPHONE_SDK}" -miphoneos-version-min=17.0)
''')

    def check_generator(self, generator, make_program, expected_directory):
        build = self.fex / "build-ios"
        # Prevent inherited project flags from turning host compiler detection
        # into a cross compile. These affect the synthetic fixture only.
        environment = dict(os.environ)
        for name in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET"):
            environment.pop(name, None)
        result = subprocess.run([
            self.cmake, "-S", str(self.fex), "-B", str(build), "-G", generator,
            "-DCMAKE_MAKE_PROGRAM=" + make_program, "-DCMAKE_CXX_COMPILER=" + str(self.compiler),
            "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_CXX_FLAGS=", "-DCMAKE_OSX_ARCHITECTURES=",
            "-DCMAKE_OSX_SYSROOT=", "-DCMAKE_OSX_DEPLOYMENT_TARGET=",
            "-DENABLE_LTO=OFF", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DFIXTURE_IPHONE_SDK=" + str(self.sdk),
        ], env=environment, text=True, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, f"{generator} configure failed:\n" + result.stderr[-4096:])
        entries = json.loads((self.root / module.DATABASE).read_text())
        self.assertEqual(len(entries), 1)
        entry, = entries
        actual_directory = Path(entry["directory"]).resolve()
        expected = build if expected_directory == "." else build / expected_directory
        self.assertEqual(actual_directory, expected)
        command = entry.get("arguments") if "arguments" in entry else shlex.split(entry["command"])
        output = (actual_directory / command[command.index("-o") + 1]).resolve()
        self.assertEqual(output, self.root / module.OBJECT)
        self.assertFalse(output.exists(), "The fixture must never compile its device-flagged target")
        replay, directory, database_hash, flags = module.compile_entry(self.root, self.compiler, self.sdk)
        self.assertEqual(directory, expected)
        self.assertEqual(database_hash, module.digest((self.root / module.DATABASE).read_bytes()))
        self.assertIn("-arch", flags)
        self.assertIn("arm64", flags)
        self.assertIn("-miphoneos-version-min=17.0", flags)
        self.assertNotIn("-o", replay)
        self.assertFalse(output.exists())

    def test_unix_makefiles_target_directory(self):
        self.check_generator("Unix Makefiles", self.make, "FEXCore/Source")

    def test_ninja_root_directory(self):
        self.check_generator("Ninja", self.ninja, ".")


if __name__ == "__main__":
    unittest.main(verbosity=2)
