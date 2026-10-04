#!/usr/bin/env python3
"""Link the exact pinned diagnostic fragments in allocator-on/off configurations.

Uses host C/C++ and nm, with no Apple SDK or FEX guest execution. The producer
fixture is the real rpmalloc POD/drain implementation; only test publication and
the surrounding logger are synthetic. A successful fixture is not an app build.
"""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("snapshot_repair_fixtures", Path(__file__).with_name("check-fex-source-repairs.py"))
fixtures = importlib.util.module_from_spec(loader)
loader.loader.exec_module(fixtures)
GUARD = "#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR\n"
SYMBOL = "rpm_cas_snapshot_take"
LOGGER_LOCATION = '#line 1 "snapshot-logger-fixture"\n'
MAIN_LOCATION = '#line 1 "snapshot-main-fixture"\n'


def region(text, start, end):
    offset = text.index(start)
    if text[:offset].endswith(GUARD):
        offset -= len(GUARD)
    return text[offset:text.index(end, offset)]


class SnapshotLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in ("c++", "cc", "nm"):
            if not shutil.which(name):
                raise RuntimeError("Snapshot link checks require installed " + name)

    def setUp(self):
        self.fixture = fixtures.FEXSourceRepairTests("test_clean_patch_idempotence_and_provenance")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        fixtures.module.apply(self.fixture.source)
        self.root = self.fixture.root
        self.original = self.fixture.original.decode()
        self.patched = self.fixture.target.read_text()

    def run_command(self, args, success=True):
        result = subprocess.run(args, text=True, capture_output=True, timeout=45)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "Unexpected link success")
        return result

    def consumer(self, text):
        declarations = region(text, "/* iOS-Madeira ml622: mirror", "#include <condition_variable>")
        drain = region(text, "      /* iOS-Madeira ml622: drain", "    }\n  }\n\n")
        return '''#include <cassert>
#include <string_view>
#include <tuple>
''' + declarations + LOGGER_LOCATION + '''
static int reports = 0, summaries = 0;
namespace LogMan::Msg {
template<class... Args> void EFmt(const char* format, Args... args) {
  ++reports;
  assert(std::string_view(format).starts_with("[rpm-cas]"));
  auto values = std::make_tuple(args...);
  assert(std::get<0>(values) == 2u);
  assert(std::string_view(std::get<1>(values)) == "QUARANTINED (block leaked, spin abandoned)");
  assert(std::get<2>(values) == 0x1000ull);
  assert(std::get<3>(values) == 0x2000ull);
  assert(std::get<4>(values) == 0x3000ull);
  assert(std::get<5>(values) == 0x4000ull);
  assert(std::get<6>(values) == 0x5000ull);
  assert(std::get<7>(values) == 0x6000ull);
  assert(std::get<8>(values) == 3u);
  assert(std::get<9>(values) == 4u);
  assert(std::get<10>(values) == 5u);
  assert(std::get<11>(values) == 6u);
  assert(std::get<12>(values) == 7u);
  assert(std::get<13>(values) == 8u);
  assert(std::get<14>(values) == 1u);
  assert(std::get<15>(values) == 0x7000ull);
  assert(std::get<16>(values) == 0x8000ull);
  assert(std::get<17>(values) == 9u);
  assert(std::get<18>(values) == 10u);
  assert(std::get<19>(values) == 11u);
}
}
void Drain() {
  ++summaries; // Work surrounding the diagnostic must remain active.
''' + drain + MAIN_LOCATION + '''
}
#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR
extern "C" void publish_test_snapshot();
#endif
int main() {
  Drain();
  assert(reports == 0 && summaries == 1);
#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR
  publish_test_snapshot();
  Drain();
  assert(reports == 1 && summaries == 2);
  Drain();
  assert(reports == 1 && summaries == 3); // The real producer drains once.
#else
  Drain();
  assert(reports == 0 && summaries == 2);
#endif
}
'''

    def compile_consumer(self, text, defines):
        source, obj = self.root / "consumer.cpp", self.root / "consumer.o"
        source.write_text(self.consumer(text))
        self.run_command(["c++", "-std=c++20", "-O0", *defines, "-c", str(source), "-o", str(obj)])
        return obj

    def compile_producer(self):
        source, obj = self.root / "producer.c", self.root / "producer.o"
        source.write_text((Path(__file__).with_name("fixtures") / "fex-rpmalloc-snapshot.c").read_text() + '''
/* Test publication only. The production drain above is unchanged. */
void publish_test_snapshot(void) {
  rpm_cas_snap = (struct rpm_cas_snapshot){
    .page_addr = 0x1000, .block_addr = 0x2000, .heap_addr = 0x3000,
    .atomic_addr = 0x4000, .owner_teb = 0x5000, .ret_addr = 0x6000,
    .size_class = 3, .page_type = 4, .block_index = 5, .block_count = 6,
    .list_size = 7, .block_used = 8, .is_full = 1,
    .prev_token = 0x7000, .cur_token = 0x8000,
    .fail_changed = 9, .fail_unchanged = 10, .fail_invalid = 11,
    .quarantined = 1, .which_loop = 2,
  };
  atomic_store_explicit(&rpm_cas_snap_ready, 1, memory_order_release);
}
''')
        self.run_command(["cc", "-std=c11", "-O0", "-c", str(source), "-o", str(obj)])
        return obj

    def symbols(self, obj):
        result = self.run_command(["nm", str(obj)])
        # Both Mach-O (_name) and ELF (name) symbol spellings are accepted.
        return [line for line in result.stdout.splitlines() if re.search(r"\b_?" + SYMBOL + r"$", line)]

    def test_original_consumer_reproduces_missing_provider_link_failure(self):
        obj = self.compile_consumer(self.original, [])
        self.assertEqual(len(self.symbols(obj)), 1)
        self.assertIn(" U ", self.symbols(obj)[0])
        result = self.run_command(["c++", str(obj), "-o", str(self.root / "broken")], success=False)
        self.assertIn(SYMBOL, result.stderr)

    def test_disabled_allocator_has_no_definition_or_reference_and_links(self):
        for flags in ([], ["-DENABLE_FEX_ALLOCATOR=0"], ["-D__APPLE__"],
                      ["-D__APPLE__", "-DENABLE_FEX_ALLOCATOR=0"],
                      ["-DFEX_IOS_HOST", "-DENABLE_FEX_ALLOCATOR=0"]):
            with self.subTest(defines=flags):
                obj = self.compile_consumer(self.patched, flags)
                self.assertEqual(self.symbols(obj), [])
                executable = self.root / "disabled"
                self.run_command(["c++", str(obj), "-o", str(executable)])
                self.assertEqual(self.symbols(executable), [])
                self.run_command([str(executable)])

    def test_enabled_allocator_keeps_real_provider_and_drain_semantics(self):
        provider = self.compile_producer()
        self.assertEqual(len(self.symbols(provider)), 1)
        self.assertIn(" T ", self.symbols(provider)[0])
        for flags in ([], ["-DFEX_IOS_HOST"], ["-DFEX_IOS_HOST", "-DARCHITECTURE_arm64ec"]):
            with self.subTest(defines=flags):
                obj = self.compile_consumer(self.patched, ["-DENABLE_FEX_ALLOCATOR=1", *flags])
                self.assertEqual(len(self.symbols(obj)), 1)
                self.assertIn(" U ", self.symbols(obj)[0])
                executable = self.root / "enabled"
                result = self.run_command(["c++", str(obj), "-o", str(executable)], success=False)
                self.assertIn(SYMBOL, result.stderr)
                self.run_command(["c++", str(obj), str(provider), "-o", str(executable)])
                self.assertEqual(len(self.symbols(executable)), 1)
                self.assertIn(" T ", self.symbols(executable)[0])
                self.run_command([str(executable)])

    def test_enabled_preprocessor_output_preserves_exact_consumer(self):
        # Darwin's assert expands __LINE__ into __assert_rtn's arguments. The
        # added production guards move the synthetic logger/main physically;
        # stable #line boundaries keep their diagnostics comparable without
        # stripping any expanded code, expressions, fields or numeric values.
        outputs = []
        for text in (self.original, self.patched):
            source = self.root / "preprocess.cpp"
            source.write_text(self.consumer(text))
            outputs.append(self.run_command(["c++", "-std=c++20", "-DENABLE_FEX_ALLOCATOR=1", "-E", "-P", str(source)]).stdout)
        self.assertEqual(*outputs)

    def test_line_sensitive_assertion_fixture_preserves_code_comparison(self):
        def preprocess(text, stable_locations=True):
            consumer = self.consumer(text).replace(
                "#include <cassert>\n",
                "#define assert(expression) fixture_assertion(__LINE__, #expression)\n", 1)
            if not stable_locations:
                consumer = consumer.replace(LOGGER_LOCATION, "", 1).replace(MAIN_LOCATION, "", 1)
            source = self.root / "line-sensitive.cpp"
            source.write_text(consumer)
            return self.run_command(["c++", "-std=c++20", "-DENABLE_FEX_ALLOCATOR=1", "-E", "-P", str(source)]).stdout
        original_raw, patched_raw = [preprocess(text, False) for text in (self.original, self.patched)]
        self.assertNotEqual(original_raw, patched_raw)
        original_lines = re.findall(r"fixture_assertion\((\d+),", original_raw)
        patched_lines = re.findall(r"fixture_assertion\((\d+),", patched_raw)
        self.assertTrue(original_lines)
        self.assertEqual(len(original_lines), len(patched_lines))
        self.assertNotEqual(original_lines, patched_lines)
        original_stable, patched_stable = [preprocess(text) for text in (self.original, self.patched)]
        self.assertEqual(original_stable, patched_stable)
        # Stable locations must not conceal an actual production diagnostic edit.
        changed = self.patched.replace("Snap.fail_changed, Snap.fail_unchanged", "Snap.fail_invalid, Snap.fail_unchanged", 1)
        self.assertNotEqual(preprocess(changed), original_stable)

    def test_cmake_definition_is_source_scoped_and_tied_to_real_provider(self):
        original = self.fixture.cmake_original.decode()
        patched = self.fixture.cmake_target.read_text()
        original_block = original.split("if (ENABLE_FEX_ALLOCATOR)\n", 1)[1].split("endif()", 1)[0]
        block = patched.split("if (ENABLE_FEX_ALLOCATOR)\n", 1)[1].split("endif()", 1)[0]
        addition = "  # Core drains rpmalloc diagnostics only when their real provider is linked.\n" \
            "  set_property(SOURCE Interface/Core/Core.cpp APPEND PROPERTY COMPILE_DEFINITIONS ENABLE_FEX_ALLOCATOR=1)\n"
        self.assertEqual(block, addition + original_block)
        self.assertEqual(patched.replace(addition, "", 1), original)
        self.assertIn("target_link_libraries(JemallocLibs PUBLIC rpmalloc)", block)
        self.assertEqual(patched.count("set_property(SOURCE Interface/Core/Core.cpp"), 1)

    def test_real_cmake_links_on_off_and_reconfigured_allocator(self):
        cmake = shutil.which("cmake")
        if not cmake:
            self.skipTest("CMake is not installed; symbol and source-wiring tests still run")
        project = self.root / "real cmake snapshot"
        source = project / "FEXCore/Source"
        (source / "Interface/Core").mkdir(parents=True)
        (source / "Utils").mkdir()
        (source / "Interface/Core/Core.cpp").write_text(self.consumer(self.patched))
        (source / "Utils/AllocatorHooks.cpp").write_text("int allocator_hook_fixture;\n")
        self.compile_producer()
        (project / "producer.c").write_text((self.root / "producer.c").read_text())
        (project / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
project(SnapshotLinkProbe LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(ENABLE_FEX_ALLOCATOR "Fixture allocator" OFF)
set(ENABLE_JEMALLOC_GLIBC_ALLOC OFF)
if (ENABLE_FEX_ALLOCATOR)
  add_library(rpmalloc STATIC producer.c)
endif()
add_subdirectory(FEXCore/Source)
''')
        (source / "CMakeLists.txt").write_text('''add_library(FEXCore_object OBJECT Interface/Core/Core.cpp)
''' + self.fixture.cmake_target.read_text() + '''
add_executable(snapshot_probe $<TARGET_OBJECTS:FEXCore_object>)
target_link_libraries(snapshot_probe PRIVATE JemallocLibs)
''')
        build = project / "build"
        # Reuse the same build tree: an old ON configuration must not leave the
        # diagnostic macro or rpmalloc linkage enabled after configuring OFF.
        for enabled in (False, True, False):
            with self.subTest(enabled=enabled):
                self.run_command([cmake, "-S", str(project), "-B", str(build),
                                  "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_C_FLAGS=", "-DCMAKE_CXX_FLAGS=",
                                  "-DENABLE_FEX_ALLOCATOR=" + ("ON" if enabled else "OFF")])
                # Darwin's Make 3.81 can miss flags/object changes inside one
                # timestamp tick. Keep the same CMake tree to test property
                # reconfiguration, but rebuild actual objects deterministically.
                self.run_command([cmake, "--build", str(build), "--clean-first", "--target", "snapshot_probe", "--parallel", "2"])
                entries = json.loads((build / "compile_commands.json").read_text())
                for filename in ("Interface/Core/Core.cpp", "Utils/AllocatorHooks.cpp"):
                    entry, = [item for item in entries if Path(item["file"]) == source / filename]
                    self.assertEqual("-DENABLE_FEX_ALLOCATOR=1" in entry["command"], enabled)
                executable = build / "FEXCore/Source/snapshot_probe"
                self.assertEqual(len(self.symbols(executable)), int(enabled))
                self.run_command([str(executable)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
