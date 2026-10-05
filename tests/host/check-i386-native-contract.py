#!/usr/bin/env python3
"""Exercise the validator on real cross-compiled Mach-O fixtures; no guest runs.

These deliberately tiny source-owned objects test evidence rejection, not Wine,
FEX or app behavior. Separate host harnesses use exact production NSI helpers.
Set CLANG, LLVM_AR and LD64_LLD to already installed trusted tools if necessary.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "build/i386-native-contract"
sys.path.insert(0, str(HERE))
import check as contract
import capture
from macho import MachO, archive_members


def tool(variable, fallback):
    value = os.environ.get(variable) or shutil.which(fallback)
    if not value:
        raise RuntimeError(f"Required trusted local tool missing: {variable}/{fallback}")
    return value


def structures(text, names):
    return "\n".join(re.search(r"struct " + name + r"\s*\{[^}]*\};", text).group(0) for name in names)


NSI_TYPES = """
typedef unsigned int ULONG, UINT, PTR32;
typedef unsigned long UINT_PTR, ULONG_PTR;
typedef int NTSTATUS;
typedef void NPI_MODULEID;
#define NULL ((void *)0)
#define STATUS_INVALID_PARAMETER ((int)0xc000000d)
extern unsigned long ios_wow_base(void);
"""


def nsi_production_fragments():
    source = (ROOT / "build/ntdll-unix/nsi_unixlib_ios.c").read_text()
    header = (ROOT / "wine/include/wine/nsi.h").read_text()
    wow = (ROOT / "build/ntdll-unix/ios_wow.h").read_text()
    native = structures(header, ("nsi_enumerate_all_ex", "nsi_get_all_parameters_ex", "nsi_get_parameter_ex"))
    helpers = wow[wow.index("static inline void *ios_wow_host_ptr"):wow.index("#endif", wow.index("static inline void *ios_wow_host_ptr"))]
    table = source[source.index("const void *nsi_unix_call_funcs[]"):source.index("/* The 32-bit counterpart.")]
    wrappers = source[source.index("typedef ULONG PTR32;"):]
    return native, helpers, table, wrappers


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang, cls.ar = tool("CLANG", "clang"), tool("LLVM_AR", "llvm-ar")
        cls.linker = tool("LD64_LLD", "ld64.lld")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="i386-native-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.objects, self.paths = {}, {}

    def run_command(self, argv, success=True):
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=60)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "failure injection unexpectedly succeeded")
        return result

    def compile(self, key, text, extra=(), suffix=".c"):
        directory = self.root / Path(key[0]).name
        directory.mkdir(exist_ok=True)
        source, obj = directory / (key[1] + suffix), directory / key[1]
        source.write_text(text)
        self.run_command([self.clang, "-target", "arm64-apple-ios17.0", "-O2", "-fvisibility=hidden", *extra,
                          "-c", source, "-o", obj])
        self.paths[key] = obj
        self.objects[key] = MachO(obj.read_bytes(), str(obj))
        return obj

    def fixture(self, overrides=None):
        native, helper, table, wrappers = nsi_production_fragments()
        sources = {
            (contract.NTDLL, "virtual.o"): """
extern int win32u_unix_lib_init(void);
extern const void *nsi_unix_call_funcs[], *nsi_unix_call_wow64_funcs[];
int ios_main_image_i386;
static volatile unsigned long ios_wow_windows[64];
static volatile unsigned ios_wow_window_count;
unsigned long ios_wow_base(void) { return 0x7100000000ul; }
unsigned long ios_wow_base_for_peb(void *p) { return (unsigned long)p + ios_wow_windows[ios_wow_window_count]; }
int ios_wow_window_reserve(void) { return 1; }
void ios_wow_window_bind(void *p) { ios_main_image_i386 = p != 0; }
void ios_wow_window_release(void *p) { ios_main_image_i386 = p == 0; }
void ios_wow_window_release_current(void) { ios_main_image_i386 = 0; }
unsigned long integration_anchor(void) {
return win32u_unix_lib_init() + (unsigned long)nsi_unix_call_funcs[0]
 + (unsigned long)nsi_unix_call_wow64_funcs[0]; }
""",
            (contract.NTDLL, "process.o"): """
extern unsigned long ios_wow_base(void), ios_wow_base_for_peb(void *);
unsigned long NtQueryInformationProcess(void *p) {
return p ? ios_wow_base_for_peb(p) : ios_wow_base(); }
""",
            (contract.NTDLL, "loader.o"): """
extern int ios_wow_window_reserve(void); extern void ios_wow_window_bind(void *);
int load_test(void *p) { ios_wow_window_bind(p); return ios_wow_window_reserve(); }
""",
            (contract.NTDLL, "server.o"): """
extern void ios_wow_window_release(void *);
void server_test(void *p) { ios_wow_window_release(p); }
""",
            (contract.NTDLL, "syscall.o"): """
unsigned long KeServiceDescriptorTable[16];
int KeAddSystemServiceTable(unsigned long *a, unsigned long *b, unsigned c, unsigned char *d, unsigned e)
{ KeServiceDescriptorTable[e] = (unsigned long)a + (unsigned long)b + c + (unsigned long)d; return 1; }
""",
            (contract.WIN32U, "syscall.o"): """
extern int KeAddSystemServiceTable(unsigned long *, unsigned long *, unsigned, unsigned char *, unsigned);
static unsigned long syscalls[2]; static unsigned char arguments[2];
int win32u_unix_lib_init_upstream(void) { return KeAddSystemServiceTable(syscalls, 0, 2, arguments, 1); }
int win32u_unix_lib_init(void) { return win32u_unix_lib_init_upstream(); }
""",
            (contract.NTDLL, "nsi_unixlib_ios.o"): NSI_TYPES + native + helper + """
static int ios_nsi_enumerate_all_ex(void *p) { return p != 0; }
extern int nsi_get_all_parameters_ex(struct nsi_get_all_parameters_ex *);
extern int nsi_get_parameter_ex(struct nsi_get_parameter_ex *);
""" + table + wrappers,
            (contract.NTDLL, "nsi_network_ios.o"): """
int nsi_get_all_parameters_ex(void *p) { return p != 0; }
int nsi_get_parameter_ex(void *p) { return p != 0; }
""",
        }
        sources.update(overrides or {})
        for key, source in sources.items():
            extra = ["-Xclang", "-fdump-record-layouts-complete"] if key[1] == "nsi_unixlib_ios.o" else []
            self.compile(key, source, extra)
        return contract.Contract(self.objects)

    def test_real_archive_and_link_contract(self):
        evidence = self.fixture()
        required, tables = evidence.validate()
        self.assertEqual([t["entries"] for t in tables], [3, 3])
        # A real ar container, including its symbol index, is parsed member by
        # member. The fixture names are never staged as app dependencies.
        archive = self.root / "contract-fixture.a"
        self.run_command([self.ar, "rcs", archive, *[p for k, p in self.paths.items() if k[0] == contract.NTDLL]])
        parsed = dict(archive_members(archive.read_bytes()))
        self.assertEqual(len(parsed), 7)
        self.assertEqual(parsed["virtual.o"], self.paths[contract.NTDLL, "virtual.o"].read_bytes())

    def test_undefined_wrong_owner_and_duplicate_do_not_count(self):
        evidence = self.fixture()
        bad = dict(self.objects)
        key = (contract.NTDLL, "virtual.o")
        bad[(contract.WIN32U, "wrong.o")] = bad.pop(key)
        with self.assertRaisesRegex(ValueError, "wrong archive member"):
            contract.Contract(bad).validate()
        bad = dict(self.objects)
        bad[(contract.WIN32U, "extra.o")] = bad[key]
        with self.assertRaisesRegex(ValueError, "duplicate external definition"):
            contract.Contract(bad).validate()
        self.compile(key, "extern int ios_main_image_i386; int *ref(void) { return &ios_main_image_i386; }")
        with self.assertRaisesRegex(ValueError, "missing/duplicate external"):
            contract.Contract(self.objects).validate()

    def test_weak_fallback_and_unrenamed_definitions_are_rejected(self):
        self.fixture()
        key = (contract.NTDLL, "virtual.o")
        obj = self.objects[key]
        source = (self.paths[key].parent / "virtual.o.c").read_text()
        self.compile(key, source.replace("int ios_main_image_i386;", "__attribute__((weak)) int ios_main_image_i386;"))
        with self.assertRaisesRegex(ValueError, "weak definition"):
            contract.Contract(self.objects).validate()
        self.objects[key] = MachO(obj.data.replace(b"_ios_wow_windows\0", b"_bad_wow_windows\0"), "fallback-without-registry")
        with self.assertRaisesRegex(ValueError, "section definition _ios_wow_windows"):
            contract.Contract(self.objects).validate()
        self.objects[key] = obj
        self.compile((contract.NTDLL, "unrenamed.o"), "void *__wine_unix_call_wow64_funcs[1];")
        with self.assertRaisesRegex(ValueError, "unrenamed unixlib"):
            contract.Contract(self.objects).validate()

    def test_missing_class_query_registration_or_guest_conversion_edges(self):
        evidence = self.fixture()
        for key, reference in [
            ((contract.NTDLL, "process.o"), "_ios_wow_base_for_peb"),
            ((contract.WIN32U, "syscall.o"), "_KeAddSystemServiceTable"),
            ((contract.NTDLL, "nsi_unixlib_ios.o"), "_ios_wow_base"),
        ]:
            obj = self.objects[key]
            wrong = "_bad" + reference[4:]
            raw = obj.data.replace(reference.encode() + b"\0", wrong.encode() + b"\0")
            self.objects[key] = MachO(raw, "wrong-compiled-reference")
            with self.assertRaises(ValueError):
                contract.Contract(self.objects).validate()
            self.objects[key] = obj

    def test_real_final_link_map_fex_provider_and_dead_strip(self):
        self.fixture()
        self.compile((contract.FEX[0], "Context.cpp.o"), """
namespace FEXCore { struct HostFeatures {}; namespace Context { class Context {
public: static void *CreateNewContext(const HostFeatures &); };
void *Context::CreateNewContext(const HostFeatures &) { return (void *)1; } } }
""", suffix=".cpp")
        self.compile((contract.FEX[1], "Config.cpp.o"), """
namespace FEXCore { namespace Config { void Initialize() {} } }
""", suffix=".cpp")
        bridge = self.compile(("bridge", "FEXBridge.o"), """
namespace FEXCore { struct HostFeatures {}; namespace Config { void Initialize(); }
namespace Context { class Context { public: static void *CreateNewContext(const HostFeatures &); }; } }
extern "C" int fex_initialize() { FEXCore::Config::Initialize(); FEXCore::HostFeatures f;
return FEXCore::Context::Context::CreateNewContext(f) != 0; }
extern "C" int fex_test_execute() { return fex_initialize(); }
""", suffix=".cpp")
        del self.objects["bridge", "FEXBridge.o"]
        bridge_source = self.root / "app/Madeira/FEXBridge.mm"
        bridge_source.parent.mkdir(parents=True, exist_ok=True)
        bridge_source.write_text((bridge.parent / "FEXBridge.o.cpp").read_text())
        bridge_capture = self.root / "records/FEXBridge.o.json"
        capture.capture(self.root, bridge_capture, bridge_source, bridge,
                        [self.clang, "-target", "arm64-apple-ios17.0", "-O2", "-c", str(bridge_source), "-o", str(bridge)])
        main = self.compile(("main", "main.o"), """
extern int fex_test_execute(void), load_test(void *); extern void server_test(void *);
extern unsigned long NtQueryInformationProcess(void *), integration_anchor(void);
int main(void) { server_test((void *)1); return fex_test_execute() + load_test((void *)1)
 + NtQueryInformationProcess((void *)1) + integration_anchor(); }
""")
        del self.objects["main", "main.o"]
        archives = []
        for archive in (contract.NTDLL, contract.WIN32U, *contract.FEX):
            target = self.root / archive
            target.parent.mkdir(parents=True, exist_ok=True)
            self.run_command([self.ar, "rcs", target, *[p for k, p in self.paths.items() if k[0] == archive]])
            archives.append(target)
        image, link_map = self.root / "fixture-image", self.root / "fixture.map"
        linker = [self.linker]
        if Path(self.linker).name == "lld":
            linker += ["-flavor", "darwin"]
        self.run_command([*linker, "-arch", "arm64", "-platform_version", "ios", "17.0", "17.0",
                          "-dead_strip", "-e", "_main", "-map", link_map, "-o", image, main, bridge, *archives])
        evidence = contract.Contract(self.objects)
        required, _ = evidence.validate()
        verified = contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)
        self.assertEqual(len(verified["fex_entry_points"]), 2)
        original = link_map.read_text()
        # The upstream helper really is dead-stripped in this optimized link.
        live = contract.parse_link_map(original, self.root)[1]
        self.assertNotIn("_win32u_unix_lib_init_upstream", live)
        link_map.write_text(original.replace(str(image), str(self.root / "other-image")))
        with self.assertRaisesRegex(ValueError, "another output image"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)
        link_map.write_text(original.replace("libntdll_unix.a(virtual.o)", "libntdll_unix.a(fake.o)"))
        with self.assertRaisesRegex(ValueError, "wrong final-link provider"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)
        link_map.write_text(original.replace("_NtQueryInformationProcess", "_WrongQueryInformationProc"))
        with self.assertRaisesRegex(ValueError, "live map disagree"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)
        link_map.write_text(original)
        wrong = dict(self.objects)
        key = (contract.FEX[0], "Context.cpp.o")
        wrong[(contract.NTDLL, "fake-fex.o")] = wrong.pop(key)
        with self.assertRaisesRegex(ValueError, "outside real FEX archives"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, contract.Contract(wrong), required)
        original_record = bridge_capture.read_bytes()
        bridge_capture.unlink()
        with self.assertRaisesRegex(ValueError, "missing, symlinked"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)
        bridge_capture.write_bytes(original_record)
        bridge_source.write_text(bridge_source.read_text() + "\n/* source changed after capture */\n")
        with self.assertRaisesRegex(ValueError, "dependency changed"):
            contract.verify_link(self.root, image, link_map, bridge, bridge_capture, evidence, required)

    def test_table_order_null_wrong_width_alias_and_missing_wow(self):
        self.fixture()
        obj = self.objects[contract.NTDLL, "nsi_unixlib_ios.o"]
        table = "_nsi_unix_call_wow64_funcs"
        symbol = obj.definition(table)
        section = obj.sections[symbol.section - 1]
        start, end = obj.extent(symbol)
        # Mutate actual relocation entries, rather than accepting an nm text
        # fixture as evidence of table contents.
        original = self.paths[contract.NTDLL, "nsi_unixlib_ios.o"].read_bytes()
        cursor = 32
        reloc_offset = None
        for _ in range(struct.unpack_from("<I", original, 16)[0]):
            cmd, length = struct.unpack_from("<II", original, cursor)
            if cmd == 0x19:
                count = struct.unpack_from("<I", original, cursor + 64)[0]
                for i in range(count):
                    base = cursor + 72 + i * 80
                    if original[base:base + 16].rstrip(b"\0").decode() == section.name:
                        reloc_offset = struct.unpack_from("<I", original, base + 56)[0]
            cursor += length
        self.assertIsNotNone(reloc_offset)
        indexes = [i for i, r in enumerate(section.relocations) if start <= r[0] < end]
        mutations = []
        reordered = bytearray(original)
        a, b = (reloc_offset + indexes[i] * 8 + 4 for i in (0, 1))
        reordered[a:a+4], reordered[b:b+4] = reordered[b:b+4], reordered[a:a+4]
        # Local section relocations share an index; swapping the pointer
        # addends catches their actual target swap as well.
        a, b = section.offset + start, section.offset + start + 8
        reordered[a:a+8], reordered[b:b+8] = reordered[b:b+8], reordered[a:a+8]
        mutations.append(reordered)
        wrong_width = bytearray(original)
        at = reloc_offset + indexes[0] * 8 + 4
        value = struct.unpack_from("<I", wrong_width, at)[0]
        struct.pack_into("<I", wrong_width, at, (value & ~(3 << 25)) | (2 << 25))
        mutations.append(wrong_width)
        null = bytearray(original)
        struct.pack_into("<Q", null, section.offset + start, 0xffffffffffffffff)
        mutations.append(null)
        for changed in mutations:
            broken = MachO(bytes(changed), "mutated-real-object")
            self.objects[contract.NTDLL, "nsi_unixlib_ios.o"] = broken
            with self.assertRaises(ValueError):
                contract.Contract(self.objects).validate()
        self.objects[contract.NTDLL, "nsi_unixlib_ios.o"] = obj
        with self.assertRaisesRegex(ValueError, "does not point"):
            obj.pointer_table(table, contract.TABLES["_nsi_unix_call_funcs"], contract.Contract(self.objects).resolve)

    def test_bad_platform_truncated_archive_and_duplicate_members(self):
        self.fixture()
        raw = self.paths[contract.NTDLL, "virtual.o"].read_bytes()
        for changed in (raw[:25], raw[:4] + struct.pack("<I", 0x1000007) + raw[8:]):
            with self.assertRaises(ValueError):
                MachO(changed, "bad-object")
        archive = self.root / "bad.a"
        self.run_command([self.ar, "rcs", archive, self.paths[contract.NTDLL, "virtual.o"]])
        data = archive.read_bytes()
        with self.assertRaises(ValueError):
            list(archive_members(data[:-9]))
        with self.assertRaises(ValueError):
            list(archive_members(data + data[8:]))

    def test_capture_binds_compiler_dependencies_object_and_layouts(self):
        native, helper, table, wrappers = nsi_production_fragments()
        source = self.root / "build/ntdll-unix/nsi_unixlib_ios.c"
        output = self.root / "build/ntdll-unix/obj/nsi_unixlib_ios.o"
        source.parent.mkdir(parents=True)
        output.parent.mkdir()
        source.write_text(NSI_TYPES + native + structures(wrappers, ("nsi_enumerate_all_ex32", "nsi_get_all_parameters_ex32", "nsi_get_parameter_ex32")))
        record_path = self.root / "records" / contract.record_name(contract.NTDLL, output.name)
        args = [self.clang, "-target", "arm64-apple-ios17.0", "-DWINE_IOS=1", "-c", str(source), "-o", str(output)]
        record = capture.capture(self.root, record_path, source, output, args)
        expected = json.loads((HERE / "contract.json").read_text())["nsi_layouts"]
        contract.check_layouts(record, expected)
        contract.capture_binding(self.root, record_path.parent, contract.NTDLL, output.name, output.read_bytes())
        bad = dict(record)
        bad["record_layouts"] = bad["record_layouts"].replace("sizeof=60,", "sizeof=64,")
        with self.assertRaisesRegex(ValueError, "compiled NSI layout"):
            contract.check_layouts(bad, expected)
        with self.assertRaisesRegex(ValueError, "stale/replaced"):
            contract.capture_binding(self.root, record_path.parent, contract.NTDLL, output.name, output.read_bytes() + b"x")
        source.write_text(source.read_text() + "\n/* changed */\n")
        with self.assertRaisesRegex(ValueError, "dependency changed"):
            contract.capture_binding(self.root, record_path.parent, contract.NTDLL, output.name, output.read_bytes())

    def test_capture_cli_preserves_bounded_real_compiler_failure_tails(self):
        source, output = self.root / "broken.c", self.root / "broken.o"
        record = self.root / "failed.json"
        for phase, code, expected in (
                ("preprocessor", "#warning OMITTED_PREFIX " + "x" * 100000 + " WARNING_TAIL_MARKER\n#error PREPROCESSOR_TAIL_MARKER\n",
                 "PREPROCESSOR_TAIL_MARKER"),
                ("compile", "#warning OMITTED_PREFIX " + "x" * 100000 +
                 " WARNING_TAIL_MARKER\nint broken = COMPILER_TAIL_MARKER;\n", "COMPILER_TAIL_MARKER")):
            with self.subTest(phase=phase):
                source.write_text(code)
                output.write_bytes(b"stale output")
                command = [sys.executable, HERE / "capture.py", "--root", self.root,
                           "--record", record, "--source", source, "--output", output, "--",
                           self.clang, "-target", "arm64-apple-ios17.0", "-fno-caret-diagnostics",
                           "-c", source, "-o", output]
                result = self.run_command(command, success=False)
                self.assertIn("error:", result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("OMITTED_PREFIX", result.stderr)
                self.assertIn("compiler exited with status", result.stderr)
                self.assertLessEqual(len(result.stderr.encode("utf-8")), 32 * 1024 + 256)
                self.assertEqual(result.stdout, "")
                self.assertFalse(record.exists())
                self.assertFalse(output.exists())

    def test_source_binding_and_absent_native_evidence_fail(self):
        spec = json.loads((HERE / "contract.json").read_text())
        contract.source_bindings(ROOT, spec)
        bad = json.loads(json.dumps(spec))
        bad["source_sha256"]["build/ntdll-unix/process_ios.c"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reviewed source changed"):
            contract.source_bindings(ROOT, bad)
        with self.assertRaises(ValueError):
            contract.validate(ROOT, self.root / "missing-native.json", self.root / "records")

    def test_aggregate_checker_with_explicitly_synthetic_fixture_manifest(self):
        self.fixture()
        fixture_here = self.root / "build/i386-native-contract"
        fixture_here.mkdir(parents=True)
        spec = json.loads((HERE / "contract.json").read_text())
        # This test-only specification is deliberately NOT the production
        # source binding. It cannot be selected with any command-line option.
        for name in spec["source_sha256"]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for filename in ("check.py", "macho.py", "capture.py"):
            shutil.copyfile(HERE / filename, fixture_here / filename)
        records = self.root / "captures"
        for key, source_name in contract.SOURCES.items():
            fixture_source = self.paths[key].parent / (key[1] + ".c")
            source, output = self.root / source_name, self.root / contract.object_path(*key)
            source.write_text(fixture_source.read_text())
            output.parent.mkdir(parents=True, exist_ok=True)
            flags = ["-target", "arm64-apple-ios17.0", "-O2", "-fvisibility=hidden", "-DWINE_IOS=1"]
            if key[0] == contract.WIN32U:
                flags += ["-D__wine_unix_lib_init=win32u_unix_lib_init"]
            capture.capture(self.root, records / contract.record_name(*key), source, output,
                            [self.clang, *flags, "-c", str(source), "-o", str(output)])
            self.paths[key] = output
        spec["source_sha256"] = {name: contract.sha((self.root / name).read_bytes()) for name in spec["source_sha256"]}
        spec["limits"] = ["SYNTHETIC VALIDATOR FIXTURE ONLY; no production native evidence"]
        (fixture_here / "contract.json").write_text(json.dumps(spec))
        loader = importlib.util.spec_from_file_location("fixture_native_artifacts", self.root / ".github/ci/native-artifacts.py")
        native = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(native)
        archives = {}
        for i, name in enumerate(native.EXPECTED_ARCHIVES):
            paths = [p for key, p in self.paths.items() if key[0] == name]
            if not paths:
                paths = [self.compile((name, f"fixture-{i}.o"), f"int fixture_{i}(void) {{ return {i}; }}")]
            archive = self.root / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            self.run_command([self.ar, "rcs", archive, *paths])
            archives[name] = {"sha256": contract.sha(archive.read_bytes())}
        receipt = self.root / "fixture-receipt.json"
        fex_script = self.root / "build/fex-ios/build.sh"
        fex_script.write_text("# Explicit synthetic compile-metadata fixture; not a build script\n")
        fex_cache = self.root / "FEX/build-ios/CMakeCache.txt"
        fex_cache.parent.mkdir(parents=True, exist_ok=True)
        fex_cache.write_text("\n".join(f"{k}:STRING={v}" for k, v in {
            "ENABLE_LTO": "OFF", "CMAKE_SYSTEM_NAME": "iOS", "CMAKE_OSX_ARCHITECTURES": "arm64",
            "CMAKE_OSX_DEPLOYMENT_TARGET": "17.0", "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", "CMAKE_OSX_SYSROOT": "iphoneos"}.items()) + "\n")
        (fex_cache.parent / "compile_commands.json").write_text("[]\n")
        inputs = {name: contract.sha((self.root / name).read_bytes()) for name in
                  ("build/fex-ios/build.sh", ".github/ci/native-artifacts.py")}
        fex_metadata = native.verified_fex_native_build({"input_sha256": inputs})
        receipt.write_text(json.dumps({"schema": 1, "stage": "native-dependencies-only", "dependencies_ready": True,
                                       "archives": archives, "source_repairs": json.loads((ROOT / "build/fex-ios/source-repairs.json").read_text()),
                                       "input_sha256": inputs, "fex_native_build": fex_metadata}))
        original_here = contract.HERE
        try:
            contract.HERE = fixture_here
            result = contract.validate(self.root, receipt, records)
            self.assertEqual(result["status"], "bounded_archive_contract_passed")
            self.assertIsNone(result["final_link"])
            self.assertEqual(result["runtime"], "not_run")
            self.assertEqual(len(result["captures"]), 8)
            archive = self.root / contract.NTDLL
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "receipt archive mismatch"):
                contract.validate(self.root, receipt, records)
        finally:
            contract.HERE = original_here

    def host_harness(self, source, succeeds=True):
        path, output = self.root / "host-harness.c", self.root / "host-harness"
        path.write_text(source)
        self.run_command([tool("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                          "-Wno-unused-function", path, "-o", output])
        return self.run_command([output], success=succeeds)

    def test_production_nsi_pointer_conversions_and_scalar_layouts(self):
        native, helpers, table, wrappers = nsi_production_fragments()
        prefix = "#include <assert.h>\n#include <stddef.h>\n" + NSI_TYPES.replace("#define NULL ((void *)0)\n", "")
        prefix += native + helpers + """
static int ios_nsi_enumerate_all_ex(void *);
int nsi_get_all_parameters_ex(struct nsi_get_all_parameters_ex *);
int nsi_get_parameter_ex(struct nsi_get_parameter_ex *);
"""
        checks = """
static unsigned long base;
unsigned long ios_wow_base(void) { return base; }
static struct nsi_enumerate_all_ex32 p0;
static struct nsi_get_all_parameters_ex32 p1;
static struct nsi_get_parameter_ex32 p2;
static int called;
static void pointer(ULONG guest, const void *host) {
assert((unsigned long)host == (guest ? base + guest : 0)); }
#define PTR(p, g, f) pointer((g).f, (p)->f)
#define SCALAR(p, g, f) assert((p)->f == (g).f)
#define COMMON(p,g) PTR(p,g,unknown[0]); PTR(p,g,unknown[1]); PTR(p,g,module); \
 SCALAR(p,g,table); SCALAR(p,g,first_arg)
#define ROWS(p,g) PTR(p,g,rw_data); SCALAR(p,g,rw_size); PTR(p,g,dynamic_data); \
 SCALAR(p,g,dynamic_size); PTR(p,g,static_data); SCALAR(p,g,static_size)
static int ios_nsi_enumerate_all_ex(void *arg) {
 struct nsi_enumerate_all_ex *p = arg; ++called;
 COMMON(p,p0); ROWS(p,p0); SCALAR(p,p0,second_arg); PTR(p,p0,key_data);
 SCALAR(p,p0,key_size); SCALAR(p,p0,count); p->count = 4321; return 7; }
int nsi_get_all_parameters_ex(struct nsi_get_all_parameters_ex *p) {
 ++called; COMMON(p,p1); ROWS(p,p1); SCALAR(p,p1,unknown2); PTR(p,p1,key); SCALAR(p,p1,key_size); return 8; }
int nsi_get_parameter_ex(struct nsi_get_parameter_ex *p) {
 ++called; COMMON(p,p2); SCALAR(p,p2,unknown2); PTR(p,p2,key); SCALAR(p,p2,key_size);
 SCALAR(p,p2,param_type); PTR(p,p2,data); SCALAR(p,p2,data_size); SCALAR(p,p2,data_offset); return 9; }
int main(void) {
 assert(sizeof(p0) == 60 && sizeof(p1) == 56 && sizeof(p2) == 48);
 assert(sizeof(struct nsi_enumerate_all_ex) == 112);
 assert(sizeof(struct nsi_get_all_parameters_ex) == 104);
 assert(sizeof(struct nsi_get_parameter_ex) == 80);
 assert(ios_wow64_nsi_enumerate_all_ex(0) == STATUS_INVALID_PARAMETER);
 assert(ios_wow64_nsi_get_all_parameters_ex(0) == STATUS_INVALID_PARAMETER);
 assert(ios_wow64_nsi_get_parameter_ex(0) == STATUS_INVALID_PARAMETER);
 assert(called == 0);
 for (int pass = 0; pass < 2; ++pass) {
  base = pass ? 0x7100000000ul : 0;
  p0 = (struct nsi_enumerate_all_ex32){{0,0xfffffff0u},0x80000000u,17,18,19,20,21,0,23,24,25,26,27,28};
  p1 = (struct nsi_get_all_parameters_ex32){{0xfffffff0u,0},0x80000000u,31,32,33,34,35,36,37,0,39,40,41};
  p2 = (struct nsi_get_parameter_ex32){{0,0xfffffff0u},0x80000000u,51,52,53,0,55,56,0xffffff00u,58,59};
  assert(ios_wow64_nsi_enumerate_all_ex(&p0) == 7 && p0.count == 4321);
  assert(ios_wow64_nsi_get_all_parameters_ex(&p1) == 8);
  assert(ios_wow64_nsi_get_parameter_ex(&p2) == 9);
 }
 assert(called == 6); return 0;
}
"""
        self.host_harness(prefix + table + wrappers + checks)
        corrupted = wrappers.replace("ios_wow_host_ptr( params32->module )", "(void *)(unsigned long)params32->module")
        self.assertNotEqual(corrupted, wrappers)
        self.host_harness(prefix + table + corrupted + checks, succeeds=False)

    def test_production_win32u_registers_slot_one(self):
        upstream = (ROOT / "wine/dlls/win32u/syscall.c").read_text()
        upstream = upstream[upstream.index("NTSTATUS __wine_unix_lib_init(void)"):]
        override = (ROOT / "build/win32u-unix/syscall_ios.c").read_text()
        override = override[override.index("NTSTATUS win32u_unix_lib_init(void)"):]
        ntdll = (ROOT / "wine/dlls/ntdll/unix/syscall.c").read_text()
        registration = ntdll[ntdll.index("BOOLEAN KeAddSystemServiceTable("):ntdll.index("void trace_syscall(")]
        prefix = """
#include <assert.h>
#include <stddef.h>
typedef unsigned long ULONG_PTR;
typedef unsigned int ULONG;
typedef unsigned char BYTE;
typedef int BOOLEAN, NTSTATUS;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
struct service_table { ULONG_PTR *ServiceTable, *CounterTable; ULONG ServiceLimit; BYTE *ArgumentTable; };
static struct service_table KeServiceDescriptorTable[4];
static ULONG_PTR syscalls[] = {10,20}, zero_bits = 0x7fffffff;
static BYTE arguments[] = {4,8};
static const char *syscall_names[] = {"a","b"}, *usercall_names[] = {"c"};
static int debug_calls;
static void ntdll_add_syscall_debug_info(unsigned index, const char **names, const char **users) {
 assert(index == 1 && names == syscall_names && users == usercall_names); ++debug_calls; }
#define __wine_unix_lib_init win32u_unix_lib_init_upstream
"""
        checks = """
int main(void) {
 KeServiceDescriptorTable[0].ServiceLimit = 777;
 assert(win32u_unix_lib_init() == 0 && zero_bits == 0 && debug_calls == 1);
 assert(KeServiceDescriptorTable[0].ServiceLimit == 777);
 assert(KeServiceDescriptorTable[1].ServiceTable == syscalls);
 assert(KeServiceDescriptorTable[1].CounterTable == 0);
 assert(KeServiceDescriptorTable[1].ServiceLimit == 2);
 assert(KeServiceDescriptorTable[1].ArgumentTable == arguments);
 assert(KeServiceDescriptorTable[2].ServiceTable == 0);
 assert(KeAddSystemServiceTable(syscalls,0,2,arguments,4) == FALSE);
 return 0;
}
"""
        self.host_harness(prefix + registration + upstream + override + checks)
        wrong_slot = upstream.replace("arguments, 1", "arguments, 0")
        self.assertNotEqual(wrong_slot, upstream)
        self.host_harness(prefix + registration + wrong_slot + override + checks, succeeds=False)

    def test_production_class_1010_queries_current_and_remote_registry(self):
        source = (ROOT / "build/ntdll-unix/process_ios.c").read_text()
        block = source[source.index("    case ProcessWineIosWowGuestBase:"):source.index("    case ProcessImageFileName:")]
        header = (ROOT / "wine/include/winternl.h").read_text()
        value = re.search(r"ProcessWineIosWowGuestBase\s*=\s*(\d+)", header)[1]
        self.assertEqual(value, "1010")
        prefix = """
#include <assert.h>
#include <stdint.h>
typedef uintptr_t ULONG_PTR;
typedef unsigned int ULONG;
typedef void *HANDLE;
#define ProcessWineIosWowGuestBase 1010
#define STATUS_INFO_LENGTH_MISMATCH ((int)0xc0000004)
#define GetCurrentProcess() ((HANDLE)(intptr_t)-1)
static ULONG_PTR self_base, other_base;
static int server_status, self_calls, remote_calls;
struct request { ULONG_PTR handle; } request;
struct reply { ULONG_PTR peb; } reply = {0x12345678000ul};
static ULONG_PTR ios_wow_base(void) { ++self_calls; return self_base; }
static ULONG_PTR ios_wow_base_for_peb(void *peb) {
 assert(peb == (void *)reply.peb); ++remote_calls; return other_base; }
static ULONG_PTR wine_server_obj_handle(HANDLE handle) { return (ULONG_PTR)handle; }
static void *wine_server_get_ptr(ULONG_PTR value) { return (void *)value; }
static int wine_server_call(struct request *req) { assert(req->handle == 42); return server_status; }
#define SERVER_START_REQ(kind) do { struct request *req = &request; struct reply *reply = &reply_value;
#define SERVER_END_REQ } while(0)
static int query(HANDLE handle, int kind, void *info, ULONG size, ULONG *ret_len) {
 struct reply reply_value = reply; ULONG len = 0; int ret = 0;
 switch (kind) {
"""
        suffix = """
 default: return 123;
 } if (ret_len) *ret_len = len; return ret;
}
int main(void) {
 ULONG_PTR value = 999; ULONG length = 999;
 assert(query(GetCurrentProcess(),1010,&value,sizeof(value),&length) == 0);
 assert(value == 0 && length == sizeof(value) && self_calls == 1 && remote_calls == 0);
 self_base = 0x7100000000ul; other_base = 0x7900000000ul;
 assert(query(GetCurrentProcess(),1010,&value,sizeof(value),&length) == 0 && value == self_base);
 assert(query((HANDLE)42,1010,&value,sizeof(value),&length) == 0 && value == other_base);
 assert(remote_calls == 1);
 server_status = 456; value = 999;
 assert(query((HANDLE)42,1010,&value,sizeof(value),&length) == 456 && value == 999 && remote_calls == 1);
 server_status = 0; other_base = 0;
 assert(query((HANDLE)42,1010,&value,sizeof(value),&length) == 0 && value == 0);
 value = 999; length = 999;
 assert(query(GetCurrentProcess(),1010,&value,4,&length) == STATUS_INFO_LENGTH_MISMATCH);
 assert(value == 999 && length == 999);
 return 0;
}
"""
        self.host_harness(prefix + block + suffix)
        broken = block.replace("ios_wow_base_for_peb( wine_server_get_ptr( reply->peb ) )", "ios_wow_base()")
        self.assertNotEqual(broken, block)
        # Suppress only the now-unused local that the deliberate broken branch leaves.
        self.host_harness(prefix.replace("struct reply *reply =", "struct reply *reply __attribute__((unused)) =") + broken + suffix, succeeds=False)


if __name__ == "__main__":
    unittest.main()
