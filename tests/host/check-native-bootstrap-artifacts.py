#!/usr/bin/env python3
"""Portable negative fixtures for CI iOS archives and complete-bundle gating."""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_artifacts", ROOT / ".github/ci/native-artifacts.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def macho(platform=2, cpu=0x0100000C, legacy=False, subtype=0):
    command = struct.pack("<4I", 0x25 if platform == 2 else 0x24, 16, 0x110000, 0x1B0000) if legacy else struct.pack("<6I", 0x32, 24, platform, 0x110000, 0x1B0000, 0)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 1, 1, len(command), 0, 0) + command


def member(name, data, bsd=False):
    if bsd:
        encoded = name.encode() + b"\0" * ((-len(name.encode())) % 8)
        name = f"#1/{len(encoded)}"
        data = encoded + data
    header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
    return header + data + (b"\n" if len(data) % 2 else b"")


def archive(*members):
    return b"!<arch>\n" + b"".join(members)


def repair_fixture(root):
    revision = "f" * 40
    sources = ("FEXCore/Source/Interface/Core/Core.cpp", "FEXCore/Source/Utils/ArchHelpers/Arm64.cpp")
    patches = ("build/fex-ios/patches/reviewed.patch", "build/fex-ios/patches/second.patch")
    data = {"build/fex-ios/apply-source-repairs.py": b"# fixture apply script\n"}
    repairs = []
    for number, (relative, patch) in enumerate(zip(sources, patches)):
        data[patch] = f"reviewed patch {number}\n".encode()
        data["FEX/" + relative] = f"reviewed patched source {number}\n".encode()
        repairs.append({"id": f"fixture-{number}", "patch": patch,
                        "patch_sha256": hashlib.sha256(data[patch]).hexdigest(),
                        "files": [{"path": relative, "original_sha256": "0" * 64,
                                   "patched_sha256": hashlib.sha256(data["FEX/" + relative]).hexdigest()}]})
    spec = {"schema_version": 1, "component": "FEX", "source_repository": "https://github.com/willfaust/FEX.git",
            "source_revision": revision, "repairs": repairs}
    encoded = (json.dumps(spec, indent=2) + "\n").encode()
    data[module.FEX_REPAIR_SPEC] = encoded
    data[module.FEX_REPAIR_RECORD] = encoded
    for name, payload in data.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    document = {"dependencies_ready": True, "source_commit": "fixture",
                "submodules": [{"path": "FEX", "commit": revision, "repository": spec["source_repository"]}],
                "input_sha256": {name: hashlib.sha256(data[name]).hexdigest() for name in (
                    module.FEX_REPAIR_SPEC, *patches, "build/fex-ios/apply-source-repairs.py")}}
    def command(*args, cwd=None):
        if cwd == root / "FEX":
            if args == ("git", "rev-parse", "HEAD"):
                return revision
            if args == ("git", "diff", "--name-only", "--no-renames", "HEAD"):
                return "\n".join(sources)
            raise AssertionError(args)
        return "fixture"
    return document, command


def native_object_fixture(root, document):
    payloads = {
        module.FEX_NATIVE_OBJECT_PATHS["source"]: b"int same_source;\n",
        module.FEX_NATIVE_OBJECT_PATHS["compile_database"]: b"[]\n",
        module.FEX_NATIVE_OBJECT_PATHS["production_object"]: macho(),
        **{name: ("reviewed helper " + name + "\n").encode() for name in module.FEX_NATIVE_INPUTS},
    }
    for name, payload in payloads.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    document.setdefault("input_sha256", {}).update({name: module.sha256(root / name) for name in module.FEX_NATIVE_INPUTS})
    document.setdefault("tool_versions", {})["iphoneos_sdk_path"] = "/fixture/iPhoneOS.sdk"
    receipt = {
        "schema_version": 1, "status": "passed", "evidence_kind": "fresh-same-source-thinlto-reproduction",
        "sdk_path": "/fixture/iPhoneOS.sdk", "helper_sha256": document["input_sha256"]["build/fex-ios/check-native-object.py"],
        **{kind: {"path": name, "sha256": module.sha256(root / name)} for kind, name in module.FEX_NATIVE_OBJECT_PATHS.items()},
        "native_configuration": {"enable_lto": False, "architecture": "arm64", "deployment_target": "17.0", "ipo_flags": []},
        "compiler": {"path": "/fixture/Apple/clang++", "version": "fixture", "sha256": "c" * 64},
        "reproduction": {"format": "LLVM bitcode", "magic_hex": "dec0170b", "sha256": "b" * 64,
                         "added_flag": "-flto=thin", "target_triple": "arm64-apple-ios17.0.0",
                         "override_module_is_error": True, "reader_exit_code": 0, "strict_validator_rejected": True},
    }
    receipt["production_object"]["format"] = "Mach-O arm64 iOS"
    path = root / "fex-native-object.json"
    path.write_text(json.dumps(receipt))
    return receipt, path


class NativeObjectEvidenceTests(unittest.TestCase):
    def test_every_evidence_field_and_current_input_required(self):
        for mutation in (None, "missing", "status", "lto", "triple", "override", "reader", "accepts-bitcode", "magic", "helper", "source", "database", "object", "compiler", "sdk", "helper-receipt"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document = {}
                receipt, path = native_object_fixture(root, document)
                if mutation == "status": receipt["status"] = "pending"
                elif mutation == "lto": receipt["native_configuration"]["enable_lto"] = True
                elif mutation == "triple": receipt["reproduction"]["target_triple"] = "arm64-apple-ios17.0.0-simulator"
                elif mutation == "override": receipt["reproduction"]["override_module_is_error"] = False
                elif mutation == "reader": receipt["reproduction"]["reader_exit_code"] = 1
                elif mutation == "accepts-bitcode": receipt["reproduction"]["strict_validator_rejected"] = False
                elif mutation == "magic": receipt["reproduction"]["magic_hex"] = "00000000"
                elif mutation == "helper": (root / module.FEX_NATIVE_INPUTS[0]).write_text("changed helper")
                elif mutation in ("source", "database", "object"):
                    kind = {"database": "compile_database", "object": "production_object"}.get(mutation, mutation)
                    (root / module.FEX_NATIVE_OBJECT_PATHS[kind]).write_text("changed input")
                elif mutation == "compiler": receipt["compiler"].pop("sha256")
                elif mutation == "sdk": receipt["sdk_path"] = "/fixture/MacOSX.sdk"
                elif mutation == "helper-receipt": receipt["helper_sha256"] = "e" * 64
                path.write_text(json.dumps(receipt))
                if mutation == "missing": path.unlink()
                with mock.patch.object(module, "ROOT", root):
                    if mutation is None:
                        self.assertEqual(module.verified_fex_native_object(document, path)["status"], "passed")
                    else:
                        with self.assertRaises(ValueError): module.verified_fex_native_object(document, path)

    def test_matching_hash_cannot_allow_host_or_bitcode_production_object(self):
        for payload in (macho(platform=1), macho(platform=7), b"BC\xc0\xde" + b"\0" * 100):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document = {}
                receipt, path = native_object_fixture(root, document)
                (root / module.FEX_NATIVE_OBJECT_PATHS["production_object"]).write_bytes(payload)
                receipt["production_object"]["sha256"] = hashlib.sha256(payload).hexdigest()
                path.write_text(json.dumps(receipt))
                with mock.patch.object(module, "ROOT", root), self.assertRaises(ValueError):
                    module.verified_fex_native_object(document, path)


class RepairProvenanceTests(unittest.TestCase):
    def test_verified_and_tampered_repair_evidence(self):
        for mutation in (None, "source", "patch", "metadata", "revision", "extra-change", "record-missing", "spec"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document, command = repair_fixture(root)
                if mutation == "source":
                    (root / "FEX/FEXCore/Source/Interface/Core/Core.cpp").write_text("unexpected source")
                elif mutation == "patch":
                    (root / "build/fex-ios/patches/reviewed.patch").write_text("unexpected patch")
                elif mutation == "metadata":
                    (root / module.FEX_REPAIR_RECORD).write_text("{}")
                elif mutation == "record-missing":
                    (root / module.FEX_REPAIR_RECORD).unlink()
                elif mutation == "spec":
                    spec = json.loads((root / module.FEX_REPAIR_SPEC).read_text())
                    spec["repairs"][0]["files"][0]["path"] = "../../outside"
                    (root / module.FEX_REPAIR_SPEC).write_text(json.dumps(spec))
                    document["input_sha256"][module.FEX_REPAIR_SPEC] = module.sha256(root / module.FEX_REPAIR_SPEC)
                    (root / module.FEX_REPAIR_RECORD).write_text(json.dumps(spec))
                original_command = command
                if mutation == "revision":
                    command = lambda *args, **kwargs: "e" * 40
                elif mutation == "extra-change":
                    command = lambda *args, **kwargs: (original_command(*args, **kwargs) + "\nother.cpp") if "diff" in args else original_command(*args, **kwargs)
                with mock.patch.object(module, "ROOT", root), mock.patch.object(module, "command", side_effect=command):
                    if mutation is None:
                        self.assertEqual(module.verified_fex_repairs(document)["component"], "FEX")
                    else:
                        with self.assertRaises(ValueError):
                            module.verified_fex_repairs(document)

    def test_every_repair_requires_complete_matching_evidence(self):
        for mutation in (None, "source", "patch", "input", "old-record", "missing-change"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document, command = repair_fixture(root)
                spec = json.loads((root / module.FEX_REPAIR_SPEC).read_text())
                second = spec["repairs"][1]
                if mutation == "source":
                    (root / "FEX" / second["files"][0]["path"]).write_text("unexpected second source")
                elif mutation == "patch":
                    (root / second["patch"]).write_text("unexpected second patch")
                elif mutation == "input":
                    del document["input_sha256"][second["patch"]]
                elif mutation == "old-record":
                    spec["repairs"].pop()
                    (root / module.FEX_REPAIR_RECORD).write_text(json.dumps(spec))
                elif mutation == "missing-change":
                    original_command = command
                    command = lambda *args, **kwargs: (original_command(*args, **kwargs).splitlines()[0]
                        if "diff" in args else original_command(*args, **kwargs))
                with mock.patch.object(module, "ROOT", root), mock.patch.object(module, "command", side_effect=command):
                    if mutation is None:
                        self.assertEqual(len(module.verified_fex_repairs(document)["repairs"]), 2)
                    else:
                        with self.assertRaises(ValueError):
                            module.verified_fex_repairs(document)


class MetalReceiptTests(unittest.TestCase):
    def test_available_signed_smoke_receipt_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metal.json"
            receipt = {"schema": 1, "status": "available", "smoke_test": {"status": "passed"},
                       "verified_executables": {name: {"verification_passed": True,
                           "requirement": "anchor apple", "sha256": "f" * 64}
                           for name in ("metal-compiler", "metallib-linker")}}
            path.write_text(json.dumps(receipt))
            self.assertEqual(module.metal_receipt(path)["status"], "available")
            for field in ("status", "smoke", "signature"):
                invalid = json.loads(json.dumps(receipt))
                if field == "status": invalid["status"] = "running"
                elif field == "smoke": invalid["smoke_test"]["status"] = "failed"
                else: invalid["verified_executables"]["metal-compiler"]["verification_passed"] = False
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError): module.metal_receipt(path)


class ArchiveTests(unittest.TestCase):
    def validate(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.a"
            path.write_bytes(data)
            return module.validate_archive(path)

    def test_device_ios(self):
        result = self.validate(archive(member("a.o/", macho())))
        self.assertEqual(result["platform"], "iOS")
        self.assertEqual(result["object_members"], 1)

    def test_legacy_ios(self):
        self.validate(archive(member("a.o/", macho(legacy=True))))

    def test_bsd_indexes_and_long_names(self):
        for index in ("__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64 SORTED"):
            result = self.validate(archive(member(index, b"index", bsd=True), member("a-very-long-object-name.o", macho(), bsd=True)))
            self.assertEqual(result["object_members"], 1)

    def test_gnu_indexes_and_long_names(self):
        self.validate(archive(member("/", b"index"), member("//", b"long-object-file-name.o/\n"), member("/0", macho())))

    def test_host_simulator_unknown_or_mixed_platform_rejected(self):
        for platform in (1, 3, 4, 7, 0, 99):
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                self.validate(archive(member("ios.o/", macho()), member("bad.o/", macho(platform=platform))))

    def test_wrong_cpu_arm64e_and_bitcode_rejected(self):
        for payload in (macho(cpu=0x01000007), macho(subtype=2), b"BC\xc0\xde" * 20, b"\xde\xc0\x17\x0b" * 20):
            with self.assertRaises(ValueError):
                self.validate(archive(member("bad.o/", payload)))

    def test_rejected_bitcode_reports_format_without_accepting_it(self):
        for magic, name in ((b"BC\xc0\xde", "LLVM bitcode"), (b"\xde\xc0\x17\x0b", "LLVM bitcode wrapper")):
            with self.subTest(format=name), self.assertRaisesRegex(ValueError, "magic=" + magic.hex() + ", " + name):
                self.validate(archive(member("bitcode.o/", magic + b"\0" * 60)))

    def test_missing_platform_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(archive(member("bad.o/", struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 1, 0, 0, 0, 0))))

    def test_truncated_bad_size_empty_thin_rejected(self):
        good = archive(member("a.o/", macho()))
        for data in (b"!<arch>\n", archive(member("/", b"index")), b"!<thin>\n", good[:-1], good[:35], b"bad"):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.validate(data)
        malformed = bytearray(macho())
        struct.pack_into("<I", malformed, 36, 1024)
        with self.assertRaises(ValueError):
            self.validate(archive(member("a.o/", malformed)))

    def test_archive_size_limit(self):
        with mock.patch.object(module, "MAX_BUNDLE_BYTES", 8), self.assertRaises(ValueError):
            self.validate(archive(member("a.o/", macho())))

    def test_missing_file_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.a"
            with self.assertRaises(ValueError):
                module.validate_archive(path)
            target = Path(directory) / "actual.a"
            target.write_bytes(archive(member("a.o/", macho())))
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                module.validate_archive(path)


class EarlyFEXArchiveTests(unittest.TestCase):
    def test_all_seven_archives_require_native_ios_objects(self):
        names = module.EXPECTED_ARCHIVES[:7]
        self.assertEqual(len(names), 7)
        self.assertTrue(all(name.startswith("FEX/build-ios/") for name in names))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive(member("native.o/", macho())))
            with mock.patch.object(module, "ROOT", root):
                self.assertEqual(set(module.validate_fex_archives()), set(names))
                last = root / names[-1]
                last.unlink()
                with self.assertRaises(ValueError): module.validate_fex_archives()
                for payload in (macho(platform=1), macho(platform=7), b"BC\xc0\xde" + b"\0" * 60):
                    last.write_bytes(archive(member("bad.o/", payload)))
                    with self.assertRaises(ValueError): module.validate_fex_archives()


class BundleTests(unittest.TestCase):
    def test_empty_crypto_symbol_table_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "symtab.c"
            path.write_text("static const int empty[] = {};\n")
            with self.assertRaises(ValueError):
                module.crypto_symbols(path)

    def test_complete_exact_archive_set_required(self):
        self.assertEqual(len(module.EXPECTED_ARCHIVES), 20)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "input.json"
            document, command = repair_fixture(root)
            native_object_fixture(root, document)
            manifest.write_text(json.dumps(document))
            for name in module.EXPECTED_ARCHIVES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive(member("a.o/", macho())))
            required = ("LICENSE", "LICENSE-EXCEPTION.md", "THIRD-PARTY-NOTICES.md", "wine/COPYING.LIB",
                        "wine/LICENSE-MADEIRA.md", "FEX/LICENSE-MADEIRA.md", "research/freetype/LICENSE.TXT",
                        "research/freetype/docs/FTL.TXT", "research/freetype/docs/GPLv2.TXT",
                        "app/Madeira/legal/LICENSES-rppairing-crates.txt", "build/crypto-unix/gnutls_symtab_ios.c",
                        "wine/build-macos/include/config.h", "wine/build-arm64ec/include/config.h")
            for name in required:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
            (root / "build/crypto-unix/gnutls_symtab_ios.c").write_text('\n'.join(
                f'{{ "{name}", &ios_gts_{i} }},' for i, name in enumerate((
                    "gnutls_global_init", "gnutls_init", "gnutls_handshake", "gnutls_cipher_init", "gnutls_x509_crt_init"))))
            with mock.patch.object(module, "ROOT", root), mock.patch.object(module, "command", side_effect=command):
                last = root / module.EXPECTED_ARCHIVES[-1]
                last.unlink()
                with self.assertRaises(ValueError):
                    module.collect(manifest, root / "partial")
                self.assertFalse((root / "partial").exists())
                last.write_bytes(archive(member("host.o/", macho(platform=1))))
                with self.assertRaises(ValueError):
                    module.collect(manifest, root / "host")
                self.assertFalse((root / "host").exists())
                last.write_bytes(archive(member("ios.o/", macho())))
                module.collect(manifest, root / "complete")
                result = json.loads((root / "complete/provenance.json").read_text())
                self.assertEqual(set(result["archives"]), set(module.EXPECTED_ARCHIVES))
                self.assertEqual(result["source_repairs"]["component"], "FEX")
                self.assertEqual(len(result["source_repairs"]["repairs"]), 2)
                self.assertEqual(result["fex_native_object"]["status"], "passed")
                self.assertEqual(len(list((root / "complete/libraries").rglob("*.a"))), 20)
                self.assertTrue((root / "complete/notices/LICENSE").exists())
                self.assertFalse(list((root / "complete").rglob("*.o")))
                with self.assertRaises(ValueError):
                    module.collect(manifest, root / "complete")


if __name__ == "__main__":
    unittest.main()
