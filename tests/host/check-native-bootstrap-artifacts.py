#!/usr/bin/env python3
"""Portable negative fixtures for CI iOS archives and complete-bundle gating."""
import importlib.util
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
        for payload in (macho(cpu=0x01000007), macho(subtype=2), b"BC\xc0\xde" * 20):
            with self.assertRaises(ValueError):
                self.validate(archive(member("bad.o/", payload)))

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
            manifest.write_text(json.dumps({"dependencies_ready": True, "source_commit": "fixture"}))
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
            with mock.patch.object(module, "ROOT", root), mock.patch.object(module, "command", return_value="fixture"):
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
                self.assertEqual(len(list((root / "complete/libraries").rglob("*.a"))), 20)
                self.assertTrue((root / "complete/notices/LICENSE").exists())
                self.assertFalse(list((root / "complete").rglob("*.o")))
                with self.assertRaises(ValueError):
                    module.collect(manifest, root / "complete")


if __name__ == "__main__":
    unittest.main()
