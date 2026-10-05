#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Synthetic PE symbol/failure-gate tests; no compiler, Wine or network.

LLVM evidence is mocked independently from fixture parameters. Optional real
LLVM evidence is produced by running symbol_audit.py against staged overlays.
"""
from pathlib import Path
import json
import hashlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import symbol_audit as audit
from guest_inventory import PE, InvalidPE


def fixture(arch="aarch64", imports=(), delayed=(), exports=(), api=None, legacy=False):
    """Each export is (ordinal, name-or-None, forwarder-or-None)."""
    data = bytearray(0x4200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    is64 = arch != "i386"
    optional, fixed = (240, 112) if is64 else (224, 96)
    machine = {"aarch64": 0xaa64, "arm64ec": 0x8664, "x86_64": 0x8664, "i386": 0x14c}[arch]
    struct.pack_into("<HH", data, 0x84, machine, 1)
    struct.pack_into("<H", data, 0x94, optional)
    opt, image_base = 0x98, 0x180000000 if is64 else 0x400000
    struct.pack_into("<H", data, opt, 0x20b if is64 else 0x10b)
    struct.pack_into("<Q" if is64 else "<I", data, opt + (24 if is64 else 28), image_base)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<I", data, opt + fixed - 4, 16)
    struct.pack_into("<8sIIII", data, opt + optional, b".apiset" if api is not None else b".rdata", 0x4000, 0x1000, 0x4000, 0x200)
    cursor, thunk_cursor = 0x1600, 0x2200

    def rva(offset):
        return offset + 0xe00

    def string(text):
        nonlocal cursor
        result = rva(cursor)
        encoded = text.encode("ascii") + b"\0"
        data[cursor:cursor + len(encoded)] = encoded
        cursor += len(encoded)
        return result

    def directory(index, offset, size):
        struct.pack_into("<II", data, opt + fixed + index * 8, rva(offset), size)

    for index, start, width, descriptors in ((1, 0x300, 20, imports), (13, 0x500, 32, delayed)):
        if not descriptors:
            continue
        directory(index, start, (len(descriptors) + 1) * width)
        delta = image_base if index == 13 and legacy else 0
        for i, (module, symbols) in enumerate(descriptors):
            off, lookup = start + i * width, rva(thunk_cursor)
            for j, symbol in enumerate(symbols):
                if isinstance(symbol, int):
                    value = (1 << (63 if is64 else 31)) | symbol
                else:
                    hint = rva(cursor)
                    struct.pack_into("<H", data, cursor, j)
                    cursor += 2
                    string(symbol)
                    value = hint + delta
                struct.pack_into("<Q" if is64 else "<I", data, thunk_cursor + j * (8 if is64 else 4), value)
            thunk_cursor += (len(symbols) + 1) * (8 if is64 else 4)
            if index == 13:
                struct.pack_into("<8I", data, off, 0 if legacy else 1, string(module) + delta, 0, lookup + delta, lookup + delta, 0, 0, 0)
            else:
                struct.pack_into("<5I", data, off, lookup, 0, 0, string(module), lookup)
    if exports:
        directory(0, 0x700, 0x300)
        base, high = min(e[0] for e in exports), max(e[0] for e in exports)
        named = [e for e in exports if e[1] is not None]
        struct.pack_into("<6I", data, 0x710, base, high - base + 1, len(named), rva(0x740), rva(0x780), rva(0x7c0))
        forward_cursor = 0x880
        for ordinal, name, target in exports:
            address = rva(0x1200)
            if target is not None:
                address = rva(forward_cursor)
                encoded = target.encode("ascii") + b"\0"
                data[forward_cursor:forward_cursor + len(encoded)] = encoded
                forward_cursor += len(encoded)
            struct.pack_into("<I", data, 0x740 + (ordinal - base) * 4, address)
        for i, (ordinal, name, _) in enumerate(named):
            struct.pack_into("<I", data, 0x780 + i * 4, string(name))
            struct.pack_into("<H", data, 0x7c0 + i * 2, ordinal - base)
    if arch == "arm64ec":
        directory(10, 0xa00, 208)
        struct.pack_into("<I", data, 0xa00, 208)
        struct.pack_into("<Q", data, 0xa00 + 200, image_base + rva(0xb00))
        struct.pack_into("<I", data, 0xb00, 2)
    if api is not None:
        start, offset = 0x200, 28 + len(api) * 24
        struct.pack_into("<7I", data, start, 6, 0x800, 0, len(api), 28, 0, 31)
        for i, (contract, hosts) in enumerate(api.items()):
            values = offset
            offset += len(hosts) * 20
            encoded = contract.encode("utf-16le")
            name = offset
            data[start + offset:start + offset + len(encoded)] = encoded
            offset += len(encoded)
            struct.pack_into("<6I", data, start + 28 + i * 24, 0, name, len(encoded), len(contract.rsplit("-", 1)[0].encode("utf-16le")), values, len(hosts))
            for j, (alias, host) in enumerate(hosts):
                a, h = alias.encode("utf-16le"), host.encode("utf-16le")
                aoff = offset
                data[start + offset:start + offset + len(a)] = a
                offset += len(a)
                hoff = offset
                data[start + offset:start + offset + len(h)] = h
                offset += len(h)
                struct.pack_into("<5I", data, start + values + j * 20, 0, aoff, len(a), hoff, len(h))
    return bytes(data)


def changed(data, offset, value, fmt="I"):
    result = bytearray(data)
    struct.pack_into("<" + fmt, result, offset, value)
    return bytes(result)


class TrackedScandir:
    """Lazy iterator that detects overconsumption and requires explicit closure."""
    def __init__(self, names, max_next, failure=None, fail_after=0):
        self.names = iter(names)
        self.max_next, self.failure, self.fail_after = max_next, failure, fail_after
        self.next_calls = self.consumed = 0
        self.entered = self.closed = False
        self.exit_type = None

    def __enter__(self):
        assert not self.entered
        self.entered = True
        return self

    def __exit__(self, kind, value, traceback):
        assert not self.closed
        self.closed = True
        self.exit_type = kind

    def __iter__(self):
        return self

    def __next__(self):
        assert self.entered and not self.closed
        self.next_calls += 1
        assert self.next_calls <= self.max_next, "directory scan exceeded limit + 1"
        if self.failure is not None and self.consumed == self.fail_after:
            raise self.failure
        name = next(self.names)
        self.consumed += 1
        return Path(name)  # Only DirEntry.name is needed; no cached stat data.


class SymbolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="madeira-symbol-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.overlay = self.root / "overlay"
        self.overlay.mkdir()
        self.tool = self.root / "llvm-readobj"
        self.tool.write_text("fixture executable, never invoked")
        self.tool.chmod(0o755)
        self.arch = "aarch64"
        self.sequence = 0
        self.evidence = {}
        self.make_farm()

    def make_farm(self):
        self.farm = self.root / "app/Madeira" / (self.arch + "-windows")
        self.farm.mkdir(parents=True, exist_ok=True)
        self.put(self.farm, "apisetschema.dll", api={})
        self.put(self.farm, "host.dll", exports=[(1, "Present", None), (7, None, None)])
        self.put(self.overlay, "app.dll", imports=[("host.dll", ["Present"])], exports=[(1, "Local", None)])

    def put(self, folder, name, **kwargs):
        path = folder / name
        path.write_bytes(fixture(arch=kwargs.pop("arch", self.arch), **kwargs))
        # Independent expected LLVM counts come from fixture inputs, not parser.
        machine = PE(path.read_bytes()).machine
        text = f"File: {path}\nFormat: COFF-fixture\n  Machine: IMAGE_FILE_MACHINE_FIXTURE (0x{machine:X})\n"
        for key, heading in (("imports", "Import"), ("delayed", "DelayImport")):
            for _, symbols in kwargs.get(key, []):
                indent = "    " if key == "delayed" else "  "
                text += heading + " {\n" + (indent + "Symbol: fixture\n") * len(symbols) + "}\n"
        export_rows = kwargs.get("exports", [])
        slots = max(e[0] for e in export_rows) - min(e[0] for e in export_rows) + 1 if export_rows else 0
        text += "Export {\n}\n" * slots
        self.evidence[path] = text
        return path

    def run_audit(self, **kwargs):
        self.sequence += 1
        self.output = self.root / ("out-" + str(self.sequence))
        with mock.patch.object(audit, "_readobj", side_effect=lambda tool, path, env=None: self.evidence[path]):
            return audit.audit(kwargs.pop("root", self.root), kwargs.pop("arch", self.arch),
                               kwargs.pop("overlay", self.overlay), kwargs.pop("readobj", self.tool),
                               kwargs.pop("out", self.output), modules=kwargs.pop("modules", ["app"]), **kwargs)

    def test_name_ordinal_delay_forwarder_and_architectures(self):
        for arch in ("aarch64", "arm64ec", "i386"):
            with self.subTest(arch=arch):
                self.arch = arch
                self.make_farm()
                self.put(self.overlay, "app.dll", imports=[("HOST.DLL", ["Present", 7])], delayed=[("host.dll", ["Present"])], exports=[(2, "Forward", "host.#7")])
                report = self.run_audit()
                self.assertEqual(report["counts"], {"exports": 1, "checked_import_symbols": 3, "checked_export_forwarders": 1})
                self.assertFalse(report["runtime_tested"])
                self.assertTrue(report["passed"])
                self.assertEqual(len(report["limits"]), 3)
                self.assertEqual(json.loads((self.output / f"{arch}-symbol-audit.json").read_text()), report)
                self.assertTrue((self.output / "readobj" / f"{arch}-app.txt").is_file())

    def test_legacy_delay_va_and_lookup_fallback(self):
        data = fixture("i386", delayed=[("host.dll", ["Present", 7])], legacy=True)
        parsed = audit.imports(PE(data))
        self.assertEqual(parsed[0]["symbols"], [{"name": "Present", "hint": 0}, {"ordinal": 7}])
        self.assertEqual(audit.imports(PE(changed(data, 0x510, 0))), parsed)
        data = fixture(imports=[("host.dll", ["Present"])])
        self.assertEqual(audit.imports(PE(changed(data, 0x300, 0))), audit.imports(PE(data)))

    def test_api_set_alias_default_fallback_and_missing(self):
        contract = "api-ms-test-l1-1-0"
        self.put(self.overlay, "app.dll", imports=[("api-ms-test-l1-1-9.dll", ["Present"])])
        for values in ([("", "absent.dll"), ("app.dll", "host.dll")], [("nonempty-default.dll", "host.dll")]):
            self.put(self.farm, "apisetschema.dll", api={contract: values})
            self.assertEqual(self.run_audit()["resolved_api_set_uses"], 1)
        self.put(self.farm, "apisetschema.dll", api={})
        self.put(self.farm, "api-ms-test-l1-1-9.dll", exports=[(1, "Present", None)])
        self.assertEqual(self.run_audit()["resolved_api_set_uses"], 0)
        for values in ([], [("", "")], [("", "host.dll"), ("app.dll", "")]):
            self.put(self.farm, "apisetschema.dll", api={contract: values})
            with self.assertRaisesRegex(ValueError, "unresolved"):
                self.run_audit()

    def test_forwarder_chain_cycle_depth_and_api_cycle(self):
        self.put(self.farm, "middle.dll", exports=[(1, "Relay", "host.#7")])
        self.put(self.overlay, "app.dll", imports=[("middle.dll", ["Relay"])])
        report = self.run_audit()
        self.assertEqual(report["modules"]["app.dll"]["symbol_resolution"][0]["resolved_symbol"], 7)
        with mock.patch.object(audit, "MAX_FORWARD_DEPTH", 1):
            with self.assertRaisesRegex(ValueError, "unresolved"):
                self.run_audit()
        self.put(self.farm, "host.dll", exports=[(7, None, "middle.Relay")])
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.run_audit()
        failed = json.loads((self.output / "aarch64-symbol-audit.json").read_text())
        self.assertFalse(failed["passed"])
        self.assertIn("cycle", failed["issues"][0]["reason"])
        self.put(self.overlay, "app.dll", imports=[("api-ms-test-l1-1-0.dll", ["Present"])])
        self.put(self.farm, "apisetschema.dll", api={"api-ms-test-l1-1-0": [("", "ext-ms-test-l1-1-0.dll")], "ext-ms-test-l1-1-0": [("", "api-ms-test-l1-1-0.dll")]})
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.run_audit()

    def test_forwarded_api_set_uses_original_importer_alias(self):
        self.put(self.farm, "middle.dll", exports=[(1, "Relay", "api-ms-test-l1-1-0.Present")])
        self.put(self.overlay, "app.dll", imports=[("middle.dll", ["Relay"])])
        self.put(self.farm, "apisetschema.dll", api={"api-ms-test-l1-1-0": [("", "host.dll"), ("app.dll", "missing.dll")]})
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.run_audit()
        report = json.loads((self.output / "aarch64-symbol-audit.json").read_text())
        self.assertEqual(report["issues"][0]["chain"][-1]["api_set_target"], "missing.dll")
        self.put(self.farm, "apisetschema.dll", api={"api-ms-test-l1-1-0": [("", "missing.dll"), ("app.dll", "host.dll")]})
        report = self.run_audit()
        self.assertEqual(report["modules"]["app.dll"]["symbol_resolution"][0]["resolved_module"], "host.dll")

    def test_unresolved_name_ordinal_module_and_export(self):
        for module, symbol in (("host.dll", "Absent"), ("host.dll", 8), ("missing.dll", "Present")):
            self.put(self.overlay, "app.dll", imports=[(module, [symbol])])
            with self.assertRaisesRegex(ValueError, "unresolved"):
                self.run_audit()
        self.put(self.overlay, "app.dll", exports=[(1, "Broken", "missing.Name")])
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.run_audit()

    def test_missing_evidence_architecture_paths_and_names(self):
        with self.assertRaisesRegex(ValueError, "missing selected"):
            self.run_audit(modules=["absent"])
        for modules in ([], ["app", "APP.DLL"], ["../app"], [""], "app", ["app.exe"]):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                self.run_audit(modules=modules)
        for tool in (Path("llvm-readobj"), self.root / "absent"):
            with self.assertRaises(ValueError):
                self.run_audit(readobj=tool)
        for folder in (self.farm, self.overlay):
            self.put(folder, "wrong.dll", arch="i386")
            with self.assertRaisesRegex(InvalidPE, "architecture"):
                self.run_audit()
            (folder / "wrong.dll").unlink()
        self.put(self.overlay, "APP.DLL")
        with self.assertRaisesRegex(ValueError, "case-colliding"):
            self.run_audit()
        (self.overlay / "APP.DLL").unlink()
        link = self.farm / "link.dll"
        link.symlink_to(self.farm / "host.dll")
        with self.assertRaisesRegex(ValueError, "nonregular"):
            self.run_audit()
        link.unlink()
        (self.farm / "directory.dll").mkdir()
        with self.assertRaisesRegex(ValueError, "nonregular"):
            self.run_audit()
        (self.farm / "directory.dll").rmdir()
        (self.farm / "apisetschema.dll").unlink()
        with self.assertRaisesRegex(ValueError, "apisetschema"):
            self.run_audit()

    def test_arm64ec_permits_existing_x64_but_not_overlay_x64(self):
        self.arch = "arm64ec"
        self.make_farm()
        self.put(self.farm, "host.dll", arch="x86_64", exports=[(1, "Present", None)])
        self.assertTrue(self.run_audit()["passed"])
        path = self.overlay / "app.dll"
        self.evidence[path] = self.evidence[path].replace("0x8664", "0xA641")
        self.assertTrue(self.run_audit()["passed"])
        self.put(self.overlay, "app.dll", arch="x86_64")
        with self.assertRaisesRegex(InvalidPE, "architecture"):
            self.run_audit()

    def test_llvm_count_header_and_empty_evidence_gate(self):
        path = self.overlay / "app.dll"
        original = self.evidence[path]
        for bad in ("", original + "Export {\n}", original + "  Symbol: bad\n", original.replace("0xAA64", "0x14C"), original.replace(str(path), "/wrong/file.dll"), original + "DelayImport {\n}"):
            self.evidence[path] = bad
            with self.assertRaisesRegex(ValueError, "evidence|discrepancy"):
                self.run_audit()
            self.assertFalse(self.output.exists())

    def test_fresh_safe_output_and_changed_input_gates(self):
        self.run_audit()
        output = self.output
        with self.assertRaisesRegex(ValueError, "already exist"):
            self.run_audit(out=output)
        with self.assertRaisesRegex(ValueError, "module directories"):
            self.run_audit(out=self.farm)
        link = self.root / "output-link"
        link.symlink_to(self.root / "untouched")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.run_audit(out=link)
        self.assertFalse((self.root / "untouched").exists())
        original = audit._read_pe
        def changed_read(path):
            result = original(path)
            if path == self.overlay / "app.dll":
                changed_read.count += 1
                if changed_read.count == 2:
                    return PE(fixture())
            return result
        changed_read.count = 0
        with mock.patch.object(audit, "_read_pe", side_effect=changed_read):
            with self.assertRaisesRegex(ValueError, "changed during"):
                self.run_audit()

    def test_input_module_snapshot_covers_effective_farm_and_overlay(self):
        # A same-named farm DLL is replaced by the overlay in the recorded set.
        self.put(self.farm, "app.dll", exports=[(1, "OldFarmVersion", None)])
        report = self.run_audit()
        self.assertEqual(set(report["input_modules"]), {"app.dll", "host.dll", "apisetschema.dll"})
        for name, record in report["input_modules"].items():
            path = self.overlay / name if name == "app.dll" else self.farm / name
            data = path.read_bytes()
            self.assertEqual(record, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                      "architecture": PE(data).architecture()})

    def test_farm_and_api_set_changes_during_llvm_fail_before_publication(self):
        for name, replacement in (("host.dll", fixture(exports=[(1, "MissingInstead", None)])),
                                  ("apisetschema.dll", fixture(api={"api-ms-changed-l1-1-0": [("", "missing.dll")]}))):
            with self.subTest(module=name):
                self.make_farm()
                output = self.root / ("race-" + name)
                def mutate_farm(tool, path, env=None):
                    (self.farm / name).write_bytes(replacement)
                    return self.evidence[path]
                with mock.patch.object(audit, "_readobj", side_effect=mutate_farm):
                    with self.assertRaisesRegex(ValueError, "input module changed during symbol audit"):
                        audit.audit(self.root, self.arch, self.overlay, self.tool, output, modules=["app"])
                self.assertFalse(output.exists())

    def test_malformed_import_and_delay_bounds(self):
        normal = fixture(imports=[("host.dll", ["Present"])])
        delayed = fixture(delayed=[("host.dll", ["Present"])])
        bad = [changed(normal, 0x98 + 112 + 8 + 4, 20),
               changed(normal, 0x98 + 112 + 8, 0),
               changed(normal, 0x300 + 12, 0),
               changed(normal, 0x300 + 16, 0),
               changed(normal, 0x300, 0xffffffff),
               changed(normal, 0x2200, (1 << 63) | (1 << 20), "Q"),
               changed(delayed, 0x500, 2),
               changed(delayed, 0x500, 0),
               changed(delayed, 0x98 + 112 + 13 * 8 + 4, 32),
               changed(normal, 0x2200, 0x100000000, "Q")]
        for data in bad:
            with self.subTest(index=bad.index(data)), self.assertRaises(InvalidPE):
                audit.imports(PE(data))
        with mock.patch.object(audit, "MAX_SYMBOLS", 0):
            with self.assertRaises(InvalidPE):
                audit.imports(PE(normal))
        with mock.patch.object(audit, "MAX_DESCRIPTORS", 1):
            with self.assertRaises(InvalidPE):
                audit.imports(PE(normal))

    def test_export_malformed_names_forwarders_counts_and_holes(self):
        valid = fixture(exports=[(2, "Named", None), (4, None, "host.#7")])
        self.assertEqual([e["ordinal"] for e in audit.exports(PE(valid))], [2, 4])
        self.put(self.overlay, "app.dll", exports=[(2, "Named", None), (4, None, "host.#7")])
        self.assertEqual(self.run_audit()["counts"]["exports"], 2)
        bad = [changed(valid, 0x98 + 112 + 4, 39), changed(valid, 0x714, 0xffffffff),
               changed(valid, 0x718, 0xffffffff), changed(valid, 0x7c0, 9, "H"),
               changed(valid, 0x740, 0), changed(valid, 0x740, 0xfffffffe)]
        for data in bad:
            with self.assertRaises(InvalidPE):
                audit.exports(PE(data))
        for target in ("missingdot", ".Name", "host.", "host.#", "host.#-1", "host.#65536", "host.#abc", "../host.Name"):
            with self.subTest(target=target), self.assertRaises(InvalidPE):
                audit.exports(PE(fixture(exports=[(1, "Named", target)])))
        duplicate = fixture(exports=[(1, "Same", None), (2, "Same", None)])
        with self.assertRaisesRegex(InvalidPE, "duplicate"):
            audit.exports(PE(duplicate))
        bad = bytearray(fixture(exports=[(1, "Name", "host.Name")]))
        bad[0x880:0xa00] = b"x" * (0xa00 - 0x880)
        with self.assertRaises(InvalidPE):
            audit.exports(PE(bad))

    def test_api_namespace_bounds_and_duplicate_aliases(self):
        valid = fixture(api={"api-ms-test-l1-1-0": [("", "host.dll")]})
        for data in (changed(valid, 0x20c, 0xffffffff), changed(valid, 0x21c + 20, 0xffffffff), changed(valid, 0x21c + 12, 3), changed(valid, 0x204, 0xffffffff)):
            with self.assertRaises(InvalidPE):
                audit.api_sets(PE(data))
        with self.assertRaisesRegex(InvalidPE, "duplicate"):
            audit.api_sets(PE(fixture(api={"api-ms-test-l1-1-0": [("", "host.dll"), ("app.dll", "host.dll"), ("app.dll", "other.dll")]})))

    def test_file_section_and_aggregate_size_bounds(self):
        path = self.farm / "host.dll"
        with mock.patch.object(audit, "MAX_PE_BYTES", 10):
            with self.assertRaisesRegex(InvalidPE, "file-size"):
                audit._read_pe(path)
        path.write_bytes(changed(path.read_bytes(), 0x86, 97, "H"))
        with self.assertRaisesRegex(InvalidPE, "section count"):
            audit._read_pe(path)
        path.write_bytes(fixture())
        with mock.patch.object(audit, "MAX_MODULES", 1):
            with self.assertRaisesRegex(ValueError, "entry count"):
                self.run_audit()
        with mock.patch.object(audit, "MAX_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "total byte"):
                self.run_audit()

    def test_scandir_closes_before_reads_and_preserves_sorted_paths(self):
        self.put(self.farm, "Z.DLL")
        (self.farm / ".gitkeep").write_text("")
        with mock.patch.object(audit.os, "listdir", side_effect=AssertionError("eager listdir")), \
             mock.patch.object(Path, "iterdir", side_effect=AssertionError("Path.iterdir is not bounded")):
            # Real filesystem enumeration must not fall back to either eager API.
            self.assertTrue(self.run_audit()["passed"])
            scans = {self.farm: TrackedScandir(("host.dll", "Z.DLL", ".gitkeep", "apisetschema.dll"), 5),
                     self.overlay: TrackedScandir(("app.dll",), 5)}
            reads, original = [], audit._read_pe

            def read_after_close(path):
                self.assertTrue(scans[path.parent].closed, "directory handle retained during PE reads")
                reads.append(path)
                return original(path)

            with mock.patch.object(audit, "MAX_MODULES", 4), \
                 mock.patch.object(audit.os, "scandir", side_effect=lambda path: scans[path]) as scandir, \
                 mock.patch.object(audit, "_read_pe", side_effect=read_after_close):
                self.assertTrue(self.run_audit()["passed"])
            self.assertEqual(scandir.call_args_list, [mock.call(self.farm), mock.call(self.overlay)])
            self.assertEqual(reads[:4], [self.farm / "Z.DLL", self.farm / "apisetschema.dll",
                                        self.farm / "host.dll", self.overlay / "app.dll"])
            for directory, consumed in ((self.farm, 4), (self.overlay, 1)):
                scan = scans[directory]
                self.assertEqual((scan.consumed, scan.next_calls), (consumed, consumed + 1))
                self.assertTrue(scan.closed)
                self.assertIsNone(scan.exit_type)

    def test_scandir_overflow_consumes_limit_plus_one_and_closes(self):
        for directory in (self.farm, self.overlay):
            for limit in (0, 3):
                with self.subTest(directory=directory.name, limit=limit):
                    # Even ignored non-PE entries count; the iterator is infinite.
                    scan = TrackedScandir(iter(lambda: "ignored.txt", None), limit + 1)
                    empty = TrackedScandir((), limit + 1)
                    with mock.patch.object(audit, "MAX_MODULES", limit), \
                         mock.patch.object(audit.os, "scandir", side_effect=lambda path: scan if path == directory else empty), \
                         mock.patch.object(audit.os, "listdir", side_effect=AssertionError("eager listdir")), \
                         mock.patch.object(Path, "iterdir", side_effect=AssertionError("Path.iterdir is not bounded")), \
                         mock.patch.object(audit, "_read_pe", side_effect=AssertionError("must not read overflow")):
                        with self.assertRaisesRegex(ValueError, "^module directory entry count exceeds audit bound$"):
                            self.run_audit()
                    self.assertEqual(scan.consumed, limit + 1)
                    self.assertEqual(scan.next_calls, limit + 1)
                    self.assertTrue(scan.closed)
                    self.assertIsNone(scan.exit_type)
                    self.assertFalse(self.output.exists())
                    if directory == self.overlay:
                        self.assertTrue(empty.closed)
                        self.assertEqual((empty.consumed, empty.next_calls), (0, 1))

    def test_scandir_errors_close_discard_partial_scan_and_keep_error_context(self):
        for directory in (self.farm, self.overlay):
            for failure in (PermissionError("injected scan failure"), RuntimeError("injected scan failure")):
                with self.subTest(directory=directory.name, failure=type(failure).__name__):
                    scan = TrackedScandir(("host.dll", "app.dll"), 4, failure, fail_after=1)
                    empty = TrackedScandir((), 1)
                    with mock.patch.object(audit.os, "scandir", side_effect=lambda path: scan if path == directory else empty), \
                         mock.patch.object(audit.os, "listdir", side_effect=AssertionError("eager listdir")), \
                         mock.patch.object(Path, "iterdir", side_effect=AssertionError("Path.iterdir is not bounded")), \
                         mock.patch.object(audit, "_read_pe", side_effect=AssertionError("must not read partial scan")):
                        with self.assertRaises(ValueError if isinstance(failure, OSError) else RuntimeError) as raised:
                            self.run_audit()
                    if isinstance(failure, OSError):
                        self.assertEqual(str(raised.exception), f"cannot enumerate module directory: {directory}: {failure}")
                        self.assertIs(raised.exception.__cause__, failure)
                    else:
                        self.assertIs(raised.exception, failure)
                    self.assertEqual((scan.consumed, scan.next_calls), (1, 2))
                    self.assertTrue(scan.closed)
                    self.assertIs(scan.exit_type, type(failure))
                    self.assertFalse(self.output.exists())
                    if directory == self.overlay:
                        self.assertTrue(empty.closed)

    def test_scandir_open_error_keeps_directory_and_cause(self):
        for directory in (self.farm, self.overlay):
            with self.subTest(directory=directory.name):
                failure = PermissionError("injected open failure")
                empty = TrackedScandir((), 1)

                def open_scan(path):
                    if path == directory:
                        raise failure
                    return empty

                with mock.patch.object(audit.os, "scandir", side_effect=open_scan), \
                     mock.patch.object(audit, "_read_pe", side_effect=AssertionError("must not read failed scan")):
                    with self.assertRaises(ValueError) as raised:
                        self.run_audit()
                self.assertEqual(str(raised.exception), f"cannot enumerate module directory: {directory}: {failure}")
                self.assertIs(raised.exception.__cause__, failure)
                self.assertFalse(self.output.exists())
                if directory == self.overlay:
                    self.assertTrue(empty.closed)

    def test_subprocess_timeout_output_and_error_bounds(self):
        # Only a host Python script is executed, never a fixture PE or guest code.
        def script(source):
            self.tool.write_text("#!" + sys.executable + "\n" + source + "\n")
        script("import time; time.sleep(5)")
        with mock.patch.object(audit, "READOBJ_TIMEOUT", 0.03):
            with self.assertRaisesRegex(ValueError, "timed out"):
                audit._readobj(self.tool, self.overlay / "app.dll")
        script("import sys; sys.stdout.write('x' * 100000)")
        with mock.patch.object(audit, "MAX_READOBJ_BYTES", 100):
            with self.assertRaisesRegex(ValueError, "exceeds bound"):
                audit._readobj(self.tool, self.overlay / "app.dll")
        script("import sys; sys.stderr.write('warning'); sys.exit(0)")
        with self.assertRaisesRegex(ValueError, "failed/warned"):
            audit._readobj(self.tool, self.overlay / "app.dll")
        script("import sys; sys.exit(1)")
        with self.assertRaisesRegex(ValueError, "failed/warned"):
            audit._readobj(self.tool, self.overlay / "app.dll")
        script("import os; print(os.environ['FIXTURE'])")
        self.assertEqual(audit._readobj(self.tool, self.overlay / "app.dll", {"FIXTURE": "kept"}), "kept\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
