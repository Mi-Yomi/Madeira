#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Portable source-built Dock packaging failures; no compiler, Steam or network."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dock_app_fixtures", ROOT / "tests/host/check-app-bootstrap.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
gate, dock, put = fixtures.gate, fixtures.gate.dock, fixtures.put


def pe(*, machine=0x8664, chpe=False, imports=None):
    """Real bounded PE headers/import descriptors, with no executable code."""
    imports = sorted(dock.EXPECTED_IMPORTS) if imports is None else imports
    data = bytearray(0x2200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, machine, 1)
    struct.pack_into("<HH", data, 0x94, 240, 2)  # PE32+, executable, not a DLL.
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<Q", data, 0x98 + 24, 0x180000000)
    struct.pack_into("<I", data, 0x98 + 60, 0x200)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<8sIIII", data, 0x98 + 240, b".rdata", 0x2000, 0x1000, 0x2000, 0x200)
    if imports:
        struct.pack_into("<II", data, 0x98 + 112 + 8, 0x1100, (len(imports) + 1) * 20)
    cursor = 0x1300
    for index, name in enumerate(imports):
        struct.pack_into("<I", data, 0x300 + index * 20 + 12, cursor + 0xe00)
        encoded = name.encode() + b"\0"
        data[cursor:cursor + len(encoded)] = encoded
        cursor += len(encoded)
    if chpe:
        struct.pack_into("<II", data, 0x98 + 112 + 10 * 8, 0x1800, 208)
        struct.pack_into("<I", data, 0xa00, 208)
        struct.pack_into("<Q", data, 0xa00 + 200, 0x180001900)
        struct.pack_into("<I", data, 0xb00, 2)
    return bytes(data)


class DockFixture:
    def __enter__(self):
        self.stack = contextlib.ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.output = self.root / dock.OUTPUT
        for name in ("LICENSE", "LICENSE-EXCEPTION.md", "COPYING", "notices/MinGW-w64-runtime.txt", "notices/LLVM.txt"):
            put(self.root / "madeira-dock" / name, (name + " fixture notice\n").encode())
        put(self.output / "dockhost.exe", pe())
        put(self.output / "dock-notices.txt", dock.expected_notices(self.root))
        self.inputs = {"schema_version": 1, "source_commit": "a" * 40,
            "source": {"repository": dock.SOURCE_REPOSITORY, "revision": dock.SOURCE_REVISION,
                       "tree": "b" * 40, "files_sha256": {"src/main.c": "c" * 64}},
            "recipe_sha256": {"build/madeira-dock/build.sh": "d" * 64},
            "toolchain": {"installation": str(self.root / "toolchain"), "archive": str(self.root / "toolchain.tar.xz")},
            "run": {key: "fixture" for key in dock.RUN_KEYS}, "scope": dock.SCOPE}
        self.record = {**copy.deepcopy(self.inputs), **dock.output_evidence(self.root, receipt=False)}
        self.write_receipt()
        self.stack.enter_context(mock.patch.object(gate, "ROOT", self.root))
        self.input_mock = self.stack.enter_context(mock.patch.object(dock, "input_evidence",
            side_effect=lambda *args: copy.deepcopy(self.inputs)))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def write_receipt(self):
        put(self.output / dock.RECEIPT, json.dumps(self.record).encode())


class SourceTests(unittest.TestCase):
    def test_exact_pin_repository_revision_and_source_bytes(self):
        for mutation in (None, "pin", "repository", "revision", "untracked", "changed", "symlink", "missing-main"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source = put(root / "madeira-dock/src/main.c", b"int main(void) { return 0; }\n")
                identity = dock.build_receipt.hash_file(source, git_blob=True)
                if mutation == "changed": source.write_text("modified source\n")
                if mutation == "symlink":
                    source.unlink()
                    source.symlink_to(put(root / "replacement.c", b"int main(void) { return 0; }\n"))
                def git(base, *args):
                    if args == ("ls-tree", "HEAD", "madeira-dock"):
                        return "160000 commit " + ("f" * 40 if mutation == "pin" else dock.SOURCE_REVISION) + "\tmadeira-dock"
                    if args == ("config", "-f", ".gitmodules", "submodule.madeira-dock.url"):
                        return "https://example.invalid/wrong.git" if mutation == "repository" else dock.SOURCE_REPOSITORY
                    if args == ("rev-parse", "HEAD"):
                        return "f" * 40 if mutation == "revision" else dock.SOURCE_REVISION
                    if args == ("ls-files", "--others", "-z"):
                        return "src/extra.c\0" if mutation == "untracked" else ""
                    if args == ("ls-tree", "-rz", "--full-tree", "HEAD"):
                        return "" if mutation == "missing-main" else "100644 blob " + identity["git_blob"] + "\tsrc/main.c\0"
                    if args == ("rev-parse", "HEAD^{tree}"): return "b" * 40
                    raise AssertionError(args)
                with mock.patch.object(dock, "git", side_effect=git):
                    if mutation:
                        with self.assertRaises(ValueError): dock.source_snapshot(root)
                    else:
                        result = dock.source_snapshot(root)
                        self.assertEqual(result["files_sha256"], {"src/main.c": identity["sha256"]})
                        self.assertEqual(result["revision"], "3cadfbea700e4da4b04e331dd7ef1ba633dfacef")

    def test_changed_build_recipe_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            blobs = {}
            for name in dock.RECIPE_INPUTS:
                blobs["HEAD:" + name] = dock.build_receipt.hash_file(put(root / name, name.encode()), git_blob=True)["git_blob"]
            with mock.patch.object(dock, "git", side_effect=lambda root, command, name: blobs[name]):
                self.assertEqual(set(dock.recipe_snapshot(root)), set(dock.RECIPE_INPUTS))
                (root / dock.RECIPE_INPUTS[0]).write_text("changed recipe")
                with self.assertRaisesRegex(ValueError, "recipe differs"): dock.recipe_snapshot(root)


class OutputTests(unittest.TestCase):
    def test_actual_pe_and_notice_receipt_pass(self):
        with DockFixture() as fx:
            self.assertEqual(gate.dock_inputs(), fx.record)
            self.assertEqual(fx.record["pe"]["architecture"], "x86_64")
            self.assertEqual(len(fx.record["pe"]["dependencies"]), 11)
            self.assertIn(dock.SOURCE_REVISION.encode(), (fx.output / "dock-notices.txt").read_bytes())
            self.assertEqual(set(gate.dock_resources(fx.record)), set(fixtures.DOCK_RESOURCES))

    def test_missing_modified_unrelated_and_symlink_generated_files_fail(self):
        cases = ("missing-host", "missing-notices", "missing-receipt", "altered-host", "altered-notices", "extra-file", "extra-directory", "symlink-host")
        for mutation in cases:
            with self.subTest(mutation=mutation), DockFixture() as fx:
                if mutation.startswith("missing-"):
                    name = {"missing-host": "dockhost.exe", "missing-notices": "dock-notices.txt", "missing-receipt": dock.RECEIPT}[mutation]
                    (fx.output / name).unlink()
                elif mutation == "altered-host":
                    with (fx.output / "dockhost.exe").open("ab") as stream: stream.write(b"changed")
                elif mutation == "altered-notices": (fx.output / "dock-notices.txt").write_text("wrong notices")
                elif mutation == "extra-file": put(fx.output / "unrelated.dll", pe())
                elif mutation == "extra-directory": (fx.output / "unrelated").mkdir()
                elif mutation == "symlink-host":
                    (fx.output / "dockhost.exe").unlink()
                    (fx.output / "dockhost.exe").symlink_to(put(fx.root / "outside.exe", pe()))
                with self.assertRaises(ValueError): gate.dock_inputs()

    def test_altered_receipt_or_current_inputs_fail(self):
        for key in ("source_commit", "source", "recipe_sha256", "toolchain", "run", "scope", "outputs_sha256", "pe", "extra"):
            with self.subTest(key=key), DockFixture() as fx:
                if key == "toolchain": fx.record[key]["installation"] += "-changed"
                else: fx.record[key] = "changed"
                fx.write_receipt()
                with self.assertRaises(ValueError): gate.dock_inputs()
        with DockFixture() as fx:
            fx.inputs["run"]["GITHUB_RUN_ATTEMPT"] = "changed"
            with self.assertRaises(ValueError): gate.dock_inputs()

    def test_wrong_architecture_unsigned_shape_and_imports_fail(self):
        for mutation in ("arm64", "i386", "chpe", "timestamp", "symbols", "dll", "signature", "debug", "imports", "empty-imports", "truncated"):
            with self.subTest(mutation=mutation), DockFixture() as fx:
                data = bytearray(pe())
                if mutation == "arm64": data = bytearray(pe(machine=0xaa64))
                elif mutation == "i386": data = bytearray(pe(machine=0x14c))
                elif mutation == "chpe": data = bytearray(pe(chpe=True))
                elif mutation == "timestamp": struct.pack_into("<I", data, 0x88, 1)
                elif mutation == "symbols": struct.pack_into("<II", data, 0x8c, 0x200, 1)
                elif mutation == "dll": struct.pack_into("<H", data, 0x96, 0x2002)
                elif mutation in ("signature", "debug"):
                    struct.pack_into("<II", data, 0x98 + 112 + {"signature": 4, "debug": 6}[mutation] * 8, 0x1100, 16)
                elif mutation == "imports": data = bytearray(pe(imports=["unexpected.dll"]))
                elif mutation == "empty-imports": data = bytearray(pe(imports=[]))
                elif mutation == "truncated": data = data[:200]
                (fx.output / "dockhost.exe").write_bytes(data)
                # Update the recorded digest: a matching checksum cannot bless
                # the wrong architecture, executable shape or dependency set.
                fx.record["outputs_sha256"]["dockhost.exe"] = dock.digest(fx.output / "dockhost.exe")
                fx.write_receipt()
                with self.assertRaises(ValueError): gate.dock_inputs()


class StageTests(unittest.TestCase):
    def test_only_exact_host_notice_hash_map_can_be_staged(self):
        with DockFixture() as fx:
            for outputs in ({}, {"dockhost.exe": "a" * 64},
                    {**fx.record["outputs_sha256"], "unexpected.exe": "a" * 64},
                    {**fx.record["outputs_sha256"], "dockhost.exe": "not-a-sha256"}):
                with self.subTest(outputs=outputs), self.assertRaises(ValueError):
                    gate.dock_resources({"outputs_sha256": outputs})

    def test_copies_only_two_verified_outputs_without_touching_farm(self):
        with DockFixture() as fx:
            app = fx.root / "products/Madeira.app"
            farm = put(app / "arm64ec-windows/tracked.dll", b"MZ unchanged source farm")
            gate.stage_dock(app, gate.dock_inputs())
            self.assertEqual(farm.read_bytes(), b"MZ unchanged source farm")
            self.assertEqual({path.name for path in farm.parent.iterdir()}, {"tracked.dll", *dock.FILES})
            for name in dock.FILES:
                self.assertEqual((farm.parent / name).read_bytes(), (fx.output / name).read_bytes())
            self.assertFalse((farm.parent / dock.RECEIPT).exists())

    def test_existing_destination_never_overwritten(self):
        for mutation in ("file", "directory", "symlink", "dangling-link"):
            with self.subTest(mutation=mutation), DockFixture() as fx:
                app = fx.root / "products/Madeira.app"
                destination = app / "arm64ec-windows/dockhost.exe"
                destination.parent.mkdir(parents=True)
                if mutation == "file": destination.write_bytes(b"existing")
                elif mutation == "directory": destination.mkdir()
                elif mutation == "symlink": destination.symlink_to(put(fx.root / "existing", b"existing"))
                else: destination.symlink_to(fx.root / "missing")
                with self.assertRaises(ValueError): gate.stage_dock(app, fx.record)
                self.assertFalse((destination.parent / "dock-notices.txt").exists())
                if mutation == "file": self.assertEqual(destination.read_bytes(), b"existing")

    def test_changed_output_between_validation_and_copy_fails(self):
        for mutation in ("missing", "changed"):
            with self.subTest(mutation=mutation), DockFixture() as fx:
                app = fx.root / "products/Madeira.app"
                (app / "arm64ec-windows").mkdir(parents=True)
                evidence = gate.dock_inputs()
                if mutation == "missing": (fx.output / "dockhost.exe").unlink()
                else: (fx.output / "dockhost.exe").write_bytes(pe() + b"changed")
                with self.assertRaises(ValueError): gate.stage_dock(app, evidence)
                self.assertFalse((app / "arm64ec-windows/dockhost.exe").exists())

    def test_final_bundle_cannot_omit_dock_even_with_matching_resource_inventory(self):
        for name in fixtures.DOCK_RESOURCES:
            for remove_evidence in (False, True):
                with self.subTest(name=name, remove_evidence=remove_evidence), tempfile.TemporaryDirectory() as temporary:
                    app = Path(temporary).resolve() / "Madeira.app"
                    resources, framework, converter = fixtures.fixture(app)
                    (app / name).unlink()
                    if remove_evidence: del resources[name]
                    with mock.patch.object(gate, "CONVERTER_SHA256", converter), self.assertRaises(ValueError):
                        gate.validate_app(app, resources, framework)

    def test_missing_dock_stops_build_before_xcode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate, "prerequisites", return_value={}), \
                    mock.patch.object(gate, "run") as run, mock.patch.object(gate.subprocess, "check_output") as command:
                with self.assertRaises(ValueError):
                    gate.build(root / "native.json", root / "products", root / "objects", root / "stage")
                run.assert_not_called()
                command.assert_not_called()

    def test_build_stages_verified_dock_and_rejects_changes_during_xcode(self):
        for mutation in (None, "source-during-build", "output-during-build", "source-farm-collision"):
            with self.subTest(mutation=mutation), DockFixture() as fx, contextlib.ExitStack() as stack:
                seed = fx.root / "fixture/Madeira.app"
                resources, framework, converter = fixtures.fixture(seed)
                resources = fixtures.farm_resources(resources)
                for name in fixtures.DOCK_RESOURCES: (seed / name).unlink()
                put(fx.root / "app/Madeira/source.c", b"fixture source\n")
                put(fx.root / gate.FRAMEWORK_SOURCE, (seed / "Frameworks/StikJIT.framework/StikJIT").read_bytes())
                native = put(fx.root / "native.json", b"fixture native receipt\n")
                prerequisite = {"source_commit": "a" * 40, "native_receipt_sha256": gate.digest(native),
                    "prerequisite_sha256": {gate.FRAMEWORK_SOURCE: framework}, "scope": gate.SCOPE}
                products, objects, diagnostics = (fx.root / name for name in ("products", "objects", "diagnostics"))
                if mutation == "source-farm-collision": resources.update(gate.dock_resources(fx.record))
                guest = {name: value for name, value in resources.items() if name.endswith((".dll", ".exe"))}
                commands = []
                def run(command):
                    commands.append(command[0])
                    if command[0] == "bash": return
                    self.assertEqual(command[0], "xcodebuild")
                    shutil.copytree(seed, products / "Debug-iphoneos/Madeira.app")
                    if mutation == "source-during-build": fx.inputs["source"]["tree"] = "f" * 40
                    if mutation == "output-during-build":
                        with (fx.output / "dockhost.exe").open("ab") as stream: stream.write(b"changed")
                def git(*args):
                    if args == ("rev-parse", "--show-toplevel"): return str(fx.root)
                    if args == ("rev-parse", "HEAD"): return "a" * 40
                    if args[0] == "ls-files": return "app/Madeira/source.c\0"
                    raise AssertionError(args)
                def output(args, **kwargs):
                    if args == ["xcodebuild", "-version"]: return "Xcode 27.0\n"
                    if args == ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"]: return "27.0\n"
                    if args == ["uname", "-m"]: return "arm64\n"
                    raise AssertionError(args)
                stack.enter_context(mock.patch.object(gate, "CONVERTER_SHA256", converter))
                stack.enter_context(mock.patch.object(gate.sys, "platform", "darwin"))
                stack.enter_context(mock.patch.object(gate, "prerequisites", return_value=prerequisite))
                stack.enter_context(mock.patch.object(gate, "resource_inputs", return_value=(resources, guest)))
                stack.enter_context(mock.patch.object(gate, "git", side_effect=git))
                stack.enter_context(mock.patch.object(gate.subprocess, "check_output", side_effect=output))
                stack.enter_context(mock.patch.object(gate, "run", side_effect=run))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if mutation:
                    with self.assertRaises(ValueError): gate.build(native, products, objects, diagnostics)
                    self.assertFalse((diagnostics / "provenance.json").exists())
                    self.assertEqual(commands, ["bash"] if mutation == "source-farm-collision" else ["bash", "xcodebuild"])
                else:
                    gate.build(native, products, objects, diagnostics)
                    receipt = json.loads((diagnostics / "provenance.json").read_text())
                    self.assertEqual(receipt["dock_build"], fx.record)
                    self.assertEqual(commands, ["bash", "xcodebuild"])
                    for name in dock.FILES:
                        relative = "arm64ec-windows/" + name
                        self.assertEqual(receipt["resources_sha256"][relative], fx.record["outputs_sha256"][name])
                        self.assertEqual((products / "Debug-iphoneos/Madeira.app" / relative).read_bytes(),
                                         (fx.output / name).read_bytes())
                    self.assertFalse(list(fx.root.rglob("*.ipa")))

    def test_steam_availability_still_requires_the_bundled_host(self):
        source = (ROOT / "app/Madeira/MadeiraDock.swift").read_text()
        self.assertIn('static var enabled: Bool { SteamSignIn.flag("MADEIRA_DOCK", default: true) && bundled }', source)
        self.assertIn('Bundle.main.url(forResource: "dockhost", withExtension: "exe", subdirectory: "arm64ec-windows") != nil', source)
        library = (ROOT / "app/Madeira/SteamOwnedLibrary.swift").read_text()
        self.assertIn('static var enabled: Bool { MadeiraDock.enabled && SteamSignIn.flag("MADEIRA_STEAM_LIBRARY", default: true) }', library)


if __name__ == "__main__":
    unittest.main()
