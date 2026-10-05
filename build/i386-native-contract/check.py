#!/usr/bin/env python3
"""Verify a bounded i386 prerequisite contract on real iOS native artifacts.

Requires a completed native-artifacts.py bundle receipt and capture.py records.
Optional final-link mode additionally requires the unstripped executable, its
ld64 map, and the actual app FEXBridge object. Never executes an app or guest.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

from macho import MachO, archive_members, require

HERE = Path(__file__).resolve().parent
NTDLL = "app/Madeira/libntdll_unix.a"
WIN32U = "app/Madeira/libwin32u_unix.a"
FEX = ("FEX/build-ios/FEXCore/Source/libFEXCore.a", "FEX/build-ios/FEXCore/Source/libFEXCore_Base.a")
# Only these two NSI arrays are covered by v1. This intentionally does not infer
# ABI correctness for ws2_32, crypto, DNS, dwrite, audio, graphics or media.
TABLES = {
    "_nsi_unix_call_funcs": ["_ios_nsi_enumerate_all_ex", "_nsi_get_all_parameters_ex", "_nsi_get_parameter_ex"],
    "_nsi_unix_call_wow64_funcs": ["_ios_wow64_nsi_enumerate_all_ex", "_ios_wow64_nsi_get_all_parameters_ex", "_ios_wow64_nsi_get_parameter_ex"],
}
SOURCES = {
    (NTDLL, "virtual.o"): "build/ntdll-unix/virtual_ios.c",
    (NTDLL, "process.o"): "build/ntdll-unix/process_ios.c",
    (NTDLL, "loader.o"): "build/ntdll-unix/loader_ios.c",
    (NTDLL, "server.o"): "build/ntdll-unix/server_ios.c",
    (NTDLL, "syscall.o"): "wine/dlls/ntdll/unix/syscall.c",
    (NTDLL, "nsi_unixlib_ios.o"): "build/ntdll-unix/nsi_unixlib_ios.c",
    (NTDLL, "nsi_network_ios.o"): "build/ntdll-unix/nsi_network_ios.c",
    (WIN32U, "syscall.o"): "build/win32u-unix/syscall_ios.c",
}
CORE = {
    (NTDLL, "virtual.o"): {
        "_ios_main_image_i386": False, "_ios_wow_base": True, "_ios_wow_base_for_peb": True,
        "_ios_wow_window_reserve": True, "_ios_wow_window_bind": True,
        "_ios_wow_window_release": True, "_ios_wow_window_release_current": True,
    },
    (NTDLL, "process.o"): {"_NtQueryInformationProcess": True},
    (NTDLL, "syscall.o"): {"_KeAddSystemServiceTable": True, "_KeServiceDescriptorTable": False},
    (NTDLL, "nsi_unixlib_ios.o"): {name: False for name in TABLES},
    (NTDLL, "nsi_network_ios.o"): {"_nsi_get_all_parameters_ex": True, "_nsi_get_parameter_ex": True},
    (WIN32U, "syscall.o"): {"_win32u_unix_lib_init": True, "_win32u_unix_lib_init_upstream": True},
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, maximum=400 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            f"missing, symlinked or oversized evidence: {path}")
    return path.read_bytes()


def source_bindings(root, spec):
    for name, expected in spec["source_sha256"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts, "unsafe source binding")
        path = root / name
        require(path.resolve().is_relative_to(root), f"source escapes checkout: {name}")
        require(sha(regular(path, 8 * 1024 * 1024)) == expected, f"reviewed source changed: {name}")
    return spec["source_sha256"]


def object_path(archive, member):
    directory = "ntdll-unix" if archive == NTDLL else "win32u-unix"
    return f"build/{directory}/obj/{member}"


def record_name(archive, member):
    return ("ntdll-" if archive == NTDLL else "win32u-") + member + ".json"


def capture_binding(root, records, archive, member, data):
    name = record_name(archive, member)
    record, binding = check_capture(root, records / name, SOURCES[archive, member], object_path(archive, member), data)
    arguments = record["arguments"]
    require("-DWINE_IOS=1" in arguments, f"missing native WINE_IOS configuration: {name}")
    if archive == WIN32U:
        require("-D__wine_unix_lib_init=win32u_unix_lib_init" in arguments, "win32u init was not renamed")
    return record, binding


def check_capture(root, record_path, source, output, data):
    name = str(record_path)
    raw = regular(record_path, 16 * 1024 * 1024)
    record = json.loads(raw)
    require(record.get("schema") == 1 and record.get("source") == source
            and record.get("object") == output, f"wrong compile capture: {name}")
    require(record.get("object_sha256") == sha(data), f"stale/replaced archive member: {name}")
    require(regular(root / record["object"]) == data, f"archive differs from captured production object: {name}")
    compiler = Path(record["compiler"])
    require(compiler.is_absolute() and sha(regular(compiler)) == record["compiler_sha256"],
            f"compiler changed since capture: {name}")
    dependencies = record.get("dependency_sha256", {})
    require(record["source"] in dependencies and dependencies, f"missing source dependency: {name}")
    for dep, expected in dependencies.items():
        path = Path(dep) if Path(dep).is_absolute() else root / dep
        require(sha(regular(path, 128 * 1024 * 1024)) == expected, f"compile dependency changed: {dep}")
    arguments = record.get("arguments", [])
    require("-c" in arguments and
            not any(a.startswith(("-flto", "@")) for a in arguments), f"unexpected compiler configuration: {name}")
    return record, {"record_sha256": sha(raw), "object_sha256": sha(data), "source": record["source"]}


def parse_layouts(text):
    result = {}
    for block in text.split("*** Dumping AST Record Layout"):
        match = re.search(r"^\s*0 \| struct (nsi_\w+)\s*$", block, re.M)
        if not match:
            continue
        name = match[1]
        require(name not in result, f"duplicate record layout: {name}")
        size = re.search(r"\[sizeof=(\d+), align=(\d+)\]", block)
        require(size is not None, f"missing record extent: {name}")
        fields = {}
        # These six records are flat. Exactly three spaces after '|' selects
        # direct fields and avoids accidentally accepting nested member offsets.
        for offset, field in re.findall(r"^\s*(\d+) \|   [^\n]*\b(\w+)\s*$", block, re.M):
            require(field not in fields, f"duplicate layout field: {name}.{field}")
            fields[field] = int(offset)
        result[name] = {"size": int(size[1]), "align": int(size[2]), "fields": fields}
    return result


def check_layouts(record, expected):
    layouts = parse_layouts(record.get("record_layouts", ""))
    for name, layout in expected.items():
        require(layouts.get(name) == layout, f"compiled NSI layout differs: {name}")
    return expected


def all_references(obj):
    names = set()
    for section in obj.sections:
        for _, index, _, _, external, _ in section.relocations:
            if external:
                require(index < len(obj.symbols), "invalid relocation symbol")
                names.add(obj.symbols[index].name)
    return names


class Contract:
    def __init__(self, objects):
        self.objects = objects
        self.providers = {}
        for key, obj in objects.items():
            for symbol in obj.symbols:
                if symbol.defined and symbol.external:
                    self.providers.setdefault(symbol.name, []).append((key, obj, symbol))

    def require_provider(self, name, key=None, code=True):
        matches = self.providers.get(name, [])
        require(len(matches) == 1, f"missing/duplicate external definition: {name}")
        actual, obj, symbol = matches[0]
        require(key is None or actual == key, f"{name}: wrong archive member {actual}, expected {key}")
        obj.definition(name, code=code, external=True)
        return actual, obj, symbol

    def resolve(self, name, origin):
        if origin.definitions(name):
            return origin, origin.definition(name, code=True)
        _, obj, symbol = self.require_provider(name)
        return obj, symbol

    def validate(self):
        required = {}
        for key, symbols in CORE.items():
            for name, code in symbols.items():
                self.require_provider(name, key, code)
                required[name] = key
        for name in ("___wine_unix_call_funcs", "___wine_unix_call_wow64_funcs", "___wine_unix_lib_init"):
            require(name not in self.providers, f"unrenamed unixlib definition: {name}")
        virtual = self.objects[NTDLL, "virtual.o"]
        # The !WINE_IOS fallback exports the same public functions but returns
        # zero/NOT_SUPPORTED. Require the real compiled registry as well.
        virtual.definition("_ios_wow_windows", code=False, external=False)
        virtual.definition("_ios_wow_window_count", code=False, external=False)
        process = self.objects[NTDLL, "process.o"]
        require({"_ios_wow_base", "_ios_wow_base_for_peb"} <= process.references("_NtQueryInformationProcess"),
                "native NtQueryInformationProcess lost guest-base references")
        for key, expected in {
            (NTDLL, "loader.o"): {"_ios_wow_window_reserve", "_ios_wow_window_bind"},
            (NTDLL, "server.o"): {"_ios_wow_window_release"},
            (NTDLL, "virtual.o"): {"_win32u_unix_lib_init", *TABLES},
        }.items():
            require(expected <= all_references(self.objects[key]), f"missing native integration references: {key}")
        win = self.objects[WIN32U, "syscall.o"]
        init_refs = win.references("_win32u_unix_lib_init")
        # Clang may inline the upstream function into the wrapper at -O2.
        require("_KeAddSystemServiceTable" in init_refs or
                ("_win32u_unix_lib_init_upstream" in init_refs and
                 "_KeAddSystemServiceTable" in win.references("_win32u_unix_lib_init_upstream")),
                "win32u wrapper has no compiled registration edge")
        ntdll = self.objects[NTDLL, "syscall.o"]
        require("_KeServiceDescriptorTable" in ntdll.references("_KeAddSystemServiceTable"),
                "service registration does not reference its actual descriptor table")
        nsi = self.objects[NTDLL, "nsi_unixlib_ios.o"]
        tables = [nsi.pointer_table(name, targets, self.resolve) for name, targets in TABLES.items()]
        for name in TABLES["_nsi_unix_call_wow64_funcs"]:
            require("_ios_wow_base" in nsi.references(name), f"WoW64 NSI conversion lost guest base: {name}")
        return required, tables


def parse_link_map(text, root):
    owners, symbols, mode = {}, {}, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("# "):
            if line in ("# Object files:", "# Sections:", "# Symbols:", "# Dead Stripped Symbols:"):
                mode = line
            continue
        if mode == "# Object files:":
            match = re.fullmatch(r"\[\s*(\d+)\]\s+(.+)", line)
            require(match is not None, "unrecognized link-map object row")
            index, name = int(match[1]), match[2]
            require(index not in owners, "duplicate link-map object index")
            owners[index] = name
        elif mode == "# Symbols:":
            match = re.fullmatch(r"(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+\[\s*(\d+)\]\s+(.+)", line)
            require(match is not None, "unrecognized live link-map symbol row")
            address, size, index, name = match.groups()
            symbols.setdefault(name, []).append((int(address, 16), int(size, 16), int(index)))
    require(owners and symbols, "missing live link-map records")
    return owners, symbols


def verify_link(root, executable, link_map, bridge, bridge_capture, contract, required):
    final_raw, map_raw, bridge_raw = regular(executable), regular(link_map, 64 * 1024 * 1024), regular(bridge)
    final = MachO(final_raw, str(executable), filetype=2)
    bridge_obj = MachO(bridge_raw, str(bridge))
    require(bridge.resolve().is_relative_to(root), "captured app bridge object must be inside the build checkout")
    _, bridge_binding = check_capture(root, bridge_capture, "app/Madeira/FEXBridge.mm",
                                      str(bridge.resolve().relative_to(root)), bridge_raw)
    map_text = map_raw.decode()
    paths = re.findall(r"^# Path: (.+)$", map_text, re.M)
    require(len(paths) == 1 and Path(paths[0]).resolve() == executable.resolve(), "link map names another output image")
    require(re.findall(r"^# Arch: (.+)$", map_text, re.M) == ["arm64"], "link map is not arm64")
    owners, symbols = parse_link_map(map_text, root)
    # These helpers may be inlined into their same-TU callers and then dead
    # stripped; archive definitions/edges are already checked above.
    required = {name: key for name, key in required.items() if name not in
                ("_win32u_unix_lib_init_upstream", "_ios_wow_window_release_current")}
    # Derive exact C++ manglings from the real app object's undefined records;
    # require the stable entry points, not any symbol containing the word FEX.
    fex_refs = {s.name for s in bridge_obj.symbols if not s.defined and s.kind & 0xe == 0
                and s.name.startswith("__ZN7FEXCore")}
    groups = ("7Context7Context16CreateNewContext", "6Config10InitializeEv")
    selected = []
    for fragment in groups:
        names = [name for name in fex_refs if fragment in name]
        require(len(names) == 1, f"FEXBridge lacks unique native reference: {fragment}")
        selected.extend(names)
    for name in selected:
        key, obj, symbol = contract.require_provider(name)
        require(key[0] in FEX, f"FEX bridge provider is outside real FEX archives: {name}")
        require(name in all_references(bridge_obj), f"FEXBridge has no relocation to {name}")
        required[name] = key
    for name, key in required.items():
        code = contract.objects[key].sections[contract.objects[key].definition(name).section - 1].executable
        actual = final.definition(name, code=code)
        rows = symbols.get(name, [])
        require(len(rows) == 1 and rows[0][0] == actual.address and rows[0][1] > 0,
                f"final image and live map disagree: {name}")
        owner = owners.get(rows[0][2], "")
        # Apple ld64 and LLD spell this as path/lib.a(member.o).
        match = re.fullmatch(r"(.+\.a)\(([^()]+)\)", owner)
        require(match is not None and Path(match[1]).resolve() == (root / key[0]).resolve()
                and match[2] == key[1], f"wrong final-link provider for {name}: {owner}")
    # Require the bridge itself to survive the link and refer to the actual
    # app object, rather than accepting a disconnected archive-only proof.
    # fex_initialize may inline into this externally called Swift/ObjC entry.
    bridge_rows = symbols.get("_fex_test_execute", [])
    require(len(bridge_rows) == 1 and Path(owners.get(bridge_rows[0][2], "")).resolve() == bridge.resolve(),
            "FEXBridge initialization is absent or from another object")
    require(final.definition("_fex_test_execute", code=True).address == bridge_rows[0][0], "FEXBridge map/image mismatch")
    return {"executable_sha256": sha(final_raw), "link_map_sha256": sha(map_raw),
            "bridge_object_sha256": sha(bridge_raw), "fex_entry_points": selected,
            "bridge_capture": bridge_binding,
            "exact_link_input_hashes": "not_independently_reconstructed; trusted_same_job_required",
            "resolved_symbols": len(required)}


def validate(root, native_receipt, records, final_inputs=None):
    root = root.resolve()
    spec = json.loads((HERE / "contract.json").read_text())
    source_bindings(root, spec)
    receipt_raw = regular(native_receipt, 16 * 1024 * 1024)
    receipt = json.loads(receipt_raw)
    loader = importlib.util.spec_from_file_location("native_artifacts", root / ".github/ci/native-artifacts.py")
    native = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(native)
    require(receipt.get("schema") == 1 and receipt.get("stage") == "native-dependencies-only" and receipt.get("dependencies_ready") is True,
            "requires completed native dependency receipt")
    require(set(receipt.get("archives", {})) == set(native.EXPECTED_ARCHIVES), "incomplete native archive receipt")
    require(sum((root / p).stat().st_size for p in native.EXPECTED_ARCHIVES) <= native.MAX_BUNDLE_BYTES,
            "native archives exceed the established bundle size limit")
    fex_spec = json.loads((root / "build/fex-ios/source-repairs.json").read_text())
    require(receipt.get("source_repairs") == fex_spec and receipt.get("fex_native_build"), "missing pinned FEX build evidence")
    require(native.verified_fex_native_build(receipt) == receipt["fex_native_build"],
            "FEX native configuration/compile database changed since collection")
    objects, captures, layouts = {}, {}, None
    for archive in native.EXPECTED_ARCHIVES:
        raw = regular(root / archive)
        require(sha(raw) == receipt["archives"][archive]["sha256"], f"native receipt archive mismatch: {archive}")
        for member, data in archive_members(raw):
            native.macho_ios_object(data, f"{archive}({member})")
            obj = MachO(data, f"{archive}({member})")
            objects[archive, member] = obj
            if (archive, member) in SOURCES:
                record, binding = capture_binding(root, records, archive, member, data)
                captures[f"{archive}({member})"] = binding
                if member == "nsi_unixlib_ios.o":
                    layouts = check_layouts(record, spec["nsi_layouts"])
    require(set(SOURCES) <= set(objects) and layouts is not None, "missing selected compiled members")
    contract = Contract(objects)
    required, tables = contract.validate()
    link = verify_link(root, *final_inputs, contract, required) if final_inputs else None
    return {"schema": 1, "mode": "i386-native-prerequisites", "runtime": "not_run",
            "application_support": "not_established", "status": "bounded_link_contract_passed" if link else "bounded_archive_contract_passed",
            "source_sha256": spec["source_sha256"], "native_receipt_sha256": sha(receipt_raw),
            "validator_sha256": {p.name: sha(p.read_bytes()) for p in (HERE / "check.py", HERE / "macho.py", HERE / "capture.py", HERE / "contract.json")},
            "captures": captures, "tables": tables, "compiled_nsi_layouts": layouts,
            "final_link": link, "limits": spec["limits"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--native-receipt", type=Path, required=True)
    parser.add_argument("--captures", type=Path, required=True)
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--link-map", type=Path)
    parser.add_argument("--fex-bridge-object", type=Path)
    parser.add_argument("--fex-bridge-capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        final = (args.executable, args.link_map, args.fex_bridge_object, args.fex_bridge_capture)
        require(all(final) or not any(final), "final-link inputs must be supplied together")
        require(not args.output.exists(), "refusing an existing contract receipt")
        result = validate(args.root, args.native_receipt, args.captures, final if all(final) else None)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(result["status"] + "; runtime not run; only the stated bounded contract was checked")
    except (OSError, ValueError, KeyError, UnicodeError) as exc:
        raise SystemExit(f"Native i386 prerequisite contract failed: {exc}") from exc


if __name__ == "__main__":
    main()
