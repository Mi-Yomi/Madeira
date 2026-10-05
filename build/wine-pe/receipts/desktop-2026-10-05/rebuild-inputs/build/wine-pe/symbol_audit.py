#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Bounded, read-only static symbol audit of a staged Wine PE overlay.

No guest execution, installation, PATH tool lookup, or runtime/ABI proof. Only
selected overlay imports and their required export-forwarder chains are checked;
this is deliberately not a recursive audit of every existing farm import.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import selectors
import signal
import struct
import subprocess
import time

from guest_inventory import ARCHES, PE, PE_SUFFIXES, InvalidPE, dll_name, manifest

MAX_PE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MODULES = 2048
MAX_AUDIT_MODULES = 128
MAX_TOTAL_DUMP_BYTES = 64 * 1024 * 1024
MAX_SYMBOLS = 65536
MAX_DESCRIPTORS = 4096
MAX_API_ENTRIES = 8192
MAX_FORWARD_DEPTH = 64
READOBJ_TIMEOUT = 30
MAX_READOBJ_BYTES = 16 * 1024 * 1024
LIMITS = [
    "Static symbol names/ordinals and forwarders only; no execution or ABI/calling-convention proof",
    "Does not recursively validate every import of existing farm DLLs, dynamic LoadLibrary/GetProcAddress, COM activation or SxS",
    "Export presence does not establish implementation quality or application compatibility",
]


def _directory(pe, index, minimum):
    base, size = pe.directory(index)
    if not base and not size:
        return 0, 0
    if not base or size < minimum or base + size > 0x100000000:
        raise InvalidPE("missing RVA or short/overflowing data directory")
    pe.rva(base, size)
    return base, size


def _module(value):
    name = dll_name(value)
    if (name in (".", "..") or name != name.strip() or
            any(ord(c) < 33 or ord(c) > 126 for c in name) or
            any(c in name for c in '<>"|?*') or name.endswith(".")):
        raise InvalidPE("unsafe DLL name")
    return name


def _symbol(value):
    if not value:
        raise InvalidPE("empty symbol name")
    return value


def forwarder(value):
    """Parse a DLL.name or DLL.#ordinal without leaking incidental exceptions."""
    if "." not in value:
        raise InvalidPE("invalid export forwarder")
    module, symbol = value.rsplit(".", 1)
    module, symbol = _module(module), _symbol(symbol)
    if symbol.startswith("#"):
        if not re.fullmatch(r"#[0-9]{1,5}", symbol) or int(symbol[1:]) > 65535:
            raise InvalidPE("invalid forwarded ordinal")
        symbol = int(symbol[1:])
    return module, symbol


def exports(pe):
    base, size = _directory(pe, 0, 40)
    if not base:
        return []
    ordinal, nfunc, nnames, funcs, names, ords = pe.unpack("6I", pe.rva(base, 40) + 16)
    if nfunc > MAX_SYMBOLS or nnames > MAX_SYMBOLS or ordinal + nfunc > 0x100000000:
        raise InvalidPE("export count/ordinal exceeds audit bounds")
    if nfunc:
        if not funcs:
            raise InvalidPE("missing export address table")
        pe.rva(funcs, nfunc * 4)
    if nnames:
        if not names or not ords:
            raise InvalidPE("missing export name/ordinal table")
        pe.rva(names, nnames * 4)
        pe.rva(ords, nnames * 2)
    by_index, seen = defaultdict(list), set()
    for i in range(nnames):
        name_rva = pe.unpack("I", pe.rva(names + i * 4, 4))[0]
        index = pe.unpack("H", pe.rva(ords + i * 2, 2))[0]
        if index >= nfunc or not name_rva:
            raise InvalidPE("export ordinal index/name exceeds table")
        name = _symbol(pe.string(name_rva))
        if name in seen:
            raise InvalidPE("duplicate export name")
        seen.add(name)
        by_index[index].append(name)
    result = []
    for i in range(nfunc):
        rva = pe.unpack("I", pe.rva(funcs + i * 4, 4))[0]
        if not rva:
            if by_index[i]:
                raise InvalidPE("named export points to an empty address slot")
            continue
        entry = {"ordinal": ordinal + i, "names": by_index[i], "rva": hex(rva)}
        if base <= rva < base + size:
            entry["forwarder"] = pe.string(rva, base + size - rva)
            forwarder(entry["forwarder"])
        elif not (rva < pe.headers or any(va <= rva < va + max(vsize, raw)
                                        for _, va, vsize, _, raw in pe.sections)):
            raise InvalidPE("export address lies outside mapped image")
        result.append(entry)
    return result


def imports(pe):
    result, total = [], 0
    for index, width, kind in ((1, 20, "import"), (13, 32, "delay")):
        base, size = _directory(pe, index, width)
        if not base:
            continue
        if size // width > MAX_DESCRIPTORS:
            raise InvalidPE("import descriptor count exceeds audit bound")
        terminated = False
        for pos in range(0, size - width + 1, width):
            fields = pe.unpack("I" * (width // 4), pe.rva(base + pos, width))
            if not any(fields):
                terminated = True
                break
            if index == 1:
                name, lookup, iat, delta = fields[3], fields[0] or fields[4], fields[4], 0
            else:
                if fields[0] not in (0, 1):
                    raise InvalidPE("unknown delay import attributes")
                delta = 0 if fields[0] else pe.image_base
                name, lookup, iat = fields[1] - delta, (fields[4] or fields[3]) - delta, fields[3] - delta
            if min(name, lookup, iat) <= 0:
                raise InvalidPE("missing/invalid import name, lookup or IAT")
            module, symbols = _module(pe.string(name)), []
            bits, width_thunk = (64, 8) if pe.pe64 else (32, 4)
            ordinal_bit = 1 << (bits - 1)
            for i in range(MAX_SYMBOLS + 1):
                value = pe.unpack("Q" if pe.pe64 else "I", pe.rva(lookup + i * width_thunk, width_thunk))[0]
                if not value:
                    break
                if total >= MAX_SYMBOLS:
                    raise InvalidPE("import symbol count exceeds audit bound")
                if value & ordinal_bit:
                    if value & ~(ordinal_bit | 0xffff):
                        raise InvalidPE("reserved bits in ordinal import thunk")
                    symbol = {"ordinal": value & 0xffff}
                else:
                    hint_rva = value - delta
                    if hint_rva <= 0 or hint_rva > 0xfffffffd:
                        raise InvalidPE("invalid import-by-name RVA")
                    symbol = {"name": _symbol(pe.string(hint_rva + 2)),
                              "hint": pe.unpack("H", pe.rva(hint_rva, 2))[0]}
                symbols.append(symbol)
                total += 1
            else:
                raise InvalidPE("unterminated import thunk table")
            pe.rva(iat, (len(symbols) + 1) * width_thunk)
            result.append({"module": module, "kind": kind, "symbols": symbols})
        if not terminated:
            raise InvalidPE(f"unterminated {kind} directory")
    return result


def api_sets(pe):
    """Read v6 namespaces, bounding nested values before any allocation/loop."""
    sections = [s for s in pe.sections if s[0] == b".apiset"]
    if len(sections) != 1:
        raise InvalidPE("apisetschema.dll must have one .apiset section")
    _, _, _, start, raw_size = sections[0]
    version, size, _, count, entries, _, _ = pe.unpack("7I", start)
    if version != 6 or size < 28 or size > raw_size or count > MAX_API_ENTRIES:
        raise InvalidPE("unsupported/truncated/oversized API-set schema")

    def part(offset, length):
        if offset < 0 or length < 0 or offset > size - length:
            raise InvalidPE("API-set offset outside namespace")
        return pe.read(start + offset, length)

    def string(offset, length):
        if length > 8192 or length % 2:
            raise InvalidPE("invalid API-set string length")
        try:
            return part(offset, length).decode("utf-16le").lower()
        except UnicodeError as exc:
            raise InvalidPE("invalid API-set string") from exc

    part(entries, count * 24)
    result, total = {}, 0
    for i in range(count):
        _, name, length, hashed, values, nvalues = struct.unpack("<6I", part(entries + i * 24, 24))
        _module(string(name, length))
        if not hashed or hashed % 2 or hashed > length:
            raise InvalidPE("invalid API-set hashed name length")
        contract = string(name, hashed)
        if contract in result:
            raise InvalidPE("duplicate API-set hashed name")
        total += nvalues
        if total > MAX_SYMBOLS:
            raise InvalidPE("API-set value count exceeds audit bound")
        part(values, nvalues * 20)
        result[contract], aliases = [], set()
        for j in range(nvalues):
            _, alias, alen, host, hlen = struct.unpack("<5I", part(values + j * 20, 20))
            a = _module(string(alias, alen)) if alen else ""
            h = _module(string(host, hlen)) if hlen else ""
            if j and a in aliases:
                raise InvalidPE("duplicate API-set importer alias")
            if j:
                aliases.add(a)
            result[contract].append((a, h))
    return result


def _read_pe(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing/nonregular PE module: {path}")
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_PE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"cannot read PE module: {path}: {exc}") from exc
    if len(data) > MAX_PE_BYTES:
        raise InvalidPE(f"PE exceeds file-size bound: {path}")
    # The PE reader bounds all reads; also cap the section loop before parsing.
    if len(data) >= 64:
        pos = struct.unpack_from("<I", data, 0x3c)[0]
        if pos + 8 <= len(data) and struct.unpack_from("<H", data, pos + 6)[0] > 96:
            raise InvalidPE("section count exceeds PE audit bound")
    return PE(data)


def _readobj(tool, path, env=None):
    """Bound stdout+stderr, wall time and descendant lifetime (POSIX host)."""
    argv = [str(tool), "--file-headers", "--coff-imports", "--coff-exports", "--coff-load-config", str(path)]
    child_env = dict(env) if env is not None else {}
    child_env["LC_ALL"] = "C"
    process = None
    try:
        process = subprocess.Popen(argv, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        chunks, total, deadline = {"out": [], "err": []}, 0, time.monotonic() + READOBJ_TIMEOUT
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "out")
            selector.register(process.stderr, selectors.EVENT_READ, "err")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError(f"llvm-readobj timed out for {path.name}")
                for key, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    if total > MAX_READOBJ_BYTES:
                        raise ValueError(f"llvm-readobj output exceeds bound for {path.name}")
                    chunks[key.data].append(block)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"llvm-readobj timed out for {path.name}")
            process.wait(timeout=remaining)
        stdout = b"".join(chunks["out"]).decode("utf-8", errors="strict")
        stderr = b"".join(chunks["err"]).decode("utf-8", errors="replace")
        if process.returncode or stderr.strip():
            raise ValueError(f"llvm-readobj failed/warned for {path.name}: {stderr[-2000:]}")
        return stdout
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"llvm-readobj could not produce evidence for {path.name}: {exc}") from exc
    finally:
        if process is not None:
            # Kill the process group even if the leader exited but left children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()


def _llvm_counts(text, path, pe, im, ex):
    # LLVM normalizes AMD64+CHPE images to ARM64EC in its displayed header.
    machines = {f"{pe.machine:X}"}
    if pe.architecture() == "arm64ec":
        machines.add("A641")
    displayed = re.findall(r"^  Machine: \S+ \(0x([0-9A-Fa-f]+)\)$", text, re.M)
    if (re.findall(r"^File: (.+)$", text, re.M) != [str(path)] or
            len(re.findall(r"^Format: COFF-[^\n]+$", text, re.M)) != 1 or
            len(displayed) != 1 or displayed[0].upper() not in machines):
        raise ValueError(f"missing/wrong llvm-readobj file/header evidence for {path.name}")
    counts = {"exports": len(re.findall(r"^Export \{", text, re.M)),
              "import_symbols": len(re.findall(r"^ {2}(?: {2})?Symbol:", text, re.M)),
              "import_descriptors": len(re.findall(r"^Import \{", text, re.M)),
              "delay_descriptors": len(re.findall(r"^DelayImport \{", text, re.M))}
    # LLVM enumerates all export address slots, including unnamed zero holes.
    base, _ = pe.directory(0)
    export_slots = pe.unpack("I", pe.rva(base, 40) + 20)[0] if base else 0
    expected = {"exports": export_slots, "import_symbols": sum(len(i["symbols"]) for i in im),
                "import_descriptors": sum(i["kind"] == "import" for i in im),
                "delay_descriptors": sum(i["kind"] == "delay" for i in im)}
    if counts != expected:
        raise ValueError(f"llvm-readobj count discrepancy for {path.name}: {counts} != {expected}")
    return counts


def audit(root, arch, overlay, readobj, out, modules=None, env=None):
    """Write fresh static receipts; raise ValueError/InvalidPE on any failed gate.

    root is the repository root. modules is a nonempty list of bare module names
    or DLL basenames; omitted means the reviewed desktop profile. The tool must
    be an explicit absolute executable path. Existing receipts are never reused.
    """
    if arch not in ARCHES:
        raise ValueError(f"unsupported architecture: {arch}")
    root, overlay, out, readobj = map(Path, (root, overlay, out, readobj))
    farm = root / "app/Madeira" / (arch + "-windows")
    for directory in (farm, overlay):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"missing/nonregular module directory: {directory}")
    farm, overlay, out = farm.resolve(), overlay.resolve(), out.absolute()
    if farm == overlay:
        raise ValueError("overlay must be separate from the existing farm")
    if not readobj.is_absolute() or readobj.is_symlink() or not readobj.is_file() or not os.access(readobj, os.X_OK):
        raise ValueError("llvm-readobj requires an explicit absolute regular executable path")
    if isinstance(modules, (str, bytes)):
        raise ValueError("modules must be a nonempty sequence")
    selected = [_module(m) for m in islice(manifest()["profiles"]["desktop"] if modules is None else modules, MAX_AUDIT_MODULES + 1)]
    if not selected or len(selected) > MAX_AUDIT_MODULES or len(set(selected)) != len(selected) or any(not m.endswith(".dll") for m in selected):
        raise ValueError("modules must be unique nonempty DLL names")
    images, files, overlay_files, originals, total_bytes = {}, {}, set(), {}, 0
    for directory in (farm, overlay):
        local = set()
        try:
            entries = list(islice(directory.iterdir(), MAX_MODULES + 1))
        except OSError as exc:
            raise ValueError(f"cannot enumerate module directory: {directory}: {exc}") from exc
        if len(entries) > MAX_MODULES:
            raise ValueError("module directory entry count exceeds audit bound")
        for path in sorted(entries):
            if path.suffix.lower() not in PE_SUFFIXES:
                continue
            name = _module(path.name)
            if name in local or (name in originals and originals[name] != path.name):
                raise ValueError(f"case-colliding module: {path.name}")
            local.add(name)
            originals[name] = path.name
            pe = _read_pe(path)
            total_bytes += len(pe.data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("module evidence exceeds total byte bound")
            actual = pe.architecture()
            allowed = (arch, "x86_64") if arch == "arm64ec" and directory == farm else (arch,)
            if actual not in allowed:
                raise InvalidPE(f"{path.name}: architecture {actual}, expected {arch}")
            images[name], files[name] = pe, path
            if directory == overlay:
                overlay_files.add(name)
    if set(selected) - overlay_files:
        raise ValueError(f"missing selected overlay modules: {sorted(set(selected) - overlay_files)}")
    if "apisetschema.dll" not in images:
        raise ValueError("missing apisetschema.dll evidence")
    api, tables = api_sets(images["apisetschema.dll"]), {}

    def table(name):
        if name not in tables:
            ex = exports(images[name])
            tables[name] = ({n: e for e in ex for n in e["names"]}, {e["ordinal"]: e for e in ex})
        return tables[name]

    def resolve(module, symbol, importer):
        chain, seen = [], set()
        for _ in range(MAX_FORWARD_DEPTH):
            module = _module(module)
            identity = (module, symbol, importer)
            entry = {"module": module, "symbol": symbol}
            chain.append(entry)
            if identity in seen:
                return {"ok": False, "reason": "forwarder/API-set cycle", "chain": chain}
            seen.add(identity)
            if module.startswith(("api-", "ext-")):
                key = module.split(".", 1)[0].rsplit("-", 1)[0]
                values = api.get(key, [])
                hosts = [h for a, h in values[1:] if a == importer]
                if not hosts and values:
                    hosts = [values[0][1]]
                if hosts and hosts[0]:
                    entry["api_set_target"] = hosts[0]
                    module = hosts[0]
                    if module.startswith(("api-", "ext-")):
                        continue
                elif key in api or module not in files:
                    return {"ok": False, "reason": "unresolved API-set", "chain": chain}
            if module not in files:
                return {"ok": False, "reason": "missing module", "chain": chain}
            names, ords = table(module)
            exp = ords.get(symbol) if isinstance(symbol, int) else names.get(symbol)
            if exp is None:
                return {"ok": False, "reason": "missing export", "chain": chain}
            if "forwarder" not in exp:
                return {"ok": True, "resolved_module": module, "resolved_symbol": symbol,
                        "resolved_rva": exp["rva"], "chain": chain}
            # Pinned Wine loader.c forwards the original importer unchanged
            # through find_forwarded_export/find_named_export for API-set aliases.
            module, symbol = forwarder(exp["forwarder"])
        return {"ok": False, "reason": "forwarder/API-set depth exceeds audit bound", "chain": chain}

    # Resolve and check all input evidence before creating any successful receipt.
    records, issues, dumps, dump_bytes = {}, [], {}, 0
    counts = Counter(checked_import_symbols=0, checked_export_forwarders=0, exports=0)
    for name in selected:
        pe, path = images[name], files[name]
        im, ex = imports(pe), exports(pe)
        text = _readobj(readobj, path, env)
        dump_bytes += len(text.encode("utf-8"))
        if dump_bytes > MAX_TOTAL_DUMP_BYTES:
            raise ValueError("aggregate llvm-readobj dumps exceed audit bound")
        if counts["checked_import_symbols"] + sum(len(i["symbols"]) for i in im) + counts["checked_export_forwarders"] + sum("forwarder" in e for e in ex) > MAX_SYMBOLS:
            raise ValueError("aggregate checked symbol count exceeds audit bound")
        llvm_counts = _llvm_counts(text, path, pe, im, ex)
        # Detect input changes between our parse and the independent tool run.
        if _read_pe(path).data != pe.data:
            raise ValueError(f"overlay changed during symbol audit: {path}")
        dumps[name] = text
        checks = []
        for imp in im:
            if not imp["symbols"]:
                raise InvalidPE("empty import descriptor has no auditable symbols")
            for sym in imp["symbols"]:
                symbol = sym.get("name", sym.get("ordinal"))
                check = {"kind": imp["kind"], "dependency": imp["module"], "symbol": symbol,
                         **resolve(imp["module"], symbol, name)}
                checks.append(check)
                counts["checked_import_symbols"] += 1
                if not check["ok"]:
                    issues.append({"importer": name, **check})
        for exp in ex:
            if "forwarder" in exp:
                target, symbol = forwarder(exp["forwarder"])
                check = {"kind": "export-forwarder", "export_ordinal": exp["ordinal"], "export_names": exp["names"],
                         **resolve(target, symbol, name)}
                checks.append(check)
                counts["checked_export_forwarders"] += 1
                if not check["ok"]:
                    issues.append({"importer": name, **check})
        dependencies = {(i["module"], i["kind"]) for i in im}
        dependencies.update((forwarder(e["forwarder"])[0], "forwarder") for e in ex if "forwarder" in e)
        counts["exports"] += len(ex)
        records[name] = {"sha256": hashlib.sha256(pe.data).hexdigest(), "bytes": len(pe.data),
                         "architecture": pe.architecture(), "dependencies": [{"name": n, "kind": k} for n, k in sorted(dependencies)],
                         "imports": im, "exports": ex, "symbol_resolution": checks, "llvm_counts": llvm_counts}
    result = {"schema_version": 1, "architecture": arch, "overlay": str(overlay), "farm": str(farm),
              "passed": not issues, "runtime_tested": False, "limits": LIMITS,
              "counts": dict(counts), "issues": issues, "modules": records,
              "input_modules": {name: {"bytes": len(pe.data), "sha256": hashlib.sha256(pe.data).hexdigest(),
                                        "architecture": pe.architecture()}
                                for name, pe in sorted(images.items())},
              "resolved_api_set_uses": sum("api_set_target" in s for m in records.values() for c in m["symbol_resolution"] for s in c["chain"])}
    if out.is_symlink() or any(p.is_symlink() for p in out.parents):
        raise ValueError("audit output may not traverse symlinks")
    for directory in (farm, overlay):
        if out.resolve() == directory or directory in out.resolve().parents:
            raise ValueError("audit receipts may not be written into module directories")
    raw = out / "readobj"
    if raw.is_symlink() or (raw.exists() and not raw.is_dir()):
        raise ValueError("readobj output must be a regular directory")
    destination = out / f"{arch}-symbol-audit.json"
    paths = [destination] + [raw / f"{arch}-{Path(n).stem}.txt" for n in selected]
    if any(p.exists() or p.is_symlink() for p in paths):
        raise ValueError("symbol audit receipts already exist; use fresh outputs")
    # The farm and API-set schema are evidence too: LLVM/forwarder processing
    # must not leave a successful receipt for an earlier dependency snapshot.
    # This is the effective merged farm+overlay set represented by input_modules.
    for name, pe in sorted(images.items()):
        if _read_pe(files[name]).data != pe.data:
            raise ValueError(f"input module changed during symbol audit: {files[name]}")
    raw.mkdir(parents=True, exist_ok=True)
    for name, text in dumps.items():
        with (raw / f"{arch}-{Path(name).stem}.txt").open("x", encoding="utf-8") as stream:
            stream.write(text)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    if issues:
        raise ValueError(f"{arch}: {len(issues)} unresolved import symbols/export forwarders; see {destination}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--readobj", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.root, args.arch, args.overlay, args.readobj, args.output)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"symbol audit failed: {exc}\n")
    print(json.dumps({"architecture": args.arch, "counts": report["counts"], "issues": report["issues"]}, sort_keys=True))


if __name__ == "__main__":
    main()
