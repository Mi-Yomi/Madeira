#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Read-only PE farm audit. No Wine, objdump, third-party packages or network.

Reports normal/delay imports and export-forwarded DLL dependencies. API-set
names are resolved using the farm's actual v6 apisetschema.dll. Static closure
is necessary, not sufficient: dynamic LoadLibrary/COM use and runtime behavior
still require application/device tests. ARM64EC executable PEs often have an
AMD64 machine header; the load-config CHPE metadata distinguishes them from
ordinary emulated x64 images. No claim is made about the correctness of code.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import itertools
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
ARCHES = ("aarch64", "arm64ec", "i386")
PROFILES = {"desktop": ["netprofm", "sensapi", "avifil32", "msvfw32", "msftedit", "riched20"],
            "vc2012": ["msvcr110", "msvcp110"]}
MAX_PE_BYTES = 64 * 1024 * 1024
MAX_FARM_BYTES = 512 * 1024 * 1024
MAX_FARM_FILES = 2048
PE_SUFFIXES = {".dll", ".exe", ".drv", ".cpl", ".acm", ".ax", ".ocx", ".sys"}


class InvalidPE(ValueError):
    pass


class PE:
    def __init__(self, data: bytes):
        self.data = data
        if self.read(0, 2) != b"MZ":
            raise InvalidPE("not an MZ executable")
        pe = self.unpack("I", 0x3c)[0]
        if pe < 0x40 or self.read(pe, 4) != b"PE\0\0":
            raise InvalidPE("invalid PE signature/offset")
        self.machine, count = self.unpack("HH", pe + 4)
        opt_size = self.unpack("H", pe + 20)[0]
        opt = pe + 24
        self.read(opt, opt_size)
        magic = self.unpack("H", opt)[0]
        if magic not in (0x10b, 0x20b):
            raise InvalidPE("unsupported optional header")
        self.pe64 = magic == 0x20b
        fixed = 112 if self.pe64 else 96
        if opt_size < fixed:
            raise InvalidPE("truncated optional header")
        self.image_base = self.unpack("Q" if self.pe64 else "I", opt + (24 if self.pe64 else 28))[0]
        self.headers = self.unpack("I", opt + 60)[0]
        directories = self.unpack("I", opt + fixed - 4)[0]
        if directories > (opt_size - fixed) // 8:
            raise InvalidPE("data directories exceed optional header")
        self.directories = [self.unpack("II", opt + fixed + i * 8) for i in range(directories)]
        self.sections = []
        for i in range(count):
            entry = opt + opt_size + i * 40
            self.read(entry, 40)
            name, virtual_size, va, raw_size, offset = self.unpack("8sIIII", entry)
            self.read(offset, raw_size)
            self.sections.append((name.rstrip(b"\0"), va, virtual_size, offset, raw_size))
        if self.headers > len(data):
            raise InvalidPE("headers exceed file")

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise InvalidPE("out-of-file read")
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack("<" + fmt, self.read(offset, struct.calcsize("<" + fmt)))

    def rva(self, value, size=1):
        if value < 0 or size < 0:
            raise InvalidPE("negative RVA")
        if value < self.headers and size <= self.headers - value:
            self.read(value, size)
            return value
        for _, va, _, offset, raw_size in self.sections:
            if va <= value and value - va < raw_size and size <= raw_size - (value - va):
                self.read(offset + value - va, size)
                return offset + value - va
        raise InvalidPE(f"RVA {value:#x} is not backed by file bytes")

    def string(self, value, limit=4096):
        result = bytearray()
        for i in range(min(limit, 4096)):
            byte = self.data[self.rva(value + i)]
            if not byte:
                try:
                    return result.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise InvalidPE("non-ASCII DLL/forwarder name") from exc
            result.append(byte)
        raise InvalidPE("unterminated DLL/forwarder name")

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def architecture(self):
        if self.machine == 0x14c and not self.pe64:
            return "i386"
        if self.machine == 0xaa64 and self.pe64:
            return "aarch64"
        if self.machine not in (0x8664, 0xa641) or not self.pe64:
            return f"unknown-{self.machine:04x}"
        lc, size = self.directory(10)
        if lc and size >= 208:
            offset = self.rva(lc, 208)
            # Both the directory and the structure's Size must cover this field.
            if self.unpack("I", offset)[0] >= 208:
                metadata = self.unpack("Q", offset + 200)[0]
                if metadata:
                    metadata_rva = metadata - self.image_base
                    version = self.unpack("I", self.rva(metadata_rva, 4))[0]
                    if version not in (1, 2):
                        raise InvalidPE(f"unknown ARM64EC CHPE metadata version {version}")
                    # v1 has 20 DWORDs; v2 appends the nine helper pointers
                    # in pinned Wine's IMAGE_ARM64EC_METADATA definition.
                    offset = self.rva(metadata_rva, 80 if version == 1 else 116)
                    code_map, code_count = self.unpack("II", offset + 4)
                    if code_count:
                        self.rva(code_map, code_count * 8)
                    return "arm64ec"
        if self.machine == 0xa641:
            raise InvalidPE("ARM64EC PE has no CHPE metadata")
        return "x86_64"

    def dependencies(self):
        result = []
        for index, width, kind in ((1, 20, "import"), (13, 32, "delay")):
            base, size = self.directory(index)
            if not base:
                if size:
                    raise InvalidPE("directory has size without RVA")
                continue
            if size < width:
                raise InvalidPE(f"short {kind} directory")
            terminated = False
            for pos in range(0, size - width + 1, width):
                values = self.unpack("I" * (width // 4), self.rva(base + pos, width))
                if not any(values):
                    terminated = True
                    break
                name = values[3] if index == 1 else values[1]
                if index == 13:
                    if values[0] not in (0, 1):
                        raise InvalidPE("unknown delay import attributes")
                    if not values[0]:
                        name -= self.image_base
                result.append((dll_name(self.string(name)), kind))
            if not terminated:
                raise InvalidPE(f"unterminated {kind} directory")
        base, size = self.directory(0)
        if not base and size:
            raise InvalidPE("export directory has size without RVA")
        if base:
            if size < 40:
                raise InvalidPE("short export directory")
            self.rva(base, size)
            offset = self.rva(base, 40)
            count, table = self.unpack("I", offset + 20)[0], self.unpack("I", offset + 28)[0]
            self.rva(table, count * 4) if count else None
            for i in range(count):
                value = self.unpack("I", self.rva(table + i * 4, 4))[0]
                if base <= value < base + size:
                    forward = self.string(value, base + size - value)
                    if "." not in forward:
                        raise InvalidPE("invalid export forwarder")
                    result.append((dll_name(forward.rsplit(".", 1)[0]), "forwarder"))
        return sorted(set(result))

    def api_sets(self):
        """Return v6 contract -> [(importer alias, host)] from actual schema."""
        section = next((s for s in self.sections if s[0] == b".apiset"), None)
        if not section:
            raise InvalidPE("apisetschema.dll has no .apiset section")
        _, _, _, start, raw_size = section
        version, size, _, count, entries, _, _ = self.unpack("7I", start)
        if version != 6 or size < 28 or size > raw_size:
            raise InvalidPE("unsupported or truncated API-set schema")

        def part(offset, length):
            if offset < 0 or length < 0 or offset > size - length:
                raise InvalidPE("API-set offset outside namespace")
            return self.read(start + offset, length)

        def string(offset, length):
            try:
                return part(offset, length).decode("utf-16le").lower()
            except UnicodeError as exc:
                raise InvalidPE("invalid API-set string") from exc

        part(entries, count * 24)
        result = {}
        for i in range(count):
            _, name, length, hashed, values, nvalues = struct.unpack("<6I", part(entries + i * 24, 24))
            dll_name(string(name, length))  # validate the full namespace name too
            if not hashed or hashed % 2 or hashed > length:
                raise InvalidPE("invalid API-set hashed name length")
            contract = string(name, hashed)
            if contract in result:
                raise InvalidPE("duplicate API-set hashed name")
            part(values, nvalues * 20)
            result[contract] = []
            for j in range(nvalues):
                _, alias, alen, host, hlen = struct.unpack("<5I", part(values + j * 20, 20))
                result[contract].append((dll_name(string(alias, alen)) if alen else "", dll_name(string(host, hlen)) if hlen else ""))
        return result


def dll_name(value):
    value = value.lower().rstrip(" ")
    if not value or any(c in value for c in "/\\:\0"):
        raise InvalidPE("unsafe or empty DLL name")
    return value if "." in value else value + ".dll"


def manifest():
    result = json.loads(Path(__file__).with_name("desktop-components.json").read_text())
    if result.get("schema_version") != 1 or result.get("profiles") != PROFILES:
        raise ValueError("manifest must contain exactly the reviewed nonempty desktop and VC2012 profiles")
    revision = result.get("wine_revision", "")
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("manifest must name an exact Wine commit")
    return result


def read_pe_bytes(path):
    """Bound before allocation and reject a file changing size during the read."""
    size = path.stat().st_size
    if not 0 < size <= MAX_PE_BYTES:
        raise InvalidPE("PE file exceeds byte budget or is empty")
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size:
        raise InvalidPE("PE file changed size during read")
    return data


def audit_farm(folder: Path, arch: str, required=(), overlay: Path | None = None):
    paths, errors = {}, []
    # Overlays are explicit same-architecture build outputs, never another farm.
    for directory in (folder, overlay):
        if directory is None or not directory.is_dir():
            continue
        local = set()
        entries = list(itertools.islice(directory.iterdir(), MAX_FARM_FILES + 1))
        if len(entries) > MAX_FARM_FILES:
            errors.append(f"farm directory exceeds entry-count budget: {directory}")
            continue
        for path in sorted(entries):
            if path.suffix.lower() not in PE_SUFFIXES:
                continue
            name = path.name.lower()
            if name in local:
                errors.append(f"case-colliding module: {path.name}")
            local.add(name)
            if path.is_symlink() or not path.is_file():
                errors.append(f"not a regular module: {path}")
                continue
            paths[name] = path
    modules, apisets, total_bytes = {}, {}, 0
    for name, path in sorted(paths.items()):
        try:
            if len(modules) >= MAX_FARM_FILES or total_bytes + path.stat().st_size > MAX_FARM_BYTES:
                raise InvalidPE("farm exceeds file-count/byte budget")
            data = read_pe_bytes(path)
            total_bytes += len(data)
            pe = PE(data)
            actual = pe.architecture()
            allowed = (arch, "x86_64") if arch == "arm64ec" else (arch,)
            if actual not in allowed or (name in required and actual != arch):
                raise InvalidPE(f"architecture {actual}, expected {arch}")
            deps = pe.dependencies()
            modules[name] = {"architecture": actual, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                             "dependencies": [{"name": n, "kind": k} for n, k in deps]}
            if name == "apisetschema.dll":
                apisets = pe.api_sets()
        except (InvalidPE, OSError) as exc:
            errors.append(f"{name}: {exc}")
    missing = []
    for name, module in modules.items():
        for dependency in module["dependencies"]:
            dep, kind = dependency["name"], dependency["kind"]
            target = dep
            if dep.startswith(("api-", "ext-")):
                # Pinned Wine get_apiset_entry compares HashedLength, excluding
                # the last '-' version component, not the complete DLL name.
                key = dep.split(".", 1)[0].rsplit("-", 1)[0]
                values = apisets.get(key, [])
                # Entry zero is the default even if its alias is nonempty.
                hosts = [host for alias, host in values[1:] if alias == name]
                if not hosts and values:
                    hosts = [values[0][1]]
                if not hosts or not hosts[0]:
                    # Wine keeps the original import name if no namespace
                    # entry exists; a physically shipped contract DLL can
                    # still satisfy that import. An empty existing mapping
                    # is different: get_apiset_target fails without fallback.
                    if key not in apisets and dep in modules:
                        target = dep
                    else:
                        missing.append({"module": name, "dependency": dep, "kind": kind, "reason": "unresolved API-set"})
                        continue
                else:
                    target = hosts[0]
            if target not in modules:
                missing.append({"module": name, "dependency": dep, "target": target, "kind": kind, "reason": "absent/invalid module"})
    return {"arch": arch, "folder": str(folder), "module_count": len(modules),
            "architectures": dict(sorted(Counter(m["architecture"] for m in modules.values()).items())),
            "missing_required": sorted(set(required) - modules.keys()), "missing_dependencies": missing,
            "errors": errors, "modules": modules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=ROOT / "app/Madeira")
    parser.add_argument("--arch", choices=ARCHES, action="append")
    parser.add_argument("--profile", choices=tuple(manifest()["profiles"]), action="append")
    parser.add_argument("--require-components", action="store_true", help="fail if selected profile modules are missing")
    parser.add_argument("--require-closure", action="store_true", help="fail on any normal/delay/forwarded dependency gap")
    parser.add_argument("--json", action="store_true", help="include module hashes and all dependency edges")
    args = parser.parse_args()
    required = {m + ".dll" for profile in args.profile or ["desktop"] for m in manifest()["profiles"][profile]}
    reports = [audit_farm(args.bundle / (a + "-windows"), a, required) for a in args.arch or ARCHES]
    if args.json:
        print(json.dumps({"schema_version": 1, "wine_revision": manifest()["wine_revision"], "farms": reports}, indent=2, sort_keys=True))
    else:
        for report in reports:
            print(f"{report['arch']}: {report['module_count']} PE modules; {report['architectures']}")
            print("  missing profile DLLs: " + (", ".join(report["missing_required"]) or "none"))
            groups = Counter(d["kind"] for d in report["missing_dependencies"])
            print(f"  unresolved dependency edges: {len(report['missing_dependencies'])} {dict(groups)}")
            for error in report["errors"]:
                print(f"  ERROR {error}")
        print("Inventory only: presence/import closure is not an application or device test.")
    return int(any(r["errors"] or (args.require_components and r["missing_required"]) or
                   (args.require_closure and (r["missing_dependencies"] or not r["module_count"])) for r in reports))


if __name__ == "__main__":
    sys.exit(main())
