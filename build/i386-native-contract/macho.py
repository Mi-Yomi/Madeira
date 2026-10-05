#!/usr/bin/env python3
"""Small, fail-closed reader for this contract's thin arm64 Mach-O evidence.

Not a general Mach-O linker. Unknown relocation forms in checked tables fail;
no tools, guest code or object constructors are executed by the reader.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded(data, offset, size):
    require(offset >= 0 and size >= 0 and offset + size <= len(data), "binary range out of bounds")
    return data[offset:offset + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, bounded(data, offset, struct.calcsize(fmt)))


def cstring(data):
    require(b"\0" in data, "unterminated Mach-O string")
    return data.split(b"\0", 1)[0].decode("utf-8")


def archive_members(data):
    require(data[:8] == b"!<arch>\n", "expected regular ar archive (no thin/fat archives)")
    offset, names, seen = 8, b"", set()
    indexes = {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "__.SYMDEF_64 SORTED"}
    while offset < len(data):
        head = bounded(data, offset, 60)
        require(head[58:] == b"`\n", "invalid ar header")
        name = head[:16].decode("ascii").rstrip()
        size = int(head[48:58].decode("ascii").strip())
        offset += 60
        body = bounded(data, offset, size)
        offset += size
        if size % 2:
            require(bounded(data, offset, 1) == b"\n", "invalid ar alignment")
            offset += 1
        if name.startswith("#1/"):
            length = int(name[3:])
            require(0 < length <= len(body), "invalid BSD ar name")
            name = body[:length].rstrip(b"\0").decode("utf-8")
            body = body[length:]
        elif name == "//":
            names = body
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = names.find(b"/\n", start)
            require(0 <= start < len(names) and end >= start, "invalid GNU ar name")
            name = names[start:end].decode("utf-8")
        elif name not in indexes:
            name = name.removesuffix("/")
        if name in indexes:
            continue
        require(name and name not in seen, f"duplicate/empty archive member: {name}")
        seen.add(name)
        yield name, body
    require(seen, "empty or index-only archive")


@dataclass(frozen=True)
class Section:
    name: str
    segment: str
    address: int
    size: int
    offset: int
    flags: int
    relocations: tuple

    @property
    def executable(self):
        return bool(self.flags & 0x80000400)

    @property
    def zerofill(self):
        return (self.flags & 0xff) in (1, 0xc, 0x12)


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: int
    section: int
    descriptor: int
    address: int

    @property
    def defined(self):
        return not self.kind & 0xe0 and self.kind & 0xe == 0xe and self.section != 0

    @property
    def external(self):
        return bool(self.kind & 1)

    @property
    def weak(self):
        return bool(self.descriptor & 0x80)


class MachO:
    def __init__(self, data, label, filetype=1):
        self.data, self.label = data, label
        magic, cpu, subtype, kind, count, size, flags, reserved = unpack("<8I", data, 0)
        require(magic == 0xfeedfacf and cpu == 0x100000c and subtype & 0xffffff == 0,
                f"{label}: expected thin arm64 Mach-O, not arm64e/bitcode")
        require(kind == filetype, f"{label}: expected Mach-O filetype {filetype}")
        require(count <= size // 8, f"{label}: invalid command count")
        bounded(data, 32, size)
        self.sections, self.symbols, platforms, symtab = [], [], [], None
        cursor = 32
        for _ in range(count):
            cmd, length = unpack("<2I", data, cursor)
            require(length >= 8 and length % 8 == 0 and cursor + length <= 32 + size,
                    f"{label}: invalid load command")
            if cmd == 0x32:
                require(length >= 24, "short LC_BUILD_VERSION")
                platform, minimum, sdk, ntools = unpack("<4I", data, cursor + 8)
                require(length == 24 + 8 * ntools, "invalid LC_BUILD_VERSION")
                platforms.append(platform)
            elif cmd in (0x24, 0x25, 0x2f, 0x30):
                require(length == 16, "invalid LC_VERSION_MIN")
                platforms.append({0x24: 1, 0x25: 2, 0x2f: 3, 0x30: 4}[cmd])
            elif cmd == 2:
                require(length == 24 and symtab is None, "invalid/duplicate LC_SYMTAB")
                symtab = unpack("<4I", data, cursor + 8)
            elif cmd == 0x19:
                require(length >= 72, "short LC_SEGMENT_64")
                nsects = unpack("<I", data, cursor + 64)[0]
                require(length == 72 + 80 * nsects, "invalid Mach-O sections")
                for i in range(nsects):
                    fields = unpack("<16s16sQQ8I", data, cursor + 72 + i * 80)
                    name, segment, address, ssize, off, align, roff, nrel, sflags, _, _, _ = fields
                    require(align <= 31 and nrel <= len(data) // 8, "invalid section bounds")
                    rels = []
                    for j in range(nrel):
                        location, value = unpack("<iI", data, roff + j * 8)
                        require(0 <= location < ssize, "scattered/out-of-section relocation")
                        rels.append((location, value & 0xffffff, (value >> 24) & 1,
                                     (value >> 25) & 3, (value >> 27) & 1, value >> 28))
                    sec = Section(cstring(name + b"\0"), cstring(segment + b"\0"), address,
                                  ssize, off, sflags, tuple(rels))
                    if not sec.zerofill:
                        bounded(data, off, ssize)
                    self.sections.append(sec)
            cursor += length
        require(cursor == size + 32 and platforms and set(platforms) == {2},
                f"{label}: missing/non-iOS platform")
        require(symtab is not None, f"{label}: missing symbol table (stripped evidence)")
        symoff, nsyms, stroff, strsize = symtab
        strings = bounded(data, stroff, strsize)
        require(nsyms <= len(data) // 16, "invalid symbol count")
        for i in range(nsyms):
            string, stype, section, desc, value = unpack("<IBBHQ", data, symoff + i * 16)
            require(string < len(strings), "invalid symbol name offset")
            symbol = Symbol(cstring(strings[string:]), stype, section, desc, value)
            if symbol.defined:
                require(section <= len(self.sections), "invalid symbol section")
                sec = self.sections[section - 1]
                # ld64's executable-header anchor is N_SECT but precedes
                # __text. It is never an acceptable code/data contract target.
                header_anchor = filetype == 2 and symbol.name == "__mh_execute_header" and section == 1 and value < sec.address
                require(sec.address <= value <= sec.address + sec.size or header_anchor,
                        f"symbol outside section: {symbol.name}")
            self.symbols.append(symbol)

    def definitions(self, name):
        return [s for s in self.symbols if s.name == name and s.defined]

    def definition(self, name, code=None, external=None):
        matches = self.definitions(name)
        require(len(matches) == 1, f"{self.label}: missing/duplicate section definition {name}")
        symbol = matches[0]
        require(not symbol.weak, f"{self.label}: weak definition {name}")
        if external is not None:
            require(symbol.external == external, f"{self.label}: incorrect visibility for {name}")
        section = self.sections[symbol.section - 1]
        if code is not None:
            require(section.executable == code, f"{self.label}: wrong code/data section for {name}")
        return symbol

    def extent(self, symbol):
        section = self.sections[symbol.section - 1]
        end = min([s.address for s in self.symbols if s.defined and s.section == symbol.section
                   and s.address > symbol.address] + [section.address + section.size])
        require(end > symbol.address, f"{self.label}: empty symbol {symbol.name}")
        return symbol.address - section.address, end - section.address

    def references(self, name):
        symbol = self.definition(name, code=True)
        start, end = self.extent(symbol)
        section = self.sections[symbol.section - 1]
        names = set()
        for offset, index, pcrel, length, external, kind in section.relocations:
            if start <= offset < end and external:
                require(index < len(self.symbols), "invalid relocation symbol index")
                names.add(self.symbols[index].name)
        return names

    def pointer_table(self, name, targets, resolve):
        symbol = self.definition(name, code=False, external=True)
        section = self.sections[symbol.section - 1]
        require(not section.zerofill, f"{self.label}: zero-fill table {name}")
        start, end = self.extent(symbol)
        require(end - start == 8 * len(targets), f"{self.label}: wrong table byte extent {name}")
        rels = [r for r in section.relocations if start <= r[0] < end]
        require(len(rels) == len(targets), f"{self.label}: wrong table relocation count {name}")
        addresses = {}
        for rel in rels:
            offset, index, pcrel, length, external, kind = rel
            require(offset not in addresses and (offset - start) % 8 == 0,
                    f"{self.label}: overlapping/misaligned table relocation")
            require((pcrel, length, kind) == (0, 3, 0),
                    f"{self.label}: expected ARM64_RELOC_UNSIGNED 64-bit pointer")
            value = unpack("<Q", self.data, section.offset + offset)[0]
            if external:
                require(index < len(self.symbols) and value == 0, "invalid/nonzero table symbol addend")
                target = self.symbols[index]
                names = {target.name}
                obj, defined = resolve(target.name, self)
            else:
                require(0 < index <= len(self.sections), "invalid table section relocation")
                matches = [s for s in self.symbols if s.defined and s.section == index and s.address == value]
                require(matches, "table relocation does not point at a named compiled function")
                names, obj, defined = {s.name for s in matches}, self, matches[0]
            require(obj.sections[defined.section - 1].executable, "table target is data, not code")
            obj.extent(defined)
            addresses[offset] = names
        for i, expected in enumerate(targets):
            require(expected in addresses.get(start + i * 8, set()),
                    f"{self.label}: {name}[{i}] does not point to {expected}")
        return {"symbol": name, "bytes": end - start, "entries": len(targets), "targets": targets}
