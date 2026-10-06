#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded, read-only evidence from both Microsoft COFF archive linker members.

This proves index selection, not that an object defines a symbol or is safe to link.
Object contents are never interpreted, returned, extracted, or executed. Callers
must supply the complete independently scanned object inventory, and must still
verify the selected object's COFF evidence and the actual linker trace.

Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
Padding: https://llvm.org/doxygen/ArchiveWriter_8cpp_source.html
LLVM computeStringTable uses one LF for longnames alignment; writeSymbolTable /
writeSymbolMap use one NUL for linker-member alignment, included in member size.
This static-member proof intentionally rejects other archive dialects and
nonprintable symbol names, including DEL-prefixed import null-thunk names.
Ambiguous symbols remain in the inventory and cannot resolve as unique triggers.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import stat
import struct

MIB = 1024 ** 2
MAX_ARCHIVE = 256 * MIB
MAX_INDEX = 16 * MIB
MAX_LONGNAMES = 16 * MIB
MAX_SYMBOLS = 1_000_000
MAX_MEMBERS = 100_000
MAX_SYMBOL_BYTES = 64 * 1024
MAX_MEMBER_NAME_BYTES = 4096
PRINTABLE = re.compile(rb'[\x20-\x7e]+\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _integer(field, label, base=10, optional=False):
    value = field.rstrip(b' ')
    if not value and optional:
        return None
    allowed = b'01234567' if base == 8 else b'0123456789'
    require(value and all(byte in allowed for byte in value), 'Invalid archive ' + label)
    return int(value, base)


def _date(field):
    # Date is inert metadata, never a size, position or allocation input.
    # Preserve the -1 sentinel consistent with captured Microsoft DUMPBIN's
    # FFFFFFFFFFFFFFFF display; its exact native header encoding is still unverified.
    if field.rstrip(b' ') == b'-1':
        return -1
    try:
        return _integer(field, 'date', optional=True)
    except ValueError as exc:
        raise ValueError('Unreviewed archive date bytes=' + field.hex() +
                         ' sha256=' + hashlib.sha256(field).hexdigest()) from exc


def _text(raw, label, cap):
    require(0 < len(raw) <= cap and PRINTABLE.fullmatch(raw), 'Invalid/oversized ' + label)
    return raw.decode('ascii')


def _metadata_tail(label, payload, offset):
    # Only called on identified archive directory/name metadata, never an OBJ.
    tail = payload[offset:]
    return (label + ' payload_offset=' + str(offset) + ' payload_length=' + str(len(payload)) +
            ' remaining_length=' + str(len(tail)) + ' prefix_hex=' + tail[:16].hex() +
            ' remaining_sha256=' + hashlib.sha256(tail).hexdigest())


def _hash(stream, size, guard):
    stream.seek(0)
    digest, remaining = hashlib.sha256(), size
    while remaining:
        guard()
        chunk = stream.read(min(MIB, remaining))
        require(chunk, 'Archive changed or truncated during hashing')
        digest.update(chunk)
        remaining -= len(chunk)
    require(not stream.read(1), 'Archive grew during hashing')
    return digest.hexdigest()


def _longnames(payload, guard):
    names, cursor = {}, 0
    while cursor < len(payload):
        guard()
        # The only supported in-member longnames pad is LLVM's single LF.
        if cursor & 1 and len(payload) - cursor == 1 and payload[cursor:] == b'\n':
            break
        end = payload.find(b'\0', cursor, cursor + MAX_MEMBER_NAME_BYTES + 1)
        if end < 0:
            raise ValueError(_metadata_tail('Unterminated/oversized archive long name', payload, cursor))
        try:
            name = _text(payload[cursor:end], 'archive long name', MAX_MEMBER_NAME_BYTES)
        except ValueError as exc:
            raise ValueError(_metadata_tail(str(exc), payload, cursor)) from exc
        require(len(names) < MAX_MEMBERS, 'Archive longnames count cap')
        names[cursor] = name
        cursor = end + 1
    return names, len(payload) - cursor


def _scan(stream, size, guard):
    """Scan physical headers independently of every offset supplied by an index."""
    stream.seek(0)
    require(stream.read(8) == b'!<arch>\n', 'Not a regular COFF archive')
    position, ordinal = 8, 0
    members, indexes = {}, []
    names, longnames_metadata = {}, None
    while position < size:
        guard()
        stream.seek(position)
        header = stream.read(60)
        require(len(header) == 60 and header[58:] == b'`\n',
                'Invalid archive member header offset=' + str(position) + ' bytes_read=' + str(len(header)) +
                ' header_sha256=' + hashlib.sha256(header).hexdigest())
        raw_name = header[:16].rstrip(b' ')
        name = _text(raw_name, 'archive header name', 16)
        require(not name.startswith(' '), 'Invalid archive header name padding')
        date = _date(header[16:28])
        for field, label, base in [(header[28:34], 'user ID', 10),
                                    (header[34:40], 'group ID', 10),
                                    (header[40:48], 'mode', 8)]:
            _integer(field, label, base, optional=True)
        length = _integer(header[48:58], 'member size')
        start, end = position + 60, position + 60 + length
        require(end <= size, 'Truncated archive member')
        if ordinal < 2:
            require(name == '/', 'Two leading COFF linker members required')
            require(length <= MAX_INDEX, 'Archive index payload cap')
            payload = stream.read(length)
            require(len(payload) == length, 'Truncated archive index payload')
            indexes.append(({'archive_header_offset': position, 'size': length,
                             'header_sha256': hashlib.sha256(header).hexdigest(),
                             'date': date, 'date_ascii': header[16:28].decode('ascii'),
                             'sha256': hashlib.sha256(payload).hexdigest()}, payload))
        elif name == '//':
            require(ordinal == 2 and longnames_metadata is None,
                    'Duplicate/misplaced archive longnames table')
            require(length <= MAX_LONGNAMES, 'Archive longnames payload cap')
            payload = stream.read(length)
            require(len(payload) == length, 'Truncated archive longnames payload')
            try:
                names, padding = _longnames(payload, guard)
            except ValueError as exc:
                raise ValueError('longnames_header_offset=' + str(position) + ': ' + str(exc)) from exc
            longnames_metadata = {'archive_header_offset': position, 'size': length,
                                  'header_sha256': hashlib.sha256(header).hexdigest(),
                                  'date': date, 'date_ascii': header[16:28].decode('ascii'),
                                  'sha256': hashlib.sha256(payload).hexdigest(),
                                  'name_count': len(names), 'alignment_padding_bytes': padding}
        else:
            require(len(members) < MAX_MEMBERS, 'Archive object count cap')
            if name.startswith('/'):
                require(name[1:].isascii() and name[1:].isdigit(), 'Unsupported archive member name')
                offset = int(name[1:])
                require(offset in names, 'Archive long-name offset is not a string start')
                name = names[offset]
            else:
                require(not name.startswith('#') and name.endswith('/'), 'Unsupported archive member name')
                name = _text(raw_name[:-1], 'archive member name', 15)
            require(length > 0, 'Empty archive object member')
            members[position] = {'member': name, 'archive_header_offset': position, 'size': length}
        if length & 1:
            stream.seek(end)
            alignment = stream.read(1)
            require(alignment == b'\n', 'Missing/invalid archive alignment byte offset=' + str(end) +
                    ' length=' + str(len(alignment)) + ' hex=' + alignment.hex())
        position = end + (length & 1)
        ordinal += 1
    require(position == size and len(indexes) == 2 and members, 'Incomplete/empty COFF archive')
    return indexes, members, longnames_metadata


def _inventory_check(inventory, members, guard):
    require(inventory is not None, 'Independent archive object inventory required')
    observed = {}
    for row in inventory:
        guard()
        require(isinstance(row, Mapping), 'Invalid independent inventory record')
        offset, name, size = (row.get(key) for key in ('archive_header_offset', 'member', 'size'))
        require(type(offset) is int and type(size) is int and isinstance(name, str),
                'Invalid independent inventory identity')
        require(offset not in observed and len(observed) < MAX_MEMBERS,
                'Duplicate/excessive independent inventory member')
        require(offset in members and members[offset] == {
            'member': name, 'archive_header_offset': offset, 'size': size},
            'Independent inventory disagrees with physical archive membership')
        observed[offset] = True
    require(observed.keys() == members.keys(), 'Independent inventory does not cover the entire archive')


def _u32(payload, cursor, endian, label):
    require(cursor + 4 <= len(payload), 'Truncated ' + label)
    return struct.unpack_from(endian + 'I', payload, cursor)[0]


def _strings(payload, cursor, count, label, guard):
    names = []
    for _ in range(count):
        guard()
        end = payload.find(b'\0', cursor, cursor + MAX_SYMBOL_BYTES + 1)
        require(end >= 0, 'Unterminated/oversized ' + label + ' symbol')
        name = _text(payload[cursor:end], label + ' symbol', MAX_SYMBOL_BYTES)
        names.append(name)
        cursor = end + 1
    tail = payload[cursor:]
    # A single NUL is justified only when the consumed payload is odd-sized.
    require(not tail or (cursor & 1 and tail == b'\0'),
            _metadata_tail('Invalid trailing ' + label + ' bytes/padding', payload, cursor))
    return names, len(tail)


def _first(payload, members, guard):
    count = _u32(payload, 0, '>', 'first linker-member symbol count')
    require(count <= MAX_SYMBOLS, 'First linker-member symbol count cap')
    cursor = 4 + 4 * count
    require(cursor <= len(payload) and count <= len(payload) - cursor,
            'Truncated first linker-member offsets/strings')
    offsets, previous = [], -1
    for (offset,) in struct.iter_unpack('>I', memoryview(payload)[4:cursor]):
        guard()
        require(offset in members, 'First linker-member offset is not an object header')
        require(offset >= previous, 'First linker-member offsets not ascending')
        offsets.append(offset)
        previous = offset
    names, padding = _strings(payload, cursor, count, 'first linker member', guard)
    return list(zip(names, offsets)), padding


def _second(payload, members, guard):
    count = _u32(payload, 0, '<', 'second linker-member object count')
    require(0 < count <= MAX_MEMBERS, 'Second linker-member object count cap')
    cursor = 4 + 4 * count
    require(cursor + 4 <= len(payload), 'Truncated second linker-member offsets')
    offsets, previous = [], -1
    for (offset,) in struct.iter_unpack('<I', memoryview(payload)[4:cursor]):
        guard()
        require(offset in members, 'Second linker-member offset is not an object header')
        require(offset > previous, 'Second linker-member offsets not strictly ascending')
        offsets.append(offset)
        previous = offset
    require(len(offsets) == len(members), 'Second linker member does not cover every archive object')
    symbol_count = _u32(payload, cursor, '<', 'second linker-member symbol count')
    require(symbol_count <= MAX_SYMBOLS, 'Second linker-member symbol count cap')
    cursor += 4
    end = cursor + 2 * symbol_count
    require(end <= len(payload) and symbol_count <= len(payload) - end,
            'Truncated second linker-member indices/strings')
    selected = []
    for (index,) in struct.iter_unpack('<H', memoryview(payload)[cursor:end]):
        guard()
        require(1 <= index <= count, 'Second linker-member index is not a valid 1-based object index')
        selected.append(offsets[index - 1])
    names, padding = _strings(payload, end, symbol_count, 'second linker member', guard)
    require(all(left <= right for left, right in zip(names, names[1:])),
            'Second linker-member symbols not in ascending lexical order')
    return list(zip(names, selected)), padding


def _owners(entries):
    owners = defaultdict(set)
    for symbol, offset in entries:
        owners[symbol].add(offset)
    return {symbol: sorted(offsets) for symbol, offsets in owners.items()}


def read_archive_index(path, inventory, guard=lambda: None):
    """Return metadata, symbol_to_header_offsets, symbol_entries, and membership.

    inventory is mandatory: a complete iterable of independently scanned rows
    with member (full name), archive_header_offset and size. Extra fields are
    allowed. metadata is safe for a small JSON evidence record. Candidate owner
    sets must agree across the indices, but entries and their multiplicities
    remain intact under symbol_entries. Duplicates elsewhere do not prevent a
    requested trigger from resolving to one unique offset. resolve_symbols
    selects only actual linker triggers; no names serve as member identities.
    Raises ValueError on malformed, unsupported, ambiguous, or changed inputs.
    """
    path = Path(path)
    initial = path.stat()
    require(stat.S_ISREG(initial.st_mode) and 8 <= initial.st_size <= MAX_ARCHIVE,
            'Missing/oversized/nonregular archive')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 8 <= before.st_size <= MAX_ARCHIVE,
                'Missing/oversized/nonregular archive')
        digest = _hash(stream, before.st_size, guard)
        indexes, members, longnames = _scan(stream, before.st_size, guard)
        _inventory_check(inventory, members, guard)
        first, first_padding = _first(indexes[0][1], members, guard)
        second, second_padding = _second(indexes[1][1], members, guard)
        owners = _owners(second)
        require(_owners(first) == owners, 'COFF archive linker members disagree on symbol ownership')
        require(_hash(stream, before.st_size, guard) == digest, 'Archive changed during index reading')
        after = os.fstat(stream.fileno())
        current = path.stat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(identity(initial) == identity(before) == identity(after) == identity(current),
                'Archive identity changed during index reading')
    first_metadata, second_metadata = indexes[0][0], indexes[1][0]
    first_metadata.update(symbol_count=len(first), alignment_padding_bytes=first_padding,
                          offsets_order='nondecreasing', integer_encoding='big-endian-u32')
    second_metadata.update(symbol_count=len(second), member_count=len(members),
                           alignment_padding_bytes=second_padding, offsets_order='strictly-increasing',
                           symbols_order='ascii-lexical', integer_encoding='little-endian-u32/u16')
    return {'metadata': {'schema_version': 1, 'format': 'coff-two-linker-members',
                         'archive_sha256': digest, 'archive_size': before.st_size,
                         'symbol_count': len(owners), 'member_count': len(members),
                         'index_agreement': True, 'inventory_cross_checked': True,
                         'agreement_kind': 'exact-symbol-owner-sets',
                         'entry_multiplicity_agreement': Counter(first) == Counter(second),
                         'first_linker_member': first_metadata, 'second_linker_member': second_metadata,
                         'longnames_member': longnames},
            'symbol_to_header_offsets': owners, 'symbol_entries': {'first': first, 'second': second},
            'members_by_header_offset': members}


def resolve_symbols(index, symbols):
    """Resolve all exact, case-sensitive triggers; never select by object basename.

    Repeated triggers are harmless and return one entry per exact symbol. An
    absent trigger rejects the entire request, even when its basename is unique.
    """
    require(not isinstance(symbols, (str, bytes)), 'Expected an iterable of trigger symbols')
    resolved = {}
    for ordinal, symbol in enumerate(symbols):
        require(ordinal < MAX_SYMBOLS, 'Archive trigger count cap')
        require(isinstance(symbol, str) and symbol in index['symbol_to_header_offsets'],
                'Trigger symbol absent from verified archive index')
        offsets = index['symbol_to_header_offsets'][symbol]
        require(len(offsets) == 1, 'Trigger symbol has multiple candidate archive members')
        offset = offsets[0]
        require(offset in index['members_by_header_offset'], 'Trigger points to absent archive member')
        resolved[symbol] = dict(index['members_by_header_offset'][offset])
    return resolved
