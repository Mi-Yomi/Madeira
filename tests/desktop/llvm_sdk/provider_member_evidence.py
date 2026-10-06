#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Diagnostic-only member evidence. This module cannot approve a provider or link."""
import hashlib
import re
import struct

MIB = 1024 ** 2
MAX_OBJECT = 8 * MIB
MAX_ARCHIVE = 256 * MIB
MAX_SYMBOLS = 100000
MAX_RELOCS = 100000
MAX_NEUTRAL_DEBUG = 64 * 1024
MAX_NEUTRAL_OBJECT = 20 + 40 + MAX_NEUTRAL_DEBUG + 5 * 18 + 16 * 1024
DIA_SYMBOLS = {'?NoRegCoCreate@@YAJPEB_WAEBU_GUID@@1PEAPEAX@Z', 'CLSID_DiaSource', 'IID_IDiaDataSource'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def string_at(data, offset, limit=4096):
    require(0 <= offset < len(data), 'String offset outside table')
    end = data.find(b'\0', offset, min(len(data), offset + limit + 1))
    require(end >= offset, 'Unterminated/oversized string')
    result = data[offset:end].decode('ascii')
    require(result and all(32 <= ord(c) < 127 for c in result), 'Invalid symbol/name string')
    return result


def codeview_pch(data):
    """Retain only PCH dependency records from a bounded modern .debug$T stream."""
    if len(data) < 4 or struct.unpack_from('<I', data)[0] != 4:
        return {'status': 'unreviewed-signature', 'signature_hex': data[:4].hex(), 'pch_records': []}
    cursor, count, result = 4, 0, []
    while cursor < len(data):
        require(cursor + 4 <= len(data), 'Truncated CodeView type header')
        length, leaf = struct.unpack_from('<HH', data, cursor)
        require(length >= 2 and cursor + 2 + length <= len(data), 'Truncated CodeView type record')
        body = data[cursor + 4:cursor + 2 + length]
        count += 1
        require(count <= 200000, 'CodeView record cap')
        if leaf == 0x1509:  # LF_PRECOMP
            require(len(body) >= 13, 'Short LF_PRECOMP')
            first, types, signature = struct.unpack_from('<III', body)
            filename = string_at(body, 12)
            result.append({'leaf': 'LF_PRECOMP', 'offset': cursor, 'first_type': first,
                           'type_count': types, 'signature': signature, 'filename': filename})
        elif leaf == 0x0014:  # LF_ENDPRECOMP
            require(len(body) >= 4, 'Short LF_ENDPRECOMP')
            result.append({'leaf': 'LF_ENDPRECOMP', 'offset': cursor,
                           'signature': struct.unpack_from('<I', body)[0]})
        cursor += 2 + length
    return {'status': 'type-records-structurally-read', 'type_records': count, 'pch_records': result}


def neutral_layout(data, sections, pointer, count):
    """Only the observed regular-COFF debug/weak-alias layout, never code/data.

    IMAGE_FILE_MACHINE_UNKNOWN (0) can denote architecture-neutral COFF; it
    does not establish x64 identity. The optional .debug$S payload is retained
    as opaque, discardable debug bytes, not interpreted as executable content.
    """
    require(len(data) <= MAX_NEUTRAL_OBJECT and sections in {0, 1} and count in {3, 5},
            'Unreviewed/unbounded neutral COFF layout')
    require(struct.unpack_from('<H', data, 18)[0] == 0, 'Unreviewed neutral COFF characteristics')
    if sections:
        require(len(data) >= 60 and count == 5, 'Truncated/unreviewed neutral debug metadata')
        section = data[20:60]
        size, offset, reloc, lines, reloc_count, line_count, flags = struct.unpack_from('<IIIIHHI', section, 16)
        require(section[:8] == b'.debug$S' and section[8:16] == b'\0' * 8 and
                flags == 0x42100040 and not any((reloc, lines, reloc_count, line_count)),
                'Neutral section is not exact read-only discardable debug metadata')
        require(0 < size <= MAX_NEUTRAL_DEBUG and offset == 60 and pointer == offset + size,
                'Unbounded/overlapping neutral debug bytes')
    else:
        require(pointer == 20, 'Unreviewed neutral section-free layout')
    end = pointer + count * 18
    require(end + 4 <= len(data), 'Truncated neutral symbol/string table')
    size = struct.unpack_from('<I', data, end)[0]
    require(4 <= size <= 16 * 1024 and end + size == len(data),
            'Unbounded/truncated/trailing neutral string table')


def neutral_symbols(symbols, sections):
    """One undefined target and alias, with only the captured local tag names."""
    aliases = [row for row in symbols if row['storage_class'] == 105]
    targets = [row for row in symbols if row['storage_class'] == 2]
    tags = [row for row in symbols if row['storage_class'] == 3]
    require(len(aliases) == len(targets) == 1 and len(symbols) == 2 + len(tags) and
            len({row['name'] for row in symbols}) == len(symbols), 'Unreviewed neutral symbol set')
    require(all(row['section'] == 0 and row['value'] == 0 and row['type'] == '0x0000'
                for row in aliases + targets) and targets[0]['auxiliary_count'] == 0,
            'Neutral alias/target is not an undefined untyped external')
    alias = aliases[0]['weak_alias']
    require(alias['search_mode'] == 3 and alias['target_index'] == targets[0]['index'],
            'Neutral weak external is not an alias to the undefined target')
    names = {row['name'] for row in tags}
    allowed_tags = ({'@comp.id', '@feat.00'},) if sections else (set(), {'@comp.id', '@feat.00'})
    require(names in allowed_tags, 'Unreviewed neutral absolute metadata tags')
    require(all(row['section'] == -1 and row['type'] == '0x0000' and row['auxiliary_count'] == 0
                for row in tags), 'Neutral metadata is not local absolute untyped tags')


def coff_evidence(data, guard=lambda: None):
    require(20 <= len(data) <= MAX_OBJECT, 'Object evidence size cap/header failure')
    header = {'size': len(data), 'sha256': sha_bytes(data), 'raw_header_hex': data[:56].hex(),
              'provider_approved': False}
    if data[:4] == b'\0\0\xff\xff':
        version, machine = struct.unpack_from('<HH', data, 4)
        header.update(machine=f'0x{machine:04x}', anonymous_version=version)
        if version != 2 or len(data) < 56 or data[12:28] != bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8'):
            return {'header': dict(header, status='unreviewed-anonymous-or-import-format'), 'sections': [], 'symbols': [], 'relocations': []}
        sections, pointer, count = struct.unpack_from('<III', data, 44)
        start, width, kind = 56, 20, 'bigobj'
    else:
        machine, sections = struct.unpack_from('<HH', data)
        pointer, count = struct.unpack_from('<II', data, 8)
        optional = struct.unpack_from('<H', data, 16)[0]
        header.update(machine=f'0x{machine:04x}', optional_header_size=optional)
        require(optional == 0, 'Object has unexpected optional header')
        start, width, kind = 20, 18, 'coff'
    header.update(kind=kind, section_count=sections, symbol_pointer=pointer, symbol_count=count)
    neutral = machine == 0 and kind == 'coff'
    if machine != 0x8664 and not neutral:
        return {'header': dict(header, status='rejected-unreviewed-architecture'), 'sections': [], 'symbols': [], 'relocations': []}
    if neutral:
        neutral_layout(data, sections, pointer, count)
    require(sections <= 200000 and start + 40 * sections <= len(data), 'Unbounded/truncated section table')
    require(count <= MAX_SYMBOLS and (pointer or count == 0), 'Unbounded/missing symbol table')
    strings = b''
    if pointer:
        end = pointer + count * width
        require(pointer >= start + 40 * sections and end + 4 <= len(data), 'Symbol table outside object')
        size = struct.unpack_from('<I', data, end)[0]
        require(4 <= size <= 4 * MIB and end + size <= len(data), 'Unbounded/truncated string table')
        strings = data[end:end + size]
    def name(raw):
        if raw[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', raw, 4)[0]
            require(offset >= 4, 'Invalid symbol string-table offset')
            return string_at(strings, offset)
        value = raw.split(b'\0', 1)[0].decode('ascii')
        require(value and all(32 <= ord(c) < 127 for c in value), 'Invalid short symbol name')
        return value
    section_rows, relocation_tables = [], []
    aggregate_directives = 0
    for i in range(sections):
        if i % 128 == 0:
            guard()
        section = data[start + i * 40:start + (i + 1) * 40]
        section_name = section[:8].split(b'\0', 1)[0].decode('ascii')
        if section_name.startswith('/'):
            require(section_name[1:].isdigit(), 'Unknown long section name encoding')
            offset = int(section_name[1:])
            require(offset >= 4, 'Invalid section name offset')
            section_name = string_at(strings, offset)
        size, offset, reloc_offset = struct.unpack_from('<III', section, 16)
        reloc_count = struct.unpack_from('<H', section, 32)[0]
        flags = struct.unpack_from('<I', section, 36)[0]
        require(not flags & 0x01000000, 'Extended relocation count requires separate review')
        require(not size or offset or flags & 0x80, 'Missing initialized section data')
        require(not offset or (offset >= start + sections * 40 and offset + size <= len(data)), 'Section bytes outside object')
        raw = data[offset:offset + size] if offset else b''
        row = {'index': i + 1, 'name': section_name, 'size': size, 'raw_offset': offset,
               'characteristics': f'0x{flags:08x}', 'executable': bool(flags & 0x20000000 and size),
               'comdat': bool(flags & 0x1000), 'debug': section_name.startswith('.debug'),
               'relocation_count': reloc_count, 'raw_sha256': sha_bytes(raw), 'raw_prefix_hex': raw[:32].hex()}
        if section_name == '.drectve':
            aggregate_directives += len(raw)
            require(aggregate_directives <= MIB, 'Aggregate directive cap')
            row['raw_directives'] = raw.decode('ascii').replace('\0', ' ')
        if section_name == '.debug$T':
            row['codeview_pch'] = codeview_pch(raw)
        section_rows.append(row)
        require(reloc_count <= MAX_RELOCS and (reloc_count == 0 or
                reloc_offset >= start + sections * 40 and reloc_offset + 10 * reloc_count <= len(data)),
                'Relocations outside object')
        relocation_tables.append((i + 1, size, reloc_offset, reloc_count))
    symbols, byindex, index = [], {}, 0
    while index < count:
        if index % 256 == 0:
            guard()
        entry = data[pointer + index * width:pointer + (index + 1) * width]
        value = struct.unpack_from('<I', entry, 8)[0]
        section = struct.unpack_from('<h' if width == 18 else '<i', entry, 12)[0]
        stype, storage, auxiliaries = struct.unpack_from('<HBB', entry, 14 if width == 18 else 16)
        require(-2 <= section <= sections and index + auxiliaries < count, 'Invalid symbol section/auxiliary bounds')
        symbol_name = name(entry[:8])
        row = {'index': index, 'name': symbol_name, 'value': value, 'section': section,
               'type': f'0x{stype:04x}', 'storage_class': storage, 'auxiliary_count': auxiliaries,
               'auxiliary_hex': [data[pointer + (index + j) * width:pointer + (index + j + 1) * width].hex()
                                 for j in range(1, auxiliaries + 1)],
               'linkage': 'weak_external' if storage == 105 else 'external' if storage == 2 else 'local',
               'definition': 'section' if section > 0 else 'absolute' if section == -1 else
                             'debug' if section == -2 else 'common' if value else 'undefined'}
        if storage == 105:
            require(section == 0 and value == 0 and stype == 0 and auxiliaries == 1, 'Malformed weak external symbol')
            aux = bytes.fromhex(row['auxiliary_hex'][0])
            target, search = struct.unpack_from('<II', aux)
            require(search in {1, 2, 3} and not any(aux[8:]), 'Unknown/malformed weak external auxiliary')
            row['weak_alias'] = {'target_index': target, 'search_mode': search}
        if storage == 3 and section > 0 and stype == 0 and symbol_name == section_rows[section - 1]['name']:
            require(auxiliaries == 1, 'Section definition requires one auxiliary record')
            aux = bytes.fromhex(row['auxiliary_hex'][0])
            length, relocations, lines, checksum, low, selection, reserved, high = struct.unpack_from('<IHHIHBBH', aux)
            require(selection <= 7 and reserved == 0 and not any(aux[18:]), 'Unknown section auxiliary/COMDAT selection')
            association = low | high << 16
            is_comdat = section_rows[section - 1]['comdat']
            require((1 <= selection <= 7) if is_comdat else selection == 0, 'COMDAT section/auxiliary disagreement')
            if selection == 5:
                require(1 <= association <= sections and association != section, 'Invalid associative COMDAT section')
            row['section_definition'] = {'length': length, 'relocations': relocations, 'line_numbers': lines,
                'checksum': checksum, 'selection': selection, 'association': association}
        symbols.append(row)
        byindex[index] = row
        index += 1 + auxiliaries
    for row in symbols:
        if 'weak_alias' in row:
            target = byindex.get(row['weak_alias']['target_index'])
            require(target is not None and target['storage_class'] == 2, 'Weak target is absent, auxiliary or non-external')
            row['weak_alias']['target_name'] = target['name']
    relocations = []
    for section, size, offset, number in relocation_tables:
        require(len(relocations) + number <= MAX_RELOCS, 'Aggregate relocation cap')
        for i in range(number):
            if i % 256 == 0:
                guard()
            address, symbol, rtype = struct.unpack_from('<IIH', data, offset + i * 10)
            require(rtype not in {0x0e, 0x0f, 0x10}, 'Span-dependent/paired relocations require separate review')
            extent = {0: 0, 1: 8, 10: 2, 12: 1}.get(rtype, 4)
            require(symbol in byindex and rtype <= 0x0d and (extent == 0 or address + extent <= size),
                    'Invalid/unreviewed relocation target/type/address')
            relocations.append({'section': section, 'offset': address, 'type': f'0x{rtype:04x}',
                                'symbol_index': symbol, 'symbol_name': byindex[symbol]['name']})
    if neutral:
        neutral_symbols(symbols, sections)
        header['status'] = 'neutral-debug-weak-alias-observed-unreviewed' if sections else 'neutral-weak-alias-observed-unreviewed'
        header['architecture'] = 'neutral'
    else:
        header['status'] = 'x64-coff-structure-observed-unreviewed'
    return {'header': header, 'sections': section_rows, 'symbols': symbols, 'relocations': relocations}


def archive_members(path, all_members, guard=lambda: None):
    """Read the whole DIA archive, or only the first object that blocked each CRT audit."""
    size = path.stat().st_size
    require(8 <= size <= MAX_ARCHIVE, 'Diagnostic archive cap')
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'Unknown diagnostic archive')
        pos, longnames, seen = 8, b'', 0
        while pos < size:
            guard()
            stream.seek(pos)
            header = stream.read(60)
            require(len(header) == 60 and header[58:] == b'`\n' and header[48:58].strip().isdigit(), 'Invalid member header')
            length, start = int(header[48:58]), pos + 60
            require(start + length <= size, 'Truncated diagnostic member')
            name = header[:16].decode('ascii').strip()
            if name == '//':
                require(not longnames and length <= 16 * MIB, 'Duplicate/oversized member-name table')
                longnames = stream.read(length)
            elif name != '/':
                seen += 1
                require(seen <= 64 and length <= MAX_OBJECT, 'Diagnostic object count/size cap')
                if name.startswith('/') and name[1:].isdigit():
                    name = string_at(longnames, int(name[1:]))
                else:
                    require(not name.startswith(('/', '#')), 'Unknown diagnostic member-name format')
                    name = name.removesuffix('/')
                require(name and all(ord(c) >= 32 for c in name), 'Invalid diagnostic member name')
                yield {'member': name, 'archive_header_offset': pos, 'size': length}, stream.read(length)
                if not all_members:
                    return
            pos = start + length + (length & 1)
        require(pos == size and seen > 0, 'Incomplete/empty diagnostic archive')


def collect(name, path, runner, dumpbin, env, recorder):
    require(name in {'diaguids', 'libcmt', 'oldnames'}, 'Unrequested member evidence target')
    size = path.stat().st_size
    require(8 <= size <= MAX_ARCHIVE, 'Diagnostic archive cap before hashing')
    runner.guard()
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    identity = {'provider': name, 'path': str(path), 'size': size,
                'archive_sha256': digest,
                'scope': 'all-DIA-members' if name == 'diaguids' else 'first-CRT-object-only',
                'provider_approved': False, 'actual_link_selection_proven': False}
    recorder.emit('PROVIDER_MEMBER_SCOPE', identity)
    if name == 'diaguids':
        recorder.emit('PROVIDER_MEMBER_EXPECTATIONS', {'provider': name, 'required_symbols': sorted(DIA_SYMBOLS),
            'source': 'LLVM22.1.4 LLVMDebugInfoPDB.lib DIASession.cpp.obj undefined COFF symbols',
            'source_library_sha256': 'ccfe7b5753307aa62633ab2b0b843f604863bdc7c1cf604bb9a0eab2a0aebad1',
            'selection_proven': False})
    details = runner.work / 'member-evidence'
    details.mkdir(exist_ok=True)
    first_path = None
    incomplete = False
    for member, data in archive_members(path, name == 'diaguids', runner.guard):
        context = {'provider': name, **member}
        recorder.emit('PROVIDER_MEMBER_RAW_HEADER', {**context, 'sha256': sha_bytes(data), 'raw_header_hex': data[:56].hex(),
            'machine_raw': f'0x{struct.unpack_from("<H", data)[0]:04x}' if len(data) >= 2 else None,
            'section_count_raw': struct.unpack_from('<H', data, 2)[0] if len(data) >= 4 else None,
            'status': 'unreviewed-diagnostic-only'})
        if name != 'diaguids':
            first_path = details / (name + '.first-member.obj')
            with first_path.open('xb') as output:
                output.write(data)
        try:
            result = coff_evidence(data, runner.guard)
            incomplete |= result['header']['status'] in {'unreviewed-anonymous-or-import-format', 'rejected-unreviewed-architecture'}
            incomplete |= any(s.get('codeview_pch', {}).get('status') == 'unreviewed-signature' for s in result['sections'])
            recorder.emit('PROVIDER_MEMBER_HEADER', {**context, **result['header']})
            for kind, key in [('SECTION', 'sections'), ('SYMBOL', 'symbols'), ('RELOCATION', 'relocations')]:
                for record in result[key]:
                    recorder.emit('PROVIDER_MEMBER_' + kind, {**context, **record})
        except (ValueError, UnicodeError, struct.error) as exc:
            incomplete = True
            recorder.emit('PROVIDER_MEMBER_PARSE_STOP', {**context, 'reason': str(exc), 'status': 'incomplete-unreviewed'})
    # Microsoft reader is used only as an inspector; no provider/member is loaded as code.
    inspected = path if name == 'diaguids' else first_path
    require(inspected is not None, 'No diagnostic member to inspect')
    commands = [('detail', ['/headers', '/symbols', '/directives', '/relocations'], inspected)]
    if name == 'diaguids':
        commands.append(('index', ['/linkermember'], path))
    for label, switches, target in commands:
        code, text = runner.command('member-' + name + '-' + label,
            [dumpbin, '/nologo', *switches, target], env, 45, required=False)
        require(len(text.encode('utf-8')) <= 8 * MIB, 'Native member evidence output cap')
        recorder.emit('PROVIDER_MEMBER_NATIVE_READER', {'provider': name, 'stage': label, 'exit': code,
            'path': str(target), 'switches': switches, 'text_sha256': sha_bytes(text.encode('utf-8')),
            'provider_approved': False})
        for line in text.splitlines():
            recorder.emit('PROVIDER_MEMBER_NATIVE_LINE', {'provider': name, 'stage': label, 'text': line})
        incomplete |= code != 0
    with path.open('rb') as stream:
        require(path.stat().st_size == identity['size'] and hashlib.file_digest(stream, 'sha256').hexdigest() == identity['archive_sha256'],
                'Diagnostic archive changed during reading')
    recorder.emit('PROVIDER_MEMBER_DECISION', {'provider': name, 'evidence_collection_incomplete': incomplete,
        'provider_approved': False, 'actual_link_selection_proven': False,
        'next_decision': 'Review exact symbol/PCH/member evidence; if inconclusive stop static retries and choose separately authorized compile/link-only probe or reject prebuilt route for this window'})
    return incomplete
