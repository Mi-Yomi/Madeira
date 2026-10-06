#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve ambiguous static archive loads by exact symbol indices, never basenames."""
import hashlib
from pathlib import Path, PureWindowsPath
import re
import struct

import archive_symbol_index as index_reader
import provider_inventory as inventory
import provider_member_evidence as member
from native_index_evidence import verify_dumpbin

require = inventory.require
MAX_AMBIGUOUS_LOADS = 128
MAX_INDEX_PROVIDERS = 16
MAX_CANDIDATES = 64
MAX_CANDIDATE_BYTES = 64 * 1024 ** 2


def key(value):
    return str(PureWindowsPath(value)).casefold()


def found_symbol(text, os_import=False):
    # Native import-descriptor roots use this documented COFF spelling. Retain
    # it only for the existing OS-import path; static-index lookup stays ASCII.
    if os_import and re.fullmatch(r'\x7f[A-Za-z0-9_.-]+_NULL_THUNK_DATA', text):
        return text
    require(isinstance(text, str) and 0 < len(text) <= 4096 and
            all(32 <= ord(c) < 127 for c in text), 'Invalid Found symbol text')
    if text.startswith('"'):
        match = re.fullmatch(r'"[^"\r\n]*" \(([^()\s]+)\)', text)
        require(match is not None, 'Unsupported decorated Found symbol display')
        return match[1]
    require(re.fullmatch(r'[^()\s"]+', text) is not None, 'Ambiguous Found symbol spelling')
    return text


def candidates(rows, name):
    if PureWindowsPath(name).name == name:
        return [row for row in rows if key(PureWindowsPath(row['member']).name) == key(name)]
    exact = [row for row in rows if key(row['member']) == key(name)]
    require(exact, 'Unmatched full archive member path')
    return exact


def candidate_metadata(path, row, trigger, guard=lambda: None):
    """Read in memory; output only hashes and bounded COFF metadata, never vendor bytes."""
    require(20 <= row['size'] <= member.MAX_OBJECT, 'Candidate object size cap')
    guard()
    with path.open('rb') as stream:
        stream.seek(row['archive_header_offset'])
        header = stream.read(60)
        require(len(header) == 60 and header[58:] == b'`\n' and header[48:58].strip().isdigit() and
                int(header[48:58]) == row['size'], 'Candidate header/size disagrees with inventory')
        data = stream.read(row['size'])
    require(len(data) == row['size'], 'Truncated candidate object')
    evidence = member.coff_evidence(data, guard)
    require(evidence['header']['status'] == 'x64-coff-structure-observed-unreviewed' and
            evidence['header']['machine'] == row['machine'] and
            evidence['header']['section_count'] == row['section_count'], 'Candidate architecture/section disagreement')
    directives = inventory.parse_directives(' '.join(x.get('raw_directives', '') for x in evidence['sections']))
    for field in ['default_libraries', 'mismatch_tags', 'other_directives_unreviewed']:
        require(directives[field] == row[field], 'Candidate directives disagree with inventory: ' + field)
    symbols = [s for s in evidence['symbols'] if s['name'] == trigger]
    require(len(symbols) <= 16, 'Candidate trigger-symbol record cap')
    sections = []
    for s in symbols:
        if s['section'] <= 0:
            continue
        section = evidence['sections'][s['section'] - 1]
        definitions = [x for x in evidence['symbols'] if x['section'] == s['section'] and 'section_definition' in x]
        require(len(definitions) == 1, 'Missing/ambiguous trigger section-definition metadata')
        aux = definitions[0]['section_definition']
        association = aux['association'] if aux['selection'] == 5 else None
        fields = ['index', 'name', 'size', 'raw_offset', 'characteristics', 'executable', 'comdat', 'debug',
                  'relocation_count', 'raw_sha256']
        describe = lambda value: {field: value[field] for field in fields}
        sections.append({'symbol_index': s['index'], 'section': describe(section), 'section_definition': definitions[0],
                         'associated_section': describe(evidence['sections'][association - 1]) if association else None})
    return {'member': row['member'], 'archive_header_offset': row['archive_header_offset'],
            'size': row['size'], 'sha256': hashlib.sha256(data).hexdigest(),
            'machine': evidence['header']['machine'], 'trigger_symbol': trigger,
            'trigger_symbol_records': symbols, 'trigger_sections': sections,
            'default_libraries': directives['default_libraries'], 'mismatch_tags': directives['mismatch_tags'],
            'other_directives_unreviewed': directives['other_directives_unreviewed'],
            'vendor_object_bytes_emitted': False, 'provider_approved': False}


def strong_definition(metadata):
    symbols = metadata['trigger_symbol_records']
    require(len(symbols) == 1, 'Missing/ambiguous candidate trigger definition')
    symbol = symbols[0]
    require(symbol['name'] == metadata['trigger_symbol'] and symbol['storage_class'] == 2 and
            symbol['section'] > 0 and symbol['definition'] == 'section' and symbol['auxiliary_count'] == 0 and
            'weak_alias' not in symbol, 'Trigger is not a strong section definition')
    require(len(metadata['trigger_sections']) == 1 and
            metadata['trigger_sections'][0]['symbol_index'] == symbol['index'], 'Trigger section metadata disagrees')
    context = metadata['trigger_sections'][0]
    section, definition = context['section'], context['section_definition']
    require(section['index'] == symbol['section'] == definition['section'] and
            definition['storage_class'] == 3 and definition['name'] == section['name'],
            'Trigger section definition identity disagrees')
    aux = definition['section_definition']
    require(aux['selection'] in range(1, 8) if section['comdat'] else aux['selection'] == 0,
            'Trigger COMDAT selection disagrees')
    if aux['selection'] == 5:
        require(context['associated_section'] is not None and
                context['associated_section']['index'] == aux['association'] != section['index'],
                'Trigger associative COMDAT metadata disagrees')
    else:
        require(context['associated_section'] is None, 'Unexpected associative COMDAT metadata')
    return symbol


def bind(entry, rows, archive, index, candidate_records):
    trigger = entry['found_symbol']
    offsets = index_reader.resolve_symbols(index, [trigger])
    offset = offsets[trigger]['archive_header_offset']
    require(sum(row['archive_header_offset'] == offset for row in rows) == 1,
            'Indexed owner does not uniquely match the loaded member candidates')
    matching = [row for row in candidate_records if row['archive_header_offset'] == offset]
    require(len(matching) == 1, 'Indexed candidate metadata missing or duplicated')
    chosen = matching[0]
    strong_definition(chosen)
    return {'status': 'unique-index-and-definition', 'load_id': entry['load_id'],
            'provider': entry['provider'], 'archive_sha256': archive['sha256'],
            'loaded_member_label': entry['member'], 'found_symbol': trigger,
            'raw_found': entry['raw_found'], 'referenced_in': entry['referenced_in'],
            'candidate_header_offsets': sorted(row['archive_header_offset'] for row in rows),
            'first_index_offsets': [off for name, off in index['symbol_entries']['first'] if name == trigger],
            'second_index_offsets': [off for name, off in index['symbol_entries']['second'] if name == trigger],
            **chosen}


def validate_binding(proof, entry, rows, archive):
    require(proof['status'] == 'unique-index-and-definition' and proof['load_id'] == entry['load_id'] and
            proof['provider'] == entry['provider'] and proof['archive_sha256'] == archive['sha256'] and
            proof['loaded_member_label'] == entry['member'] and proof['found_symbol'] == entry['found_symbol'] and
            proof['trigger_symbol'] == entry['found_symbol'], 'Static proof context/identity disagreement')
    require(proof['raw_found'] == entry['raw_found'] and proof['referenced_in'] == entry['referenced_in'],
            'Static proof Found/referrer context changed')
    require(proof['candidate_header_offsets'] == sorted(row['archive_header_offset'] for row in rows),
            'Static proof candidate set changed')
    offset = proof['archive_header_offset']
    require(set(proof['first_index_offsets']) == set(proof['second_index_offsets']) == {offset},
            'Static proof index owners conflict or are nonunique')
    matching = [row for row in rows if row['archive_header_offset'] == offset]
    require(len(matching) == 1 and matching[0]['member'] == proof['member'] and
            matching[0]['size'] == proof['size'] and matching[0]['machine'] == proof['machine'] == '0x8664' and
            re.fullmatch('[0-9a-f]{64}', proof['sha256']), 'Static proof candidate metadata disagrees')
    for field in ['default_libraries', 'mismatch_tags', 'other_directives_unreviewed']:
        require(matching[0][field] == proof[field], 'Static proof directive disagreement')
    strong_definition(proof)
    return matching[0]


def collect(loaded, providers, objects, runner, tools, env, recorder):
    ambiguous = []
    for entry in loaded:
        if providers[entry['provider']]['role']['kind'] == 'os_import':
            continue
        rows = candidates(objects[entry['provider']], entry['member'])
        require(rows, 'Loaded static member missing from inventory')
        if len(rows) > 1:
            require(len(rows) <= MAX_CANDIDATES, 'Ambiguous member candidate cap')
            ambiguous.append((entry, rows))
    require(len(ambiguous) <= MAX_AMBIGUOUS_LOADS, 'Ambiguous static-load cap')
    names = sorted({entry['provider'] for entry, _ in ambiguous})
    require(len(names) <= MAX_INDEX_PROVIDERS, 'Archive-index provider cap')
    recorder.emit('STATIC_SELECTION_SCOPE', {'static_loaded_count': sum(providers[x['provider']]['role']['kind'] != 'os_import' for x in loaded),
                  'ambiguous_loads': len(ambiguous), 'providers': names, 'provider_approved': False})
    indexes, failures, proofs, byte_total = {}, [], {}, 0
    for name in names:
        archive = providers[name]
        path = Path(archive['path'])
        try:
            require(inventory.sha(path) == archive['sha256'], 'Indexed provider differs from recorded archive')
            code, text = runner.command('static-index-' + name, [tools['dumpbin'], '/nologo', '/linkermember', path],
                                        env, 45, required=False)
            require(len(text.encode('utf-8')) <= 8 * 1024 ** 2, 'Native archive-index output cap')
            for line in text.splitlines():
                recorder.emit('STATIC_INDEX_NATIVE_LINE', {'provider': name, 'text': line})
            recorder.emit('STATIC_INDEX_NATIVE_CAPTURE', {'provider': name, 'exit': code,
                          'text_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
                          'text_bytes': len(text.encode('utf-8')), 'provider_approved': False,
                          'raw_index_status': 'not-yet-evaluated'})
            require(code == 0, 'Native archive-index reader failed')
            index = index_reader.read_archive_index(path, objects[name], runner.guard)
            require(index['metadata']['archive_sha256'] == archive['sha256'], 'Index/archive identity mismatch')
            recorder.emit('STATIC_ARCHIVE_INDEX', {'provider': name, **index['metadata'], 'provider_approved': False})
            native = verify_dumpbin(text, index)
            recorder.emit('STATIC_INDEX_NATIVE_MATCH', {'provider': name, **native})
            indexes[name] = index
        except (ValueError, OSError, UnicodeError, struct.error) as exc:
            failure = {'provider': name, 'stage': 'index', 'reason': str(exc)}
            failures.append(failure)
            recorder.emit('STATIC_SELECTION_FAILURE', failure)
    for entry, rows in ambiguous:
        name = entry['provider']
        if name not in indexes:
            continue
        try:
            candidate_records = []
            for row in rows:
                byte_total += row['size']
                require(byte_total <= MAX_CANDIDATE_BYTES, 'Aggregate candidate-byte cap')
                metadata = candidate_metadata(Path(providers[name]['path']), row, entry['found_symbol'], runner.guard)
                recorder.emit('STATIC_CANDIDATE_METADATA', {'provider': name, 'load_id': entry['load_id'], **metadata})
                candidate_records.append(metadata)
            proof = bind(entry, rows, providers[name], indexes[name], candidate_records)
            validate_binding(proof, entry, rows, providers[name])
            recorder.emit('STATIC_SELECTION_PROOF', proof)
            proofs[entry['load_id']] = proof
        except (ValueError, OSError, UnicodeError, struct.error) as exc:
            failure = {'provider': name, 'load_id': entry['load_id'], 'stage': 'candidate', 'reason': str(exc)}
            failures.append(failure)
            recorder.emit('STATIC_SELECTION_FAILURE', failure)
    for name in names:
        require(inventory.sha(providers[name]['path']) == providers[name]['sha256'], 'Provider changed during index/candidate proof')
    recorder.emit('STATIC_SELECTION_SUMMARY', {'ambiguous_loads': len(ambiguous), 'resolved_loads': len(proofs),
                  'failures': failures, 'candidate_bytes_read': byte_total, 'provider_approved': False})
    require(not failures and len(proofs) == len(ambiguous), 'Incomplete/conflicting static archive selection proof')
    return proofs
