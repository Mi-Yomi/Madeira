#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real trace/native-reader regressions and explicitly reconstructed index proofs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/llvm_sdk'
FIXTURES = ROOT / 'tests/host/fixtures/llvm-archive-index'
sys.path.insert(0, str(SOURCE))
import dia_link as d
import archive_symbol_index as idx
import static_member_proof as proof
from native_index_evidence import verify_dumpbin
spec = importlib.util.spec_from_file_location('index_test_helpers', ROOT / 'tests/host/check-llvm-archive-index.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def source_owned_object(symbol, *, comdat=True):
    """Inert reconstruction with one code section and one strong public symbol."""
    raw = bytearray(64)
    struct.pack_into('<HHIIIHH', raw, 0, 0x8664, 1, 0, 64, 3, 0, 0)
    raw[20:28] = b'.text\0\0\0'
    struct.pack_into('<II', raw, 36, 4, 60)
    struct.pack_into('<I', raw, 56, 0x60501020 if comdat else 0x60500020)
    raw[60:64] = b'\x90\x90\x90\xc3'
    raw += b'.text\0\0\0' + struct.pack('<IhHBB', 0, 1, 0, 3, 1)
    raw += struct.pack('<IHHIHBBH', 4, 0, 0, 0, 0, 2 if comdat else 0, 0, 0)
    raw += struct.pack('<IIIhHBB', 0, 4, 0, 1, 0x20, 2, 0)
    strings = symbol.encode() + b'\0'
    return bytes(raw) + struct.pack('<I', len(strings) + 4) + strings


def native_text(index):
    """Synthetic native-reader format witness, not an executed dumpbin result."""
    lines = []
    offsets = sorted(index['members_by_header_offset'])
    for which in ['first', 'second']:
        meta = index['metadata'][which + '_linker_member']
        lines += [f'Archive member name at {meta["archive_header_offset"]:X}: /',
                  f'{meta["size"]:X} size', 'correct header end', '']
        if which == 'second':
            lines += [str(len(offsets)) + ' offsets', '']
            lines += [f'{i} {offset:X}' for i, offset in enumerate(offsets, 1)]
        lines += ['', str(meta['symbol_count']) + ' public symbols', '']
        for name, offset in index['symbol_entries'][which]:
            label = f'{offset:X}' if which == 'first' else str(offsets.index(offset) + 1)
            lines.append(label + ' ' + name)
        lines.append('')
    return '\n'.join(lines) + '\n'


class StaticSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'reconstructed.lib'
        fixture = {'objects': [
            {'member': 'source/mt/shared.obj', 'payload_hex': source_owned_object('_handle_nan').hex()},
            {'member': 'source/mt_fma/shared.obj', 'payload_hex': source_owned_object('_handle_nan_fma').hex()}],
            'symbols': [{'name': '_handle_nan', 'object': 0}, {'name': '_handle_nan_fma', 'object': 1}]}
        data, _, _ = helpers.reconstruct(fixture)
        self.path.write_bytes(data)
        self.rows = []
        self.archive = d.inv.scan_library(self.path, self.rows.append)
        self.archive.update(path=str(self.path), role={'kind': 'static_code'})
        self.index = idx.read_archive_index(self.path, self.rows)
        self.entry = {'load_id': 7, 'provider': 'fixture', 'member': 'shared.obj', 'found_symbol': '_handle_nan',
                      'raw_found': '_handle_nan', 'referenced_in': ['source.obj']}
        self.metadata = [proof.candidate_metadata(self.path, row, '_handle_nan') for row in self.rows]
        self.binding = proof.bind(self.entry, self.rows, self.archive, self.index, self.metadata)

    def test_exact_index_and_actual_strong_definition_bind_offset(self):
        selected = proof.validate_binding(self.binding, self.entry, self.rows, self.archive)
        self.assertEqual(selected, self.rows[0])
        self.assertEqual(self.binding['sha256'], self.metadata[0]['sha256'])
        self.assertEqual(self.binding['trigger_symbol_records'][0]['storage_class'], 2)
        self.assertEqual(self.binding['trigger_sections'][0]['section_definition']['section_definition']['selection'], 2)
        self.assertNotIn('raw_prefix_hex', repr(self.metadata))
        self.assertNotIn('payload_hex', repr(self.metadata))
        self.assertTrue(all(row['vendor_object_bytes_emitted'] is False for row in self.metadata))
        self.assertEqual(self.metadata[1]['trigger_symbol_records'], [])

    def test_missing_duplicate_and_wrong_owner_indices_reject(self):
        for owners in [[], [self.rows[0]['archive_header_offset'], self.rows[1]['archive_header_offset']],
                       [self.rows[1]['archive_header_offset']]]:
            index = copy.deepcopy(self.index)
            if not owners:
                index['symbol_to_header_offsets'].pop('_handle_nan')
            else:
                index['symbol_to_header_offsets']['_handle_nan'] = owners
            with self.subTest(owners=owners), self.assertRaises(ValueError):
                proof.bind(self.entry, self.rows, self.archive, index, self.metadata)

    def test_context_offset_definition_and_directive_disagreements_reject(self):
        mutations = [('archive_sha256', '0' * 64), ('load_id', 8), ('found_symbol', 'other'),
                     ('member', 'other.obj'), ('machine', '0x014c'), ('size', 999),
                     ('second_index_offsets', [self.rows[1]['archive_header_offset']]),
                     ('candidate_header_offsets', []), ('default_libraries', ['msvcrt'])]
        for field, value in mutations:
            bad = copy.deepcopy(self.binding)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                proof.validate_binding(bad, self.entry, self.rows, self.archive)
        for field, value in [('section', 0), ('storage_class', 105), ('auxiliary_count', 1), ('definition', 'common')]:
            bad = copy.deepcopy(self.binding)
            bad['trigger_symbol_records'][0][field] = value
            with self.subTest(symbol_field=field), self.assertRaises(ValueError):
                proof.validate_binding(bad, self.entry, self.rows, self.archive)
        bad = copy.deepcopy(self.binding)
        bad['trigger_symbol_records'] *= 2
        with self.assertRaises(ValueError):
            proof.validate_binding(bad, self.entry, self.rows, self.archive)
        for field, value in [('index', 2), ('comdat', False), ('name', '.other')]:
            bad = copy.deepcopy(self.binding)
            bad['trigger_sections'][0]['section'][field] = value
            with self.subTest(section_field=field), self.assertRaises(ValueError):
                proof.validate_binding(bad, self.entry, self.rows, self.archive)

    def test_bare_member_never_hides_same_basename_full_path(self):
        rows = [dict(self.rows[0], member='shared.obj'), dict(self.rows[1])]
        self.assertEqual(len(proof.candidates(rows, 'shared.obj')), 2)
        with self.assertRaises(ValueError):
            d.select_member(rows, 'shared.obj')
        self.assertEqual(d.select_member(rows, self.rows[1]['member']), rows[1])

    def test_found_context_cannot_cross_verified_archives(self):
        providers = {'a': {'path': 'C:\\sdk\\a.lib', 'role': {'kind': 'static_code'}},
                     'b': {'path': 'C:\\sdk\\b.lib', 'role': {'kind': 'static_code'}}}
        trace = 'Searching C:\\sdk\\a.lib:\nSearching C:\\sdk\\b.lib:\nFound foo\nLoaded C:\\sdk\\a.lib(shared.obj)\n'
        with self.assertRaisesRegex(ValueError, 'Found symbol context'):
            d.parse_link_selection(trace, providers)

    def test_native_index_entry_multisets_and_negative_evidence(self):
        text = native_text(self.index)
        result = verify_dumpbin(text, self.index)
        self.assertTrue(result['both_index_entry_multisets_match'])
        for changed in [text.replace('_handle_nan_fma', 'wrong'), text.replace('2 offsets', '3 offsets'),
                        text.replace('2 public symbols', '1 public symbols'), text[:-15],
                        text.replace(' 2 ', ' 0 ') + 'unexpected-symbol\n']:
            with self.subTest(text=changed[-50:]), self.assertRaises(ValueError):
                verify_dumpbin(changed, self.index)

    def test_actual_native_dumpbin_evidence(self):
        provenance = json.loads((FIXTURES / 'captured-dia-linkermember.json').read_text())
        text = (FIXTURES / 'captured-dia-linkermember.log').read_text()
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), provenance['text_sha256'])
        index = provenance['expected_index']
        index['members_by_header_offset'] = {int(k): v for k, v in index['members_by_header_offset'].items()}
        result = verify_dumpbin(text, index)
        self.assertEqual((result['first_entry_count'], result['second_entry_count']), (99, 99))
        bad = text.replace('21C5D2 ?NoRegCoCreate', '22C272 ?NoRegCoCreate')
        with self.assertRaises(ValueError):
            verify_dumpbin(bad, index)

    def test_actual_full_trace_all_loads_and_unresolved_static_ambiguity(self):
        fixture = json.loads((FIXTURES / 'captured-full-verbose-selection.json').read_text())
        text = '\n'.join(row['text'] for row in fixture['events']) + '\n'
        loaded = d.parse_link_selection(text, fixture['providers'])
        self.assertEqual(len(loaded), 320)
        static = [x for x in loaded if fixture['providers'][x['provider']]['role']['kind'] != 'os_import']
        self.assertEqual(len(static), 225)
        ambiguous = [(x, proof.candidates(fixture['objects'][x['provider']], x['member'])) for x in static]
        ambiguous = [(x, rows) for x, rows in ambiguous if len(rows) > 1]
        self.assertEqual(len(ambiguous), 1)
        entry, rows = ambiguous[0]
        self.assertEqual((entry['load_id'], entry['found_symbol'], entry['referenced_in']),
                         (206, '_handle_nan', ['libucrt.lib(ceil.obj)']))
        self.assertEqual([x['archive_header_offset'] for x in rows], [41071970, 42511290])
        with self.assertRaises(ValueError):
            d.select_member(rows, 'libm_error.obj')
        self.assertEqual(loaded[0]['found_symbol'], '?NoRegCoCreate@@YAJPEB_WAEBU_GUID@@1PEAPEAX@Z')
        self.assertEqual(sum(x['found_symbol'].startswith('\x7f') for x in loaded), 2)
        for bad in ['\x7fKERNEL32_NULL_THUNK_DATA', '"unterminated', 'two words', 'a(b)', '']:
            with self.subTest(symbol=bad), self.assertRaises(ValueError):
                proof.found_symbol(bad)
        self.assertEqual(proof.found_symbol('\x7fKERNEL32_NULL_THUNK_DATA', True), '\x7fKERNEL32_NULL_THUNK_DATA')
        without_found = text.replace('      Found _handle_nan\n', '')
        with self.assertRaises(ValueError):
            d.parse_link_selection(without_found, fixture['providers'])

    def test_collect_processes_all_ambiguous_loads_and_preserves_failures(self):
        records = []
        recorder = types.SimpleNamespace(emit=lambda kind, value: records.append((kind, value)))
        runner = types.SimpleNamespace(guard=lambda: None,
            command=lambda *args, **kwargs: (0, native_text(self.index)))
        entries = [dict(self.entry), dict(self.entry, load_id=8, found_symbol='missing', raw_found='missing')]
        with self.assertRaisesRegex(ValueError, 'Incomplete/conflicting'):
            proof.collect(entries, {'fixture': self.archive}, {'fixture': self.rows}, runner,
                          {'dumpbin': 'never-executed'}, {}, recorder)
        summary = [value for kind, value in records if kind == 'STATIC_SELECTION_SUMMARY'][0]
        self.assertEqual((summary['ambiguous_loads'], summary['resolved_loads'], len(summary['failures'])), (2, 1, 1))
        self.assertEqual(summary['failures'][0]['load_id'], 8)
        self.assertEqual(sum(kind == 'STATIC_CANDIDATE_METADATA' for kind, _ in records), 4)
        self.assertTrue(any(kind == 'STATIC_SELECTION_PROOF' for kind, _ in records))

    def test_candidate_inventory_mismatch_and_caps(self):
        for change in [{'size': 19}, {'size': proof.member.MAX_OBJECT + 1}, {'archive_header_offset': 9},
                       {'machine': '0x014c'}, {'section_count': 999}, {'default_libraries': ['msvcrt']}]:
            bad = dict(self.rows[0], **change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                proof.candidate_metadata(self.path, bad, '_handle_nan')

    def test_raw_parser_rejection_retains_native_metadata_and_no_proof(self):
        records, calls = [], []
        text = native_text(self.index)
        recorder = types.SimpleNamespace(emit=lambda kind, value: records.append((kind, value)))
        def command(*args, **kwargs):
            calls.append('native')
            return 0, text
        def raw_reader(*args, **kwargs):
            calls.append('raw')
            self.assertTrue(any(kind == 'STATIC_INDEX_NATIVE_LINE' for kind, _ in records))
            self.assertTrue(any(kind == 'STATIC_INDEX_NATIVE_CAPTURE' for kind, _ in records))
            raise ValueError('reconstructed unsupported longnames padding')
        runner = types.SimpleNamespace(guard=lambda: None, command=command)
        with patch.object(proof.index_reader, 'read_archive_index', side_effect=raw_reader):
            with self.assertRaisesRegex(ValueError, 'Incomplete/conflicting'):
                proof.collect([self.entry], {'fixture': self.archive}, {'fixture': self.rows}, runner,
                              {'dumpbin': 'never-executed'}, {}, recorder)
        self.assertEqual(calls, ['native', 'raw'])
        captured = next(value for kind, value in records if kind == 'STATIC_INDEX_NATIVE_CAPTURE')
        self.assertEqual(captured['text_sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(captured['raw_index_status'], 'not-yet-evaluated')
        self.assertFalse(captured['provider_approved'])
        self.assertFalse(any(kind in {'STATIC_INDEX_NATIVE_MATCH', 'STATIC_SELECTION_PROOF'} for kind, _ in records))
        summary = next(value for kind, value in records if kind == 'STATIC_SELECTION_SUMMARY')
        self.assertEqual(summary['resolved_loads'], 0)
        self.assertIn('unsupported longnames padding', summary['failures'][0]['reason'])
        self.assertFalse(summary['provider_approved'])

    def test_hash_rejection_precedes_native_capture(self):
        archive = dict(self.archive, sha256='0' * 64)
        calls, records = [], []
        runner = types.SimpleNamespace(guard=lambda: None, command=lambda *args, **kwargs: calls.append(args))
        recorder = types.SimpleNamespace(emit=lambda kind, value: records.append((kind, value)))
        with self.assertRaises(ValueError):
            proof.collect([self.entry], {'fixture': archive}, {'fixture': self.rows}, runner,
                          {'dumpbin': 'never-executed'}, {}, recorder)
        self.assertEqual(calls, [])
        self.assertFalse(any(kind == 'STATIC_INDEX_NATIVE_CAPTURE' for kind, _ in records))


if __name__ == '__main__':
    unittest.main()
