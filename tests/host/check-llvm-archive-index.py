#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert, reconstructed COFF archive-index controls; no native tools or builds."""
import argparse
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/llvm_sdk'
FIXTURES = Path(__file__).parent / 'fixtures/llvm-archive-index'
spec = importlib.util.spec_from_file_location('archive_symbol_index', SOURCE / 'archive_symbol_index.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
FIXTURE = json.loads((FIXTURES / 'reconstructed-index.json').read_text())
WINDOWS_CAPTURE_HASHES = ('e03920fe0a78395eff81319bdf95450794ece2f2ceedd20e7383ab13f4292222',
                          'd73e3803c9f380784485d4a81cbca410d1c3bdfc51fe96c14e8a9007659af1e6')


@contextmanager
def captured_windows_runtime(*, os_name='nt', platform='win32', implementation='cpython',
                             version=(3, 12, 10, 'final', 0), platform_version=(10, 0, 26100)):
    """Reconstructed runtime interface used only around the pure comparison."""
    class WindowsVersion(tuple):
        pass

    windows = WindowsVersion((10, 0, 26100, 2, ''))
    windows.platform_version = platform_version
    with ExitStack() as stack:
        stack.enter_context(patch.object(reader.os, 'name', os_name))
        stack.enter_context(patch.object(reader.sys, 'platform', platform))
        stack.enter_context(patch.object(reader.sys.implementation, 'name', implementation))
        stack.enter_context(patch.object(reader.sys, 'version_info', version))
        stack.enter_context(patch.object(reader.sys, 'getwindowsversion', return_value=windows, create=True))
        yield


def member(name, payload):
    header = (name.encode('ascii').ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) +
              b'0'.ljust(6) + b'644'.ljust(8) + str(len(payload)).encode('ascii').ljust(10) + b'`\n')
    assert len(header) == 60
    return header + payload + (b'\n' if len(payload) & 1 else b'')


def reconstruct(fixture=None, *, first_symbols=None, second_symbols=None, inside_pad=True,
                short_names=False, longnames_tail=None, first_tail=None, second_tail=None):
    """Build source-owned bytes without calling any production parser helper."""
    fixture = copy.deepcopy(fixture or FIXTURE)
    first = sorted(first_symbols if first_symbols is not None else fixture['symbols'], key=lambda row: row['object'])
    second = sorted(second_symbols if second_symbols is not None else fixture['symbols'], key=lambda row: row['name'])
    objects = fixture['objects']
    longnames, names = b'', []
    for ordinal, row in enumerate(objects):
        names.append((row['member'] + '/') if short_names else '/' + str(len(longnames)))
        longnames += row['member'].encode('ascii') + b'\0'
    if longnames_tail is None:
        longnames += b'\n' if inside_pad and len(longnames) & 1 else b''
    else:
        longnames += longnames_tail

    def payloads(offsets):
        left = struct.pack('>I', len(first)) + b''.join(struct.pack('>I', offsets[row['object']]) for row in first)
        left += b''.join(row['name'].encode('ascii') + b'\0' for row in first)
        right = struct.pack('<I', len(objects)) + b''.join(struct.pack('<I', value) for value in offsets)
        right += struct.pack('<I', len(second)) + b''.join(struct.pack('<H', row['object'] + 1) for row in second)
        right += b''.join(row['name'].encode('ascii') + b'\0' for row in second)
        left += first_tail if first_tail is not None else (b'\0' if inside_pad and len(left) & 1 else b'')
        right += second_tail if second_tail is not None else (b'\0' if inside_pad and len(right) & 1 else b'')
        return left, right

    left, right = payloads([0] * len(objects))
    prefix = b'!<arch>\n' + member('/', left) + member('/', right)
    if not short_names:
        prefix += member('//', longnames)
    offset, offsets, inventory, bodies = len(prefix), [], [], []
    for name, row in zip(names, objects):
        payload = bytes.fromhex(row['payload_hex'])
        offsets.append(offset)
        inventory.append({'member': row['member'], 'archive_header_offset': offset, 'size': len(payload)})
        body = member(name, payload)
        bodies.append(body)
        offset += len(body)
    left, right = payloads(offsets)
    data = b'!<arch>\n' + member('/', left) + member('/', right)
    if not short_names:
        data += member('//', longnames)
    positions = {'first': 8, 'second': 8 + len(member('/', left)),
                 'longnames': 8 + len(member('/', left)) + len(member('/', right)),
                 'first_strings': 8 + 60 + 4 + 4 * len(first),
                 'second_indices': 8 + len(member('/', left)) + 60 + 8 + 4 * len(objects),
                 'second_strings': 8 + len(member('/', left)) + 60 + 8 + 4 * len(objects) + 2 * len(second),
                 'first_size': len(left), 'second_size': len(right), 'longnames_size': len(longnames)}
    return data + b''.join(bodies), inventory, positions


class ArchiveIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'reconstructed.lib'
        self.data, self.inventory, self.positions = reconstruct()

    def read(self, data=None, inventory=None):
        self.path.write_bytes(self.data if data is None else data)
        return reader.read_archive_index(self.path, self.inventory if inventory is None else inventory)

    def rejects(self, data, message=None, inventory=None):
        with self.assertRaisesRegex(ValueError, message or '.'):
            self.read(data, inventory)

    def mutate(self, offset, content):
        data = bytearray(self.data)
        data[offset:offset + len(content)] = content
        return bytes(data)

    def test_unique_trigger_resolves_duplicate_basename_exactly(self):
        result = self.read()
        selected = reader.resolve_symbols(result, ['alpha', 'zeta', 'gamma', 'alpha'])
        self.assertEqual(selected['alpha'], self.inventory[1])
        self.assertEqual(selected['zeta'], self.inventory[0])
        self.assertEqual(selected['gamma'], self.inventory[2])
        self.assertEqual(len(selected), 3)
        metadata = result['metadata']
        self.assertEqual(metadata['archive_sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual((metadata['symbol_count'], metadata['member_count']), (4, 3))
        for name in ['first', 'second']:
            row = metadata[name + '_linker_member']
            payload = self.data[row['archive_header_offset'] + 60:row['archive_header_offset'] + 60 + row['size']]
            self.assertEqual(row['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(row['alignment_padding_bytes'], 1)
        self.assertEqual(len(result['symbol_entries']['first']), 4)
        self.assertEqual(metadata['longnames_member']['alignment_padding_bytes'], 1)
        self.assertTrue(metadata['index_agreement'] and metadata['inventory_cross_checked'])
        self.assertNotIn('payload', repr(result))

    def test_missing_and_wrong_case_trigger_rejected(self):
        index = self.read()
        for symbols in [['missing'], ['Alpha'], ['alpha', 'missing'], 'alpha']:
            with self.subTest(symbols=symbols), self.assertRaises(ValueError):
                reader.resolve_symbols(index, symbols)

    def test_inert_negative_one_date_sentinel_does_not_change_bounds(self):
        data = bytearray(self.data)
        for offset in [self.positions['first'], self.positions['second']]:
            data[offset + 16:offset + 28] = b'-1'.ljust(12)
        result = self.read(bytes(data))
        self.assertEqual(result['metadata']['first_linker_member']['date'], -1)
        self.assertEqual(result['metadata']['second_linker_member']['date_ascii'], '-1          ')
        self.assertEqual(reader.resolve_symbols(result, ['alpha'])['alpha'], self.inventory[1])
        for offset, width, value in [(8 + 16, 12, b'-2'), (8 + 16, 12, b'+1'),
                                      (8 + 28, 6, b'-1'), (8 + 48, 10, b'-1')]:
            bad = bytearray(self.data)
            bad[offset:offset + width] = value.ljust(width)
            self.rejects(bytes(bad))

    def test_rejected_padding_reports_only_bounded_directory_metadata(self):
        data, inventory, _ = reconstruct(first_tail=b'X' * 2048)
        with self.assertRaises(ValueError) as caught:
            self.read(data, inventory)
        text = str(caught.exception)
        self.assertIn('payload_offset=', text)
        self.assertIn('remaining_length=2048', text)
        self.assertIn('prefix_hex=' + '58' * 16, text)
        self.assertNotIn('58' * 17, text)
        self.assertLess(len(text), 300)
        data, inventory, _ = reconstruct(longnames_tail=b'\0')
        with self.assertRaises(ValueError) as caught:
            self.read(data, inventory)
        self.assertIn('longnames_header_offset=', str(caught.exception))
        self.assertIn('payload_offset=', str(caught.exception))

    def test_duplicate_symbols_preserve_entries_and_reject_only_ambiguous_trigger(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture['symbols'] += [{'name': 'duplicate', 'object': 0}, {'name': 'duplicate', 'object': 1}]
        data, inventory, _ = reconstruct(fixture)
        result = self.read(data, inventory)
        self.assertEqual(len(result['symbol_entries']['first']), 6)
        self.assertEqual(len(result['symbol_entries']['second']), 6)
        self.assertEqual(result['symbol_to_header_offsets']['duplicate'], [row['archive_header_offset'] for row in inventory[:2]])
        with self.assertRaisesRegex(ValueError, 'multiple candidate'):
            reader.resolve_symbols(result, ['duplicate'])
        self.assertEqual(reader.resolve_symbols(result, ['alpha'])['alpha'], inventory[1])

    def test_repeated_same_owner_and_multiplicity_are_preserved(self):
        first = FIXTURE['symbols'] + [FIXTURE['symbols'][1]]
        data, inventory, _ = reconstruct(first_symbols=first)
        result = self.read(data, inventory)
        self.assertEqual(len(result['symbol_entries']['first']), 5)
        self.assertEqual(len(result['symbol_entries']['second']), 4)
        self.assertFalse(result['metadata']['entry_multiplicity_agreement'])
        self.assertEqual(reader.resolve_symbols(result, ['alpha'])['alpha'], inventory[1])

    def test_duplicate_full_member_names_use_offsets(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture['objects'][1]['member'] = fixture['objects'][0]['member']
        data, inventory, _ = reconstruct(fixture)
        selected = reader.resolve_symbols(self.read(data, inventory), ['zeta', 'alpha'])
        self.assertEqual(selected['zeta']['member'], selected['alpha']['member'])
        self.assertNotEqual(selected['zeta']['archive_header_offset'], selected['alpha']['archive_header_offset'])

    def test_import_control_prefix_is_outside_static_proof_scope(self):
        fixture = copy.deepcopy(FIXTURE)
        for name in ['\x7fFixture_NULL_THUNK_DATA', '\x7fOther', 'prefix\x7fFixture_NULL_THUNK_DATA']:
            fixture['symbols'][0]['name'] = name
            data, inventory, _ = reconstruct(fixture)
            self.rejects(data, inventory=inventory)

    def test_both_indices_must_agree_on_all_owners(self):
        second = copy.deepcopy(FIXTURE['symbols'])
        second[1]['object'] = 0
        data, inventory, _ = reconstruct(second_symbols=second)
        self.rejects(data, 'disagree', inventory)
        second[1]['name'] = 'alien'
        data, inventory, _ = reconstruct(second_symbols=second)
        self.rejects(data, 'disagree', inventory)

    def test_bad_offsets_order_indices_and_counts(self):
        first = self.positions['first'] + 60
        second = self.positions['second'] + 60
        indices = self.positions['second_indices']
        cases = [(first + 4, '>I', 8), (first + 4, '>I', self.inventory[0]['archive_header_offset'] + 60),
                 (first + 4, '>I', self.inventory[2]['archive_header_offset']),
                 (second + 4, '<I', 8), (second + 4, '<I', self.inventory[0]['archive_header_offset'] + 1),
                 (second + 8, '<I', self.inventory[0]['archive_header_offset']),
                 (indices, '<H', 0), (indices, '<H', len(self.inventory) + 1),
                 (first, '>I', reader.MAX_SYMBOLS + 1), (second, '<I', reader.MAX_MEMBERS + 1),
                 (second + 4 + 4 * len(self.inventory), '<I', reader.MAX_SYMBOLS + 1)]
        for offset, fmt, value in cases:
            with self.subTest(offset=offset, value=value):
                self.rejects(self.mutate(offset, struct.pack(fmt, value)))

    def test_truncated_and_invalid_strings(self):
        for cut in [0, 7, 8, 60, len(self.data) - 1]:
            with self.subTest(cut=cut):
                self.rejects(self.data[:cut])
        self.rejects(self.mutate(self.positions['first_strings'], b'\0'), 'symbol')
        self.rejects(self.mutate(self.positions['first_strings'], b'\xff'), 'symbol')
        self.rejects(self.mutate(self.positions['first_strings'], b'\n'), 'symbol')
        self.rejects(self.mutate(self.positions['second_strings'], b'zzzzz'), 'lexical')
        for first_tail, second_tail in [(b'X', None), (b'\0\0', None), (None, b'\n')]:
            data, inventory, _ = reconstruct(first_tail=first_tail, second_tail=second_tail)
            self.rejects(data, 'padding', inventory)
        data, inventory, positions = reconstruct(inside_pad=False)
        end = positions['first'] + 60 + positions['first_size']
        malformed = bytearray(data)
        malformed[end - 1] = ord('x')
        self.rejects(bytes(malformed), 'Unterminated', inventory)

    def test_padding_only_when_justified(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture['symbols'][2]['name'] = 'beta'  # even consumed index size
        for kwargs in [{'first_tail': b'\0'}, {'second_tail': b'\0'}]:
            data, inventory, _ = reconstruct(fixture, **kwargs)
            self.rejects(data, 'padding', inventory)
        data, inventory, _ = reconstruct(inside_pad=False)
        result = self.read(data, inventory)
        self.assertEqual(result['metadata']['first_linker_member']['alignment_padding_bytes'], 0)
        odd_object = self.inventory[1]
        pad = odd_object['archive_header_offset'] + 60 + odd_object['size']
        self.rejects(self.mutate(pad, b'\0'), 'alignment')

    def test_headers_and_longnames(self):
        first_object = self.inventory[0]['archive_header_offset']
        for offset, value in [(0, b'!<thin>\n'), (8, b'//'), (8 + 58, b'xx'),
                              (8 + 48, b'-'), (8 + 16, b'Q'), (8 + 40, b'8'),
                              (self.positions['longnames'], b'/ '), (first_object, b'/1 '),
                              (first_object, b'// '), (first_object, b'/  '),
                              (first_object, b'/99999 '), (first_object, b'#1/20 '),
                              (first_object + 48, b'9999999999')]:
            with self.subTest(offset=offset, value=value):
                self.rejects(self.mutate(offset, value))
        long_start = self.positions['longnames'] + 60
        self.rejects(self.mutate(long_start, b'\0'), 'long name')
        for tail in [b'X', b'\0', b'\n\n']:
            data, inventory, _ = reconstruct(longnames_tail=tail)
            self.rejects(data, inventory=inventory)
        fixture = copy.deepcopy(FIXTURE)
        fixture['objects'][0]['member'] += 'x'  # no alignment byte is justified
        data, inventory, _ = reconstruct(fixture, longnames_tail=b'\n')
        self.rejects(data, inventory=inventory)
        data, inventory, positions = reconstruct(longnames_tail=b'')
        end = positions['longnames'] + 60 + positions['longnames_size']
        invalid = bytearray(data)
        invalid[end - 1] = ord('x')
        self.rejects(bytes(invalid), 'long name', inventory)

    def test_short_names_without_longnames_table(self):
        fixture = copy.deepcopy(FIXTURE)
        for ordinal, row in enumerate(fixture['objects']):
            row['member'] = f'object{ordinal}.obj'
        data, inventory, _ = reconstruct(fixture, short_names=True)
        self.assertIsNone(self.read(data, inventory)['metadata']['longnames_member'])

    def test_inventory_must_cover_exact_physical_objects(self):
        for rows in [[], self.inventory[:-1], self.inventory + [self.inventory[0]],
                     [dict(row, size=row['size'] + 1) for row in self.inventory],
                     [dict(row, member='shared.obj') for row in self.inventory],
                     [dict(row, archive_header_offset=True) for row in self.inventory]]:
            with self.subTest(rows=rows):
                self.rejects(self.data, 'inventory', rows)
        self.path.write_bytes(self.data)
        with self.assertRaisesRegex(ValueError, 'inventory required'):
            reader.read_archive_index(self.path, None)

    def test_payload_name_and_object_resource_caps(self):
        for key, cap in [('MAX_ARCHIVE', len(self.data) - 1), ('MAX_INDEX', 8),
                         ('MAX_LONGNAMES', 8), ('MAX_MEMBERS', 2), ('MAX_SYMBOLS', 3),
                         ('MAX_SYMBOL_BYTES', 2), ('MAX_MEMBER_NAME_BYTES', 2)]:
            with self.subTest(key=key), patch.object(reader, key, cap):
                self.rejects(self.data)
        self.path.write_bytes(self.data)
        with self.path.open('r+b') as stream:
            stream.truncate(reader.MAX_ARCHIVE + 1)  # sparse: no huge fixture allocation
        with self.assertRaisesRegex(ValueError, 'oversized'):
            reader.read_archive_index(self.path, self.inventory)

    def test_archive_mutation_and_guard_propagate(self):
        self.path.write_bytes(self.data)
        fixed_metadata = self.path.stat()
        original_hash, calls = reader._hash, []

        def changed_hash(stream, size, guard):
            calls.append(True)
            if len(calls) == 2:
                with self.path.open('r+b') as out:
                    out.seek(self.inventory[0]['archive_header_offset'] + 60)
                    out.write(b'X')
            return original_hash(stream, size, guard)

        with patch.object(reader, '_hash', changed_hash), \
                patch.object(reader.Path, 'stat', return_value=fixed_metadata), \
                patch.object(reader.os, 'fstat', return_value=fixed_metadata), \
                self.assertRaisesRegex(ValueError, '^Archive changed during index reading$'):
            reader.read_archive_index(self.path, self.inventory)
        self.path.write_bytes(self.data)
        with self.assertRaisesRegex(RuntimeError, 'budget'):
            reader.read_archive_index(self.path, self.inventory, lambda: (_ for _ in ()).throw(RuntimeError('budget')))

    def identity_snapshots(self):
        # Reconstructed API observations, not captured Windows stat results.
        base = dict(st_dev=2**63 + 17, st_ino=2**127 + 23, st_size=len(self.data),
                    st_mtime_ns=2**60 + 100200300, st_ctime_ns=2**60 + 100100100,
                    st_mode=0o100644, st_nlink=1, st_atime_ns=2**60 + 100300400,
                    st_birthtime_ns=2**60 + 100100100, st_file_attributes=32, st_reparse_tag=0)
        return [dict(base) for _ in range(4)]

    def read_with_identity_snapshots(self, snapshots):
        self.path.write_bytes(self.data)
        values = [types.SimpleNamespace(**row) for row in snapshots]
        with patch.object(reader, '_windows_identity_profile', return_value=None), \
                patch.object(reader.Path, 'stat', side_effect=[values[0], values[3]]), \
                patch.object(reader.os, 'fstat', side_effect=values[1:3]):
            return reader.read_archive_index(self.path, self.inventory)

    def captured_identity_failure(self, snapshots):
        with self.assertRaisesRegex(ValueError, 'Archive identity changed') as caught:
            self.read_with_identity_snapshots(snapshots)
        text = str(caught.exception)
        self.assertLessEqual(len(text.encode('ascii')), reader.MAX_IDENTITY_EVIDENCE)
        encoded = text.split('ARCHIVE_IDENTITY_EVIDENCE=', 1)[1]
        return json.loads(encoded)

    def test_every_identity_field_still_rejects_and_records_exact_observations(self):
        expected_fields = ['st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns']
        for field in expected_fields:
            with self.subTest(field=field):
                snapshots = self.identity_snapshots()
                snapshots[2][field] += 1
                evidence = self.captured_identity_failure(snapshots)
                diagnostic_fields = list(reader.WINDOWS_IDENTITY_FIELDS) if reader.os.name == 'nt' or reader.sys.platform == 'win32' else expected_fields
                self.assertEqual(evidence['identity_fields'], diagnostic_fields)
                labels = ['initial_path_stat', 'before_handle_fstat', 'after_handle_fstat', 'current_path_stat']
                expected = {label: {key: str(value) for key, value in row.items()}
                            for label, row in zip(labels, snapshots)}
                self.assertEqual(evidence['snapshots'], expected)
                self.assertEqual(evidence['stat_scalar_encoding'], 'decimal-string-or-null')
                differences = {(row['left'], row['right']): row['fields']
                               for row in evidence['identity_differences']}
                self.assertEqual(len(differences), 6)
                self.assertEqual(differences[('before_handle_fstat', 'after_handle_fstat')], [field])
                self.assertEqual(differences[('initial_path_stat', 'current_path_stat')], [])
                self.assertFalse(evidence['provider_approved'])
                self.assertEqual(evidence['sha256_before'], hashlib.sha256(self.data).hexdigest())
                self.assertEqual(evidence['sha256_before'], evidence['sha256_after'])
                self.assertTrue(evidence['runtime']['python'])
                self.assertNotIn('payload', evidence)

    def test_cross_api_ctime_pattern_is_evidence_not_an_exception_to_gate(self):
        snapshots = self.identity_snapshots()
        snapshots[1]['st_ctime_ns'] += 100
        snapshots[2]['st_ctime_ns'] += 100
        evidence = self.captured_identity_failure(snapshots)
        differences = {(row['left'], row['right']): row['fields']
                       for row in evidence['identity_differences']}
        self.assertEqual(differences[('initial_path_stat', 'before_handle_fstat')], ['st_ctime_ns'])
        self.assertEqual(differences[('before_handle_fstat', 'after_handle_fstat')], [])
        self.assertEqual(differences[('initial_path_stat', 'current_path_stat')], [])
        for ordinal in range(4):
            with self.subTest(observation=ordinal):
                snapshots = self.identity_snapshots()
                snapshots[ordinal]['st_ctime_ns'] += 1
                self.captured_identity_failure(snapshots)

    def test_diagnostic_only_fields_do_not_expand_identity_gate(self):
        snapshots = self.identity_snapshots()
        for ordinal, row in enumerate(snapshots):
            row['st_atime_ns'] += ordinal
            row.pop('st_birthtime_ns')  # absent on some supported hosts
            row.pop('st_file_attributes')
            row.pop('st_reparse_tag')
        result = self.read_with_identity_snapshots(snapshots)
        self.assertEqual(reader.resolve_symbols(result, ['alpha'])['alpha'], self.inventory[1])
        snapshots[2]['st_ino'] += 1
        evidence = self.captured_identity_failure(snapshots)
        self.assertIsNone(evidence['snapshots']['after_handle_fstat']['st_birthtime_ns'])

    def test_identity_evidence_cap_preserves_rejection_without_truncated_snapshots(self):
        snapshots = self.identity_snapshots()
        snapshots[2]['st_ctime_ns'] += 1
        with patch.object(reader, 'MAX_IDENTITY_EVIDENCE', 1024):
            evidence = self.captured_identity_failure(snapshots)
        self.assertEqual(evidence['diagnostic_status'], 'evidence-cap-exceeded')
        self.assertGreater(evidence['evidence_bytes'], 1024)
        self.assertEqual(len(evidence['evidence_sha256']), 64)
        self.assertFalse(evidence['provider_approved'])
        self.assertNotIn('snapshots', evidence)

    def test_failure_records_runtime_and_both_windows_version_views(self):
        class WindowsVersion(tuple):
            platform_version = (10, 0, 26100)

        snapshots = self.identity_snapshots()
        snapshots[2]['st_ctime_ns'] += 1
        version = WindowsVersion((6, 2, 9200, 2, ''))  # reconstructed compatibility view
        with patch.object(reader.sys, 'getwindowsversion', return_value=version, create=True):
            evidence = self.captured_identity_failure(snapshots)
        self.assertEqual(evidence['runtime']['python'], reader.sys.version[:512])
        self.assertEqual(evidence['runtime']['implementation'], reader.sys.implementation.name)
        self.assertEqual(evidence['runtime']['windows_reported_version'], [6, 2, 9200])
        self.assertEqual(evidence['runtime']['windows_platform_version'], [10, 0, 26100])

    def windows_capture(self, ordinal):
        raw = (FIXTURES / f'archive-identity-112353662278-{ordinal}.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), WINDOWS_CAPTURE_HASHES[ordinal - 1])
        record = json.loads(raw)
        labels = ['initial_path_stat', 'before_handle_fstat', 'after_handle_fstat', 'current_path_stat']
        observations = [types.SimpleNamespace(**{key: int(value) if value is not None else None
                                                 for key, value in record['snapshots'][label].items()})
                        for label in labels]
        return record, observations

    def test_actual_windows_records_normalize_and_bind_exact_reconstructed_bytes(self):
        provenance = json.loads((FIXTURES / 'windows-job-112353662278-provenance.json').read_text())
        self.assertEqual(provenance['source_sha'], 'abb1bb034d97dda3940983fa0f4144bf78e8a278')
        for ordinal in [1, 2]:
            with self.subTest(capture=ordinal):
                record, values = self.windows_capture(ordinal)
                self.assertEqual(provenance['records'][ordinal - 1]['sha256'], WINDOWS_CAPTURE_HASHES[ordinal - 1])
                with captured_windows_runtime():
                    normalized = reader._file_identity(*values)
                self.assertEqual(normalized['profile'], reader.WINDOWS_IDENTITY_PROFILE)
                self.assertEqual(normalized['path_ctime_ns'], record['snapshots']['initial_path_stat']['st_ctime_ns'])
                self.assertEqual(normalized['handle_ctime_ns'], record['snapshots']['before_handle_fstat']['st_ctime_ns'])
                if ordinal == 1:
                    data, inventory, _ = reconstruct(inside_pad=False)
                else:
                    fixture = copy.deepcopy(FIXTURE)
                    for number, row in enumerate(fixture['objects']):
                        row['member'] = f'object{number}.obj'
                    data, inventory, _ = reconstruct(fixture, short_names=True)
                self.assertEqual(len(data), values[0].st_size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), record['sha256_before'])
                self.assertEqual(record['sha256_before'], record['sha256_after'])
                self.path.write_bytes(data)
                # Only the runtime selector is reconstructed. All four native
                # observations and the independently hashed bytes are unaltered.
                with patch.object(reader, '_windows_identity_profile', return_value=reader.WINDOWS_IDENTITY_PROFILE), \
                        patch.object(reader.Path, 'stat', side_effect=[values[0], values[3]]), \
                        patch.object(reader.os, 'fstat', side_effect=values[1:3]):
                    result = reader.read_archive_index(self.path, inventory)
                self.assertEqual(result['metadata']['file_identity'], normalized)
                self.assertEqual(result['metadata']['archive_sha256'], record['sha256_before'])
                self.assertEqual(reader.resolve_symbols(result, ['alpha'])['alpha'], inventory[1])

    def test_original_equal_tuple_still_succeeds_without_optional_or_runtime_metadata(self):
        _, values = self.windows_capture(1)
        for value in values:
            value.st_ctime_ns = values[0].st_ctime_ns
            del value.st_birthtime_ns
        for runtime in [{}, {'version': (3, 99, 1, 'final', 0)}, {'os_name': 'posix', 'platform': 'linux'},
                        {'implementation': 'unknown', 'platform_version': None}]:
            with self.subTest(runtime=runtime), captured_windows_runtime(**runtime), \
                    patch.object(reader, '_windows_identity_profile', side_effect=AssertionError('must not be queried')):
                self.assertIsNone(reader._file_identity(*values))

    def test_windows_exception_rejects_each_field_and_observation_mutation(self):
        _, original = self.windows_capture(1)
        for field in reader.WINDOWS_IDENTITY_FIELDS:
            for ordinal in range(4):
                values = copy.deepcopy(original)
                setattr(values[ordinal], field, getattr(values[ordinal], field) + 1)
                with self.subTest(field=field, observation=ordinal), captured_windows_runtime(), self.assertRaises(ValueError):
                    reader._file_identity(*values)
        values = copy.deepcopy(original)
        values[0].st_ctime_ns += 1
        values[3].st_ctime_ns += 1  # stable, but violates the reviewed path-ctime/birthtime relation
        with captured_windows_runtime(), self.assertRaisesRegex(ValueError, 'creation-time semantics'):
            reader._file_identity(*values)
        values = copy.deepcopy(original)
        values[1].st_ctime_ns += 12345
        values[2].st_ctime_ns += 12345  # metadata change time need not equal last-write time
        with captured_windows_runtime():
            self.assertIsNotNone(reader._file_identity(*values))

    def test_windows_exception_rejects_missing_invalid_and_unsupported_metadata(self):
        _, original = self.windows_capture(1)
        for field in reader.WINDOWS_IDENTITY_FIELDS:
            for value in [None, True, '123']:
                values = copy.deepcopy(original)
                setattr(values[2], field, value)
                with self.subTest(field=field, value=value), captured_windows_runtime(), self.assertRaises(ValueError):
                    reader._file_identity(*values)
            values = copy.deepcopy(original)
            delattr(values[2], field)
            with self.subTest(missing=field), captured_windows_runtime(), self.assertRaises(ValueError):
                reader._file_identity(*values)
        for field, value in [('st_dev', 0), ('st_dev', 2**64), ('st_ino', 0), ('st_ino', 2**128),
                             ('st_birthtime_ns', 0), ('st_size', 0)]:
            values = copy.deepcopy(original)
            for row in values:
                setattr(row, field, value)
            with self.subTest(field=field, value=value), captured_windows_runtime(), self.assertRaises(ValueError):
                reader._file_identity(*values)
        runtimes = [{'os_name': 'posix'}, {'platform': 'linux'}, {'implementation': 'pypy'},
                    {'version': (3, 12, 9, 'final', 0)}, {'version': (3, 13, 0, 'final', 0)},
                    {'version': (3, 12, 10, 'candidate', 1)}, {'platform_version': (10, 0, 26200)},
                    {'platform_version': None}]
        for runtime in runtimes:
            with self.subTest(runtime=runtime), captured_windows_runtime(**runtime), self.assertRaises(ValueError):
                reader._file_identity(*original)
        with captured_windows_runtime(), patch.object(reader.sys, 'getwindowsversion', side_effect=OSError('fixture')), \
                self.assertRaisesRegex(ValueError, 'Unavailable'):
            reader._file_identity(*original)
        with captured_windows_runtime():
            getter = reader.sys.getwindowsversion
            del reader.sys.getwindowsversion
            try:
                with self.assertRaisesRegex(ValueError, 'Missing'):
                    reader._file_identity(*original)
            finally:
                reader.sys.getwindowsversion = getter
        values = copy.deepcopy(original)
        del values[2].st_birthtime_ns
        evidence = reader._identity_failure(*values, 'a' * 64, 'a' * 64,
                                            reason='Missing/noninteger Windows archive identity metadata',
                                            identity_fields=reader.WINDOWS_IDENTITY_FIELDS)
        record = json.loads(evidence.split('ARCHIVE_IDENTITY_EVIDENCE=', 1)[1])
        self.assertIsNone(record['snapshots']['after_handle_fstat']['st_birthtime_ns'])
        self.assertIn('st_birthtime_ns', record['identity_fields'])
        self.assertIn('Missing', record['failure_reason'])

    def test_windows_normalization_cannot_override_content_hash_mutation(self):
        _, values = self.windows_capture(1)
        data, inventory, _ = reconstruct(inside_pad=False)
        self.path.write_bytes(data)
        original_hash, calls = reader._hash, []

        def changed_hash(stream, size, guard):
            calls.append(True)
            if len(calls) == 2:
                with self.path.open('r+b') as out:
                    out.seek(inventory[0]['archive_header_offset'] + 60)
                    out.write(b'X')
            return original_hash(stream, size, guard)

        with patch.object(reader, '_hash', changed_hash), \
                patch.object(reader, '_windows_identity_profile', return_value=reader.WINDOWS_IDENTITY_PROFILE) as profile, \
                patch.object(reader.Path, 'stat', return_value=values[0]), \
                patch.object(reader.os, 'fstat', return_value=values[1]), \
                self.assertRaisesRegex(ValueError, '^Archive changed during index reading$'):
            reader.read_archive_index(self.path, inventory)
        profile.assert_not_called()

    def test_non_windows_keeps_original_cross_api_time_rule(self):
        _, original = self.windows_capture(1)
        for platform in ['linux', 'darwin', 'freebsd14', 'cygwin']:
            with self.subTest(platform=platform), captured_windows_runtime(os_name='posix', platform=platform), \
                    self.assertRaisesRegex(ValueError, '^Archive identity changed during index reading$'):
                reader._file_identity(*original)


def crosscheck_sdk(directory):
    """Optional offline cross-check; emits only counts/hashes, never object bytes."""
    scanner_spec = importlib.util.spec_from_file_location('provider_inventory', SOURCE / 'provider_inventory.py')
    scanner = importlib.util.module_from_spec(scanner_spec)
    scanner_spec.loader.exec_module(scanner)
    paths = sorted(Path(directory).glob('*.lib'))
    if not paths:
        raise ValueError('No preserved SDK .lib files found')
    symbols = objects = checked = skipped = 0
    for path in paths:
        inventory = []
        scanner.scan_library(path, emit=inventory.append)
        if any(row.get('kind') == 'short_import' or row.get('import_sections') for row in inventory):
            skipped += 1
            print(json.dumps({'archive': path.name, 'status': 'outside-static-index-proof-scope',
                              'reason': 'Independent scanner identifies import members'}))
            continue
        result = reader.read_archive_index(path, inventory)
        metadata = result['metadata']
        checked += 1
        symbols += metadata['symbol_count']
        objects += metadata['member_count']
        print(json.dumps({'archive': path.name, **metadata}, sort_keys=True))
    print(f'Offline static index cross-check: {checked} archives, {objects} objects, '
          f'{symbols} distinct-per-archive symbols; {skipped} import archives outside proof scope')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-lib-dir', type=Path, help='Optional preserved official SDK libraries; read only')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveIndexTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.sdk_lib_dir:
        crosscheck_sdk(args.sdk_lib_dir)
