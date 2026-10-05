#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert external-symbol, weak-alias, COMDAT, relocation and diagnostic-only controls."""
import importlib.util
from pathlib import Path
import struct
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('member_evidence', ROOT / 'tests/desktop/llvm_sdk/provider_member_evidence.py')
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
checks = 0


def check(value, label):
    global checks
    assert value, label
    checks += 1


def reject(call, label):
    global checks
    try:
        call()
    except (ValueError, UnicodeError, OSError, struct.error):
        checks += 1
        return
    raise AssertionError('Invalid member evidence accepted: ' + label)


def object_bytes(symbols, sections=(), machine=0x8664, big=False):
    width, header_size = (20, 56) if big else (18, 20)
    raw = bytearray(header_size + len(sections) * 40)
    if big:
        struct.pack_into('<HHHH', raw, 0, 0, 0xffff, 2, machine)
        raw[12:28] = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
        struct.pack_into('<I', raw, 44, len(sections))
    else:
        struct.pack_into('<HH', raw, 0, machine, len(sections))
    for i, (name, data, flags, relocs) in enumerate(sections):
        base = header_size + i * 40
        raw[base:base + 8] = name.encode('ascii').ljust(8, b'\0')
        struct.pack_into('<II', raw, base + 16, len(data), len(raw))
        raw += data
        struct.pack_into('<IH', raw, base + 24, len(raw), 0)
        struct.pack_into('<H', raw, base + 32, len(relocs))
        struct.pack_into('<I', raw, base + 36, flags)
        for relocation in relocs:
            raw += struct.pack('<IIH', *relocation)
    pointer = len(raw)
    string_table, entries = bytearray(b'\0' * 4), bytearray()
    for name, value, section, stype, storage, aux in symbols:
        encoded = name.encode('ascii')
        if len(encoded) > 8:
            field = struct.pack('<II', 0, len(string_table))
            string_table += encoded + b'\0'
        else:
            field = encoded.ljust(8, b'\0')
        entries += field + struct.pack('<I', value) + struct.pack('<hHBB' if width == 18 else '<iHBB', section, stype, storage, len(aux))
        for entry in aux:
            assert len(entry) == width
            entries += entry
    struct.pack_into('<II', raw, 48 if big else 8, pointer, len(entries) // width)
    struct.pack_into('<I', string_table, 0, len(string_table))
    return bytes(raw + entries + string_table)


def symbol(name, section=0, storage=2, aux=(), value=0, stype=0):
    return (name, value, section, stype, storage, list(aux))


def weak_aux(target=2, mode=3, width=18):
    return struct.pack('<II', target, mode) + b'\0' * (width - 8)


def section_aux(length=8, selection=0, association=0, width=18):
    return struct.pack('<IHHIHBBH', length, 0, 0, 0, association & 0xffff, selection, 0, association >> 16) + b'\0' * (width - 18)


def archive(rows):
    data = bytearray(b'!<arch>\n')
    for name, body in rows:
        header = name.encode().ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'0'.ljust(8)
        header += str(len(body)).encode().ljust(10) + b'`\n'
        data += header + body + (b'\n' if len(body) % 2 else b'')
    return bytes(data)


neutral = object_bytes([symbol('alias', storage=105, aux=[weak_aux()]), symbol('target')], machine=0)
r = e.coff_evidence(neutral)
check(r['header']['status'] == 'neutral-weak-alias-observed-unreviewed', 'Neutral alias is observed, not accepted for link')
check(r['header']['machine'] == '0x0000' and r['header']['provider_approved'] is False, 'Neutral is never mislabeled x64')
check(r['symbols'][0]['weak_alias']['target_name'] == 'target', 'Weak target ownership')
check(r['symbols'][1]['definition'] == 'undefined', 'Undefined external classified')
for target, mode in [(1, 3), (99, 3), (2, 4), (2, 0)]:
    reject(lambda t=target, m=mode: e.coff_evidence(object_bytes([
        symbol('alias', storage=105, aux=[weak_aux(t, m)]), symbol('target')], machine=0)), 'Invalid weak auxiliary target/mode')
for wrong in [symbol('alias', section=-1, storage=105, aux=[weak_aux()]),
              symbol('alias', storage=105, aux=[]), symbol('alias', storage=105, value=1, aux=[weak_aux()])]:
    reject(lambda s=wrong: e.coff_evidence(object_bytes([s, symbol('target')], machine=0)), 'Invalid weak symbol shape')
for machine in [0x14c, 0xa641, 0x1234]:
    r = e.coff_evidence(object_bytes([symbol('foo')], machine=machine))
    check(r['header']['status'] == 'rejected-unreviewed-architecture' and not r['symbols'], 'Unknown/wrong architecture remains rejected')
r = e.coff_evidence(object_bytes([symbol('foo')], [('.text', b'\0' * 8, 0x60000020, [])], machine=0))
check(r['header']['status'] == 'rejected-unreviewed-architecture', 'Machine-neutral code is not allowed')

for big in [False, True]:
    width = 20 if big else 18
    sections = [('.text', b'\0' * 8, 0x60000020, [(0, 3, 4)])]
    symbols = [symbol('.text', section=1, storage=3, aux=[section_aux(width=width)]),
               symbol('function', section=1, stype=0x20), symbol('needed_external')]
    obj = object_bytes(symbols, sections, big=big)
    r = e.coff_evidence(obj)
    check(r['relocations'][0]['symbol_name'] == 'needed_external', 'Relocation resolves real symbol index, skipping auxiliary')
    check(r['symbols'][0]['section_definition']['selection'] == 0, 'Non-COMDAT section auxiliary')
    check(r['symbols'][1]['definition'] == 'section', 'External definition has section ownership')
    for relocation in [(0, 1, 4), (0, 90, 4), (7, 3, 4), (0, 3, 0x999),
                       (0, 3, 0x0e), (0, 3, 0x0f), (0, 3, 0x10)]:
        bad_sections = [('.text', b'\0' * 8, 0x60000020, [relocation])]
        reject(lambda s=bad_sections: e.coff_evidence(object_bytes(symbols, s, big=big)), 'Invalid relocation target/type/extent')
    bad = bytearray(obj)
    struct.pack_into('<I', bad, 48 if big else 8, len(bad) + 1)
    reject(lambda: e.coff_evidence(bad), 'Symbol table outside object')
    bad = bytearray(obj);struct.pack_into('<I', bad, 52 if big else 12, e.MAX_SYMBOLS + 1)
    reject(lambda: e.coff_evidence(bad), 'Symbol count cap')
    bad = bytearray(obj);struct.pack_into('<I', bad, (56 if big else 20) + 36, 0x61000020)
    reject(lambda: e.coff_evidence(bad), 'Relocation overflow requires explicit future review')

sections = [('.text', b'\0' * 8, 0x60001020, []), ('.rdata', b'\0' * 8, 0x40001040, [])]
symbols = [symbol('.text', section=1, storage=3, aux=[section_aux(selection=2)]),
           symbol('.rdata', section=2, storage=3, aux=[section_aux(selection=5, association=1)])]
r = e.coff_evidence(object_bytes(symbols, sections))
check(r['symbols'][1]['section_definition']['association'] == 1, 'Associative COMDAT records owning section')
for selection, association in [(5, 2), (5, 3), (9, 1), (0, 0)]:
    altered = [symbols[0], symbol('.rdata', section=2, storage=3, aux=[section_aux(selection=selection, association=association)])]
    reject(lambda s=altered: e.coff_evidence(object_bytes(s, sections)), 'Invalid COMDAT association/selection')

body = struct.pack('<III', 0x1000, 23, 0x12345678) + b'stdafx.pch\0'
cv = struct.pack('<IHH', 4, len(body) + 2, 0x1509) + body + struct.pack('<HHI', 6, 0x14, 0x12345678)
r = e.codeview_pch(cv)
check([x['leaf'] for x in r['pch_records']] == ['LF_PRECOMP', 'LF_ENDPRECOMP'], 'PCH producer/consumer type records retained')
check(r['pch_records'][0]['filename'] == 'stdafx.pch', 'PCH filename/signature evidence')
check(e.codeview_pch(b'\x01\0\0\0')['status'] == 'unreviewed-signature', 'Unknown CodeView signature stays unreviewed')
for malformed in [cv[:-1], struct.pack('<IHH', 4, 1, 0x1509), struct.pack('<IHHI', 4, 6, 0x1509, 0)]:
    reject(lambda d=malformed: e.codeview_pch(d), 'Malformed CodeView dependency record')
reject(lambda: e.coff_evidence(b'bad'), 'Short object')
with patch.object(e, 'MAX_OBJECT', 16):
    reject(lambda: e.coff_evidence(neutral), 'Object size cap')

with tempfile.TemporaryDirectory() as td:
    work = Path(td)
    lib = work / 'diaguids.lib'
    lib.write_bytes(archive([('one.obj/', neutral), ('two.obj/', object_bytes([symbol('long_guid_symbol', section=1)],
                       [('.rdata', b'\0' * 16, 0x40000040, [])]))]))
    check(len(list(e.archive_members(lib, True))) == 2, 'All DIA members read')
    check(len(list(e.archive_members(lib, False))) == 1, 'CRT failure diagnosis remains first-member scope')
    class Recorder:
        def __init__(self): self.records = []
        def emit(self, kind, value): self.records.append((kind, value))
    class Runner:
        def __init__(self, root): self.work, self.commands = root, []
        def guard(self): pass
        def command(self, stage, argv, env, timeout, required):
            self.commands.append((stage, argv, timeout, required))
            return 0, 'COFF SYMBOL TABLE\n000 UNDEF External | target\n'
    recorder, runner = Recorder(), Runner(work)
    with patch.object(e, 'MAX_ARCHIVE', 16), patch.object(e.hashlib, 'file_digest', side_effect=AssertionError('Size guard must precede hashing')):
        reject(lambda: e.collect('diaguids', lib, runner, work / 'dumpbin.exe', {}, recorder), 'Archive cap before hash/read')
    check(e.collect('diaguids', lib, runner, work / 'dumpbin.exe', {}, recorder) is False, 'Diagnostic collection is separate from approval')
    check(len(runner.commands) == 2 and all(c[1][0].name == 'dumpbin.exe' for c in runner.commands), 'Only native inspector invoked')
    check(all(c[3] is False and c[2] == 45 for c in runner.commands), 'Native inspection is bounded and retains failures')
    check(any(k == 'PROVIDER_MEMBER_RAW_HEADER' for k, _ in recorder.records), 'Raw failing header evidence emitted before interpretation')
    check(all(v.get('provider_approved') is not True and v.get('actual_link_selection_proven') is not True for _, v in recorder.records),
          'No member evidence can become approval/selection proof')
    reject(lambda: e.collect('unrequested', lib, runner, work / 'dumpbin.exe', {}, recorder), 'Only requested provider targets inspected')
    recorder, runner = Recorder(), Runner(work)
    check(e.collect('libcmt', lib, runner, work / 'dumpbin.exe', {}, recorder) is False, 'CRT first-member diagnostic retained')
    extracted = work / 'member-evidence/libcmt.first-member.obj'
    check(extracted.read_bytes() == neutral and lib.read_bytes().startswith(b'!<arch>\n'), 'Extraction preserves exact bytes and original archive')
    check(len(runner.commands) == 1 and runner.commands[0][1][-1] == extracted, 'Only exact copied CRT member goes to native inspector')

print(f'PASS: {checks} inert member symbol/auxiliary/weak-alias/COMDAT/relocation/PCH/diagnostic controls')
print('NOT RUN: Windows inspectors, compilation/linking, runtime/JIT; neutral metadata and all providers remain unapproved')
