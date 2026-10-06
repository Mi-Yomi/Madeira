# SPDX-License-Identifier: MIT
"""Reconstructed neutral COFF witnesses and adversarial mutations, never CRT bytes."""
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def fixtures():
    captured = json.loads((HERE / 'neutral-crt-captured-evidence.json').read_text())
    for provider in ('libcmt', 'oldnames'):
        witness = json.loads((HERE / (provider + '-neutral-reconstructed.json')).read_text())
        yield provider, bytes.fromhex(witness['object_hex']), witness, captured['providers'][provider]


def malformed(data):
    pointer, = struct.unpack_from('<I', data, 8)
    target, weak, auxiliary = pointer + 36, pointer + 54, pointer + 72
    cases = [
        ('multiple sections', 2, '<H', 2), ('optional header', 16, '<H', 1),
        ('file characteristics', 18, '<H', 2), ('physical address', 28, '<I', 1),
        ('virtual address', 32, '<I', 1), ('empty debug', 36, '<I', 0),
        ('unbounded debug', 36, '<I', 65537), ('raw header overlap', 40, '<I', 59),
        ('raw gap', 40, '<I', 61), ('relocation pointer', 44, '<I', 60),
        ('line pointer', 48, '<I', 60), ('relocation count', 52, '<H', 1),
        ('line count', 54, '<H', 1), ('symbol overlap', 8, '<I', pointer - 1),
        ('symbol gap', 8, '<I', pointer + 1), ('symbol count', 12, '<I', 6),
        ('executable flags', 56, '<I', 0x62100060), ('writable flags', 56, '<I', 0xc2100040),
        ('non-discardable flags', 56, '<I', 0x40100040), ('COMDAT flags', 56, '<I', 0x42101040),
        ('extended relocations', 56, '<I', 0x43100040),
        ('auxiliary target', auxiliary, '<I', 4), ('absent target', auxiliary, '<I', 99),
        ('self target', auxiliary, '<I', 3), ('local target', auxiliary, '<I', 0),
        *[('weak search ' + str(mode), auxiliary + 4, '<I', mode) for mode in (0, 1, 2, 4)],
        ('weak reserved bytes', auxiliary + 8, '<B', 1),
        ('weak section', weak + 12, '<h', 1), ('weak value', weak + 8, '<I', 1),
        ('weak type', weak + 14, '<H', 0x20), ('weak no auxiliary', weak + 17, '<B', 0),
        ('weak extra auxiliary', weak + 17, '<B', 2), ('weak storage', weak + 16, '<B', 2),
        ('defined target', target + 12, '<h', 1), ('absolute target', target + 12, '<h', -1),
        ('common target', target + 8, '<I', 1), ('typed target', target + 14, '<H', 0x20),
        ('target auxiliary', target + 17, '<B', 1), ('target storage', target + 16, '<B', 3),
        ('defined tag', pointer + 12, '<h', 1), ('external tag', pointer + 16, '<B', 2),
        ('typed tag', pointer + 14, '<H', 1), ('tag auxiliary', pointer + 17, '<B', 1),
        ('small string table', pointer + 90, '<I', 3),
        ('oversized string table', pointer + 90, '<I', 16385),
        ('bad long symbol offset', target, '<II', (0, 0xffff)),
    ]
    for label, offset, fmt, value in cases:
        bad = bytearray(data)
        struct.pack_into(fmt, bad, offset, *(value if isinstance(value, tuple) else (value,)))
        yield label, bytes(bad)
    for name in (b'.text', b'.data', b'.rdata', b'.drectve', b'.idata$2', b'.debug$T'):
        bad = bytearray(data)
        bad[20:28] = name.ljust(8, b'\0')
        yield 'unreviewed section ' + name.decode(), bytes(bad)
    for label, offset, value in [('unknown local tag', pointer, b'other.id'),
                                 ('duplicate local tag', pointer + 18, data[pointer:pointer + 8]),
                                 ('alias same as target', weak, data[target:target + 8])]:
        bad = bytearray(data)
        bad[offset:offset + len(value)] = value
        yield label, bytes(bad)
    for end in (19, 59, pointer - 1, pointer + 17, pointer + 89, len(data) - 1):
        yield 'truncated at ' + str(end), data[:end]
    yield 'trailing bytes', data + b'\0'
