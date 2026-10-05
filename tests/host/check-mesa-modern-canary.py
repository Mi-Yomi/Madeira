#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure-host strict modern proof controls; synthetic text is never a GL pass.

The fixture is independently constructed, never obtained from the parser's
oracle. Fixed checksum/color and selected sentinel anchors prevent the fixture
and validator from agreeing merely because they reuse the same implementation.
No compiler, executable, network request, Windows or device code is invoked.
"""
from collections import Counter
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/mesa_wgl'
SPEC = importlib.util.spec_from_file_location('modern_reference_under_test', SOURCE / 'windows_reference.py')
REF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REF)
DIRECTORY = r'C:\sandbox\bundle'
RENDERER = 'llvmpipe (LLVM 19.1.7, 256 bits)'
SEEDS = (0x13579BDF, 0x2468ACE0)
FLOORS = {'vertex_blocks': 12, 'fragment_blocks': 12, 'compute_blocks': 12,
          'bindings': 12, 'combined_blocks': 24, 'compute_invocations': 1,
          'draw_buffers': 2, 'color_attachments': 2, 'block_bytes': 16}
SUMS = ((0x0738B58F, 0x64529B73, 0x954F8AD2, 0x8BB33BFB),
        (0xF7567380, 0x434AB37C, 0xC6A0D407, 0xCF145F0E))
COLORS = ((20, 60, 89, 255), (51, 220, 200, 255))
ANCHORS = {
    (0, 0): (0x10480F09, 0x31F4C95D, 0xC0373C6A, 0x99C02CD8),
    (0, 5): (0x7198B787, 0x75E2E1AD, 0x82C2B703, 0x383FE5AC),
    (0, 11): (0x3B6605D7, 0x4C56EAD0, 0xBD1D6AB9, 0x2D8ED827),
    (1, 0): (0x2BE3B0E4, 0x4072B8DC, 0x530D239E, 0xA9EB623B),
    (1, 5): (0xDDB3F0F9, 0x77902191, 0xE49D74E9, 0x276062DD),
    (1, 11): (0x0B32A1AA, 0x3A7572C8, 0xFB6194C5, 0xF815D250),
}
COUNTS = Counter()
FAILURES = []


def check(condition, label, category='oracle/source'):
    COUNTS[category] += 1
    if not condition:
        FAILURES.append(label)


def oracle_words(seed):
    """Model unsigned instructions using modular arithmetic and division."""
    result = []
    for block in range(12):
        row = []
        for lane in range(4):
            value = seed ^ ((block + 1) * 2654435769 % 2**32)
            value = (value + (lane + 1) * 2246822507) % 2**32
            value = ((value ^ (value // 65536)) * 2146121005) % 2**32
            row.append(value ^ (value // 32768))
        result.append(tuple(row))
    return result


def oracle_sums(words):
    result = [826366247 * (lane + 1) % 2**32 for lane in range(4)]
    for block, row in enumerate(words):
        for lane, value in enumerate(row):
            result[lane] = (result[lane] + value * (3 + 2 * (block + lane))) % 2**32
    return tuple(result)


def oracle_color(values):
    octets = [value.to_bytes(4, 'little') for value in values]
    return (octets[0][0] ^ octets[1][1], octets[1][0] ^ octets[2][2],
            octets[2][0] ^ octets[3][3], 255)


def word_text(values):
    return ','.join(f'{value:08x}' for value in values)


def color_text(values):
    return ','.join(map(str, values))


WORDS = tuple(oracle_words(seed) for seed in SEEDS)


def base_rows(stage):
    rows = [f'CANARY stage={stage} pointer_bits=64', 'PASS stage=window',
            'PASS stage=gdi-memory', 'PASS stage=gdi-window']
    if stage == 'gdi':
        return rows
    renderer = RENDERER if stage == 'modern' else 'softpipe'
    rows += [f'MODULE opengl32={DIRECTORY}\\opengl32.dll',
             f'MODULE gallium={DIRECTORY}\\libgallium_wgl.dll', 'PASS stage=gl-load',
             'PASS stage=pixel-format',
             f'GL renderer={renderer} version=4.5 (Compatibility Profile) Mesa 26.2.4',
             'LEGACY version=4.5 profile=0x2', 'PASS stage=legacy-context']
    for initial, swap, backing, rgb in [
            ('legacy-clear-readback', 'legacy-swap', 'legacy-window-readback', '64,128,191'),
            ('legacy-second-readback', 'legacy-second-swap', 'legacy-second-window-readback', '191,64,128')]:
        rows += [f'PIXEL stage={initial} rgba={rgb},255 gl_error=0x0',
                 f'PASS stage={initial}', f'PASS stage={swap}',
                 f'WINDOW_PIXEL stage={backing} rgb={rgb}', f'PASS stage={backing}']
    if stage in ('core43', 'modern'):
        rows += ['CORE version=4.5 profile=0x1', 'PASS stage=core43-context',
                 'PIXEL stage=core-shader-readback rgba=255,0,0,255 gl_error=0x0',
                 'PASS stage=core-shader-readback', 'PASS stage=core-swap',
                 'WINDOW_PIXEL stage=core-window-readback rgb=255,0,0',
                 'PASS stage=core-window-readback']
    return rows


def pixel_rows(phase, trial, sample, x, y, values, rgba=None):
    key = f'phase={phase} trial={trial} sample={sample} xy={x},{y}'
    return [f'MODERN_UINT {key} values={word_text(values)}',
            f'MODERN_PIXEL {key} rgba={color_text(oracle_color(values) if rgba is None else rgba)}']


def transcript():
    rows = base_rows('modern')
    rows += [f'MODERN_IDENTITY renderer={RENDERER} version=4.5 (Core Profile) Mesa 26.2.4 glsl=4.50',
             'MODERN_EXTENSIONS enumerated=220 draw_parameters=1 clip_control=1']
    rows += [f'MODERN_LIMIT {name}={value}' for name, value in FLOORS.items()]
    rows += [f'MODERN_WORKGROUP axis={axis} count=65535 size={1024 if axis < 2 else 64}'
             for axis in range(3)]
    rows += ['PASS stage=modern-identity-limits']
    for program, stages in [('compute', (2,)), ('storage', (0, 1)),
                            ('indirect', (0, 1)), ('clip', (0, 1))]:
        rows += [f'MODERN_LOG program={program} kind=compile stage={stage} status=1 bytes=0 hex='
                 for stage in stages]
        rows += [f'MODERN_LOG program={program} kind=link stage=3 status=1 bytes=0 hex=']
        if program == 'storage':
            # The C canary compiles both storage programs, reflects both, then
            # compiles the indirect and clip programs.
            for reflected_program, compute in (('compute', 1), ('storage', 0)):
                rows += [f'MODERN_BLOCK_COUNT program={reflected_program} count=12']
                rows += [f'MODERN_BLOCK program={reflected_program} block={block} binding={block} bytes=16 '
                         f'vertex={1-compute} fragment={1-compute} compute={compute}' for block in range(12)]
    for trial, seed in enumerate(SEEDS):
        rows += [f'MODERN_SSBO trial={trial} seed={seed:08x} block={block} words={word_text(values)}'
                 for block, values in enumerate(WORDS[trial])]
        rows += pixel_rows('storage', trial, 0, 4, 4, SUMS[trial], COLORS[trial])
        rows += [f'WINDOW_PIXEL stage=modern-storage-window-{trial} rgb={color_text(COLORS[trial][:3])}',
                 f'PASS stage=modern-storage-window-{trial}']
    rows += ['PASS stage=modern-storage']
    for draw, (base_vertex, base_instance) in enumerate(((5, 7), (9, 11))):
        for instance in range(2):
            # A divisor-one integer attribute includes baseInstance; InstanceID does not.
            attribute = int.from_bytes(bytes((64 + base_instance + instance,
                                            48 + base_instance + instance,
                                            32 + base_instance + instance,
                                            16 + base_instance + instance)), 'little')
            rows += pixel_rows('indirect', draw, instance, 4 + 16 * draw, 4 + 16 * instance,
                               (base_vertex, base_instance, draw, attribute))
    rows += ['PASS stage=modern-indirect']
    # Explicit expected matrix independently names origin, range and z outcomes.
    cases = [(0x8CA1, 0x935E, '-0.5', 0, '0.25'),
             (0x8CA1, 0x935E, '0.5', 0, '0.75'),
             (0x8CA1, 0x935F, '-0.5', None, '1'),
             (0x8CA1, 0x935F, '0.5', 0, '0.5'),
             (0x8CA2, 0x935E, '-0.5', 1, '0.25'),
             (0x8CA2, 0x935E, '0.5', 1, '0.75'),
             (0x8CA2, 0x935F, '-0.5', None, '1'),
             (0x8CA2, 0x935F, '0.5', 1, '0.5')]
    for trial, (origin, mode, z, drawn_sample, depth) in enumerate(cases):
        rows += [f'MODERN_CLIP trial={trial} origin=0x{origin:x} depth=0x{mode:x} z={z}']
        for sample, y in enumerate((4, 27)):
            drawn = sample == drawn_sample
            rows += pixel_rows('clip', trial, sample, 4, y,
                               (1, 2, 3, 4) if drawn else (0, 0, 0, 0),
                               (255, 255, 255, 255) if drawn else (0, 0, 0, 255))
            rows += [f'MODERN_DEPTH trial={trial} sample={sample} value={depth if drawn else "1"}']
    rows += ['PASS stage=modern-clip', 'MODERN_ELAPSED milliseconds=123',
             'PASS stage=modern-cleanup', 'PASS stage=modern-capabilities',
             f'MODULE opengl32-after={DIRECTORY}\\opengl32.dll',
             f'MODULE gallium-after={DIRECTORY}\\libgallium_wgl.dll',
             'PASS stage=modern-module-recheck', 'PASS stage=modern-platform-cleanup',
             'PASS requested-stage=modern']
    return rows


ROWS = transcript()


def parse(rows, code=0, stage='modern', directory=DIRECTORY):
    return REF.parse_proof('\n'.join(rows), code, stage, directory)


def accept(rows, label, **kwargs):
    COUNTS['acceptance'] += 1
    try:
        result = parse(rows, **kwargs)
        if result['status'] != 'passed':
            raise AssertionError(result)
        return result
    except (ValueError, AssertionError) as error:
        FAILURES.append(f'{label}: unexpectedly rejected: {error}')
        return None


def reject(rows, label, category='mutations', **kwargs):
    COUNTS[category] += 1
    try:
        parse(rows, **kwargs)
    except ValueError:
        return
    FAILURES.append(f'{label}: unsafe proof accepted')


def replace(index, value):
    result = ROWS.copy()
    result[index] = value
    return result


def change(prefix, old, new):
    matches = [index for index, row in enumerate(ROWS) if row.startswith(prefix)]
    assert len(matches) == 1, (prefix, matches)
    index = matches[0]
    assert old in ROWS[index], (prefix, old)
    return replace(index, ROWS[index].replace(old, new, 1))


def field(row, name, value):
    result, count = re.subn(rf'(?<=\b{name}=)[^ ]*', str(value), row, count=1)
    assert count == 1, (name, row)
    return result


def reject_field(index, name, value, category):
    reject(replace(index, field(ROWS[index], name, value)), f'row {index} {name}={value}', category)


def main():
    for trial in range(2):
        check(oracle_sums(WORDS[trial]) == SUMS[trial], f'authoritative checksum {trial}')
        check(oracle_color(SUMS[trial]) == COLORS[trial], f'authoritative color {trial}')
        for block in (0, 5, 11):
            check(WORDS[trial][block] == ANCHORS[trial, block], f'fixed sentinel anchor {trial}/{block}')
        for block in range(12):
            for lane in range(4):
                value = WORDS[trial][block][lane]
                check(value != 0xDEADBEEF, f'compute init sentinel collision {trial}/{block}/{lane}')
                check(value != WORDS[1-trial][block][lane], f'seed distinction {trial}/{block}/{lane}')
                changed = [list(row) for row in WORDS[trial]]
                changed[block][lane] ^= 1
                sums = oracle_sums(changed)
                check(sums[lane] != SUMS[trial][lane] and all(sums[k] == SUMS[trial][k]
                      for k in range(4) if k != lane), f'checksum sensitivity {trial}/{block}/{lane}')
    proof = accept(ROWS, 'complete synthetic strict modern transcript')
    if proof:
        details = proof['modern']
        check(details['required'] and details['status'] == 'passed', 'strict modern status')
        check(details['limits'] == FLOORS, 'all limit receipts')
        check(len(details['sentinels']) == 24, 'both seed twelve-block receipts')
        check(tuple(details['storage_checksums']) == SUMS, 'full uint checksum receipts')
        check(len(details['shader_logs']) == 11, 'all eleven compile/link receipts')
        check((details['indirect_draws'], details['instances_per_draw'], details['clip_draws']) == (2, 2, 8), 'bounded workloads')
        check(all(details[name] is False for name in ('blender_execution_proven',
              'madeira_execution_proven', 'ios_execution_proven')), 'no synthetic target-execution claim')
        check(proof['compositor_display_proven'] is False, 'no synthetic compositor claim')
    for stage in ('gdi', 'legacy', 'core43'):
        accept(base_rows(stage) + [f'PASS requested-stage={stage}'], f'original {stage}', stage=stage)
    for reason in ('missing-create-context-attribs', 'context-rejected win32_error=8341',
                   'context-rejected win32_error=8342'):
        unsupported = base_rows('legacy')
        unsupported[0] = 'CANARY stage=core43 pointer_bits=64'
        unsupported += [f'UNAVAILABLE core43={reason}']
        check(parse(unsupported, code=77, stage='core43')['status'] == 'unavailable',
              f'original classified core43 unavailability {reason}', 'legacy compatibility')
        unsupported[0] = 'CANARY stage=modern pointer_bits=64'
        unsupported = [row.replace('renderer=softpipe', f'renderer={RENDERER}') for row in unsupported]
        reject(unsupported, f'strict modern unavailable {reason}', 'outcome', code=77)
    # Every fixture row is required evidence, including all inherited GDI/core rows.
    for index, row in enumerate(ROWS):
        reject(ROWS[:index] + ROWS[index+1:], f'delete required {row}', 'record deletion')
        reject(ROWS[:index] + [row] + ROWS[index:], f'duplicate required {row}', 'record duplication')
    for index, row in enumerate(ROWS):
        if row.startswith('MODERN_SSBO '):
            values = row.split('words=')[1].split(',')
            for lane in range(4):
                altered = values.copy()
                altered[lane] = f'{int(altered[lane], 16) ^ 1:08x}'
                reject_field(index, 'words', ','.join(altered), 'each SSBO word')
            for replacement in ('deadbeef,deadbeef,deadbeef,deadbeef', ','.join(values[::-1]),
                                ','.join(values[:-1]), ','.join(values + ['00000000'])):
                reject_field(index, 'words', replacement, 'SSBO structure/seed')
            reject_field(index, 'seed', f'{SEEDS[1-int(re.search(r"trial=(\d)", row)[1])]:08x}', 'SSBO structure/seed')
        elif row.startswith(('MODERN_UINT ', 'MODERN_PIXEL ')):
            key, radix = ('values', 16) if row.startswith('MODERN_UINT') else ('rgba', 10)
            values = row.split(key + '=')[1].split(',')
            for lane in range(4):
                changed = values.copy()
                changed[lane] = (f'{int(values[lane], 16) ^ 1:08x}' if radix == 16
                                 else str(int(values[lane]) ^ 1))
                reject_field(index, key, ','.join(changed), 'every uint/color channel')
            for xy in ('0,0', '4,5', '-1,4', '4,32', 'nan,4'):
                if f'xy={xy} ' not in row:
                    reject_field(index, 'xy', xy, 'sample coordinates')
            for bad in ('-1', 'nan', 'inf', '4294967296' if radix == 16 else '256'):
                reject_field(index, key, ','.join([bad] + values[1:]), 'numeric ranges')
    for trial in range(2):
        altered = ROWS.copy()
        for index, row in enumerate(ROWS):
            if row.startswith(f'MODERN_SSBO trial={trial} '):
                block = int(re.search(r' block=(\d+) ', row)[1])
                altered[index] = field(row, 'words', word_text(WORDS[1-trial][block]))
        reject(altered, f'all stale opposite-seed words trial {trial}', 'stale/swapped')
        prefix = f'MODERN_UINT phase=storage trial={trial} '
        reject(change(prefix, word_text(SUMS[trial]), word_text(SUMS[1-trial])),
               f'stale uint storage checksum trial {trial}', 'stale/swapped')
        reject(change(f'MODERN_PIXEL phase=storage trial={trial} ', color_text(COLORS[trial]),
                      color_text(COLORS[1-trial])), f'stale color trial {trial}', 'stale/swapped')
        # High bits matter even when all four normalized color bytes remain identical.
        altered = (SUMS[trial][0] ^ 0x1000000,) + SUMS[trial][1:]
        check(oracle_color(altered) == COLORS[trial], f'color-collision control {trial}')
        reject(change(prefix, word_text(SUMS[trial]), word_text(altered)),
               f'uint high-bit corruption hidden by same color trial {trial}', 'stale/swapped')
    swapped = [re.sub(r'trial=([01]) ', lambda m: f'trial={1-int(m[1])} ', row)
               if row.startswith('MODERN_SSBO ') else row for row in ROWS]
    reject(swapped, 'swap entire SSBO trial keys', 'stale/swapped')
    for index, row in enumerate(ROWS):
        if row.startswith('MODERN_LIMIT '):
            name, original = row.split()[1].split('=')
            ceiling = 2**63 - 1 if name == 'block_bytes' else 2**31 - 1
            for value in (FLOORS[name]-1, -1, ceiling+1, 'nan', '1e9'):
                reject_field(index, name, value, 'limits')
            accept(replace(index, f'MODERN_LIMIT {name}={ceiling}'), f'{name} signed query upper bound')
        elif row.startswith('MODERN_WORKGROUP '):
            for name in ('count', 'size'):
                for value in (0, -1, 2**31, 'nan'):
                    reject_field(index, name, value, 'limits')
                accept(replace(index, field(row, name, 1)), f'{row} minimum {name}')
            reject_field(index, 'axis', 3, 'limits')
        elif row.startswith('MODERN_BLOCK_COUNT '):
            for value in (0, 11, 13):
                reject_field(index, 'count', value, 'reflection')
        elif row.startswith('MODERN_BLOCK '):
            binding = int(re.search(r' binding=(\d+) ', row)[1])
            reject_field(index, 'binding', (binding + 1) % 12, 'reflection')
            reject_field(index, 'bytes', 15, 'reflection')
            reject_field(index, 'bytes', 32, 'reflection')
            for name in ('vertex', 'fragment', 'compute'):
                value = int(re.search(rf'\b{name}=(\d+)', row)[1])
                reject_field(index, name, 1-value, 'reflection')
    identity_controls = [
        ('CANARY ', 'pointer_bits=64', 'pointer_bits=32'),
        ('CANARY ', 'stage=modern', 'stage=core43'),
        ('GL renderer=', RENDERER, 'softpipe'),
        ('GL renderer=', RENDERER, 'llvmpipe'),
        ('GL renderer=', 'Mesa 26.2.4', 'Mesa 26.2.3'),
        ('MODERN_IDENTITY ', RENDERER, 'softpipe'),
        ('MODERN_IDENTITY ', RENDERER, 'llvmpipe (LLVM 18.1.7, 256 bits)'),
        ('MODERN_IDENTITY ', 'Mesa 26.2.4', 'Mesa 26.2.40'),
        ('MODERN_IDENTITY ', '4.5 (Core Profile)', '4.2 (Core Profile)'),
        ('MODERN_IDENTITY ', '(Core Profile)', '(Compatibility Profile)'),
        ('MODERN_IDENTITY ', 'glsl=4.50', 'glsl=4.20'),
        ('MODERN_IDENTITY ', 'glsl=4.50', 'glsl=3.30'),
        ('MODERN_IDENTITY ', 'glsl=4.50', 'glsl=nan'),
        ('CORE version=', 'version=4.5', 'version=4.2'),
        ('CORE version=', 'version=4.5', 'version=4.3'),
        ('CORE version=', 'profile=0x1', 'profile=0x0'),
        ('CORE version=', 'profile=0x1', 'profile=0x2'),
        ('CORE version=', 'profile=0x1', 'profile=0x3'),
        ('LEGACY version=', 'version=4.5', 'version=2.1'),
    ]
    for prefix, old, new in identity_controls:
        reject(change(prefix, old, new), f'identity {prefix} {new}', 'identity')
    for version, glsl in [('4.3', '4.30'), ('4.6', '4.60')]:
        candidate = [row.replace('version=4.5', 'version=' + version).replace('glsl=4.50', 'glsl=' + glsl)
                     if row.startswith(('CORE version=', 'MODERN_IDENTITY ')) else row for row in ROWS]
        accept(candidate, f'actual core {version} at/above floor')
    for prefix in ('MODULE opengl32=', 'MODULE gallium=', 'MODULE opengl32-after=', 'MODULE gallium-after='):
        reject(change(prefix, DIRECTORY, r'C:\Windows\System32'), f'module substitution {prefix}', 'identity')
        reject(change(prefix, '.dll', '.dll.evil'), f'module suffix {prefix}', 'identity')
    normalized = [row.replace(DIRECTORY, r'c:/SANDBOX/bundle/.') if row.startswith('MODULE ') else row for row in ROWS]
    accept(normalized, 'Windows case/separator/dot path normalization')
    for name in ('draw_parameters', 'clip_control'):
        for value in (0, 2, -1, 'true'):
            reject(change('MODERN_EXTENSIONS ', f'{name}=1', f'{name}={value}'), f'extension {name}/{value}', 'extensions')
    for value in (0, 1, 4097, -1, 'nan'):
        reject(change('MODERN_EXTENSIONS ', 'enumerated=220', f'enumerated={value}'), f'extension count {value}', 'extensions')
    for value in (2, 4096):
        accept(change('MODERN_EXTENSIONS ', 'enumerated=220', f'enumerated={value}'), f'extension count boundary {value}')
    for index, row in enumerate(ROWS):
        if row.startswith('MODERN_LOG '):
            for key, value in [('status', 0), ('status', 2), ('stage', 4), ('bytes', -1),
                               ('bytes', 1), ('hex', 'ff'), ('hex', 'z0'), ('hex', '0'),
                               ('kind', 'validate'), ('program', 'unknown')]:
                reject_field(index, key, value, 'compile/link logs')
            encoded = b'warning\nPASS stage=modern-cleanup\r\nFAIL stage=injected\x00\xff'
            candidate = field(field(row, 'bytes', len(encoded)), 'hex', encoded.hex())
            accept(replace(index, candidate), 'encoded control/log bytes remain inert')
            candidate = field(field(row, 'bytes', 2047), 'hex', '61' * 2047)
            accept(replace(index, candidate), 'maximum bounded shader log')
            candidate = field(field(row, 'bytes', 2048), 'hex', '61' * 2048)
            reject(replace(index, candidate), 'overlong shader log', 'compile/link logs')
            reject(replace(index, row + '\nPASS stage=modern-cleanup'), 'raw newline proof injection', 'compile/link logs')
    # Encoded success text cannot replace missing real evidence.
    log_index = next(i for i, row in enumerate(ROWS) if row.startswith('MODERN_LOG '))
    injection = b'PASS stage=modern-cleanup'
    injected = replace(log_index, field(field(ROWS[log_index], 'bytes', len(injection)), 'hex', injection.hex()))
    reject([row for row in injected if row != 'PASS stage=modern-cleanup'], 'hex log cannot mint checkpoint', 'compile/link logs')
    for index, row in enumerate(ROWS):
        if row.startswith('MODERN_CLIP '):
            for name, alternatives in [('origin', ('0x8ca1', '0x8ca2', '0x0')),
                                       ('depth', ('0x935e', '0x935f', '0x0')),
                                       ('z', ('-0.5', '0.5', 'nan', 'inf'))]:
                for value in alternatives:
                    if f'{name}={value}' not in row:
                        reject_field(index, name, value, 'clip state/depth')
        elif row.startswith('MODERN_DEPTH '):
            expected = float(row.split('value=')[1])
            for value in ('nan', 'NaN', 'inf', '-inf', '-0.1', '1.1', '1e0',
                          '0.5' if expected != 0.5 else '0.25'):
                reject_field(index, 'value', value, 'clip state/depth')
            rejected = expected - 0.00001
            reject_field(index, 'value', f'{rejected:.8f}', 'clip state/depth')
            accepted = expected - 0.0000005
            accept(replace(index, field(row, 'value', f'{accepted:.8f}')), 'bounded depth precision tolerance')
    for trial in range(2):
        prefix = f'WINDOW_PIXEL stage=modern-storage-window-{trial} '
        original = color_text(COLORS[trial][:3])
        for channel in range(3):
            for offset in (-1, 1):
                changed = list(COLORS[trial][:3]); changed[channel] += offset
                accept(change(prefix, original, color_text(changed)), f'backing channel {trial}/{channel} tolerance {offset}')
            for offset in (-2, 2):
                changed = list(COLORS[trial][:3]); changed[channel] += offset
                reject(change(prefix, original, color_text(changed)), f'backing channel {trial}/{channel} outside tolerance', 'window backing')
    # Model common indirect mistakes against all four observable samples.
    for draw, (base_vertex, base_instance) in enumerate(((5, 7), (9, 11))):
        for instance in range(2):
            prefix = f'MODERN_UINT phase=indirect trial={draw} sample={instance} '
            original = (base_vertex, base_instance, draw, 0x10203040 + 0x01010101 * (base_instance+instance))
            alternatives = [(0, base_instance, draw, original[3]),
                            (base_vertex, 0, draw, original[3]),
                            (base_vertex, base_instance, 1-draw, original[3]),
                            (base_vertex, base_instance, draw, 0x10203040+0x01010101*instance),
                            (base_vertex, base_instance, draw, 0x10203040+0x01010101*(base_instance+1-instance))]
            for wanted in alternatives:
                reject(change(prefix, word_text(original), word_text(wanted)),
                       f'indirect baseVertex/baseInstance/drawID/divisor addressing {draw}/{instance}', 'indirect semantics')
    for code in (1, 2, 77, -1, 124, 259):
        reject(ROWS, f'nonzero exit {code}', 'outcome', code=code)
    for failure in ('modern-functions', 'modern-compute-readback', 'modern-compile-link', 'modern-shader-cleanup',
                    'modern-program-cleanup', 'modern-cleanup', 'modern-module-recheck', 'modern-deadline',
                    'detach', 'delete-core', 'delete-legacy', 'release-dc', 'destroy-window', 'free-gl-module', 'unregister-class'):
        reject(ROWS[:-1] + [f'FAIL stage={failure} win32_error=8', ROWS[-1]], failure, 'outcome')
    for reason in ('core43=missing-create-context-attribs', 'core43=context-rejected win32_error=8341',
                   'modern=unsupported', 'modern=missing-extension'):
        for code in (0, 77):
            reject(ROWS[:-1] + ['UNAVAILABLE ' + reason, ROWS[-1]], 'strict unavailable ' + reason, 'outcome', code=code)
    for value in (-1, 45000, 45001, 2**32, 'nan'):
        reject(change('MODERN_ELAPSED ', 'milliseconds=123', f'milliseconds={value}'), f'elapsed {value}', 'outcome')
    for value in (0, 44999):
        accept(change('MODERN_ELAPSED ', 'milliseconds=123', f'milliseconds={value}'), f'elapsed boundary {value}')
    ordered = ['modern-storage', 'modern-indirect', 'modern-clip', 'modern-cleanup',
               'modern-capabilities', 'modern-module-recheck', 'modern-platform-cleanup']
    for first, second in zip(ordered, ordered[1:]):
        candidate = ROWS.copy()
        a, b = (candidate.index('PASS stage=' + name) for name in (first, second))
        candidate[a], candidate[b] = candidate[b], candidate[a]
        reject(candidate, f'checkpoint order {first}/{second}', 'outcome')
    reject(ROWS + ['BEGIN stage=late-after-success'], 'final success is not terminal', 'outcome')
    for row in ('MODERN_UNEXPECTED result=1', 'MODERN_ERROR stage=anything gl_error=0x0',
                'PASS stage=modern-unexpected', 'WINDOW_PIXEL stage=modern-unexpected rgb=1,2,3',
                'MODERN_SSBO trial=2 seed=13579bdf block=0 words=00000000,00000000,00000000,00000000'):
        reject(ROWS[:-1] + [row, ROWS[-1]], 'unexpected supplemental record', 'outcome')
    source_controls()
    acceptance_hook_controls()
    if FAILURES:
        for failure in FAILURES:
            print('FAIL: ' + failure)
        print(f'FAILED: {len(FAILURES)} of {sum(COUNTS.values())} host controls')
        return 1
    print(f'PASS: {sum(COUNTS.values())} pure-host modern proof controls; {len(ROWS)} required synthetic records')
    print('COUNTS: ' + ', '.join(f'{name}={count}' for name, count in sorted(COUNTS.items())))
    print('SOURCE: tests/host/check-mesa-modern-canary.py')
    print('NOT RUN: Windows/PE/device code, graphics runtime, downloads, publication, Madeira/iOS or Blender acceptance')
    return 0


def source_controls():
    """Source guards cover firstIndex, which no single text field can establish.

    These check the deliberate poison indices and shader geometry. They are
    structural regression guards, not evidence that a GL driver executed them.
    """
    header = (SOURCE / 'wgl_canary_modern.h').read_text()
    compact = re.sub(r'\s+', '', header)
    command_match = re.search(r'conststructindirect_commandcommands\[2\]=\{\{([^}]+)\},\{([^}]+)\}\};', compact)
    indices_match = re.search(r'constuint32_tindices\[9\]=\{([^}]+)\};', compact)
    check(command_match is not None and indices_match is not None, 'indirect command/index sources present')
    if command_match and indices_match:
        commands = [tuple(map(int, group.split(','))) for group in command_match.groups()]
        indices = list(map(int, indices_match[1].split(',')))
        check(commands == [(3, 2, 2, 5, 7), (3, 2, 6, 9, 11)], 'authoritative twenty-byte indexed commands')
        check(indices == [99, 99, 0, 1, 2, 99, 3, 4, 5], 'poisoned distinct nonzero firstIndex sources')
        for draw, (count, instances, first, base, instance) in enumerate(commands):
            fetched = indices[first:first+count]
            check(fetched == [3*draw, 3*draw+1, 3*draw+2] and instances == 2,
                  f'firstIndex in uint elements {first}')
            check([index+base-base-3*draw for index in fetched] == [0, 1, 2],
                  f'draw-specific local vertex triangle {draw}')
            check(indices[:count] != fetched, f'ignoring firstIndex is observable {first}')
            check(indices[first//4:first//4+count] != fetched, f'byte-valued firstIndex is observable {first}')
            check([value+base for value in fetched] != fetched, f'nonzero baseVertex observable {base}')
            check(instance != 0, f'nonzero baseInstance {instance}')
        check([index-3 for index in indices[2:5]] != [0, 1, 2],
              'reusing first command indices for second draw is observable')
    for token in ['int32_tbase_vertex;', '_Static_assert(sizeof(structindirect_command)==20,',
                  'm.MultiDrawElementsIndirect(GL_TRIANGLES,GL_UNSIGNED_INT,(void*)0,2,sizeof(commands[0]));',
                  'm.VertexAttribIPointer(0,1,GL_UNSIGNED_INT,sizeof(uint32_t),(void*)0);',
                  'm.VertexAttribDivisor(0,1);', 'intlocal=gl_VertexID-gl_BaseVertexARB-3*gl_DrawIDARB;',
                  'float(gl_DrawIDARB),float(gl_InstanceID)',
                  'parameters=uvec4(gl_BaseVertexARB,gl_BaseInstanceARB,gl_DrawIDARB,instance_value);',
                  'local==2?vec2(0,1):vec2(8,8)',
                  'm.DispatchCompute(1,1,1);',
                  'm.MemoryBarrier(GL_SHADER_STORAGE_BARRIER_BIT|GL_BUFFER_UPDATE_BARRIER_BIT);',
                  'm.GetStringi(GL_EXTENSIONS,(GLuint)i)',
                  'GL_REFERENCED_BY_VERTEX_SHADER,GL_REFERENCED_BY_FRAGMENT_SHADER,GL_REFERENCED_BY_COMPUTE_SHADER',
                  'm.ClipControl(origin_value,depth_value);',
                  'get_integer(GL_CLIP_ORIGIN,&actual_origin);get_integer(GL_CLIP_DEPTH_MODE,&actual_depth);',
                  'read_pixels(4,y,1,1,GL_DEPTH_COMPONENT,GL_FLOAT,&observed);',
                  '!(observed>=wanted-.000001f&&observed<=wanted+.000001f)']:
        check(token in compact, 'source semantic guard: ' + token)
    for token in ('m.IsBuffer(', 'm.IsProgram(', 'm.IsShader(', 'm.IsTexture(',
                  'm.IsFramebuffer(', 'm.IsVertexArray('):
        check(token in header, 'object cleanup identity guard: ' + token)


def acceptance_hook_controls():
    """Exercise the hook with ordinary data files and a non-executing fake runner."""
    spec = importlib.util.spec_from_file_location('modern_hook_under_test', SOURCE / 'modern_acceptance.py')
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    environment = {'GALLIUM_DRIVER': 'llvmpipe', 'LP_NUM_THREADS': '2',
                   'PATH': 'fixture-only', 'SYSTEMROOT': r'C:\Windows'}

    def rejection(call, label, errors=(ValueError, OSError)):
        COUNTS['acceptance hook'] += 1
        try:
            call()
        except errors:
            return
        FAILURES.append('acceptance hook: unsafe input accepted: ' + label)

    hook.validate_environment(environment)
    check(True, 'clean environment accepted', 'acceptance hook')
    hook.validate_environment({'gallium_driver': 'llvmpipe', 'lp_num_threads': '2'})
    check(True, 'Windows case-insensitive selection accepted', 'acceptance hook')
    for key, value in [('GALLIUM_DRIVER', 'softpipe'), ('GALLIUM_DRIVER', 'zink'),
                       ('LP_NUM_THREADS', '1'), ('LP_NUM_THREADS', '4'),
                       ('LP_NUM_THREADS', '02'), ('LP_NUM_THREADS', 2)]:
        altered = dict(environment); altered[key] = value
        rejection(lambda altered=altered: hook.validate_environment(altered), key + '=' + str(value))
    for key in ('GALLIUM_DRIVER', 'LP_NUM_THREADS'):
        altered = dict(environment); del altered[key]
        rejection(lambda altered=altered: hook.validate_environment(altered), 'missing ' + key)
    for key in ('MESA_GL_VERSION_OVERRIDE', 'MESA_GLSL_VERSION_OVERRIDE', 'MESA_EXTENSION_OVERRIDE',
                'MESA_DEBUG', 'LIBGL_ALWAYS_SOFTWARE', 'LIBGL_DRIVERS_PATH', 'NIR_DEBUG',
                'TGSI_PRINT_SANITY', 'DRAW_USE_LLVM', 'GALLIUM_HUD', 'GALLIUM_TRACE',
                'LP_DEBUG', 'LP_PERF', 'GALLIVM_PERF', 'GALLIVM_LLC_OPTIONS'):
        for spelling in (key, key.lower()):
            for value in ('', 'no_opt'):
                altered = dict(environment); altered[spelling] = value
                rejection(lambda altered=altered: hook.validate_environment(altered), spelling + '=' + value)
    for key in ('gallium_driver', 'lp_num_threads'):
        altered = dict(environment); altered[key] = environment[key.upper()]
        rejection(lambda altered=altered: hook.validate_environment(altered), 'duplicate key ' + key)

    class FakeRunner:
        def __init__(self, rows=ROWS, code=0, action=None):
            self.rows, self.code, self.action, self.calls = rows, code, action, []

        def command(self, name, argv, env, seconds, cwd):
            self.calls.append((name, argv, dict(env), seconds, cwd))
            if self.action:
                self.action()
            output = '\n'.join(self.rows).replace(DIRECTORY, str(cwd))
            return self.code, output

    def make_bundle(parent, number):
        bundle = parent / f'bundle-{number}'
        bundle.mkdir()
        records = {}
        for name in ('wgl-canary.exe', 'opengl32.dll', 'libgallium_wgl.dll'):
            # Deliberately not PE binaries. These bytes are never executable inputs.
            data = ('inert test fixture for ' + name).encode()
            (bundle / name).write_bytes(data)
            records[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        return bundle, records

    with tempfile.TemporaryDirectory(prefix='madeira-modern-host-') as temporary:
        parent = Path(temporary)
        bundle, audit = make_bundle(parent, 0)
        runner = FakeRunner()
        result = hook.accept_modern(runner, bundle, environment, audit, REF.parse_proof)
        check(result['proof']['modern']['status'] == 'passed', 'hook accepts complete strict fixture', 'acceptance hook')
        check(result['binaries_before'] == audit == result['binaries_after'],
              'hook preserves exact before/after identities', 'acceptance hook')
        check(result['process_deadline_seconds'] == 45, 'hook returns fixed deadline', 'acceptance hook')
        check(runner.calls == [('canary-modern-required',
              [bundle / 'wgl-canary.exe', '--stage', 'modern', '--source-built-reference'],
              environment, 45, bundle)], 'exact required invocation, clean environment, cwd and 45-second contract',
              'acceptance hook')
        check('no Blender/Madeira/iOS execution' in result['scope'], 'bounded acceptance scope', 'acceptance hook')
        rejection(lambda: hook.verify_bundle(bundle, {}), 'empty audited set')
        for name in sorted(audit):
            altered = {key: dict(value) for key, value in audit.items()}; del altered[name]
            rejection(lambda altered=altered: hook.verify_bundle(bundle, altered), 'missing audit ' + name)
            altered = {key: dict(value) for key, value in audit.items()}; altered['extra.dll'] = dict(audit[name])
            rejection(lambda altered=altered: hook.verify_bundle(bundle, altered), 'extra audit ' + name)
            for value in (0, -1, True, '1', 128*1024**2+1, audit[name]['size']+1):
                altered = {key: dict(record) for key, record in audit.items()}; altered[name]['size'] = value
                rejection(lambda altered=altered: hook.verify_bundle(bundle, altered), 'audit size ' + name + '/' + str(value))
            for value in ('0'*64, 'a'*63, 'a'*65, 'A'*64, 'z'*64, None):
                altered = {key: dict(record) for key, record in audit.items()}; altered[name]['sha256'] = value
                rejection(lambda altered=altered: hook.verify_bundle(bundle, altered), 'audit hash ' + name + '/' + str(value))
            for missing in ('size', 'sha256'):
                altered = {key: dict(record) for key, record in audit.items()}; del altered[name][missing]
                rejection(lambda altered=altered: hook.verify_bundle(bundle, altered), 'missing audit field ' + missing)
        for code in (1, 2, 77, -1, 124):
            runner = FakeRunner(code=code)
            def forbidden_parser(*args):
                raise AssertionError('nonzero exit reached parser')
            rejection(lambda runner=runner: hook.accept_modern(runner, bundle, environment, audit, forbidden_parser),
                      'nonzero exit cannot be overridden by parser ' + str(code))
        for forged in ({}, {'stage': 'legacy', 'status': 'passed', 'modern': {'required': True, 'status': 'passed'}},
                       {'stage': 'modern', 'status': 'unavailable', 'modern': {'required': True, 'status': 'passed'}},
                       {'stage': 'modern', 'status': 'passed'},
                       {'stage': 'modern', 'status': 'passed', 'modern': {'required': False, 'status': 'passed'}},
                       {'stage': 'modern', 'status': 'passed', 'modern': {'required': 1, 'status': 'passed'}},
                       {'stage': 'modern', 'status': 'passed', 'modern': {'required': True, 'status': 'unavailable'}}):
            rejection(lambda forged=forged: hook.accept_modern(FakeRunner(), bundle, environment, audit,
                      lambda *args: forged), 'mandatory modern proof fields ' + repr(forged))
        rejection(lambda: hook.accept_modern(FakeRunner(rows=ROWS[:-1]), bundle, environment, audit, REF.parse_proof),
                  'hook invokes real strict parser')
        invalid_env = dict(environment, MESA_GL_VERSION_OVERRIDE='4.6')
        runner = FakeRunner()
        rejection(lambda: hook.accept_modern(runner, bundle, invalid_env, audit, REF.parse_proof), 'override before command')
        check(not runner.calls, 'invalid environment rejected before command', 'acceptance hook')
        runner = FakeRunner()
        rejection(lambda: hook.accept_modern(runner, bundle, environment, {}, REF.parse_proof), 'invalid audit before command')
        check(not runner.calls, 'invalid bundle rejected before command', 'acceptance hook')

        mutations = [
            ('extra file', lambda b: (b / 'extra.dll').write_bytes(b'extra')),
            ('extra directory', lambda b: (b / 'nested').mkdir()),
        ]
        for name in sorted(audit):
            mutations.extend([
                ('missing ' + name, lambda b, name=name: (b / name).unlink()),
                ('same-size hash ' + name, lambda b, name=name:
                 (b / name).write_bytes(b'X' * (b / name).stat().st_size)),
                ('size ' + name, lambda b, name=name: (b / name).write_bytes(b'X')),
            ])
        number = 1
        for label, mutation in mutations:
            for when in ('before', 'after'):
                b, records = make_bundle(parent, number); number += 1
                runner = FakeRunner(action=lambda b=b, mutation=mutation: mutation(b)) if when == 'after' else FakeRunner()
                if when == 'before':
                    mutation(b)
                rejection(lambda runner=runner, b=b, records=records:
                          hook.accept_modern(runner, b, environment, records, REF.parse_proof), when + ' ' + label)
                check(len(runner.calls) == int(when == 'after'), 'mutation detected at correct boundary ' + when + ' ' + label,
                      'acceptance hook')
        for name in sorted(audit):
            b, records = make_bundle(parent, number); number += 1
            path = b / name
            external = parent / f'external-{number}'
            path.rename(external); path.symlink_to(external)
            rejection(lambda b=b, records=records: hook.verify_bundle(b, records), 'binary symlink ' + name)
            path.unlink(); path.mkdir()
            rejection(lambda b=b, records=records: hook.verify_bundle(b, records), 'directory in place of binary ' + name)
        alias = parent / 'bundle-alias'; alias.symlink_to(bundle, target_is_directory=True)
        rejection(lambda: hook.verify_bundle(alias, audit), 'bundle root symlink')
        def timeout():
            raise TimeoutError('synthetic process-tree deadline')
        rejection(lambda: hook.accept_modern(FakeRunner(action=timeout), bundle, environment, audit, REF.parse_proof),
                  'runner timeout propagates as failure', errors=(TimeoutError,))


if __name__ == '__main__':
    raise SystemExit(main())
