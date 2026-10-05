#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict supplemental proof contract. Pure parsing never establishes a GL pass.

windows_reference.parse_proof first validates original GDI/legacy/core evidence,
module paths, exit code, core version/profile and rejects any FAIL/UNAVAILABLE.
"""
import ntpath
import re

SEEDS = (0x13579BDF, 0x2468ACE0)
LIMITS = {'vertex_blocks': 12, 'fragment_blocks': 12, 'compute_blocks': 12,
          'bindings': 12, 'combined_blocks': 24, 'compute_invocations': 1,
          'draw_buffers': 2, 'color_attachments': 2, 'block_bytes': 16}


def word(seed, block, lane):
    x = ((seed ^ ((0x9E3779B9 * (block + 1)) & 0xFFFFFFFF)) + 0x85EBCA6B * (lane + 1)) & 0xFFFFFFFF
    x ^= x >> 16
    x = (x * 0x7FEB352D) & 0xFFFFFFFF
    return x ^ (x >> 15)


def checksums(seed):
    return tuple((0x31415927 * (lane + 1) + sum(word(seed, block, lane) * (2 * block + 3 + 2 * lane)
                  for block in range(12))) & 0xFFFFFFFF for lane in range(4))


def color(values):
    a, b, c, d = values
    return ((a ^ (b >> 8)) & 255, (b ^ (c >> 16)) & 255, (c ^ (d >> 24)) & 255, 255)


def instance_value(index):
    return 0x10203040 + 0x01010101 * index


def validate_modern(rows, expected_dir):
    """Require every expected independently checked result exactly once."""
    consumed = set()

    def record(prefix, pattern):
        matches = [(i, row) for i, row in enumerate(rows) if (row == prefix if prefix.startswith("PASS ") else row.startswith(prefix))]
        if len(matches) != 1:
            raise ValueError(f'Missing/repeated modern proof: {prefix}')
        index, row = matches[0]
        match = re.fullmatch(pattern, row)
        if not match:
            raise ValueError(f'Malformed modern proof: {prefix}')
        consumed.add(index)
        return match

    for checkpoint in ['modern-identity-limits', 'modern-storage', 'modern-indirect', 'modern-clip',
                       'modern-cleanup', 'modern-capabilities', 'modern-module-recheck', 'modern-platform-cleanup']:
        record(f'PASS stage={checkpoint}', re.escape(f'PASS stage={checkpoint}'))
    for name, filename in [('opengl32-after', 'opengl32.dll'), ('gallium-after', 'libgallium_wgl.dll')]:
        match = record(f'MODULE {name}=', rf'MODULE {name}=(.+)')
        if ntpath.normcase(ntpath.normpath(match[1])) != ntpath.normcase(ntpath.join(str(expected_dir), filename)):
            raise ValueError('Modern module path changed')
    identity = record('MODERN_IDENTITY ',
        r'MODERN_IDENTITY renderer=(llvmpipe \([^\r\n]+\)) version=(\d+)\.(\d+) \(Core Profile\) Mesa 26\.2\.4 glsl=(\d+)\.(\d+)')
    if (int(identity[2]), int(identity[3])) < (4, 3) or (int(identity[4]), int(identity[5])) < (4, 30):
        raise ValueError('Modern identity below required version')
    core = [re.fullmatch(r'CORE version=(\d+)\.(\d+) profile=0x1', row) for row in rows if row.startswith('CORE version=')]
    if len(core) != 1 or not core[0] or (core[0][1], core[0][2]) != (identity[2], identity[3]):
        raise ValueError('Core string/numeric identity disagree')
    legacy = [re.fullmatch(r'GL renderer=(.+) version=.+', row) for row in rows if row.startswith('GL renderer=')]
    if len(legacy) != 1 or not legacy[0] or legacy[0][1] != identity[1]:
        raise ValueError('Legacy/core renderer identity changed')
    extensions = record('MODERN_EXTENSIONS ', r'MODERN_EXTENSIONS enumerated=(\d+) draw_parameters=1 clip_control=1')
    if not 2 <= int(extensions[1]) <= 4096:
        raise ValueError('Invalid enumerated extension count')
    limits = {}
    for name, minimum in LIMITS.items():
        match = record(f'MODERN_LIMIT {name}=', rf'MODERN_LIMIT {name}=(\d+)')
        limits[name] = int(match[1])
        if not minimum <= limits[name] <= (2**63 - 1 if name == 'block_bytes' else 2**31 - 1):
            raise ValueError(f'Modern limit below floor/out of range: {name}')
    workgroups = []
    for axis in range(3):
        match = record(f'MODERN_WORKGROUP axis={axis} ', rf'MODERN_WORKGROUP axis={axis} count=(\d+) size=(\d+)')
        values = tuple(map(int, match.groups()))
        if any(not 1 <= n <= 2**31 - 1 for n in values):
            raise ValueError('Invalid compute workgroup limit')
        workgroups.append(values)
    shader_logs = []
    for program, stages in [('compute', [2]), ('storage', [0, 1]), ('indirect', [0, 1]), ('clip', [0, 1])]:
        for kind, stage in [('compile', stage) for stage in stages] + [('link', 3)]:
            prefix = f'MODERN_LOG program={program} kind={kind} stage={stage} '
            match = record(prefix, re.escape(prefix) + r'status=1 bytes=(\d+) hex=([0-9a-f]*)')
            if len(match[2]) != int(match[1]) * 2 or int(match[1]) > 2047:
                raise ValueError('Invalid/overlong shader log')
            shader_logs.append({'program': program, 'kind': kind, 'stage': stage, 'hex': match[2]})
    for program, compute in [('compute', 1), ('storage', 0)]:
        record(f'MODERN_BLOCK_COUNT program={program} ', f'MODERN_BLOCK_COUNT program={program} count=12')
        for block in range(12):
            prefix = f'MODERN_BLOCK program={program} block={block} '
            record(prefix, re.escape(prefix) + f'binding={block} bytes=16 vertex={1-compute} fragment={1-compute} compute={compute}')

    def pixel(phase, trial, sample, x, y, values, rgba=None):
        prefix = f'phase={phase} trial={trial} sample={sample} '
        value_text = ','.join(f'{value:08x}' for value in values)
        record('MODERN_UINT ' + prefix, re.escape(f'MODERN_UINT {prefix}xy={x},{y} values={value_text}'))
        colors = color(values) if rgba is None else rgba
        color_text = ','.join(map(str, colors))
        record('MODERN_PIXEL ' + prefix, re.escape(f'MODERN_PIXEL {prefix}xy={x},{y} rgba={color_text}'))

    sentinels = []
    for trial, seed in enumerate(SEEDS):
        for block in range(12):
            values = [word(seed, block, lane) for lane in range(4)]
            expected = ','.join(f'{value:08x}' for value in values)
            prefix = f'MODERN_SSBO trial={trial} '
            # Block is part of the key, so malformed/changed seed cannot disappear.
            matches = [row for row in rows if row.startswith(prefix) and re.search(rf' block={block} ', row)]
            exact = f'{prefix}seed={seed:08x} block={block} words={expected}'
            if matches != [exact]:
                raise ValueError('Missing/repeated/wrong compute sentinels')
            consumed.add(rows.index(exact))
            sentinels.append({'trial': trial, 'block': block, 'words': values})
        values = checksums(seed)
        pixel('storage', trial, 0, 4, 4, values)
        window_stage = f'modern-storage-window-{trial}'
        record(f'PASS stage={window_stage}', re.escape(f'PASS stage={window_stage}'))
        window = record(f'WINDOW_PIXEL stage={window_stage} ', rf'WINDOW_PIXEL stage={window_stage} rgb=(\d+),(\d+),(\d+)')
        if any(not 0 <= int(a) <= 255 or abs(int(a) - b) > 1 for a, b in zip(window.groups(), color(values))):
            raise ValueError('Missing/wrong post-swap storage backing pixel')
    for draw, (base_vertex, base_instance) in enumerate([(5, 7), (9, 11)]):
        for instance in range(2):
            values = (base_vertex, base_instance, draw, instance_value(base_instance + instance))
            pixel('indirect', draw, instance, 4 + 16 * draw, 4 + 16 * instance, values)
    for origin in range(2):
        for depth in range(2):
            for positive in range(2):
                trial = origin * 4 + depth * 2 + positive
                origin_value, depth_value = (0x8CA2 if origin else 0x8CA1), (0x935F if depth else 0x935E)
                expected = f'MODERN_CLIP trial={trial} origin=0x{origin_value:x} depth=0x{depth_value:x} z={"0.5" if positive else "-0.5"}'
                record(f'MODERN_CLIP trial={trial} ', re.escape(expected))
                for sample in range(2):
                    visible = sample == origin and (not depth or positive)
                    pixel('clip', trial, sample, 4, 27 if sample else 4,
                          (1, 2, 3, 4) if visible else (0, 0, 0, 0),
                          (255, 255, 255, 255) if visible else (0, 0, 0, 255))
                    match = record(f'MODERN_DEPTH trial={trial} sample={sample} ',
                        rf'MODERN_DEPTH trial={trial} sample={sample} value=(0(?:\.\d+)?|1(?:\.0+)?)')
                    wanted = (0.5 if depth else 0.75 if positive else 0.25) if visible else 1
                    if abs(float(match[1]) - wanted) > 0.000001:
                        raise ValueError('Clip depth readback does not match clip-control mode')
    elapsed = record('MODERN_ELAPSED ', r'MODERN_ELAPSED milliseconds=(\d+)')
    if not 0 <= int(elapsed[1]) < 45000:
        raise ValueError('Modern runtime exceeded deadline')
    for index, row in enumerate(rows):
        if row.startswith(('MODERN_', 'PASS stage=modern-', 'WINDOW_PIXEL stage=modern-', 'MODULE opengl32-after=', 'MODULE gallium-after=')) and index not in consumed:
            raise ValueError(f'Unexpected modern evidence: {row}')
    if rows[-1] != 'PASS requested-stage=modern':
        raise ValueError('Modern success must follow platform cleanup')
    positions = {row: index for index, row in enumerate(rows)}
    ordered = ['PASS stage=modern-storage', 'PASS stage=modern-indirect', 'PASS stage=modern-clip',
               'PASS stage=modern-cleanup', 'PASS stage=modern-capabilities', 'PASS stage=modern-module-recheck',
               'PASS stage=modern-platform-cleanup', 'PASS requested-stage=modern']
    if [positions[row] for row in ordered] != sorted(positions[row] for row in ordered):
        raise ValueError('Contradictory modern checkpoint order')
    return {'required': True, 'status': 'passed', 'limits': limits, 'workgroups': workgroups,
            'shader_logs': shader_logs, 'sentinels': sentinels,
            'storage_checksums': [checksums(seed) for seed in SEEDS],
            'indirect_draws': 2, 'instances_per_draw': 2, 'clip_draws': 8,
            'elapsed_milliseconds': int(elapsed[1]), 'blender_execution_proven': False,
            'madeira_execution_proven': False, 'ios_execution_proven': False}
