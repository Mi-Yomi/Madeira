#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mandatory acceptance hook for a separately reviewed llvmpipe build runner.

No build, download, publication, or standalone execution entrypoint. The caller
supplies its bounded process-tree runner and the just-built PE dependency audit.
The existing softpipe workflow intentionally does not call this module.
"""
import hashlib
import re
from pathlib import Path

BUNDLE_NAMES = {'wgl-canary.exe', 'opengl32.dll', 'libgallium_wgl.dll'}
FORBIDDEN_PREFIXES = ('MESA_', 'LIBGL_', 'NIR_', 'TGSI_', 'DRAW_', 'GALLIVM_', 'GALLIUM_', 'LP_')


def validate_environment(env):
    """Driver/thread selection is permitted; capability overrides never are."""
    graphics = {key.upper(): value for key, value in env.items()
                if key.upper().startswith(FORBIDDEN_PREFIXES)}
    if graphics != {'GALLIUM_DRIVER': 'llvmpipe', 'LP_NUM_THREADS': '2'}:
        raise ValueError('Modern acceptance requires clean, bounded llvmpipe environment')
    if len([key for key in env if key.upper() in graphics]) != len(graphics):
        raise ValueError('Duplicate case-insensitive graphics environment keys')


def verify_bundle(bundle, audited_binaries):
    """Bind execution to the caller's exact audited outputs before and after."""
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir() or set(audited_binaries) != BUNDLE_NAMES:
        raise ValueError('Modern acceptance requires the exact audited runtime bundle')
    entries = list(bundle.iterdir())
    if len(entries) != 3 or {path.name for path in entries} != BUNDLE_NAMES:
        raise ValueError('Unexpected file/directory in modern runtime bundle')
    identities = {}
    for path in entries:
        record = audited_binaries[path.name]
        if (path.is_symlink() or not path.is_file() or
                not isinstance(record.get('size'), int) or isinstance(record['size'], bool) or
                not 1 <= record['size'] <= 128 * 1024**2 or
                not re.fullmatch(r'[0-9a-f]{64}', str(record.get('sha256', ''))) or
                path.stat().st_size != record['size']):
            raise ValueError('Invalid audited modern binary identity or size')
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != record['sha256']:
            raise ValueError('Modern runtime bundle hash changed')
        identities[path.name] = {'size': record['size'], 'sha256': actual}
    return identities


def accept_modern(runner, bundle, env, audited_binaries, parse_proof):
    """A required step: every nonzero result, including 77, fails the job.

    runner.command must enforce the supplied 45-second deadline by terminating the
    complete process tree, bound the log and total work/resources, and keep the
    receipt even on failure. audited_binaries must come from a reviewed PE-x64
    import/export closure audit of this same job's source-built outputs. Hash
    checks are evidence binding, not a substitute for that provenance audit.
    """
    validate_environment(env)
    before = verify_bundle(bundle, audited_binaries)
    bundle = Path(bundle)
    code, output = runner.command('canary-modern-required',
        [bundle / 'wgl-canary.exe', '--stage', 'modern', '--source-built-reference'],
        env, 45, bundle)
    after = verify_bundle(bundle, audited_binaries)
    if before != after:
        raise ValueError('Modern runtime identity changed during execution')
    if code != 0:
        raise ValueError(f'Required modern canary exited {code}')
    proof = parse_proof(output, code, 'modern', bundle)
    if (proof.get('stage') != 'modern' or proof.get('status') != 'passed' or
            proof.get('modern', {}).get('status') != 'passed' or
            proof.get('modern', {}).get('required') is not True):
        raise ValueError('Modern llvmpipe acceptance is mandatory, never optional/unavailable')
    return {'proof': proof, 'binaries_before': before, 'binaries_after': after,
            'process_deadline_seconds': 45,
            'scope': 'Windows llvmpipe graphics prerequisites only; no Blender/Madeira/iOS execution'}
