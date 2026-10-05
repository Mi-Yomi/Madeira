#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Bounded report-only symbol comparison; no Madeira or provider execution."""
from __future__ import annotations
import hashlib
import itertools
import json
import os
from pathlib import Path
import sys
import time

MAX_PROVIDERS = 64
MAX_PROVIDER_BYTES = 128 * 1024 ** 2
MAX_SYMBOLS = 4096
MAX_DEPTH = 32
MAX_SECONDS = 20
MAX_REPORT_BYTES = 1024 ** 2
LIMITS = [
    'Static selected probe imports and followed export/API-set names only',
    'No provider transitive-import, dynamic LoadLibrary, COM or SxS closure',
    'Export presence does not prove implementation, calling convention or thunk correctness',
    'No Madeira/Wine/FEX/ARM64EC/iOS execution or iPhone performance measurement',
    'Plain x86_64 probe and emitted x86_64 JIT code still need the guest CPU/JIT and ARM64EC import-transition path',
]


def resolve_symbol(module, symbol, importer, provider, schema, normalize, forwarder):
    """Keep the original importer through forwarders, matching the existing audit."""
    chain, seen = [], set()
    for _ in range(MAX_DEPTH):
        module = normalize(module)
        identity = (module, symbol, importer)
        entry = {'module': module, 'symbol': symbol}
        chain.append(entry)
        if identity in seen:
            return {'resolved': False, 'reason': 'forwarder/API-set cycle', 'chain': chain}
        seen.add(identity)
        if module.startswith(('api-', 'ext-')):
            api = schema()
            key = module.split('.', 1)[0].rsplit('-', 1)[0]
            values = api.get(key, [])
            hosts = [host for alias, host in values[1:] if alias == importer]
            if not hosts and values:
                hosts = [values[0][1]]
            if hosts and hosts[0]:
                entry['api_set_target'] = hosts[0]
                module = normalize(hosts[0])
                if module.startswith(('api-', 'ext-')):
                    continue
            elif key in api or provider(module) is None:
                return {'resolved': False, 'reason': 'unresolved API-set', 'chain': chain}
        table = provider(module)
        if table is None:
            return {'resolved': False, 'reason': 'missing module', 'chain': chain}
        names, ordinals = table
        exported = ordinals.get(symbol) if isinstance(symbol, int) else names.get(symbol)
        if exported is None:
            return {'resolved': False, 'reason': 'missing export', 'chain': chain}
        if 'forwarder' not in exported:
            return {'resolved': True, 'resolved_module': module, 'resolved_symbol': symbol,
                    'resolved_rva': exported['rva'], 'chain': chain}
        module, symbol = forwarder(exported['forwarder'])
    return {'resolved': False, 'reason': 'forwarder/API-set depth limit', 'chain': chain}


def assess(probe, root, source_commit, guard=lambda: None):
    """Return explicit incomplete/gap reports without changing native success."""
    root = Path(root)
    farm = root / 'app/Madeira/arm64ec-windows'
    start = time.monotonic()
    report = {'schema_version': 1, 'scope': 'report-only selected-import symbol comparison',
              'source_commit': source_commit, 'farm': 'app/Madeira/arm64ec-windows',
              'probe_sha256': probe['sha256'], 'probe_architecture': probe['architecture'],
              'probe_machine': probe['machine'], 'runtime_tested': False,
              'abi_transition_verified': False, 'jit_guest_execution_verified': False,
              'affects_native_windows_acceptance': False, 'limits': list(LIMITS),
              'status': 'incomplete', 'checks': [], 'providers': {}, 'complete': False}
    images, paths, tables, total_bytes = {}, {}, {}, 0
    api = None

    def bounded():
        guard()
        if time.monotonic() - start > MAX_SECONDS:
            raise ValueError('Static comparison exceeded its 20-second limit')

    try:
        sys.path.insert(0, str(root / 'build/wine-pe'))
        # Existing pure readers stay unchanged. No readobj or provider execution.
        from symbol_audit import _module, _read_pe, api_sets, exports, forwarder
        if farm.is_symlink() or not farm.is_dir() or not farm.resolve().is_relative_to(root.resolve()):
            raise ValueError('Same-checkout ARM64EC provider farm is unavailable')
        with os.scandir(farm) as scan:
            entries = list(itertools.islice(scan, 2049))
        if len(entries) > 2048:
            raise ValueError('Provider directory entry bound exceeded')
        for entry in entries:
            if not entry.name.lower().endswith('.dll'):
                continue
            name = _module(entry.name)
            if name in paths:
                raise ValueError('Case-colliding provider DLL names')
            paths[name] = farm / entry.name
        required = sum(len(item['symbols']) for item in probe['imports'])
        report['required_symbol_count'] = required
        if not 0 < required <= MAX_SYMBOLS:
            raise ValueError('Probe import symbol count is absent or exceeds comparison bound')

        def load(name):
            nonlocal total_bytes
            bounded()
            if name not in paths:
                return None
            if name not in images:
                if len(images) >= MAX_PROVIDERS:
                    raise ValueError('Provider count bound exceeded')
                if paths[name].stat().st_size > MAX_PROVIDER_BYTES - total_bytes:
                    raise ValueError('Provider byte bound would be exceeded')
                pe = _read_pe(paths[name])
                total_bytes += len(pe.data)
                if total_bytes > MAX_PROVIDER_BYTES:
                    raise ValueError('Provider byte bound exceeded')
                architecture = pe.architecture()
                if architecture not in {'arm64ec', 'x86_64'}:
                    raise ValueError(f'Wrong ARM64EC-farm provider architecture: {name}: {architecture}')
                images[name] = pe
                report['providers'][name] = {'sha256': hashlib.sha256(pe.data).hexdigest(),
                    'bytes': len(pe.data), 'machine': f'0x{pe.machine:04x}', 'architecture': architecture}
            return images[name]

        def provider(name):
            pe = load(name)
            if pe is None:
                return None
            if name not in tables:
                records = exports(pe)
                tables[name] = ({n: item for item in records for n in item['names']},
                                {item['ordinal']: item for item in records})
            return tables[name]

        def schema():
            nonlocal api
            if api is None:
                pe = load('apisetschema.dll')
                if pe is None:
                    raise ValueError('Required same-checkout API-set schema is unavailable')
                api = api_sets(pe)
            return api

        check_bytes = 0
        for item in probe['imports']:
            if item['kind'] not in {'import', 'delay'} or not item['symbols']:
                raise ValueError('Invalid or empty probe import descriptor')
            for value in item['symbols']:
                bounded()
                symbol = value.get('name', value.get('ordinal'))
                if symbol is None:
                    raise ValueError('Import lacks a name or ordinal')
                result = resolve_symbol(item['module'], symbol, 'abi-jit-probe.exe',
                                        provider, schema, _module, forwarder)
                check = {'kind': item['kind'], 'dependency': item['module'], 'symbol': symbol, **result}
                check_bytes += len(json.dumps(check).encode('utf-8'))
                if check_bytes > MAX_REPORT_BYTES - 65536:
                    raise ValueError('Symbol-resolution detail exceeds bounded log evidence')
                report['checks'].append(check)
                if result.get('reason') == 'forwarder/API-set depth limit':
                    raise ValueError('Forwarder/API-set depth limit leaves the remaining path uninspected')
        # Every parsed provider is bound to its immutable same-checkout bytes.
        for name, pe in images.items():
            bounded()
            if _read_pe(paths[name]).data != pe.data:
                raise ValueError('Provider changed during static comparison')
        unresolved = sum(not check['resolved'] for check in report['checks'])
        report.update(complete=True, unresolved_symbol_count=unresolved,
                      status='selected-import-gaps' if unresolved else 'selected-imports-resolved-statically')
    except (OSError, ValueError, ImportError) as exc:
        report.update(status='incomplete', complete=False, reason=str(exc))
    report.update(checked_symbol_count=len(report['checks']),
                  provider_bytes=total_bytes, seconds=round(time.monotonic() - start, 3))
    if len(json.dumps(report, sort_keys=True).encode('utf-8')) > MAX_REPORT_BYTES:
        # Exact probe imports remain in the independent PROBE_PE log record.
        report['checks'] = []
        report.update(status='incomplete', complete=False, reason='Static report exceeded 1-MiB log evidence bound',
                      symbol_check_details_omitted=True)
    return report
