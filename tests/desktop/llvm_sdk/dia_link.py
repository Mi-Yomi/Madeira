#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded native Windows DIA member-selection diagnostic. Never run its output."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import struct
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
import provider_inventory as inv
import provider_member_evidence as member
p = inv.p
require, sha = p.require, p.sha
MIB = 1024 ** 2
MAX_CAPTURED_OBJECT = 128 * 1024
REQUIRED = frozenset(member.DIA_SYMBOLS)
FORBIDDEN_CRT = {'msvcrt', 'msvcrtd', 'msvcprt', 'msvcprtd', 'libcmtd', 'libcpmtd',
                 'vcruntime', 'vcruntimed', 'ucrt', 'ucrtd', 'libvcruntimed', 'libucrtd'}


class DiagnosticRun(p.Run):
    def guard(self, force=False):
        require(time.monotonic() - self.started <= 7 * 60, 'Seven-minute diagnostic deadline reached')
        super().guard(force)
        total = 0
        for path in self.work.rglob('*'):
            try:
                if path.is_file():
                    total += path.stat().st_size
            except FileNotFoundError:
                pass  # Compiler/linker temporary files may disappear between reads.
        require(total <= 64 * MIB, '64-MiB diagnostic work cap exceeded')


def load_request():
    path = HERE / 'dia-link-request.json'
    data = json.loads(path.read_text())
    require(data.get('schema_version') == 1 and
            re.fullmatch(r'llvm-dia-member-link-[0-9]{8}-[0-9]+', data.get('request', '')),
            'Invalid DIA diagnostic request')
    require(data.get('maximum_job_minutes') == 10 and data.get('maximum_compile_jobs') == 1 and
            data.get('maximum_link_jobs') == 1, 'Diagnostic budget changed')
    for name in ['compilation', 'linking']:
        require(data.get(name) is True, 'Missing link-only diagnostic intent')
    for name in ['sdk_download', 'runtime_execution', 'jit', 'installations', 'system_mutation',
                 'artifact_upload', 'cache', 'signing_or_ipa']:
        require(data.get(name) is False, 'Diagnostic scope broadened: ' + name)
    return data, sha(path)


def winpath(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\0\r\n"'), 'Unsafe trace path')
    return str(PureWindowsPath(value)).casefold()


def object_evidence(data):
    evidence = member.coff_evidence(data)
    require(evidence['header']['status'] == 'x64-coff-structure-observed-unreviewed',
            'Diagnostic source object is not complete x64 COFF')
    undefined = {x['name'] for x in evidence['symbols'] if x['storage_class'] == 2 and
                 x['section'] == 0 and x['value'] == 0 and x['auxiliary_count'] == 0}
    live_sections = {x['index'] for x in evidence['sections'] if not x['debug'] and
                     x['name'] not in {'.drectve', '.chks64'} and x['size'] > 0}
    relocated = {x['symbol_name'] for x in evidence['relocations'] if x['type'] != '0x0000' and
                 x['section'] in live_sections}
    require(REQUIRED <= undefined and REQUIRED <= relocated,
            'All three exact strong undefined DIA references and real relocations are required')
    require(all(sum(x['name'] == name for x in evidence['symbols']) == 1 for name in REQUIRED),
            'Required source-object symbol identity is ambiguous')
    directives = inv.parse_directives(' '.join(x.get('raw_directives', '') for x in evidence['sections']))
    return evidence, directives


def capture_source_object(path, source_hash, recorder):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_CAPTURED_OBJECT,
            'Missing/empty/oversized source-object evidence (128 KiB cap)')
    with path.open('rb') as stream:
        data = stream.read(MAX_CAPTURED_OBJECT + 1)
    require(0 < len(data) <= MAX_CAPTURED_OBJECT and path.stat().st_size == len(data),
            'Source-object evidence changed or exceeded the 128 KiB cap')
    recorder.emit('DIA_COMPILED_OBJECT_BYTES', {
        'scope': 'source-owned diagnostic object only; never linked or executed by evidence collection',
        'semantic_gates': 'not-yet-evaluated', 'encoding': 'base64', 'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(), 'source_sha256': source_hash,
        'data_b64': base64.b64encode(data).decode('ascii')})
    return data


def require_release_crt(row, require_default=False):
    defaults = set(row.get('default_libraries', []))
    require(not defaults & FORBIDDEN_CRT, 'Selected member requests a dynamic/debug CRT')
    tags = row.get('mismatch_tags', {})
    if 'RuntimeLibrary' in tags:
        require(tags['RuntimeLibrary'] == ['MT_StaticRelease'], 'Selected member has incompatible RuntimeLibrary tag')
    if '_ITERATOR_DEBUG_LEVEL' in tags:
        require(tags['_ITERATOR_DEBUG_LEVEL'] == ['0'], 'Selected member has a debug iterator ABI')
    require(all(len(values) == 1 for values in tags.values()), 'Selected member contains conflicting ABI tags')
    for token in row.get('other_directives_unreviewed', []):
        directive = re.match(r'[/-]([A-Za-z0-9_]+)', token)
        require(directive is not None and directive[1].lower() not in
                {'force', 'nodefaultlib', 'wholearchive', 'ignore', 'wx', 'libpath'},
                'Selected member contains a linker override/suppression directive')
    if require_default:
        # The real source object from run 37470687893 also names uuid.lib.
        # UUID is GUID data, already a mandatory inventoried/hash-bound explicit
        # link input; it does not broaden the static CRT family or provider set.
        require('libcmt' in defaults and defaults <= {'libcmt', 'oldnames', 'uuid'},
                'Source object does not establish its ordinary release /MT defaults')


def parse_link_selection(text, providers):
    """Require loaded records, resolving basenames only under their preceding exact search path."""
    require(len(text.encode('utf-8')) <= 8 * MIB, 'Link trace cap')
    bypath = {winpath(row['path']): name for name, row in providers.items()}
    require(len(bypath) == len(providers), 'Provider paths are ambiguous')
    loaded, searched, current = [], set(), None
    for line in text.splitlines():
        stripped = line.strip()
        search = re.fullmatch(r'Searching (.+\.lib):', stripped, re.I)
        if search:
            key = winpath(search[1])
            require(key in bypath, 'Link searched an unrecorded provider: ' + search[1])
            current = bypath[key]
            searched.add(current)
        elif stripped.startswith('Searching ') and '.lib' in stripped.lower():
            raise ValueError('Unrecognized provider-search trace')
        if stripped.startswith('Loaded '):
            match = re.fullmatch(r'Loaded (.+\.lib)\((.+)\)', stripped, re.I)
            require(match is not None, 'Unrecognized loaded-member record')
            archive, object_name = match.groups()
            key = winpath(archive)
            if PureWindowsPath(archive).is_absolute():
                require(key in bypath, 'Link loaded an unrecorded provider')
                name = bypath[key]
            else:
                require(PureWindowsPath(archive).name == archive and current is not None and
                        winpath(PureWindowsPath(providers[current]['path']).name) == key,
                        'Loaded provider basename lacks an exact matching search path')
                name = current
            require(name in searched, 'Loaded provider lacks recorded exact search evidence')
            entry = {'provider': name, 'member': object_name}
            require(len(loaded) < 10000, 'Excessive loaded-member evidence')
            loaded.append(entry)
    require(loaded, 'No actual loaded-member records in link trace')
    return loaded


def select_member(rows, value):
    key = winpath(value)
    exact = [row for row in rows if winpath(row['member']) == key]
    if exact:
        require(len(exact) == 1, 'Duplicate exact member identity')
        return exact[0]
    require(PureWindowsPath(value).name == value, 'Unmatched full archive member path')
    matches = [row for row in rows if winpath(PureWindowsPath(row['member']).name) == key]
    require(len(matches) == 1, 'Absent or ambiguous member basename')
    return matches[0]


def map_owners(text):
    require(len(text.encode('utf-8')) <= 8 * MIB, 'Link map cap')
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] not in REQUIRED:
            continue
        require(len(fields) >= 4 and re.fullmatch(r'[0-9a-fA-F]{4}:[0-9a-fA-F]{8,16}', fields[0]) and
                re.fullmatch(r'[0-9a-fA-F]{8,16}', fields[2]), 'Malformed required map symbol record')
        tail = fields[3:]
        while tail and tail[0] in {'f', 'i'}:
            tail.pop(0)
        require(len(tail) == 1 and fields[1] not in found, 'Ambiguous map ownership')
        match = re.fullmatch(r'diaguids(?:\.lib)?:(.+)', tail[0], re.I)
        require(match is not None, 'Required symbol is not owned by the actual DIA archive')
        found[fields[1]] = match[1]
    require(set(found) == REQUIRED, 'Map omits one or more required DIA definitions')
    return found


def verify_selection(trace, map_text, providers, objects, dia_details):
    loaded = parse_link_selection(trace, providers)
    selected = []
    for item in loaded:
        if providers[item['provider']]['role']['kind'] == 'os_import':
            # Windows import archives reuse a DLL member name for many imports.
            # This trace cannot establish a unique object offset for those names.
            key = winpath(item['member'])
            candidates = [row for row in objects[item['provider']] if winpath(row['member']) == key]
            require(candidates, 'Loaded import member is absent from recorded provider')
            for candidate in candidates:
                require_release_crt(candidate)
                modules = set(candidate.get('imported_modules', []))
                if candidate.get('imported_module'):
                    modules.add(candidate['imported_module'])
                require(candidate.get('machine') == '0x8664' and not candidate.get('executable_sections') and
                        (candidate.get('kind') == 'short_import' or candidate.get('import_sections')) and
                        modules <= inv.OBSERVED_OS_DLLS and not candidate.get('other_directives_unreviewed'),
                        'Ambiguous import member includes unknown code/module/directives')
            selected.append({**item, 'candidate_count': len(candidates),
                             'member_identity': 'ambiguous-within-verified-import-archive',
                             'exact_import_member_selection_proven': False})
            continue
        row = select_member(objects[item['provider']], item['member'])
        require_release_crt(row)
        require(not any(x.get('provider') == item['provider'] and x.get('member') == row['member'] for x in selected),
                'Duplicate static-code member selection')
        selected.append({'provider': item['provider'], 'member': row['member'],
                         'archive_header_offset': row['archive_header_offset'], 'size': row['size']})
    dia = [x for x in selected if x['provider'] == 'diaguids']
    require(dia, 'DIA archive was not actually selected')
    owners = map_owners(map_text)
    expected = {}
    for symbol in REQUIRED:
        definitions = [row for row in dia_details if symbol in row['strong_definitions']]
        require(len(definitions) == 1, 'DIA symbol definition is missing or ambiguous')
        expected[symbol] = definitions[0]
        observed = select_member(dia_details, owners[symbol])
        require(observed['member'] == definitions[0]['member'] and
                any(x['member'] == observed['member'] for x in dia), 'Map/trace/COFF symbol owner disagreement')
    expected_names = {x['member'] for x in expected.values()}
    require({x['member'] for x in dia} == expected_names, 'Unexpected DIA member selected; no implicit PCH exception')
    for row in dia:
        detail = select_member(dia_details, row['member'])
        row['sha256'] = detail['sha256']
    return {'loaded_members': selected, 'dia_members': dia,
            'required_symbol_owners': {name: row['member'] for name, row in sorted(expected.items())}}


def collect_providers(requirements, tool_record, runner, recorder):
    roots = inv.provider_roots(tool_record)
    providers, objects, findings, total = {}, {}, [], 0
    for name, role in sorted(requirements['provider_roles'].items()):
        try:
            path = inv.resolve_provider(name, role, roots)
        except (ValueError, OSError) as exc:
            if role['required']:
                raise
            recorder.emit('DIA_OPTIONAL_PROVIDER_ABSENT', {'name': name, 'reason': str(exc)})
            continue
        size = path.stat().st_size
        total += size
        require(size <= inv.MAX_PROVIDER and total <= inv.MAX_PROVIDER_BYTES, 'Provider-byte cap')
        rows = []
        record = inv.scan_library(path, rows.append, runner.guard)
        record.update(path=str(path), role=role, link_approved=False)
        providers[name], objects[name] = record, rows
        recorder.emit('DIA_PROVIDER', {'name': name, **record})
        for row in rows:
            recorder.emit('DIA_PROVIDER_MEMBER', {'provider': name, **row})
        findings.extend(inv.provider_findings(name, role, record, requirements['provider_roles']))
    for name, row in providers.items():
        for dependency in row['default_libraries']:
            if dependency in requirements['provider_roles'] and dependency not in providers:
                findings.append({'kind': 'unresolved_known_provider_edge', 'provider': name,
                                 'dependency': dependency, 'status': 'rejected'})
    for finding in findings:
        recorder.emit('DIA_PROVIDER_FINDING', finding)
    # These are observations, not an approval gate silently relaxed for this diagnostic.
    return roots, providers, objects, findings


def dia_members(path, runner, recorder):
    details = []
    for row, data in member.archive_members(path, True, runner.guard):
        evidence = member.coff_evidence(data, runner.guard)
        require(evidence['header']['status'] == 'x64-coff-structure-observed-unreviewed',
                'DIA contains an unknown member format')
        directives = inv.parse_directives(' '.join(x.get('raw_directives', '') for x in evidence['sections']))
        detail = {**row, 'sha256': hashlib.sha256(data).hexdigest(), **directives,
                  'strong_definitions': [x['name'] for x in evidence['symbols'] if
                                         x['storage_class'] == 2 and x['section'] > 0],
                  'provider_approved': False}
        recorder.emit('DIA_MEMBER', detail)
        details.append(detail)
    return details


def emit_text(recorder, kind, text):
    require(len(text.encode('utf-8')) <= 8 * MIB, 'Native diagnostic text cap')
    for line in text.splitlines():
        recorder.emit(kind, {'text': line})


def diagnostic(work):
    require(os.name == 'nt' and platform.machine().lower() in {'amd64', 'x86_64'}, 'Native x64 Windows required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'Mi-Yomi/Madeira' and
            os.environ.get('GITHUB_REF') == 'refs/heads/compatibility/desktop-apps' and
            os.environ.get('GITHUB_EVENT_NAME') == 'push', 'Wrong repository/ref/request-push event')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    require(event.get('repository', {}).get('private') is False, 'Public-repository guard missing')
    request, request_hash = load_request()
    requirements, inventory_request = inv.load_requirements()
    lock = json.loads((HERE / 'inputs.lock.json').read_text())
    require(platform.python_version() == lock['host_python'] and sys.maxsize > 2 ** 32, 'Pinned x64 Python required')
    temp, work = Path(os.environ['RUNNER_TEMP']).resolve(), work.absolute()
    require(not work.exists() and not work.is_symlink() and work.resolve().is_relative_to(temp) and
            work.resolve() != temp and not work.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(work.resolve()),
            'Diagnostic root must be fresh, below RUNNER_TEMP, separate from checkout')
    work.mkdir(parents=True)
    (work / 'temp').mkdir()
    job = p.install_job_limits()  # Kept live; no generated binary is ever started.
    runner = DiagnosticRun(work)
    runner.guard(True)
    threading.Thread(target=runner.monitor, daemon=True).start()
    recorder = inv.Recorder(work / 'dia-link-evidence.jsonl')
    result = {'status': 'incomplete-rejected', 'compiled': False, 'linked': False,
              'runtime_tested': False, 'jit_executed': False, 'sdk_downloaded': False,
              'provider_closure_approved': False, 'sdk_abi_jit_verified': False,
              'madeira_abi_or_runtime_verified': False, 'source_commit': os.environ.get('GITHUB_SHA'),
              'request': request['request'], 'request_sha256': request_hash,
              'requirements_sha256': inventory_request['requirements_sha256']}
    try:
        tools, env, tool_record = p.tool_environment(runner)
        env['VSLANG'] = '1033'
        recorder.emit('DIA_TOOLCHAIN', {'request': request, 'image_version': os.environ.get('ImageVersion'),
                                      'tool_record': tool_record})
        roots, providers, objects, findings = collect_providers(requirements, tool_record, runner, recorder)
        details = dia_members(Path(providers['diaguids']['path']), runner, recorder)
        # Restrict linker search to the exact recorded toolchain roots. Ordinary defaults remain enabled.
        env['LIB'] = os.pathsep.join(str(roots[key]) for key in ['msvc', 'windows_um', 'windows_ucrt', 'atl', 'dia'])
        source, obj, exe, mapfile = HERE / 'dia_link_probe.cpp', work / 'dia-probe.obj', work / 'dia-probe.exe', work / 'dia-probe.map'
        source_hash = sha(source)
        recorder.emit('DIA_INPUTS', {'source_sha256': source_hash, 'source': str(source),
            'required_symbols': sorted(REQUIRED), 'lib_search': env['LIB'],
            'raw_sdk_edge': requirements['external_dia_edge'], 'metadata_modified': False,
            'dia_provider': providers['diaguids']['path'], 'dia_sha256': providers['diaguids']['sha256']})
        code, output = runner.command('dia-compile', [tools['cl'], '/nologo', '/c', '/O2', '/MT', '/W4', '/WX',
            '/std:c++17', '/GR-', '/EHs-c-', '/D_HAS_EXCEPTIONS=0', '/D_ITERATOR_DEBUG_LEVEL=0', '/DNDEBUG',
            '/Fo' + str(obj), source], env, 60, required=False)
        emit_text(recorder, 'DIA_COMPILER_LINE', output)
        require(code == 0, 'Diagnostic source compilation failed')
        result['compiled'] = True
        object_bytes = capture_source_object(obj, source_hash, recorder)
        evidence, directives = object_evidence(object_bytes)
        recorder.emit('DIA_COMPILED_OBJECT', {'header': evidence['header'], 'directives': directives,
            'crt_gate_status': 'not-yet-evaluated',
            'raw_directive_text_format': 'ASCII with NUL bytes represented as spaces; exact bytes in DIA_COMPILED_OBJECT_BYTES',
            'raw_directive_sections': [{key: section[key] for key in
                                       ['index', 'raw_directives', 'raw_sha256', 'size']}
                                      for section in evidence['sections'] if 'raw_directives' in section],
            'required_symbols': [x for x in evidence['symbols'] if x['name'] in REQUIRED],
            'required_relocations': [x for x in evidence['relocations'] if x['symbol_name'] in REQUIRED]})
        require_release_crt(directives, True)
        args = ['/NOLOGO', '/MACHINE:X64', '/INCREMENTAL:NO', '/WX', '/VERBOSE:LIB',
                '/MAP:' + str(mapfile), '/OUT:' + str(exe), str(obj)]
        args += [providers[name]['path'] for name in ['diaguids', 'uuid', 'advapi32', 'kernel32']]
        require(all(not any(c in x for c in '\0"\r\n') for x in args), 'Unsafe linker response argument')
        response = work / 'dia-link.rsp'
        response.write_text('\n'.join('"' + x + '"' for x in args) + '\n', encoding='utf-8')
        code, trace = runner.command('dia-link', [tools['link'], '@' + str(response)], env, 90, required=False)
        result['linked'] = code == 0
        emit_text(recorder, 'DIA_LINK_LINE', trace)
        if mapfile.is_file():
            require(mapfile.stat().st_size <= 8 * MIB, 'Link map size cap')
            map_text = mapfile.read_text(encoding='utf-8', errors='strict')
            emit_text(recorder, 'DIA_MAP_LINE', map_text)
        else:
            map_text = ''
        for name, row in providers.items():
            require(Path(row['path']).stat().st_size == row['size'] and sha(row['path']) == row['sha256'],
                    'Provider changed during diagnostic: ' + name)
        require(sha(source) == source_hash, 'Diagnostic source changed during compile/link')
        require(code == 0, 'Diagnostic link failed; trace retained')
        selection = verify_selection(trace, map_text, providers, objects, details)
        recorder.emit('DIA_SELECTION', selection)
        pe = p.audit_pe(exe)
        recorder.emit('DIA_PE', pe)
        result.update(status='minimal-dia-mt-link-selection-observed',
                      provider_finding_count=len(findings), provider_count=len(providers),
                      selected_dia_members=selection['dia_members'], executable_sha256=pe['sha256'],
                      executable_never_executed=True, link_configuration='Release /MT, no /DEBUG, ordinary defaults')
        return 0
    except Exception as exc:
        result['reason'] = str(exc)
        return 2
    finally:
        result.update(seconds=round(time.monotonic() - runner.started, 3), commands=runner.records,
                      evidence_sha256_before_receipt=sha(recorder.path))
        recorder.emit('DIA_LINK_DIAGNOSTIC', result)
        recorder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-root', type=Path, required=True)
    try:
        return diagnostic(parser.parse_args().work_root)
    except Exception as exc:
        print('DIA_LINK_STOP ' + json.dumps({'status': 'incomplete-rejected', 'reason': str(exc),
              'runtime_tested': False, 'provider_closure_approved': False, 'sdk_abi_jit_verified': False}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
