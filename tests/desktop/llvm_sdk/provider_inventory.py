#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only inventory of preinstalled Windows providers. Never an SDK/link/JIT pass."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import struct
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('sdk_preflight', HERE / 'preflight.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
detail_spec = importlib.util.spec_from_file_location('provider_member_evidence', HERE / 'provider_member_evidence.py')
detail = importlib.util.module_from_spec(detail_spec)
detail_spec.loader.exec_module(detail)
require, sha = p.require, p.sha
MIB = 1024 ** 2
MAX_PROVIDER = 256 * MIB
MAX_PROVIDER_BYTES = 1024 * MIB
MAX_RECORD_BYTES = 32 * MIB
MAX_MEMBER_RECORD = 256 * 1024
MAX_SECONDS = 7 * 60
MAX_MEMBERS = 100000
SDK_SHA = 'ed775bdaea7087c6c1aeac9498352cfcd8610d92dc4fe9eda9aecb15ce712a2c'
EXPLICIT_SYSTEMS = {'advapi32', 'delayimp', 'ntdll', 'ole32', 'psapi', 'shell32', 'uuid', 'ws2_32'}
EXPORTED_OPTIONS = {'-delayload:shell32.dll', '-delayload:ole32.dll', '-INCLUDE:malloc'}
SDK_MISMATCH_TAGS = {
    'RuntimeLibrary': {'MT_StaticRelease'}, 'LLVM_ENABLE_ABI_BREAKING_CHECKS': {'0'},
    '_ITERATOR_DEBUG_LEVEL': {'0'}, '_CRT_STDIO_ISO_WIDE_SPECIFIERS': {'0'},
    '_MSC_VER': {'1900'}, 'annotate_string': {'0'}, 'annotate_vector': {'0'},
    '_PPLTASK_ASYNC_LOGGING': {'1'}, 'ppltask_saved_frame_numbers': {'PPL_TASK_SAVE_FRAME_COUNT'},
}
OBSERVED_OS_DLLS = p.SYSTEM_DLLS | {'oleaut32.dll'}
DIA_EDGE = 'C:/Program Files/Microsoft Visual Studio/2022/Enterprise/DIA SDK/lib/amd64/diaguids.lib'
ROLE_NAMES = {
    'windows_um': {'advapi32', 'kernel32', 'ntdll', 'ole32', 'oleaut32', 'psapi',
                   'shell32', 'shlwapi', 'user32', 'ws2_32', 'uuid'},
    'windows_ucrt': {'libucrt'},
    'msvc': {'libcmt', 'libcpmt', 'libvcruntime', 'oldnames', 'delayimp', 'libconcrt'},
    'atl': {'atls'}, 'dia': {'diaguids'},
}
EXPECTED_ROLES = {name: root for root, names in ROLE_NAMES.items() for name in names}


def load_requirements():
    path = HERE / 'provider-requirements.json'
    request = json.loads((HERE / 'provider-inventory-request.json').read_text())
    require(request.get('schema_version') == 1 and
            request.get('requirements_sha256') == sha(path), 'Request/requirements digest disagreement')
    require(re.fullmatch(r'llvm-msvc-provider-inventory-[0-9]{8}-[0-9]+', request.get('request', '')),
            'Invalid explicit request token')
    require(request.get('maximum_job_minutes') == 10, 'Unexpected requested budget')
    for name in ['sdk_download', 'compilation', 'linking', 'jit', 'installations',
                 'system_mutation', 'artifact_upload', 'cache', 'signing_or_ipa']:
        require(request.get(name) is False, 'Inventory request broadened: ' + name)
    data = json.loads(path.read_text())
    validate_requirements(data)
    return data, request


def validate_requirements(data):
    require(data.get('schema_version') == 1 and data.get('sdk', {}).get('sha256') == SDK_SHA,
            'Unknown SDK source inventory')
    selected = data.get('selected_libraries_link_order', [])
    require(len(selected) == 70 and len(set(selected)) == 70 and
            all(re.fullmatch(r'LLVM[A-Za-z0-9_]+', x) for x in selected), 'Invalid exact selected set')
    require(set(selected) == set(data.get('selected_libraries', {})) == set(data.get('exported_edges', {})) ==
            set(data.get('exported_link_options', {})), 'Incomplete selected-library evidence')
    require({'LLVMBitWriter', 'LLVMDebugInfoPDB', 'LLVMInterpreter', 'LLVMMCA', 'LLVMX86TargetMCA'} <= set(selected),
            'Exact SDK component-alias evidence missing')
    require(not {'LLVMWindowsDriver', 'LLVMWindowsManifest', 'LLVMOrcJIT'} & set(selected),
            'Unreviewed expanded SDK selection')
    for row in data['selected_libraries'].values():
        require(re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')) and
                0 < row.get('size', 0) <= MAX_PROVIDER and row.get('objects', 0) > 0,
                'Invalid SDK archive evidence')
        require(all(key in SDK_MISMATCH_TAGS and set(values) <= SDK_MISMATCH_TAGS[key] and
                    len(values) == 1 for key, values in row.get('mismatches', {}).items()),
                'Unreviewed SDK mismatch evidence')
    defaults = {name for row in data['selected_libraries'].values() for name in row['default_libraries']}
    require(defaults == set(data.get('coff_default_libraries', [])) and defaults <= set(EXPECTED_ROLES),
            'Unreviewed/incomplete SDK defaults')
    roles = data.get('provider_roles', {})
    require(set(roles) == set(EXPECTED_ROLES), 'Provider inventory roles changed')
    for name, role in roles.items():
        require(role.get('root') == EXPECTED_ROLES[name], 'Provider root role changed: ' + name)
        kind = 'guid_data' if name in {'uuid', 'diaguids'} else 'os_import' if role['root'] == 'windows_um' else 'static_code'
        require(role.get('kind') == kind and role.get('required') is (name != 'libconcrt'),
                'Provider kind/requirement changed: ' + name)
    dia = data.get('external_dia_edge', {})
    require(dia.get('target') == 'LLVMDebugInfoPDB' and dia.get('raw') == DIA_EDGE and
            dia.get('relative_to_selected_vs') == 'DIA SDK/lib/amd64/diaguids.lib', 'Unknown DIA producer edge')
    require(DIA_EDGE in data['exported_edges']['LLVMDebugInfoPDB'], 'DIA edge absent from exact graph')
    require(set(data.get('explicit_system_libraries', [])) == EXPLICIT_SYSTEMS and
            set(data.get('link_options', [])) == EXPORTED_OPTIONS, 'Unreviewed explicit library/options policy')
    require(all(item in EXPORTED_OPTIONS for options in data['exported_link_options'].values() for item in options if item),
            'Unknown exported link option')
    allowed = set(selected) | EXPLICIT_SYSTEMS | EXPORTED_OPTIONS | {DIA_EDGE}
    require(all(item in allowed for edges in data['exported_edges'].values() for item in edges if item),
            'Unknown exported edge')


def directive_tokens(text):
    require(len(text) <= MIB and all(c in '\t\r\n' or ord(c) >= 32 for c in text), 'Invalid directive text')
    tokens, last = [], 0
    for match in re.finditer(r'(?:[^\s"]|"[^"]*")+', text):
        require(not text[last:match.start()].strip(), 'Unparsed directive gap/quote')
        tokens.append(match.group())
        last = match.end()
    require(not text[last:].strip(), 'Unparsed directive tail/quote')
    return tokens


def parse_directives(text):
    defaults, mismatches, other, kinds = set(), defaultdict(set), [], Counter()
    for token in directive_tokens(text):
        match = re.fullmatch(r'[/-]([A-Za-z0-9_]+)(?::(.*))?', token)
        require(match is not None, 'Malformed linker directive')
        key, value = match[1].lower(), (match[2] or '')
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        kinds[key] += 1
        if key == 'defaultlib':
            require(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', value), 'Unsafe default-library name')
            defaults.add(value.lower().removesuffix('.lib'))
        elif key == 'failifmismatch':
            name, separator, val = value.partition('=')
            require(separator and re.fullmatch(r'[A-Za-z0-9_]{1,128}', name) and 0 < len(val) <= 256,
                    'Malformed mismatch directive')
            mismatches[name].add(val)
        else:
            other.append(token)
    return {'default_libraries': sorted(defaults), 'mismatch_tags': {k: sorted(v) for k, v in sorted(mismatches.items())},
            'other_directives_unreviewed': other, 'directive_kinds': dict(kinds)}


def scan_library(path, emit=lambda record: None, guard=lambda: None):
    """Bounded regular COFF, bigobj and short-import inventory; never load provider code."""
    size = path.stat().st_size
    require(8 <= size <= MAX_PROVIDER, 'Missing/oversized provider archive')
    digest = sha(path)
    counts, defaults, mismatches, others, modules = Counter(), set(), defaultdict(set), set(), set()
    members = 0
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'Not a regular COFF archive')
        pos, longnames = 8, b''
        while pos < size:
            guard()
            stream.seek(pos)
            header = stream.read(60)
            require(len(header) == 60 and header[58:] == b'`\n', 'Invalid archive member header')
            number = header[48:58].strip()
            require(number.isdigit(), 'Invalid archive member length')
            length, start = int(number), pos + 60
            require(start + length <= size, 'Truncated archive member')
            name = header[:16].decode('ascii').strip()
            if name == '//':
                require(not longnames and length <= 16 * MIB, 'Duplicate/oversized longnames table')
                longnames = stream.read(length)
            elif name != '/':
                members += 1
                require(members <= MAX_MEMBERS, 'Too many provider objects')
                if name.startswith('/') and name[1:].isdigit():
                    offset = int(name[1:])
                    require(offset < len(longnames), 'Invalid archive long-name offset')
                    end = longnames.find(b'\0', offset)
                    if end < 0:
                        end = longnames.find(b'/\n', offset)
                    require(0 <= end - offset <= 4096, 'Unterminated/oversized member name')
                    name = longnames[offset:end].decode('utf-8')
                else:
                    require(not name.startswith(('/', '#')) and len(name) <= 16, 'Unknown archive name format')
                    name = name.removesuffix('/')
                require(name and not any(ord(c) < 32 for c in name), 'Invalid member name')
                head = stream.read(min(length, 56))
                require(len(head) >= 20, 'Short COFF member')
                require(not head.startswith((b'BC\xc0\xde', b'\xde\xc0\x17\x0b')), 'Unreviewed bitcode provider')
                row = {'member': name, 'archive_header_offset': pos, 'size': length, 'machine': '0x8664'}
                if head[:2] == b'\0\0' and head[:4] != b'\0\0\xff\xff':
                    require(length <= detail.MAX_NEUTRAL_OBJECT, 'Neutral member size cap')
                    stream.seek(start)
                    evidence = detail.coff_evidence(stream.read(length), guard)
                    require(evidence['header']['status'] in {'neutral-weak-alias-observed-unreviewed',
                            'neutral-debug-weak-alias-observed-unreviewed'}, 'Unreviewed neutral member')
                    row.update(kind='neutral_coff', machine='0x0000', architecture='neutral', provider_approved=False,
                               section_count=evidence['header']['section_count'], executable_sections=0,
                               import_sections=[], imported_modules=[], raw_directives=[], default_libraries=[],
                               mismatch_tags={}, other_directives_unreviewed=[], directive_kinds={},
                               neutral_evidence=evidence)
                    counts['neutral_coff'] += 1
                elif head[:4] == b'\0\0\xff\xff' and struct.unpack_from('<H', head, 4)[0] == 0:
                    machine = struct.unpack_from('<H', head, 6)[0]
                    data_size, ordinal, flags = struct.unpack_from('<IHH', head, 12)
                    require(machine == 0x8664 and 0 < data_size <= MIB and 20 + data_size == length,
                            'Wrong/unbounded short import member')
                    require(flags >> 5 == 0 and flags & 3 <= 2 and (flags >> 2) & 7 <= 4, 'Unknown short import flags')
                    stream.seek(start + 20)
                    data = stream.read(data_size)
                    require(data.endswith(b'\0'), 'Unterminated import strings')
                    parts = data[:-1].split(b'\0')
                    require(len(parts) == (3 if (flags >> 2) & 7 == 4 else 2) and all(parts), 'Malformed import strings')
                    names = [x.decode('ascii') for x in parts]
                    require(all(0 < len(x) <= 4096 and all(33 <= ord(c) < 127 for c in x) for x in names),
                            'Invalid/oversized short-import symbol strings')
                    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}\.dll', names[1], re.I), 'Unsafe/unknown imported module')
                    row.update(kind='short_import', import_symbol=names[0], imported_module=names[1].lower(),
                               import_type=flags & 3, name_type=(flags >> 2) & 7, ordinal_or_hint=ordinal)
                    if len(names) == 3:
                        row['export_as'] = names[2]
                    modules.add(names[1].lower())
                    counts['short_import'] += 1
                else:
                    if head[:4] == b'\0\0\xff\xff':
                        require(len(head) >= 56 and struct.unpack_from('<H', head, 4)[0] == 2 and
                                head[12:28] == bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8'), 'Unknown anonymous/bigobj header')
                        machine, sections, section_offset = struct.unpack_from('<H', head, 6)[0], struct.unpack_from('<I', head, 44)[0], 56
                        kind = 'bigobj'
                        symbol_pointer, symbol_count = struct.unpack_from('<II', head, 48)
                        symbol_width = 20
                    else:
                        machine, sections = struct.unpack_from('<HH', head)
                        require(struct.unpack_from('<H', head, 16)[0] == 0, 'Unexpected COFF optional header')
                        section_offset, kind = 20, 'coff'
                        symbol_pointer, symbol_count = struct.unpack_from('<II', head, 8)
                        symbol_width = 18
                    require(machine == 0x8664 and 0 <= sections <= 200000 and (sections > 0 or symbol_count > 0), 'Wrong/unbounded COFF machine/sections')
                    require(section_offset + sections * 40 <= length, 'Truncated section table')
                    require(symbol_count <= 2000000 and (symbol_pointer != 0 or symbol_count == 0), 'Unbounded/missing symbol table')
                    strings = b''
                    if symbol_pointer:
                        string_offset = symbol_pointer + symbol_count * symbol_width
                        require(symbol_pointer >= section_offset + sections * 40 and string_offset + 4 <= length,
                                'Truncated/overlapping symbol table')
                        stream.seek(start + string_offset)
                        string_size = struct.unpack('<I', stream.read(4))[0]
                        require(4 <= string_size <= 16 * MIB and string_offset + string_size <= length,
                                'Unbounded/truncated COFF string table')
                        strings = b'\0' * 4 + stream.read(string_size - 4)
                    stream.seek(start + section_offset)
                    table = stream.read(sections * 40)
                    texts, executable, import_sections, object_modules = [], 0, [], set()
                    directive_bytes = 0
                    for index in range(sections):
                        if index % 256 == 0:
                            guard()
                        section = table[index * 40:(index + 1) * 40]
                        secname = section[:8].rstrip(b'\0').decode('ascii')
                        if secname.startswith('/'):
                            require(secname[1:].isdigit(), 'Unknown section-name encoding')
                            name_offset = int(secname[1:])
                            require(4 <= name_offset < len(strings), 'Invalid long section-name offset')
                            name_end = strings.find(b'\0', name_offset)
                            require(0 <= name_end - name_offset <= 4096, 'Unterminated long section name')
                            secname = strings[name_offset:name_end].decode('ascii')
                        count, offset = struct.unpack_from('<II', section, 16)
                        flags = struct.unpack_from('<I', section, 36)[0]
                        require(offset == 0 or offset + count <= length, 'Truncated COFF section bytes')
                        if flags & 0x20000000 and count:
                            executable += 1
                        if secname.startswith(('.idata', '.didat')):
                            import_sections.append(secname)
                            require(count <= MIB and offset + count <= length, 'Unbounded import section')
                            if offset:
                                stream.seek(start + offset)
                                for value in stream.read(count).split(b'\0'):
                                    if re.fullmatch(rb'[A-Za-z0-9_.-]{1,128}\.dll', value, re.I):
                                        object_modules.add(value.decode('ascii').lower())
                        if secname == '.drectve' and count:
                            directive_bytes += count
                            require(directive_bytes <= MIB, 'Aggregate object directive cap exceeded')
                            require(count <= MIB and offset >= section_offset + sections * 40 and offset + count <= length,
                                    'Unbounded/truncated directive section')
                            stream.seek(start + offset)
                            texts.append(stream.read(count).decode('ascii').replace('\0', ' '))
                    directives = parse_directives(' '.join(texts))
                    row.update(kind=kind, section_count=sections, executable_sections=executable,
                               import_sections=import_sections, imported_modules=sorted(object_modules),
                               raw_directives=texts, **directives)
                    counts[kind] += 1
                    counts['executable_objects'] += int(executable > 0)
                    counts['full_import_objects'] += int(bool(import_sections))
                    counts['directive_objects'] += int(bool(texts))
                    defaults.update(directives['default_libraries'])
                    for key, values in directives['mismatch_tags'].items():
                        mismatches[key].update(values)
                    others.update(directives['other_directives_unreviewed'])
                    require(len(others) <= 16384, 'Unbounded directive token inventory')
                    modules.update(object_modules)
                emit(row)
            pos = start + length + (length & 1)
        require(pos == size and members > 0, 'Trailing bytes/empty provider archive')
    require(path.stat().st_size == size and sha(path) == digest, 'Provider changed during inspection')
    machine = ('neutral' if counts['neutral_coff'] == members else 'mixed-x86_64-and-neutral') if counts['neutral_coff'] else 'x86_64'
    return {'size': size, 'sha256': digest, 'machine': machine, 'provider_approved': False,
            'members': members, 'member_types': dict(counts),
            'default_libraries': sorted(defaults), 'mismatch_tags': {k: sorted(v) for k, v in sorted(mismatches.items())},
            'other_directives_unreviewed': sorted(others), 'imported_modules': sorted(modules)}


def provider_roots(tool_record):
    vs, vc, sdk = (Path(tool_record[k]).resolve() for k in ['visual_studio', 'msvc', 'windows_sdk'])
    version = tool_record['windows_sdk_version']
    require(vc.is_relative_to(vs) and re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version), 'Invalid selected provider roots')
    roots = {'msvc': vc / 'lib/x64', 'atl': vc / 'atlmfc/lib/x64',
             'windows_um': sdk / 'Lib' / version / 'um/x64',
             'windows_ucrt': sdk / 'Lib' / version / 'ucrt/x64', 'dia': vs / 'DIA SDK/lib/amd64'}
    for name, root in roots.items():
        anchor = sdk if name.startswith('windows_') else vc if name in {'msvc', 'atl'} else vs
        require(root.resolve().is_relative_to(anchor) and root.resolve() == root.absolute(),
                'Provider root redirected or escaped exact selected installation/version')
    return roots


def resolve_provider(name, role, roots):
    require(name in EXPECTED_ROLES and role['root'] == EXPECTED_ROLES[name], 'Unknown provider role')
    root = roots[role['root']].resolve()
    path = root / (name + '.lib')
    require(path.resolve().is_relative_to(root), 'Provider escaped exact role directory')
    require(path.is_file() and not path.is_symlink(), 'Preinstalled provider missing: ' + name)
    return path.resolve()


def provider_findings(name, role, row, role_names):
    findings = []
    for dependency in row['default_libraries']:
        if dependency not in role_names:
            findings.append({'kind': 'unresolved_default_library', 'provider': name, 'dependency': dependency,
                             'status': 'rejected-unreviewed'})
    for module in row['imported_modules']:
        if module not in OBSERVED_OS_DLLS:
            findings.append({'kind': 'unreviewed_import_module', 'provider': name, 'module': module,
                             'status': 'rejected-unreviewed'})
    for key, values in row['mismatch_tags'].items():
        if len(values) != 1:
            findings.append({'kind': 'conflicting_mismatch_tag', 'provider': name, 'tag': key,
                             'values': values, 'status': 'rejected'})
        if key not in SDK_MISMATCH_TAGS:
            findings.append({'kind': 'unreviewed_mismatch_tag', 'provider': name, 'tag': key,
                             'values': values, 'status': 'rejected-unreviewed'})
        elif not set(values) <= SDK_MISMATCH_TAGS[key]:
            findings.append({'kind': 'non_mt_runtime_tag' if key == 'RuntimeLibrary' else 'incompatible_mismatch_tag',
                             'provider': name, 'tag': key, 'values': values, 'status': 'rejected'})
    types = row['member_types']
    has_imports = types.get('short_import', 0) + types.get('full_import_objects', 0) > 0
    if role['kind'] == 'guid_data' and (has_imports or types.get('executable_objects', 0)):
        findings.append({'kind': 'guid_provider_contains_code_or_imports', 'provider': name, 'status': 'rejected-unreviewed'})
    if role['kind'] == 'os_import' and not has_imports:
        findings.append({'kind': 'expected_import_provider_has_no_import_evidence', 'provider': name, 'status': 'rejected-unreviewed'})
    if role['kind'] == 'static_code' and has_imports:
        findings.append({'kind': 'static_provider_contains_import_objects', 'provider': name, 'status': 'rejected-unreviewed'})
    # This task inventories these options. It does not approve a new linker policy.
    for token in row['other_directives_unreviewed']:
        findings.append({'kind': 'unreviewed_linker_directive', 'provider': name, 'directive': token,
                         'status': 'rejected-for-link-pending-review'})
    return findings


class InventoryRun(p.Run):
    def guard(self, force=False):
        require(time.monotonic() - self.started <= MAX_SECONDS, 'Seven-minute inventory deadline reached')
        super().guard(force)
        require(sum(x.stat().st_size for x in self.work.rglob('*') if x.is_file()) <= 64 * MIB,
                '64-MiB inventory work cap exceeded')


class Recorder:
    def __init__(self, path):
        self.path, self.total = path, 0
        self.stream = path.open('x', encoding='utf-8')

    def emit(self, kind, value):
        line = kind + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'
        size = len(line.encode('utf-8'))
        require(size <= MAX_MEMBER_RECORD and self.total + size <= MAX_RECORD_BYTES, 'Inventory record/log cap exceeded')
        self.stream.write(line)
        self.stream.flush()
        self.total += size
        print(line, end='', flush=True)

    def close(self):
        self.stream.close()


def inspect_dia_runtime(vs):
    root = (Path(vs) / 'DIA SDK/bin/amd64').resolve()
    require(root.is_relative_to(Path(vs).resolve()), 'DIA runtime root escaped selected VS')
    path = root / 'msdia140.dll'
    if not path.is_file():
        return {'path': str(path), 'present': False, 'observation_only': True,
                'meaning': 'DIA dynamic functionality unverified; absence does not prove probe needs it'}
    require(not path.is_symlink() and path.resolve().is_relative_to(root) and path.stat().st_size <= MAX_PROVIDER,
            'Unsafe/oversized DIA runtime')
    with path.open('rb') as stream:
        head = stream.read(64)
        require(len(head) == 64 and head[:2] == b'MZ', 'Invalid DIA runtime DOS header')
        offset = struct.unpack_from('<I', head, 60)[0]
        require(64 <= offset and offset + 26 <= path.stat().st_size, 'Invalid DIA PE header offset')
        stream.seek(offset)
        pe = stream.read(26)
        require(pe[:4] == b'PE\0\0' and struct.unpack_from('<H', pe, 4)[0] == 0x8664 and
                struct.unpack_from('<H', pe, 24)[0] == 0x20b, 'DIA runtime not x64 PE32+')
    return {'path': str(path.resolve()), 'present': True, 'sha256': sha(path), 'size': path.stat().st_size,
            'machine': 'x86_64', 'observation_only': True, 'loaded_or_registered': False,
            'imports_audited': False, 'meaning': 'PE identity only; not approved as an OS/runtime dependency'}


def inventory(work):
    require(os.name == 'nt' and platform.machine().lower() in {'amd64', 'x86_64'}, 'Native x64 Windows required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'Mi-Yomi/Madeira' and
            os.environ.get('GITHUB_REF') == 'refs/heads/compatibility/desktop-apps' and
            os.environ.get('GITHUB_EVENT_NAME') == 'push', 'Wrong Actions repository/ref/event')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    require(event.get('repository', {}).get('private') is False, 'Public-repository guard missing')
    requirements, request = load_requirements()
    host_lock = json.loads((HERE / 'inputs.lock.json').read_text())
    require(platform.python_version() == host_lock['host_python'] and sys.maxsize > 2 ** 32,
            'Pinned preinstalled Python x64 required')
    temp, work = Path(os.environ['RUNNER_TEMP']).resolve(), work.absolute()
    require(not work.exists() and not work.is_symlink() and work.resolve().is_relative_to(temp) and
            work.resolve() != temp and not work.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(work.resolve()),
            'Inventory root must be fresh, below RUNNER_TEMP, separate from checkout')
    work.mkdir(parents=True)
    (work / 'temp').mkdir()
    job = p.install_job_limits()  # Keep this handle live through all discovery/reading.
    runner = InventoryRun(work)
    runner.guard(True)
    threading.Thread(target=runner.monitor, daemon=True).start()
    recorder = Recorder(work / 'provider-evidence.jsonl')
    try:
        tools, env, tool_record = p.tool_environment(runner)
        roots = provider_roots(tool_record)
        recorder.emit('PROVIDER_TOOLCHAIN', {'request': request, 'source_commit': os.environ.get('GITHUB_SHA'),
            'image_version': os.environ.get('ImageVersion'), 'tools': tool_record,
            'provider_roots': {k: str(v) for k, v in roots.items()}, 'original_lib_search': env['LIB'],
            'sdk_selected_libraries': requirements['selected_libraries_link_order'],
            'sdk_abi_jit_verified': False, 'provider_closure_approved': False})
        records, findings, missing_optional, provider_paths = {}, [], set(), {}
        total_bytes = 0
        for name, role in sorted(requirements['provider_roles'].items()):
            try:
                path = resolve_provider(name, role, roots)
            except (ValueError, OSError) as exc:
                if not role['required']:
                    missing_optional.add(name)
                    recorder.emit('PROVIDER_OPTIONAL_ABSENT', {'name': name, 'reason': str(exc), 'required_by_edge': False})
                    continue
                issue = {'kind': 'provider_missing_or_unsafe', 'provider': name, 'reason': str(exc), 'status': 'rejected'}
                findings.append(issue)
                recorder.emit('PROVIDER_REJECTED', issue)
                continue
            try:
                provider_size = path.stat().st_size
                require(provider_size <= MAX_PROVIDER, 'Per-provider size cap before diagnostic eligibility')
                total_bytes += provider_size
                require(total_bytes <= MAX_PROVIDER_BYTES, '1-GiB aggregate provider-byte cap exceeded')
                provider_paths[name] = path
                row = scan_library(path, lambda obj, n=name: recorder.emit('PROVIDER_OBJECT', {'provider': n, **obj}), runner.guard)
                row.update(name=name, path=str(path), role=role, link_approved=False)
                records[name] = row
                recorder.emit('PROVIDER_LIBRARY', row)
                findings.extend(provider_findings(name, role, row, requirements['provider_roles']))
            except (ValueError, OSError, UnicodeError, struct.error) as exc:
                issue = {'kind': 'provider_parse_or_resource_failure', 'provider': name, 'path': str(path),
                         'reason': str(exc), 'status': 'rejected-incomplete'}
                findings.append(issue)
                recorder.emit('PROVIDER_REJECTED', issue)
        for name, row in records.items():
            for dependency in row['default_libraries']:
                if dependency in requirements['provider_roles'] and dependency not in records:
                    findings.append({'kind': 'unresolved_known_provider_edge', 'provider': name,
                                     'dependency': dependency, 'status': 'rejected'})
        for provider in ['diaguids', 'libcmt', 'oldnames']:
            if provider not in provider_paths:
                continue  # Existing missing-provider finding already rejects this inventory.
            try:
                if detail.collect(provider, provider_paths[provider], runner, tools['dumpbin'], env, recorder):
                    findings.append({'kind': 'member_evidence_incomplete', 'provider': provider,
                                     'status': 'rejected-incomplete-no-selection-proof'})
            except (ValueError, OSError, UnicodeError, struct.error) as exc:
                findings.append({'kind': 'member_evidence_incomplete', 'provider': provider,
                                 'reason': str(exc), 'status': 'rejected-incomplete-no-selection-proof'})
        recorder.emit('PROVIDER_DIA_MAPPING', {'raw_edge': requirements['external_dia_edge'],
            'resolved_provider': records.get('diaguids', {}).get('path'),
            'resolved_sha256': records.get('diaguids', {}).get('sha256'),
            'metadata_modified': False, 'link_performed': False, 'mapping_approved_for_link': False})
        try:
            recorder.emit('PROVIDER_DIA_RUNTIME', inspect_dia_runtime(tool_record['visual_studio']))
        except (ValueError, OSError, struct.error) as exc:
            findings.append({'kind': 'dia_runtime_identity_unresolved', 'reason': str(exc), 'status': 'rejected-unreviewed'})
        for issue in findings:
            recorder.emit('PROVIDER_FINDING', issue)
        runner.guard(True)
        incomplete = any(x['kind'] in {'provider_missing_or_unsafe', 'provider_parse_or_resource_failure',
                                    'dia_runtime_identity_unresolved', 'member_evidence_incomplete'} for x in findings)
        result = {'status': 'incomplete-rejected' if incomplete else
                  'inventory-recorded-with-rejections' if findings else 'inventory-recorded-awaiting-review',
            'collection_complete': not incomplete,
            'scope': 'preinstalled provider inventory only', 'source_commit': os.environ.get('GITHUB_SHA'),
            'request': request['request'], 'requirements_sha256': request['requirements_sha256'],
            'providers_recorded': len(records), 'provider_bytes': total_bytes, 'finding_count': len(findings),
            'optional_absent': sorted(missing_optional), 'seconds': round(time.monotonic() - runner.started, 3),
            'sdk_downloaded': False, 'compiled': False, 'linked': False, 'jit_executed': False,
            'provider_closure_approved': False, 'sdk_abi_jit_verified': False,
            'madeira_abi_or_runtime_verified': False, 'evidence_sha256_before_receipt': sha(recorder.path)}
        recorder.emit('PROVIDER_INVENTORY', result)
        return 2 if findings else 0
    finally:
        recorder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        return inventory(args.work_root)
    except Exception as exc:
        print('PROVIDER_INVENTORY_STOP ' + json.dumps({'status': 'incomplete-rejected', 'reason': str(exc),
            'sdk_abi_jit_verified': False, 'provider_closure_approved': False}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
