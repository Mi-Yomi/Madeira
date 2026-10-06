#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert provider fixtures; no SDK download or Windows code execution."""
import contextlib
import copy
import importlib.util
import hashlib
import os
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/llvm_sdk'
spec = importlib.util.spec_from_file_location('provider_inventory', SOURCE / 'provider_inventory.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fixture_spec = importlib.util.spec_from_file_location('neutral_cases', ROOT / 'tests/host/fixtures/llvm-providers/neutral_cases.py')
neutral_cases = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(neutral_cases)
checks = 0


def check(condition, message):
    global checks
    assert condition, message
    checks += 1


def reject(call, message):
    global checks
    try:
        call()
    except (ValueError, OSError, UnicodeError, struct.error):
        checks += 1
        return
    raise AssertionError('Unsafe/inconclusive input accepted: ' + message)


def coff(text='', machine=0x8664, bigobj=False, long_section=False, section=b'.drectve', flags=0):
    data = text.encode('ascii') if isinstance(text, str) else text
    head = bytearray(56 if bigobj else 20)
    if bigobj:
        struct.pack_into('<HHHH', head, 0, 0, 0xffff, 2, machine)
        head[12:28] = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
        struct.pack_into('<I', head, 44, 1)
    else:
        struct.pack_into('<HH', head, 0, machine, 1)
    sec = bytearray(40)
    sec[:8] = (b'/4' if long_section else section).ljust(8, b'\0')
    struct.pack_into('<II', sec, 16, len(data), len(head) + 40)
    struct.pack_into('<I', sec, 36, flags)
    strings = b''
    if long_section:
        strings = struct.pack('<I', len(section) + 5) + section + b'\0'
        struct.pack_into('<I', head, 48 if bigobj else 8, len(head) + 40 + len(data))
    return bytes(head + sec) + data + strings


def short_import(module='KERNEL32.dll', symbol='Sleep', machine=0x8664, flags=4, export_as=None):
    data = (symbol + '\0' + module + '\0' + (export_as + '\0' if export_as else '')).encode('ascii')
    return struct.pack('<HHHHIIHH', 0, 0xffff, 0, machine, 0, len(data), 0, flags) + data


def archive(rows):
    result = bytearray(b'!<arch>\n')
    for name, obj in rows:
        header = name.encode('ascii').ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'0'.ljust(8)
        header += str(len(obj)).encode('ascii').ljust(10) + b'`\n'
        assert len(header) == 60
        result += header + obj + (b'\n' if len(obj) & 1 else b'')
    return bytes(result)


def scan_bytes(path, data):
    path.write_bytes(data)
    rows = []
    summary = m.scan_library(path, rows.append)
    return summary, rows


requirements, request = m.load_requirements()
check(len(requirements['selected_libraries']) == 70, 'Exact selected inventory')
check(request['requirements_sha256'] == m.sha(SOURCE / 'provider-requirements.json'), 'Request digest binding')
for change in [
    lambda r: r['sdk'].update(sha256='0' * 64),
    lambda r: r['selected_libraries_link_order'].pop(),
    lambda r: r['selected_libraries_link_order'].append(r['selected_libraries_link_order'][0]),
    lambda r: r['selected_libraries'].pop('LLVMDebugInfoPDB'),
    lambda r: r['exported_edges'].pop('LLVMInterpreter'),
    lambda r: r['exported_link_options'].pop('LLVMMCA'),
    lambda r: r['external_dia_edge'].update(raw='C:/untrusted/diaguids.lib'),
    lambda r: r['external_dia_edge'].update(relative_to_selected_vs='../../diaguids.lib'),
    lambda r: r['provider_roles']['atls'].update(root='msvc'),
    lambda r: r['provider_roles']['uuid'].update(kind='os_import'),
    lambda r: r['provider_roles']['atls'].update(required=False),
    lambda r: r['provider_roles'].update(evil={'root': 'msvc', 'kind': 'static_code', 'required': True}),
    lambda r: r['coff_default_libraries'].append('evil'),
    lambda r: r['explicit_system_libraries'].append('evil'),
    lambda r: r['link_options'].append('/FORCE'),
    lambda r: r['exported_edges']['LLVMSupport'].append('evil'),
    lambda r: r['exported_link_options']['LLVMSupport'].append('/FORCE'),
    lambda r: r['selected_libraries']['LLVMCore'].update(sha256='bad'),
    lambda r: r['selected_libraries']['LLVMCore']['mismatches'].update(_MSC_VER=['1800', '1900']),
]:
    altered = copy.deepcopy(requirements)
    change(altered)
    reject(lambda r=altered: m.validate_requirements(r), 'Mutated source dependency inventory')

# Exercise actual Git checkout conversion, not a Python newline normalization.
# The sealed file must keep its exact digest with core.autocrlf=true, while an
# unprotected sibling proves the checkout really performed LF -> CRLF conversion.
with tempfile.TemporaryDirectory() as checkout_td:
    checkout = Path(checkout_td)
    empty_config = checkout / 'empty-config'
    empty_config.write_bytes(b'')
    fixture = checkout / 'repo'
    fixture.mkdir()
    git_env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    git_env.update(GIT_CONFIG_NOSYSTEM='1', GIT_ATTR_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(empty_config))
    def git(*arguments, autocrlf='false'):
        result = subprocess.run(['git', '-c', 'core.autocrlf=' + autocrlf,
            '-c', 'core.attributesfile=' + str(empty_config), *arguments],
            cwd=fixture, env=git_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=True)
        return result.stdout
    git('init', '--quiet')
    relative = 'tests/desktop/llvm_sdk/provider-requirements.json'
    control_relative = 'tests/desktop/llvm_sdk/provider-requirements-control.json'
    sealed = fixture / relative
    control = fixture / control_relative
    sealed.parent.mkdir(parents=True)
    original = (SOURCE / 'provider-requirements.json').read_bytes()
    check(b'\r' not in original and b'\n' in original, 'Pinned source evidence is exact LF bytes')
    sealed.write_bytes(original)
    control.write_bytes(original)
    (fixture / '.gitattributes').write_bytes((ROOT / '.gitattributes').read_bytes())
    git('add', '--', '.gitattributes', relative, control_relative)
    sealed.unlink()
    control.unlink()
    git('checkout-index', '--all', autocrlf='true')
    check(git('check-attr', 'text', '--', relative).decode().strip().endswith(': text: unset'),
          'Exact sealed-file attribute disables checkout conversion')
    check(git('check-attr', 'text', '--', control_relative).decode().strip().endswith(': text: unspecified'),
          'Byte-preservation attribute does not expand to sibling evidence')
    check(sealed.read_bytes() == original, 'Real autocrlf checkout preserves sealed bytes')
    expected_crlf = original.replace(b'\n', b'\r\n')
    check(control.read_bytes() == expected_crlf, 'Unprotected control really converts to CRLF')
    check(hashlib.sha256(sealed.read_bytes()).hexdigest() == request['requirements_sha256'],
          'Actual protected checkout keeps requested evidence digest')
    check(hashlib.sha256(control.read_bytes()).hexdigest() != request['requirements_sha256'],
          'Actual unprotected checkout reproduces evidence digest mismatch')
    (sealed.parent / 'provider-inventory-request.json').write_bytes(
        (SOURCE / 'provider-inventory-request.json').read_bytes())
    with patch.object(m, 'HERE', sealed.parent):
        check(m.load_requirements()[1]['requirements_sha256'] == request['requirements_sha256'],
              'Unchanged production loader accepts actual protected checkout')
        sealed.write_bytes(control.read_bytes())
        reject(m.load_requirements, 'Unchanged production loader rejects actual CRLF checkout bytes')

parsed = m.parse_directives(' /DEFAULTLIB:LIBCMT.LIB -defaultlib:"uuid.lib" /FAILIFMISMATCH:"RuntimeLibrary=MT_StaticRelease" /INCLUDE:malloc')
check(parsed['default_libraries'] == ['libcmt', 'uuid'], 'Canonical defaults')
check(parsed['mismatch_tags'] == {'RuntimeLibrary': ['MT_StaticRelease']}, 'Exact runtime tags')
check(parsed['other_directives_unreviewed'] == ['/INCLUDE:malloc'], 'Unreviewed option is retained')
for text in ['"broken', '/DEFAULTLIB:"unterminated', '/DEFAULTLIB:"bad name.lib"', '/DEFAULTLIB:../evil.lib',
             '/DEFAULTLIB:C:\\evil.lib', '/DEFAULTLIB:', '/FAILIFMISMATCH:no_equal', '/FAILIFMISMATCH:"=bad"',
             '/FAILIFMISMATCH:"RuntimeLibrary="', '/DEFAULTLIB:good.lib\x01', 'not_an_option']:
    reject(lambda t=text: m.parse_directives(t), 'Malformed/unsafe directive')
for token in ['/LIBPATH:elsewhere', '/NODEFAULTLIB:libcmt', '/FORCE:UNRESOLVED', '/ALTERNATENAME:a=b',
              '/MERGE:ATL=.rdata', '/EXPORT:custom', '/INCLUDE:custom']:
    row = {'default_libraries': [], 'mismatch_tags': {}, 'member_types': {'coff': 1}, 'imported_modules': [],
           'other_directives_unreviewed': m.parse_directives(token)['other_directives_unreviewed']}
    check(any(x['kind'] == 'unreviewed_linker_directive' for x in
              m.provider_findings('atls', {'kind': 'static_code'}, row, requirements['provider_roles'])),
          'Hidden/unknown directive cannot pass')

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    lib = root / 'fixture.lib'
    base = '/DEFAULTLIB:libcmt.lib /FAILIFMISMATCH:"RuntimeLibrary=MT_StaticRelease"'
    for provider, obj, witness, _ in neutral_cases.fixtures():
        summary, rows = scan_bytes(lib, archive([('neutral.obj/', obj)]))
        check(summary['machine'] == 'neutral' and summary['provider_approved'] is False and
              summary['member_types'] == {'neutral_coff': 1}, 'Metadata-only archive is not relabeled x64/approved')
        check(rows[0]['machine'] == '0x0000' and rows[0]['provider_approved'] is False and
              rows[0]['neutral_evidence']['symbols'][-1]['weak_alias']['target_name'] == witness['expected_alias']['target_name'],
              'Neutral inventory preserves exact symbol evidence')
        summary, rows = scan_bytes(lib, archive([('neutral.obj/', obj), ('after.obj/', coff(base))]))
        check(summary['members'] == 2 and len(rows) == 2 and rows[1]['member'] == 'after.obj' and
              rows[1]['machine'] == '0x8664' and summary['machine'] == 'mixed-x86_64-and-neutral',
              'Full inventory continues after neutral metadata and retains both machine identities')
        check(summary['default_libraries'] == ['libcmt'] and summary['mismatch_tags']['RuntimeLibrary'] == ['MT_StaticRelease'],
              'Later member directives/CRT evidence cannot be hidden by neutral metadata')
        incompatible = '/FAILIFMISMATCH:"RuntimeLibrary=MD_DynamicRelease"'
        summary, rows = scan_bytes(lib, archive([('neutral.obj/', obj), ('badcrt.obj/', coff(incompatible))]))
        check(any(x['kind'] == 'non_mt_runtime_tag' for x in
                  m.provider_findings(provider, {'kind': 'static_code'}, summary, requirements['provider_roles'])),
              'Later incompatible CRT retains fail-closed rejection')
        reject(lambda: scan_bytes(lib, archive([('neutral.obj/', obj), ('wrong.obj/', coff(base, machine=0x14c))])),
               'Later wrong architecture remains rejected')
        for label, bad in neutral_cases.malformed(obj):
            reject(lambda bad=bad: scan_bytes(lib, archive([('bad.obj/', bad), ('after.obj/', coff(base))])),
                   provider + ' neutral inventory: ' + label)
        with patch.object(m.detail, 'MAX_NEUTRAL_OBJECT', len(obj) - 1):
            reject(lambda: scan_bytes(lib, archive([('neutral.obj/', obj)])), 'Neutral cap precedes whole-member read')
    for big in [False, True]:
        for long in [False, True]:
            summary, rows = scan_bytes(lib, archive([('probe.obj/', coff(base, bigobj=big, long_section=long))]))
            check(summary['default_libraries'] == ['libcmt'], 'Regular/bigobj/long section directives')
            check(summary['mismatch_tags']['RuntimeLibrary'] == ['MT_StaticRelease'], 'CRT identity preserved')
            check(len(rows) == 1 and rows[0]['raw_directives'] == [base], 'Raw object evidence preserved')
    summary, rows = scan_bytes(lib, archive([('//', b'very-long-provider-object.obj\0'), ('/0', coff(base))]))
    check(rows[0]['member'] == 'very-long-provider-object.obj', 'Archive long name resolved')
    summary, rows = scan_bytes(lib, archive([('null.obj/', coff(b'', section=b'.text'))]))
    check(not summary['default_libraries'] and summary['members'] == 1, 'Directive-free data not silently rejected')
    summary, rows = scan_bytes(lib, archive([('imp.obj/', short_import())]))
    check(summary['member_types']['short_import'] == 1 and summary['imported_modules'] == ['kernel32.dll'], 'Short import evidence')
    check(rows[0]['import_symbol'] == 'Sleep', 'Exact short import symbol')
    summary, rows = scan_bytes(lib, archive([('imp.obj/', short_import(flags=16, export_as='RealSleep'))]))
    check(rows[0]['export_as'] == 'RealSleep', 'Export-as import preserved')
    summary, rows = scan_bytes(lib, archive([('desc.obj/', coff(b'KERNEL32.dll\0', section=b'.idata$7'))]))
    check(summary['imported_modules'] == ['kernel32.dll'] and summary['member_types']['full_import_objects'] == 1,
          'Full import descriptor evidence')
    data_obj = coff(b'\0' * 16, section=b'.rdata')
    summary, rows = scan_bytes(lib, archive([('guid.obj/', data_obj)]))
    check(not m.provider_findings('diaguids', {'kind': 'guid_data'}, summary, requirements['provider_roles']), 'GUID-only archive role')
    summary, rows = scan_bytes(lib, archive([('code.obj/', coff(b'\xc3', section=b'.text', flags=0x60000020))]))
    check(any(x['kind'] == 'guid_provider_contains_code_or_imports' for x in
              m.provider_findings('uuid', {'kind': 'guid_data'}, summary, requirements['provider_roles'])), 'Code cannot pass GUID role')
    overlap = bytearray(coff(b' ' * (600 * 1024)))
    struct.pack_into('<H', overlap, 2, 2)
    section = bytearray(overlap[20:60]);struct.pack_into('<I', section, 20, 100)
    overlap = overlap[:20] + section + section + overlap[60:]
    reject(lambda: scan_bytes(lib, archive([('overlap.obj/', overlap)])), 'Aggregate overlapping directive-section cap')
    valid = archive([('probe.obj/', coff(base))])
    invalid = [b'', b'!<thin>\n', valid[:-1], valid + b'x', archive([('bad.obj/', b'BC\xc0\xde' + b'\0' * 56)]),
               archive([('bad.obj/', coff(base, machine=0x14c))]), archive([('bad.obj/', coff(base, machine=0xa641))]),
               archive([('bad.obj/', short_import(machine=0x14c))]), archive([('bad.obj/', short_import(flags=3))]),
               archive([('bad.obj/', short_import(machine=0))]), archive([('bad.obj/', coff(base, machine=0, bigobj=True))]),
               archive([('bad.obj/', short_import(flags=0x100))]), archive([('bad.obj/', short_import(flags=20))]),
               archive([('bad.obj/', short_import(module='../evil.dll'))]), archive([('bad.obj/', short_import(module='evil.exe'))]),
               archive([('bad.obj/', short_import(symbol='line\nbreak'))]), archive([('bad.obj/', short_import(flags=16))]),
               archive([('/0', coff(base))]), archive([('//', b'no-terminator'), ('/0', coff(base))]),
               archive([('//', b'a\0'), ('//', b'b\0'), ('/0', coff(base))]), archive([('#1/8', coff(base))])]
    # Corrupt known positions in independent structural fixtures.
    for offset, value in [(0, b'BADMAGIC'), (8 + 58, b'xx'), (8 + 48, b'not-a-size')]:
        bad = bytearray(valid); bad[offset:offset + len(value)] = value; invalid.append(bytes(bad))
    for big in [False, True]:
        obj = bytearray(coff(base, bigobj=big, long_section=True))
        sec = 56 if big else 20
        mutations = [(sec, b'/999999\0'), (sec + 16, struct.pack('<I', m.MIB + 1)),
                     (sec + 20, struct.pack('<I', 1)), (sec + 20, struct.pack('<I', len(obj) + 100)),
                     (48 if big else 8, struct.pack('<I', len(obj) + 100)),
                     (52 if big else 12, struct.pack('<I', 2000001))]
        if big:
            mutations += [(12, b'bad!'), (4, struct.pack('<H', 3))]
        else:
            mutations += [(16, struct.pack('<H', 2))]
        for offset, value in mutations:
            bad = bytearray(obj);bad[offset:offset + len(value)] = value
            invalid.append(archive([('bad.obj/', bad)]))
    for i, data in enumerate(invalid):
        reject(lambda data=data: scan_bytes(lib, data), 'Malformed COFF/archive fixture ' + str(i))
    lib.write_bytes(valid)
    with patch.object(m, 'MAX_PROVIDER', 16):
        reject(lambda: m.scan_library(lib), 'Per-provider cap')
    with patch.object(m, 'MAX_MEMBERS', 0):
        reject(lambda: m.scan_library(lib), 'Member cap')
    with patch.object(m, 'sha', side_effect=['a' * 64, 'b' * 64]):
        reject(lambda: m.scan_library(lib), 'Provider changed during read')
    reject(lambda: m.scan_library(lib, guard=lambda: (_ for _ in ()).throw(ValueError('deadline'))), 'Guard propagates')

    vs = root / 'vs'; vc = vs / 'VC/Tools/MSVC/14.50'; sdk = root / 'sdk'
    tool = {'visual_studio': str(vs), 'msvc': str(vc), 'windows_sdk': str(sdk), 'windows_sdk_version': '10.0.1.0'}
    roots = m.provider_roots(tool)
    for path in roots.values():
        path.mkdir(parents=True, exist_ok=True)
    provider = roots['atl'] / 'atls.lib';provider.write_bytes(valid)
    check(m.resolve_provider('atls', requirements['provider_roles']['atls'], roots) == provider.resolve(), 'Exact ATL root')
    reject(lambda: m.resolve_provider('evil', {'root': 'atl'}, roots), 'Unknown basename')
    reject(lambda: m.resolve_provider('atls', {'root': 'msvc'}, roots), 'Wrong provider root')
    reject(lambda: m.resolve_provider('diaguids', requirements['provider_roles']['diaguids'], roots), 'Missing DIA provider')
    with patch.object(Path, 'is_symlink', return_value=True):
        reject(lambda: m.resolve_provider('atls', requirements['provider_roles']['atls'], roots), 'Symlink provider')
    reject(lambda: m.provider_roots(dict(tool, msvc=str(root / 'outside'))), 'MSVC outside selected VS')
    reject(lambda: m.provider_roots(dict(tool, windows_sdk_version='../outside')), 'SDK version traversal')
    original_resolve = Path.resolve
    for redirected, destination in [(roots['msvc'], vs / 'VC/Tools/MSVC/other/lib/x64'),
                                    (roots['atl'], vc / 'atlmfc/lib/other'),
                                    (roots['windows_um'], sdk / 'Lib/10.0.2.0/um/x64')]:
        def resolve_fixture(self, *args, **kwargs):
            return destination.absolute() if self.absolute() == redirected.absolute() else original_resolve(self, *args, **kwargs)
        with patch.object(Path, 'resolve', resolve_fixture):
            reject(lambda: m.provider_roots(tool), 'Role directory redirection to sibling version/path')
    check(not m.inspect_dia_runtime(vs)['present'], 'Missing optional DIA runtime is observation')
    runtime = vs / 'DIA SDK/bin/amd64/msdia140.dll';runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b'not-a-pe')
    reject(lambda: m.inspect_dia_runtime(vs), 'Malformed DIA runtime')
    pe = bytearray(256);pe[:2] = b'MZ';struct.pack_into('<I', pe, 60, 128);pe[128:132] = b'PE\0\0'
    struct.pack_into('<H', pe, 132, 0x8664);struct.pack_into('<H', pe, 152, 0x20b);runtime.write_bytes(pe)
    check(m.inspect_dia_runtime(vs)['loaded_or_registered'] is False, 'DIA PE read cannot load/register it')
    struct.pack_into('<H', pe, 132, 0x14c);runtime.write_bytes(pe)
    reject(lambda: m.inspect_dia_runtime(vs), 'Wrong DIA runtime architecture')
    recorder = m.Recorder(root / 'records.jsonl')
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            recorder.emit('FIXTURE', {'link_approved': False})
        check(recorder.total > 0, 'Evidence written')
        with patch.object(m, 'MAX_MEMBER_RECORD', 4):
            reject(lambda: recorder.emit('FIXTURE', {}), 'Per-record output cap')
        with patch.object(m, 'MAX_RECORD_BYTES', recorder.total):
            reject(lambda: recorder.emit('FIXTURE', {}), 'Aggregate output cap')
    finally:
        recorder.close()
    run = m.InventoryRun(root);run.started = time.monotonic() - 421
    reject(lambda: run.guard(), 'Inventory-specific deadline')

base_row = {'default_libraries': [], 'mismatch_tags': {}, 'member_types': {'coff': 1},
            'imported_modules': [], 'other_directives_unreviewed': []}
for change, kind in [
    (lambda r: r.update(default_libraries=['mystery']), 'unresolved_default_library'),
    (lambda r: r.update(imported_modules=['mystery.dll']), 'unreviewed_import_module'),
    (lambda r: r.update(imported_modules=['api-ms-win-crt-runtime-l1-1-0.dll']), 'unreviewed_import_module'),
    (lambda r: r.update(mismatch_tags={'RuntimeLibrary': ['MD_DynamicRelease']}), 'non_mt_runtime_tag'),
    (lambda r: r.update(mismatch_tags={'RuntimeLibrary': ['MT_StaticDebug']}), 'non_mt_runtime_tag'),
    (lambda r: r.update(mismatch_tags={'_ITERATOR_DEBUG_LEVEL': ['2']}), 'incompatible_mismatch_tag'),
    (lambda r: r.update(member_types={'short_import': 1}), 'static_provider_contains_import_objects'),
    (lambda r: r.update(mismatch_tags={'_MSC_VER': ['1800', '1900']}), 'conflicting_mismatch_tag'),
    (lambda r: r.update(mismatch_tags={'_MSC_VER': ['1800']}), 'incompatible_mismatch_tag'),
    (lambda r: r.update(mismatch_tags={'UnrecognizedABI': ['yes']}), 'unreviewed_mismatch_tag'),
]:
    row = copy.deepcopy(base_row);change(row)
    check(any(x['kind'] == kind for x in m.provider_findings('libcmt', {'kind': 'static_code'}, row,
                                                          requirements['provider_roles'])), 'Unreviewed dependency/type/CRT rejected')
check(any(x['kind'] == 'expected_import_provider_has_no_import_evidence' for x in
          m.provider_findings('kernel32', {'kind': 'os_import'}, base_row, requirements['provider_roles'])), 'Empty import evidence rejected')

workflow = (ROOT / '.github/workflows/llvm-provider-inventory.yml').read_text()
check('timeout-minutes: 10' in workflow and 'runs-on: windows-2025' in workflow, 'Standard bounded job')
check('tests/desktop/llvm_sdk/provider-inventory-request.json' in workflow and 'workflow_dispatch:' not in workflow,
      'Explicit request-file push trigger')
for forbidden in ['upload-artifact@', 'actions/cache@', 'setup-python@', 'preflight.py --work-root', 'pip install', 'choco ', 'winget ']:
    check(forbidden not in workflow, 'No install/download/runtime/upload workflow path')
check('contents: read' in workflow and 'persist-credentials: false' in workflow, 'Read-only workflow checkout')
print(f'PASS: {checks} inert provider inventory requirement, COFF/import, path, CRT, directive and resource controls')
print('NOT RUN: installed Windows providers, SDK download, compile/link/JIT, Mesa, Madeira/FEX/ARM64EC/iOS, signing or IPA')

# The same bounded host stage also exercises the read-only member-evidence reader.
import runpy
runpy.run_path(str(ROOT / "tests/host/check-llvm-member-evidence.py"), run_name="__main__")
