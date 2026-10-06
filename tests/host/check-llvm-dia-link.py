#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Captured compiler/member evidence and inert adversarial link-evidence controls."""
import contextlib
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import time
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dia_link', ROOT / 'tests/desktop/llvm_sdk/dia_link.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
FIXTURES = ROOT / 'tests/host/fixtures/llvm-dia-link'
checks = 0


def check(value, label):
    global checks
    assert value, label
    checks += 1


def reject(call, label):
    global checks
    try:
        call()
    except (ValueError, OSError, UnicodeError, struct.error):
        checks += 1
        return
    raise AssertionError('Unsafe or incomplete evidence accepted: ' + label)


provenance = json.loads((FIXTURES / 'provenance.json').read_text())
real = (FIXTURES / 'llvm-diasession.coff').read_bytes()
check(hashlib.sha256(real).hexdigest() == provenance['member_sha256'], 'Exact real LLVM compiler object identity')
check(len(real) == provenance['size'] == 74813, 'Exact captured object size')
evidence, real_directives = m.object_evidence(real)
check(evidence['header']['machine'] == '0x8664', 'Captured compiler object is x64')
check(real_directives['mismatch_tags']['RuntimeLibrary'] == ['MT_StaticRelease'], 'Captured LLVM /MT evidence')
m.require_release_crt(real_directives)
for name in m.REQUIRED:
    corrupt = real.replace(name.encode(), ('X' + name[1:]).encode())
    reject(lambda b=corrupt: m.object_evidence(b), 'One required real COFF symbol removed: ' + name)
for size in [0, 19, 55, len(real) - 1]:
    reject(lambda n=size: m.object_evidence(real[:n]), 'Truncated captured object')
wrong = bytearray(real)
struct.pack_into('<H', wrong, 0, 0x14c)
reject(lambda: m.object_evidence(bytes(wrong)), 'Wrong compiler-object architecture')
# Remove the actual required relocations while preserving the real symbol table.
no_relocations = bytearray(real)
required_indexes = {x['index'] for x in evidence['symbols'] if x['name'] in m.REQUIRED}
sections = struct.unpack_from('<H', real, 2)[0]
for i in range(sections):
    base = 20 + 40 * i
    offset = struct.unpack_from('<I', real, base + 24)[0]
    count = struct.unpack_from('<H', real, base + 32)[0]
    for j in range(count):
        if struct.unpack_from('<I', real, offset + j * 10 + 4)[0] in required_indexes:
            struct.pack_into('<H', no_relocations, offset + j * 10 + 8, 0)
reject(lambda: m.object_evidence(bytes(no_relocations)), 'Names alone without real references')

captured = json.loads((FIXTURES / 'captured-dia-members.json').read_text())
details = captured['members']
providers = {'diaguids': captured['provider']}
objects = {'diaguids': copy.deepcopy(details)}
owners = {name: next(row for row in details if name in row['strong_definitions']) for name in m.REQUIRED}
expected = {row['member'] for row in owners.values()}
check({Path(x.replace('\\', '/')).name for x in expected} == {'guidstr.obj', 'dia2_i.obj'}, 'Real captured DIA ownership')
md = next(row for row in details if row['member'].endswith('stdafx.obj'))
reject(lambda: m.require_release_crt(md), 'Actual captured MD stdafx directives')
# These trace/map strings are synthetic format contracts, never a claimed Windows link.
trace = 'Searching ' + providers['diaguids']['path'] + ':\n' + ''.join(
    '  Loaded diaguids.lib(' + row['member'] + ')\n' for row in details if row['member'] in expected)
map_text = '\n'.join(' 0001:00001000 ' + name + ' 0000000140001000 f diaguids:' +
                     row['member'].replace('\\', '/').rsplit('/', 1)[-1] for name, row in sorted(owners.items()))
result = m.verify_selection(trace, map_text, providers, objects, details)
check({x['member'] for x in result['dia_members']} == expected, 'Trace/map/real symbol ownership agree')
check(all(x['sha256'] for x in result['dia_members']), 'Selected DIA hashes retained')
for name in m.REQUIRED:
    reject(lambda n=name: m.verify_selection(trace, map_text.replace(n, 'missing_symbol'), providers, objects, details),
           'Required map definition omitted')
for bad in [trace.replace('Loaded', 'Searching'), trace.split('\n', 1)[1],
            trace.replace(providers['diaguids']['path'], 'C:\\untrusted\\diaguids.lib'),
            trace.replace('diaguids.lib(', 'alternate.lib('),
            trace + '  Loaded diaguids.lib(' + md['member'] + ')\n',
            trace + trace.split('\n')[1] + '\n']:
    reject(lambda t=bad: m.verify_selection(t, map_text, providers, objects, details), 'Incomplete, conflicting or MD selection')
for bad in [map_text.replace('diaguids:', 'fakeguids:'), map_text + '\n' + map_text.splitlines()[0],
            map_text.replace('guidstr.obj', 'stdafx.obj'), map_text.replace('0001:00001000', 'unparsed')]:
    reject(lambda t=bad: m.verify_selection(trace, t, providers, objects, details), 'Wrong/duplicate/unparsed map ownership')
ambiguous = copy.deepcopy(details)
ambiguous.append(copy.deepcopy(next(x for x in details if x['member'] in expected)))
reject(lambda: m.verify_selection(trace, map_text, providers, objects, ambiguous), 'Duplicate strong definition owner')
for default in sorted(m.FORBIDDEN_CRT):
    reject(lambda d=default: m.require_release_crt({'default_libraries': [d]}), 'Dynamic/debug CRT default ' + default)
for tag in ['MD_DynamicRelease', 'MDd_DynamicDebug', 'MTd_StaticDebug', 'unknown']:
    reject(lambda t=tag: m.require_release_crt({'mismatch_tags': {'RuntimeLibrary': [t]}}), 'Non-/MT runtime tag')
m.require_release_crt({'default_libraries': ['libcmt', 'oldnames']}, True)
check(True, 'Source /MT default does not require a header-generated mismatch tag')
reject(lambda: m.require_release_crt({'default_libraries': ['oldnames']}, True), 'Missing source /MT evidence')
for directive in ['/FORCE', '/NODEFAULTLIB:msvcrt', '/WHOLEARCHIVE:diaguids', '/IGNORE:4098', '/WX:NO', '/LIBPATH:C:\\unknown']:
    reject(lambda d=directive: m.require_release_crt({'other_directives_unreviewed': [d]}),
           'No link override or warning suppression: ' + directive)

# Actual Windows import libraries repeat DLL member names; no invented offset identity.
providers2, objects2 = copy.deepcopy(providers), copy.deepcopy(objects)
providers2['kernel32'] = {'path': 'C:\\SDK\\Lib\\um\\x64\\kernel32.lib', 'role': {'kind': 'os_import'}}
objects2['kernel32'] = [{'member': 'KERNEL32.dll', 'machine': '0x8664', 'kind': 'short_import',
                        'import_symbol': name, 'imported_module': 'kernel32.dll'} for name in ['Sleep', 'GetLastError']]
trace2 = trace + 'Searching C:\\SDK\\Lib\\um\\x64\\kernel32.lib:\n' + ' Loaded kernel32.lib(KERNEL32.dll)\n' * 2
r = m.verify_selection(trace2, map_text, providers2, objects2, details)
imports = [x for x in r['loaded_members'] if x['provider'] == 'kernel32']
check(len(imports) == 2 and all(x['candidate_count'] == 2 and not x['exact_import_member_selection_proven'] for x in imports),
      'Repeated import names remain explicitly ambiguous, without dropping trace records')
for mutation in [{'imported_module': 'msvcrt.dll'}, {'executable_sections': 1}, {'machine': '0x014c'},
                 {'other_directives_unreviewed': ['/NODEFAULTLIB']}, {'default_libraries': ['msvcrt']}]:
    bad = copy.deepcopy(objects2)
    bad['kernel32'][1].update(mutation)
    reject(lambda o=bad: m.verify_selection(trace2, map_text, providers2, o, details), 'Unsafe candidate in ambiguous import group')

# Exercise the whole orchestration with inert command substitutes. No compiler,
# linker or executable is started; this checks stage ordering and terminal receipts.
def exercise(compile_exit=0, link_exit=0, corrupt_provider=False, source_defaults=None, object_parse_error=False):
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        event = temp / 'event.json'
        event.write_text('{"repository":{"private":false}}')
        lib = temp / 'diaguids.lib'
        lib.write_bytes(b'!<arch>\nfixture')
        native = {'diaguids': {'path': str(lib), 'size': lib.stat().st_size, 'sha256': m.sha(lib)}}
        calls = []
        class Runner:
            def __init__(self, work):
                self.work, self.started, self.records = work, time.monotonic(), []
            def guard(self, force=False):
                pass
            def monitor(self):
                raise AssertionError('Inert fixture must not start a thread')
            def command(self, name, argv, env, timeout, required=True):
                calls.append((name, list(map(str, argv)), dict(env), timeout))
                check(name in {'dia-compile', 'dia-link'}, 'Only compile/link stage can be invoked')
                if name == 'dia-compile':
                    (self.work / 'dia-probe.obj').write_bytes(real)
                    return compile_exit, 'inert compiler output'
                (self.work / 'dia-probe.exe').write_bytes(b'inert, never executable')
                (self.work / 'dia-probe.map').write_text(map_text)
                if corrupt_provider:
                    lib.write_bytes(b'changed provider')
                return link_exit, trace
        fake_os = types.SimpleNamespace(name='nt', pathsep=';', environ={
            'GITHUB_REPOSITORY': 'Mi-Yomi/Madeira', 'GITHUB_REF': 'refs/heads/compatibility/desktop-apps',
            'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(event),
            'RUNNER_TEMP': str(temp), 'GITHUB_SHA': 'a' * 40})
        roots = {key: temp for key in ['msvc', 'windows_um', 'windows_ucrt', 'atl', 'dia']}
        # Explicit fixture aliases permit constructing the real linker command.
        for name in ['uuid', 'advapi32', 'kernel32']:
            native[name] = dict(native['diaguids'])
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(m, 'os', fake_os))
            stack.enter_context(patch.object(m.platform, 'machine', return_value='AMD64'))
            stack.enter_context(patch.object(m.platform, 'python_version', return_value='3.12.10'))
            stack.enter_context(patch.object(m.p, 'install_job_limits', return_value=object()))
            stack.enter_context(patch.object(m, 'DiagnosticRun', Runner))
            stack.enter_context(patch.object(m.threading, 'Thread', return_value=types.SimpleNamespace(start=lambda: None)))
            stack.enter_context(patch.object(m.p, 'tool_environment', return_value=({'cl': 'verified-cl.exe', 'link': 'verified-link.exe'}, {}, {})))
            stack.enter_context(patch.object(m, 'collect_providers', return_value=(roots, native, objects, [])))
            stack.enter_context(patch.object(m, 'dia_members', return_value=details))
            stack.enter_context(patch.object(m, 'object_evidence',
                side_effect=ValueError('inert semantic rejection') if object_parse_error else None,
                return_value=(evidence, {
                'default_libraries': ['libcmt'] if source_defaults is None else source_defaults, 'mismatch_tags': {}})))
            stack.enter_context(patch.object(m, 'verify_selection', return_value=result))
            stack.enter_context(patch.object(m.p, 'audit_pe', return_value={'sha256': 'b' * 64, 'imports': []}))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = m.diagnostic(temp / 'work')
        records = [json.loads(x.partition(' ')[2]) for x in output.getvalue().splitlines() if x.startswith('DIA_LINK_DIAGNOSTIC ')]
        check(len(records) == 1, 'Exactly one terminal diagnostic receipt')
        receipt = records[0]
        check(all(receipt[key] is False for key in ['runtime_tested', 'jit_executed', 'sdk_downloaded',
              'provider_closure_approved', 'sdk_abi_jit_verified', 'madeira_abi_or_runtime_verified']), 'No widened acceptance claim')
        if compile_exit:
            check(code == 2 and len(calls) == 1 and not receipt['compiled'] and not receipt['linked'], 'Compile failure stops before link')
        elif object_parse_error:
            check(code == 2 and len(calls) == 1 and receipt['compiled'] and not receipt['linked'],
                  'Semantic object failure stops before linking')
            check('DIA_COMPILED_OBJECT_BYTES ' in output.getvalue() and
                  'DIA_COMPILED_OBJECT ' not in output.getvalue(), 'Raw object retained before semantic parsing fails')
        elif source_defaults is not None:
            check(code == 2 and len(calls) == 1 and receipt['compiled'] and not receipt['linked'],
                  'Unreviewed source defaults still stop before link')
            check(receipt['reason'] == 'Source object does not establish its ordinary release /MT defaults',
                  'Original source-default rejection remains unchanged')
            compiled = [json.loads(x.partition(' ')[2]) for x in output.getvalue().splitlines()
                        if x.startswith('DIA_COMPILED_OBJECT ')]
            check(len(compiled) == 1 and compiled[0]['directives']['default_libraries'] == source_defaults,
                  'Rejected source defaults are durably emitted')
            check(compiled[0]['header']['sha256'] == provenance['member_sha256'] and
                  compiled[0]['crt_gate_status'] == 'not-yet-evaluated', 'Evidence identity does not imply CRT acceptance')
            check(compiled[0]['raw_directive_sections'] == [{key: section[key] for key in
                  ['index', 'raw_directives', 'raw_sha256', 'size']} for section in evidence['sections']
                  if 'raw_directives' in section], 'Exact raw directive evidence retained alongside parsed fields')
            check(output.getvalue().index('DIA_COMPILED_OBJECT ') < output.getvalue().index('DIA_LINK_DIAGNOSTIC '),
                  'Actual object evidence precedes the terminal rejection')
        elif link_exit or corrupt_provider:
            check(code == 2 and receipt['compiled'] and receipt['linked'] is (link_exit == 0), 'Link/audit failure is truthful')
            check('DIA_LINK_LINE ' in output.getvalue(), 'Failed link retains trace')
        else:
            check(code == 0 and receipt['status'] == 'minimal-dia-mt-link-selection-observed', 'Only narrow diagnostic status')
            check([x[0] for x in calls] == ['dia-compile', 'dia-link'], 'No generated executable invocation')
            check('/MT' in calls[0][1] and '/WX' in calls[0][1] and calls[0][3] == 60 and calls[1][3] == 90, 'Bounded one-compiler one-linker commands')
            response = (temp / 'work/dia-link.rsp').read_text()
            check('/VERBOSE:LIB' in response and '/MAP:' in response and '/WX' in response and
                  not any(x in response for x in ['/NODEFAULTLIB', '/FORCE', '/WHOLEARCHIVE', '/INCLUDE', '/DEBUG']), 'Ordinary release link semantics')
        if not compile_exit:
            captured_bytes = [json.loads(x.partition(' ')[2]) for x in output.getvalue().splitlines()
                              if x.startswith('DIA_COMPILED_OBJECT_BYTES ')]
            check(len(captured_bytes) == 1 and base64.b64decode(captured_bytes[0]['data_b64'], validate=True) == real,
                  'Exact source-object bytes survive the temporary runner')
            check(captured_bytes[0]['size'] == len(real) and captured_bytes[0]['sha256'] == provenance['member_sha256'] and
                  captured_bytes[0]['semantic_gates'] == 'not-yet-evaluated', 'Encoded evidence carries identity without acceptance')
for args in [{}, {'compile_exit': 1}, {'link_exit': 1}, {'corrupt_provider': True},
             {'source_defaults': ['libcmt', 'oldnames', 'uuid']}, {'source_defaults': ['oldnames']},
             {'object_parse_error': True}]:
    exercise(**args)

with tempfile.TemporaryDirectory() as directory:
    obj = Path(directory) / 'source.obj'
    records = []
    recorder = types.SimpleNamespace(emit=lambda kind, value: records.append((kind, value)))
    for size in [0, m.MAX_CAPTURED_OBJECT + 1]:
        obj.write_bytes(b'X' * size)
        reject(lambda: m.capture_source_object(obj, 'a' * 64, recorder), 'Empty/oversized object is never partially encoded')
        check(not records, 'Rejected evidence has no misleading partial-byte record')
    boundary = b'X' * m.MAX_CAPTURED_OBJECT
    obj.write_bytes(boundary)
    check(m.capture_source_object(obj, 'a' * 64, recorder) == boundary, 'Explicit source-object evidence boundary')
    kind, record = records[0]
    check(len((kind + ' ' + json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()) < m.inv.MAX_MEMBER_RECORD,
          'Worst-case base64 record fits existing 256 KiB per-record cap')
    check(base64.b64decode(record['data_b64'], validate=True) == boundary and record['source_sha256'] == 'a' * 64,
          'Boundary bytes and source provenance retained exactly')

workflow = (ROOT / '.github/workflows/llvm-dia-link-diagnostic.yml').read_text()
check('\n  push:' in workflow and 'workflow_dispatch:' not in workflow and
      'branches: [compatibility/desktop-apps]' in workflow and
      '      - tests/desktop/llvm_sdk/dia-link-request.json' in workflow and
      workflow.count('      - tests/desktop/llvm_sdk/') == 1, 'Dedicated request-only push trigger')
check('timeout-minutes: 10' in workflow and 'timeout-minutes: 8' in workflow, 'Ten-minute job and eight-minute execution step')
check('upload-artifact' not in workflow and 'actions/cache' not in workflow, 'No artifact/cache storage')
request, digest = m.load_request()
check(request['runtime_execution'] is False and request['maximum_compile_jobs'] == request['maximum_link_jobs'] == 1,
      'Explicit bounded link-only request')
print(f'PASS {checks} DIA link diagnostic controls')
print('NOT RUN: MSVC compilation/linking, generated executable, SDK ABI/JIT, Mesa or Madeira runtime')
