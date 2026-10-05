#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable adversarial controls; does not download or execute Windows binaries."""
import importlib.util
import io
import json
from pathlib import Path, PureWindowsPath
import struct
import tarfile
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/llvm_sdk'
spec = importlib.util.spec_from_file_location('sdk_preflight', SOURCE / 'preflight.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
report_spec = importlib.util.spec_from_file_location('madeira_imports', SOURCE / 'madeira_imports.py')
mi = importlib.util.module_from_spec(report_spec)
report_spec.loader.exec_module(mi)
lock = json.loads((SOURCE / 'inputs.lock.json').read_text())
checks = 0


def reject(call, label):
    global checks
    try:
        call()
    except (ValueError, OSError, tarfile.TarError):
        checks += 1
        return
    raise AssertionError('Unsafe/inconclusive input accepted: ' + label)


def archive(path, rows):
    with tarfile.open(path, 'w:xz') as out:
        for name, kind, value in rows:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = value
            elif kind == tarfile.REGTYPE:
                member.size = len(value)
            out.addfile(member, io.BytesIO(value) if kind == tarfile.REGTYPE else None)


def coff_library(path, directives, machine=0x8664, bigobj=False, prefix=None):
    data = directives.encode('ascii')
    if prefix is not None:
        obj = prefix
    else:
        if bigobj:
            header = bytearray(56)
            struct.pack_into('<HHHH', header, 0, 0, 0xffff, 2, machine)
            header[12:28] = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
            struct.pack_into('<I', header, 44, 1)
        else:
            header = bytearray(20)
            struct.pack_into('<HH', header, 0, machine, 1)
        section = bytearray(40)
        section[:8] = b'.drectve'
        struct.pack_into('<II', section, 16, len(data), len(header) + 40)
        obj = bytes(header + section) + data
    member = b'probe.obj/      ' + b'0           ' + b'0     ' + b'0     ' + b'0       '
    member += str(len(obj)).encode('ascii').ljust(10) + b'`\n'
    assert len(member) == 60
    path.write_bytes(b'!<arch>\n' + member + obj + (b'\n' if len(obj) & 1 else b''))


def pe_fixture(name, delay=False):
    # Minimal source-owned PE import descriptors. These bytes are never run.
    data = bytearray(2048)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<H', data, 0x94, 240)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20b)
    struct.pack_into('<Q', data, opt + 24, 0x140000000)
    struct.pack_into('<I', data, opt + 60, 0x200)
    struct.pack_into('<I', data, opt + 108, 16)
    struct.pack_into('<8sIIII', data, opt + 240, b'.rdata', 0x600, 0x1000, 0x600, 0x200)
    index, width = (13, 32) if delay else (1, 20)
    struct.pack_into('<II', data, opt + 112 + 8 * index, 0x1100, 2 * width)
    if delay:
        struct.pack_into('<8I', data, 0x300, 1, 0x1300, 0, 0x1220, 0x1200, 0, 0, 0)
    else:
        struct.pack_into('<5I', data, 0x300, 0x1200, 0, 0, 0x1300, 0x1220)
    struct.pack_into('<QQ', data, 0x400, 0x8000000000000001, 0)
    struct.pack_into('<QQ', data, 0x420, 0x8000000000000001, 0)
    encoded = name.encode('ascii') + b'\0'
    data[0x500:0x500 + len(encoded)] = encoded
    return bytes(data)


def export_fixture(name='ProbeApi', target=None):
    data = bytearray(pe_fixture('kernel32.dll'))
    opt = 0x98
    struct.pack_into('<II', data, opt + 112 + 8, 0, 0)  # no imports in this provider
    struct.pack_into('<II', data, opt + 112, 0x1100, 0x200)
    struct.pack_into('<6I', data, 0x300 + 16, 1, 1, 1, 0x1150, 0x1160, 0x1170)
    struct.pack_into('<I', data, 0x350, 0x1200 if target else 0x1500)
    struct.pack_into('<I', data, 0x360, 0x1180)
    struct.pack_into('<H', data, 0x370, 0)
    encoded = name.encode('ascii') + b'\0'
    data[0x380:0x380 + len(encoded)] = encoded
    if target:
        encoded = target.encode('ascii') + b'\0'
        data[0x400:0x400 + len(encoded)] = encoded
    return bytes(data)


# Discovery fixtures are inert files. No Visual Studio or Windows code runs.
with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder).resolve()
    program, program32 = folder / 'Program Files', folder / 'Program Files (x86)'
    work, windows = folder / 'work', folder / 'Windows'
    work.mkdir()

    def installation(path, version, identity):
        script = path / 'Common7/Tools/VsDevCmd.bat'
        script.parent.mkdir(parents=True)
        script.write_text('fixture-never-execute')
        return {'installationPath': str(path), 'installationVersion': version,
                'instanceId': identity, 'isComplete': True, 'isLaunchable': True,
                'isPrerelease': False, 'isRebootRequired': False}

    older = installation(program / 'Microsoft Visual Studio/2022/Enterprise', '17.14.1.1', 'vs2022')
    newest = installation(program / 'Microsoft Visual Studio/18/Enterprise', '18.10.1.1', 'vs2026')
    smaller = installation(program32 / 'Microsoft Visual Studio/18/BuildTools', '18.9.1.1', 'buildtools')
    for rows in [[newest], [older, smaller, newest], [newest, smaller, older]]:
        vs, selected = p.select_visual_studio('\ufeff' + json.dumps(rows), program, program32)
        assert vs == Path(newest['installationPath']) and selected['instance_id'] == 'vs2026'
        assert selected['instance_count'] == len(rows)
        checks += 1
    tied = dict(smaller, installationVersion=newest['installationVersion'])
    expected = min([newest, tied], key=lambda row: row['installationPath'].casefold())
    for rows in [[newest, tied], [tied, newest]]:
        assert p.select_visual_studio(json.dumps(rows), program, program32)[1]['instance_id'] == expected['instanceId']
        checks += 1
    for output in ['', '[]', '{}', '[null]', json.dumps([newest] * 17), ' ' * (64 * 1024 + 1),
                   json.dumps([newest, newest]), json.dumps([newest, dict(older, instanceId='vs2026')])]:
        reject(lambda output=output: p.select_visual_studio(output, program, program32), 'empty/malformed/excessive/duplicate VS discovery')
    for key, value in [('installationVersion', '19.0.0.0'), ('installationVersion', '16.11.0.0'),
                       ('installationVersion', '18.x.0.0'), ('installationVersion', 18),
                       ('isComplete', False), ('isLaunchable', False), ('isPrerelease', True),
                       ('isRebootRequired', True), ('isComplete', 1), ('instanceId', ''),
                       ('installationPath', str(folder / 'outside')),
                       ('installationPath', str(program)), ('installationPath', 'relative/path'),
                       ('installationPath', str(program / 'missing')),
                       ('installationPath', str(program / 'unsafe%PATH%')),
                       ('installationPath', str(program / 'unsafe\npath'))]:
        row = dict(newest, **{key: value})
        reject(lambda row=row: p.select_visual_studio(json.dumps([row]), program, program32), 'invalid VS identity/state/path')
    for key in newest:
        row = {k: v for k, v in newest.items() if k != key}
        reject(lambda row=row: p.select_visual_studio(json.dumps([row]), program, program32), 'incomplete VS metadata')

    environ = {'SystemRoot': str(windows), 'ProgramFiles': str(program), 'ProgramFiles(x86)': str(program32),
               'ProgramData': str(folder / 'ProgramData'), 'ALLUSERSPROFILE': str(folder / 'ProgramData'),
               'PATH': 'untrusted', 'INCLUDE': 'untrusted', 'LIB': 'untrusted', 'LIBPATH': 'untrusted',
               'CL': '/MD', '_CL_': '/MD', 'LINK': '/FORCE', '_LINK_': '/FORCE',
               'VSINSTALLDIR': 'untrusted', 'VCToolsInstallDir': 'untrusted', 'VCPKG_ROOT': 'untrusted'}
    base_env = p.tool_base_environment(environ, work)
    assert base_env['PROGRAMDATA'] == environ['ProgramData']
    assert base_env['ALLUSERSPROFILE'] == environ['ALLUSERSPROFILE']
    assert base_env['PATH'] == str(windows / 'System32')
    assert not set(['INCLUDE', 'LIB', 'LIBPATH', 'CL', '_CL_', 'LINK', '_LINK_', 'VSINSTALLDIR',
                    'VCTOOLSINSTALLDIR', 'VCPKG_ROOT']) & base_env.keys()
    checks += 1
    reject(lambda: p.tool_base_environment({k: v for k, v in environ.items() if k != 'ProgramData'}, work),
           'missing ProgramData fails before locator')

    vs = Path(newest['installationPath'])
    vc, sdk = vs / 'VC/Tools/MSVC/14.51.36231', program32 / 'Windows Kits/10'
    sdk_version = '10.0.26100.0'
    fixture_tools = [program32 / 'Microsoft Visual Studio/Installer/vswhere.exe', program / 'CMake/bin/cmake.exe']
    fixture_tools += [vc / 'bin/Hostx64/x64' / (name + '.exe') for name in ['cl', 'link', 'nmake', 'dumpbin']]
    fixture_tools += [sdk / 'bin' / sdk_version / 'x64' / (name + '.exe') for name in ['rc', 'mt']]
    for path in fixture_tools:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture-never-execute')
    for path in [vc / 'include', vc / 'lib/x64', sdk / 'Include', sdk / 'Lib']:
        path.mkdir(parents=True, exist_ok=True)

    class DiscoveryRun:
        def __init__(self, output):
            self.work, self.output, self.stages = work, output, []

        def command(self, stage, argv, env, timeout):
            self.stages.append(stage)
            assert env['PROGRAMDATA'] == environ['ProgramData']
            if stage == 'vs-locate':
                assert argv[1:] == ['-products', '*', '-version', '[17.0,19.0)', '-requires',
                    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-format', 'json', '-utf8', '-nologo']
                assert timeout == 30 and env['PATH'] == str(windows / 'System32')
                return 0, self.output
            if stage == 'vs-environment':
                script = Path(argv[-1]).read_text()
                assert str(vs / 'Common7/Tools/VsDevCmd.bat') in script
                assert '-arch=x64 -host_arch=x64' in script
                return 0, (f'INCLUDE={vc / "include"};{sdk / "Include"}\nLIB={vc / "lib/x64"};{sdk / "Lib"}\n'
                           f'VC_TOOLS={vc}\nSDK_DIR={sdk}\nSDK_VERSION={sdk_version}\n')
            assert stage == 'cmake-version'
            return 0, 'cmake version 4.4.3\n'

    with patch.dict(p.os.environ, environ, clear=True):
        runner = DiscoveryRun(json.dumps([older, newest, smaller]))
        tools, env, record = p.tool_environment(runner)
        assert tools['cl'] == vc / 'bin/Hostx64/x64/cl.exe'
        assert record['visual_studio_selection']['instance_id'] == 'vs2026'
        assert runner.stages == ['vs-locate', 'vs-environment', 'cmake-version']
        checks += 1
        runner = DiscoveryRun('[]')
        reject(lambda: p.tool_environment(runner), 'no-install must stop before developer script/download')
        assert runner.stages == ['vs-locate']
        checks += 1


for name in ['../escape', '/sdk/file', 'sdk/a/../file', 'sdk/./file', 'sdk//file',
             'sdk/C:/file', 'sdk/a\\file', 'other/file', 'sdk/a.', 'sdk/a ',
             'sdk/CON.txt', 'sdk/nul', 'sdk/LPT9', 'sdk/a\nb', 'sdk/a:stream']:
    reject(lambda name=name: p.safe_path(name, 'sdk'), name)
for name in ['sdk/COM¹', 'sdk/LPT².txt', 'sdk/COM³', 'sdk/CONIN$', 'sdk/CONOUT$.txt']:
    reject(lambda name=name: p.safe_path(name, 'sdk'), name)
assert p.safe_path('sdk/include/llvm/file.h', 'sdk') == 'sdk/include/llvm/file.h'
checks += 1
with tempfile.TemporaryDirectory() as folder:
    folder = Path(folder)
    target = folder / 'test.tar.xz'
    for rows, label in [
        ([('sdk/a', tarfile.REGTYPE, b'a'), ('SDK/A', tarfile.REGTYPE, b'b')], 'case alias'),
        ([('sdk/a', tarfile.SYMTYPE, 'sdk/b')], 'symlink'),
        ([('sdk/a', tarfile.LNKTYPE, '../outside')], 'hardlink escape'),
        ([('sdk/a', tarfile.LNKTYPE, 'sdk/missing')], 'hardlink absent'),
        ([('sdk/a', tarfile.LNKTYPE, 'sdk/b'), ('sdk/b', tarfile.LNKTYPE, 'sdk/a')], 'hardlink cycle'),
        ([('sdk/a', tarfile.REGTYPE, b'x'), ('sdk/a/b', tarfile.REGTYPE, b'x')], 'file parent'),
        ([('sdk/a', tarfile.CHRTYPE, '')], 'device'),
    ]:
        archive(target, rows)
        reject(lambda: p.inspect_archive(target, 'sdk', 100), label)
    archive(target, [('sdk/a', tarfile.REGTYPE, b'a' * 8), ('sdk/b', tarfile.LNKTYPE, 'sdk/a')])
    reject(lambda: p.inspect_archive(target, 'sdk', 15), 'hardlink materialization cap')
    members, size = p.inspect_archive(target, 'sdk', 16)
    assert size == 16
    p.extract_archive(target, folder / 'output', 'sdk', members)
    assert (folder / 'output/sdk/b').read_bytes() == b'a' * 8
    assert not (folder / 'outside').exists()
    checks += 1
    archive(target, [('sdk/a', tarfile.REGTYPE, b'a' * 101)])
    reject(lambda: p.inspect_archive(target, 'sdk', 100), 'file expansion cap')
    lib = folder / 'probe.lib'
    directives = ' /DEFAULTLIB:libcmt /DEFAULTLIB:oldnames /FAILIFMISMATCH:"RuntimeLibrary=MT_StaticRelease" '
    for bigobj in [False, True]:
        coff_library(lib, directives, bigobj=bigobj)
        assert p.audit_static_library(lib)['coff_machine'] == 'x86_64'
        checks += 1
    for bad in [directives + '/DEFAULTLIB:libxml2s.lib', directives + '/DEFAULTLIB:MSVCRT',
                directives + '/FAILIFMISMATCH:"RuntimeLibrary=MD_DynamicRelease"',
                directives + '/LIBPATH:C:/private', directives + '/FORCE:UNRESOLVED',
                directives + '/NODEFAULTLIB:MSVCRT', directives + '/NODEFAULTLIB',
                directives + '/FORCE', '']:
        coff_library(lib, bad)
        reject(lambda: p.audit_static_library(lib), 'COFF implicit dependency/CRT control')
    coff_library(lib, directives, machine=0xaa64)
    reject(lambda: p.audit_static_library(lib), 'ARM64 object in x64 library')
    coff_library(lib, '', prefix=b'BC\xc0\xde' + b'\0' * 64)
    reject(lambda: p.audit_static_library(lib), 'bitcode needs reviewed toolchain')
    coff_library(lib, '', prefix=b'\x00\x00\xff\xff' + b'\0' * 64)
    reject(lambda: p.audit_static_library(lib), 'import library posing as static')
    coff_library(lib, directives)
    lib.write_bytes(lib.read_bytes()[:-2])
    reject(lambda: p.audit_static_library(lib), 'truncated COFF archive')

targets = list(lock['required_libraries'])
assert p.selected_libraries(' '.join(t + '.lib' for t in targets), lock) == targets
checks += 1
for corrupt in ['LLVMSupport.lib', ' '.join(t + '.lib' for t in targets) + ' LLVMWindowsManifest.lib',
                ' '.join(t + '.lib' for t in targets) + ' LLVMSupport.lib',
                ' '.join(t + '.lib' for t in targets) + ' C:/outside.lib']:
    reject(lambda corrupt=corrupt: p.selected_libraries(corrupt, lock), 'selected component closure')
graph = {t: [] for t in targets}
options = {t: [] for t in targets}
graph['LLVMSupport'] = lock['system_libraries'] + lock['link_options']
graph['LLVMCore'] = ['LLVMSupport']
systems, flags = p.validate_closure(targets, graph, options, lock)
assert set(systems) == set(lock['system_libraries']) and set(flags) == set(lock['link_options'])
checks += 1
for unexpected in ['libxml2s.lib', 'LibXml2::LibXml2', 'LLVMWindowsManifest', 'zstd::libzstd_static',
                   'LLVMUnselected', 'C:/build/libxml2s.lib', '$<LINK_ONLY:psapi>',
                   '/FORCE:UNRESOLVED', '-NODEFAULTLIB:LIBCMT', '-INCLUDE:unknown', 'rpcrt4']:
    changed = dict(graph, LLVMCore=[unexpected])
    reject(lambda changed=changed: p.validate_closure(targets, changed, options, lock), unexpected)
for removed in lock['system_libraries'] + lock['link_options']:
    changed = dict(graph, LLVMSupport=[x for x in graph['LLVMSupport'] if x != removed])
    reject(lambda changed=changed: p.validate_closure(targets, changed, options, lock), 'dropped dependency/link flag')
reject(lambda: p.validate_closure(targets, {k: v for k, v in graph.items() if k != 'LLVMCore'}, options, lock), 'missing target metadata')
assert p.split_exported_properties('LLVMSupport;MADEIRA_EXPORT_OPTIONS_BOUNDARY;-INCLUDE:malloc\n') == (['LLVMSupport'], ['-INCLUDE:malloc'])
checks += 1
for text in ['LLVMSupport', 'MADEIRA_EXPORT_OPTIONS_BOUNDARY;MADEIRA_EXPORT_OPTIONS_BOUNDARY']:
    reject(lambda text=text: p.split_exported_properties(text), 'absent/repeated export boundary')
p.validate_pe_dependencies([{'module': 'kernel32.dll', 'kind': 'import'}, {'module': 'ole32.dll', 'kind': 'delay'}])
checks += 1
for name, kind in [('api-ms-win-core-imaginary.dll', 'import'), ('ext-ms-win-imaginary.dll', 'import'),
                   ('libxml2.dll', 'import'), ('msvcp140.dll', 'import'), ('kernel32.dll', 'delay')]:
    reject(lambda name=name, kind=kind: p.validate_pe_dependencies([{'module': name, 'kind': kind}]), 'unknown/unaudited PE dependency')
with tempfile.TemporaryDirectory() as folder:
    binary = Path(folder) / 'synthetic-never-execute.exe'
    for name, delay in [('kernel32.dll', False), ('shell32.dll', True)]:
        binary.write_bytes(pe_fixture(name, delay))
        assert p.audit_pe(binary)['imports'][0]['module'] == name
        checks += 1
    for name, delay in [('libxml2.dll', False), ('kernel32.dll', True), ('msvcp140.dll', False),
                        ('api-ms-win-core-imaginary.dll', False), ('ext-ms-win-imaginary.dll', False)]:
        binary.write_bytes(pe_fixture(name, delay))
        reject(lambda: p.audit_pe(binary), 'real-byte PE dependency boundary')
    changed = bytearray(pe_fixture('kernel32.dll'))
    struct.pack_into('<H', changed, 0x84, 0xaa64)
    binary.write_bytes(changed)
    reject(lambda: p.audit_pe(binary), 'real-byte ARM64 PE')

# Report-only matching preserves name/ordinal, importer aliases, forwarders and
# unresolved states. No fixture is executed; native proof parsing is separate.
from symbol_audit import _module, forwarder
tables = {'kernel32.dll': ({'ProbeApi': {'forwarder': 'api-ms-win-probe-l1-1-0.Forwarded'}}, {}),
          'kernelbase.dll': ({'Forwarded': {'rva': '0x1500'}}, {7: {'rva': '0x1500'}}),
          'wrong.dll': ({}, {})}
schema = {'api-ms-win-probe-l1-1': [('', 'wrong.dll'), ('abi-jit-probe.exe', 'kernelbase.dll')]}
result = mi.resolve_symbol('kernel32.dll', 'ProbeApi', 'abi-jit-probe.exe', tables.get,
                           lambda: schema, _module, forwarder)
assert result['resolved'] and result['resolved_module'] == 'kernelbase.dll'
assert result['chain'][1]['api_set_target'] == 'kernelbase.dll'
checks += 1
result = mi.resolve_symbol('kernelbase.dll', 7, 'abi-jit-probe.exe', tables.get, lambda: {}, _module, forwarder)
assert result['resolved'] and result['resolved_symbol'] == 7
checks += 1
for module, symbol, reason in [('absent.dll', 'ProbeApi', 'missing module'),
                               ('kernelbase.dll', 'Absent', 'missing export'),
                               ('api-ms-win-absent-l1-1-0.dll', 'Absent', 'unresolved API-set')]:
    result = mi.resolve_symbol(module, symbol, 'abi-jit-probe.exe', tables.get, lambda: {}, _module, forwarder)
    assert not result['resolved'] and result['reason'] == reason
    checks += 1
cycles = {'a.dll': ({'x': {'forwarder': 'b.x'}}, {}), 'b.dll': ({'x': {'forwarder': 'a.x'}}, {})}
result = mi.resolve_symbol('a.dll', 'x', 'abi-jit-probe.exe', cycles.get, lambda: {}, _module, forwarder)
assert not result['resolved'] and result['reason'] == 'forwarder/API-set cycle'
checks += 1
chain = {f'a{n}.dll': ({'x': {'forwarder': f'a{n+1}.x'}}, {}) for n in range(mi.MAX_DEPTH + 1)}
result = mi.resolve_symbol('a0.dll', 'x', 'abi-jit-probe.exe', chain.get, lambda: {}, _module, forwarder)
assert not result['resolved'] and result['reason'] == 'forwarder/API-set depth limit'
checks += 1
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    farm = root / 'app/Madeira/arm64ec-windows'
    farm.mkdir(parents=True)
    (farm / 'kernel32.dll').write_bytes(export_fixture(target='kernelbase.Forwarded'))
    (farm / 'kernelbase.dll').write_bytes(export_fixture(name='Forwarded'))
    probe = {'sha256': 'a' * 64, 'architecture': 'x86_64', 'machine': '0x8664',
             'imports': [{'module': 'kernel32.dll', 'kind': 'import', 'symbols': [{'name': 'ProbeApi'}]},
                         {'module': 'kernelbase.dll', 'kind': 'delay', 'symbols': [{'ordinal': 1}]}]}
    result = mi.assess(probe, root, 'fixture-commit')
    assert result['complete'] and result['status'] == 'selected-imports-resolved-statically'
    assert result['checked_symbol_count'] == 2 and result['unresolved_symbol_count'] == 0
    assert result['providers']['kernel32.dll']['machine'] == '0x8664'
    assert result['providers']['kernelbase.dll']['architecture'] == 'x86_64'
    assert result['runtime_tested'] is False and result['abi_transition_verified'] is False
    assert result['affects_native_windows_acceptance'] is False
    checks += 1
    (farm / 'kernelbase.dll').write_bytes(export_fixture(name='MissingInstead'))
    result = mi.assess(probe, root, 'fixture-commit')
    assert result['complete'] and result['status'] == 'selected-import-gaps'
    assert result['unresolved_symbol_count'] == 1  # ordinal 1 still exists
    checks += 1
    (farm / 'kernelbase.dll').write_bytes(b'not PE bytes')
    result = mi.assess(probe, root, 'fixture-commit')
    assert not result['complete'] and result['status'] == 'incomplete'
    checks += 1
    (farm / 'kernelbase.dll').write_bytes(export_fixture(name='Forwarded'))
    for attribute, limit in [('MAX_PROVIDERS', 1), ('MAX_PROVIDER_BYTES', 1),
                             ('MAX_SECONDS', -1), ('MAX_SYMBOLS', 1), ('MAX_REPORT_BYTES', 1)]:
        old = getattr(mi, attribute)
        setattr(mi, attribute, limit)
        result = mi.assess(probe, root, 'fixture-commit')
        setattr(mi, attribute, old)
        assert not result['complete'] and result['status'] == 'incomplete'
        checks += 1
    for n in range(mi.MAX_DEPTH + 2):
        target = f'a{n+1}.ProbeApi' if n <= mi.MAX_DEPTH else None
        (farm / f'a{n}.dll').write_bytes(export_fixture(target=target))
    deep_probe = dict(probe, imports=[{'module': 'a0.dll', 'kind': 'import', 'symbols': [{'name': 'ProbeApi'}]}])
    result = mi.assess(deep_probe, root, 'fixture-commit')
    assert not result['complete'] and result['status'] == 'incomplete'
    assert result['checks'][0]['reason'] == 'forwarder/API-set depth limit'
    checks += 1

for path in [PureWindowsPath(r'C:\Program Files\Microsoft Visual Studio\18\Enterprise\cl.exe'),
             PureWindowsPath(r'C:\Program Files (x86)\Windows Kits\10\bin\rc.exe')]:
    assert p.cmake_path(path) == str(path).replace('\\', '/')
    checks += 1
for path in [PureWindowsPath(r'relative\cl.exe'), PureWindowsPath(r'C:\unsafe;path\cl.exe'),
             PureWindowsPath('C:\\unsafe\npath\\cl.exe'), PureWindowsPath(r'C:\${unsafe}\cl.exe'),
             Path('/tmp/literal\\backslash')]:
    reject(lambda path=path: p.cmake_path(path), 'unsafe/relative CMake tool path')
with tempfile.TemporaryDirectory() as folder:
    class ExportRun:
        def __init__(self):
            self.work = Path(folder).resolve()
            self.calls = []

        def command(self, name, argv, env, timeout):
            self.calls.append((name, argv))
            assert timeout == 180 and env == {'fixture': 'inert'}
            for key, tool in [('CMAKE_CXX_COMPILER', 'cl'), ('CMAKE_MAKE_PROGRAM', 'nmake'),
                              ('CMAKE_RC_COMPILER', 'rc'), ('CMAKE_MT', 'mt')]:
                expected = '-D' + key + '=' + tools[tool].as_posix()
                assert argv.count(expected) == 1 and '\\' not in expected
            generated = (self.work / (name + '-source/CMakeLists.txt')).read_text()
            assert 'C:/LLVM SDK/lib/cmake/llvm/LLVMExports.cmake' in generated
            assert not any(marker in generated for marker in ['@SDK@', '@TARGETS@', '@PROBE@'])
            return 0, ''

    tools = {name: PureWindowsPath(r'C:\Program Files\Trusted Tools') / (name + '.exe')
             for name in ['cmake', 'cl', 'nmake', 'rc', 'mt']}
    runner = ExportRun()
    for name in ['export-fixture', 'sdk-exports']:
        build = p.configure_exports(runner, tools, {'fixture': 'inert'}, PureWindowsPath(r'C:\LLVM SDK'),
                                    ['LLVMSupport'], name)
        assert build == runner.work / (name + '-build')
        checks += 1
    assert len(runner.calls) == 2

assert p.cmake_value('set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)\n', 'CMAKE_MSVC_RUNTIME_LIBRARY') == 'MultiThreaded'
checks += 1
for bad in ['', 'set(X a)\nset(X b)', 'set(X ${guessed})', 'set(X a;b)']:
    reject(lambda bad=bad: p.cmake_value(bad, 'X'), 'missing/ambiguous/unevaluated metadata')

rows = []
for n, (x, y) in enumerate(p.SEEDS):
    result = ((x * 6364136223846793005) ^ (y + 1442695040888963407)) & ((1 << 64) - 1)
    rows.append(f'JIT seed={n} x={x} y={y} value={result}')
rows.append('PASS llvm=22.1.4 abi=msvc-x64 crt=MT pointer_bits=64 passes=O1 jit=MCJIT seeds=2 cleanup=complete')
proof = '\n'.join(rows)
assert p.parse_proof(proof, 0)['actual_native_code_executed']
checks += 1
for bad in [proof + '\nFAIL cleanup', proof + '\n' + rows[0], '\n'.join(rows[1:]),
            proof.replace('crt=MT', 'crt=MD'), proof.replace('22.1.4', '22.1.3'),
            proof.replace('pointer_bits=64', 'pointer_bits=32'), proof.replace('seed=1', 'seed=0'),
            proof.replace('value=', 'value=0'), proof.replace('cleanup=complete', 'cleanup=unknown')]:
    reject(lambda bad=bad: p.parse_proof(bad, 0), 'missing/contradictory JIT/ABI proof')
reject(lambda: p.parse_proof(proof, 19), 'failed runtime exit')

workflow = (ROOT / '.github/workflows/llvm-sdk-windows-preflight.yml').read_text()
for value in ['runs-on: windows-2025', 'timeout-minutes: 45', 'contents: read',
              'persist-credentials: false', "github.repository == 'Mi-Yomi/Madeira'",
              'github.event.repository.private == false', "github.ref == 'refs/heads/compatibility/desktop-apps'",
              'tests/desktop/llvm_sdk/preflight-request.json', 'workflow_dispatch:']:
    assert value in workflow, value
assert workflow.count('uses:') == 1
assert 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' in workflow
assert not any(x in workflow.lower() for x in ['pull_request', 'schedule:', 'secrets.', 'upload-artifact', 'actions/cache'])
assert p.MAX_SDK == 6 * p.GIB and p.MAX_WORK == 8 * p.GIB and p.MIN_FREE == 3 * p.GIB
assert p.MAX_SECONDS <= 40 * 60 and p.MAX_LOG <= 8 * 1024 ** 2 and p.MAX_ALL_LOGS <= 64 * 1024 ** 2
assert lock['sdk']['size'] == 861945788
assert lock['sdk']['sha256'] == 'ed775bdaea7087c6c1aeac9498352cfcd8610d92dc4fe9eda9aecb15ce712a2c'
request = json.loads((SOURCE / 'preflight-request.json').read_text())
assert request['mesa_build_authorized_by_this_request'] is False
assert request['maximum_compile_jobs'] == 2 and request['maximum_link_jobs'] == 1
print(f'PASS: {checks} portable positive/negative VS discovery, archive, COFF/CRT, closure, metadata and proof controls; workflow bounds')
print('NOT RUN: SDK download/archive inventory, Windows compilation/link/runtime, Mesa, Wine/FEX/ARM64EC/iOS/Blender')
