#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed native Windows LLVM SDK ABI/dependency prerequisite; no Mesa build."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GIB = 1024 ** 3
MAX_SDK = 6 * GIB
MAX_WORK = 8 * GIB
MIN_FREE = 3 * GIB
MAX_SECONDS = 40 * 60
MAX_LOG = 8 * 1024 ** 2
MAX_ALL_LOGS = 64 * 1024 ** 2
SYSTEM_DLLS = {'advapi32.dll', 'kernel32.dll', 'ntdll.dll', 'user32.dll',
               'version.dll', 'ws2_32.dll', 'ole32.dll', 'shell32.dll',
               'shlwapi.dll', 'bcrypt.dll', 'dbghelp.dll', 'psapi.dll'}
SEEDS = [(7, 19), (0x123456789abcdef0, 211)]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(name, root):
    require(isinstance(name, str) and name and len(name) <= 240,
            'Absent or oversized archive name')
    require(not any(ord(c) < 32 for c in name) and not any(c in name for c in '\\:*?"<>|'),
            'Unsafe Windows archive name')
    raw = name.rstrip('/').split('/')
    require(all(p not in {'', '.', '..'} and not p.endswith((' ', '.')) for p in raw),
            'Noncanonical archive name')
    require(raw[0] == root and not PurePosixPath(name).is_absolute(), 'Wrong archive root')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'} | {
        f'{p}{n}' for p in ['COM', 'LPT'] for n in '123456789¹²³'}
    require(all(p.split('.')[0].upper() not in reserved for p in raw), 'Windows device archive name')
    return '/'.join(raw)


def inspect_archive(path, root, cap=MAX_SDK, guard=lambda: None):
    """Inspect every entry before writing; materialized hardlinks count as copies."""
    members = {}
    total = 0
    with tarfile.open(path, mode='r|xz') as archive:
        for member in archive:
            guard()
            name = safe_path(member.name, root)
            key = name.casefold()
            require(key not in members and len(members) < 100000, 'Duplicate/excessive archive entries')
            require(member.isdir() or member.isreg() or member.islnk(), 'Unsupported archive entry (including symlink)')
            require(not member.sparse and 0 <= member.size <= GIB, 'Sparse/oversized archive member')
            require(member.isreg() or member.size == 0, 'Nonregular entry contains bytes')
            target = safe_path(member.linkname, root) if member.islnk() else None
            members[key] = {'name': name, 'size': member.size,
                            'kind': 'file' if member.isreg() else 'hardlink' if member.islnk() else 'dir',
                            'target': target}
            total += member.size
            require(total <= cap, 'SDK expanded-size cap exceeded during inspection')
    for row in members.values():
        parts = row['name'].split('/')
        for n in range(1, len(parts)):
            ancestor = members.get('/'.join(parts[:n]).casefold())
            require(ancestor is None or ancestor['kind'] == 'dir', 'File used as archive parent')
        if row['kind'] == 'hardlink':
            target = members.get(row['target'].casefold())
            require(target is not None and target['kind'] == 'file', 'Hardlink must target an in-archive regular file')
            total += target['size']
    require(total <= cap, 'SDK materialized-size cap exceeded')
    require(members and any(x['kind'] == 'file' for x in members.values()), 'Empty SDK archive')
    return members, total


def extract_archive(path, dest, root, members, guard=lambda: None):
    # Never call extractall or restore permissions, owner, timestamps or links.
    with tarfile.open(path, mode='r|xz') as archive:
        for member in archive:
            guard()
            name = safe_path(member.name, root)
            row = members[name.casefold()]
            target = dest / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                require(row['kind'] == 'file' and member.size == row['size'], 'Archive changed after inspection')
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                require(source is not None, 'Missing archive member stream')
                remaining = member.size
                with target.open('xb') as output:
                    while remaining:
                        chunk = source.read(min(1024 ** 2, remaining))
                        require(chunk, 'Truncated archive member')
                        output.write(chunk)
                        remaining -= len(chunk)
                        guard()
    for row in members.values():
        if row['kind'] == 'hardlink':
            target = dest / row['name']
            target.parent.mkdir(parents=True, exist_ok=True)
            with (dest / row['target']).open('rb') as source, target.open('xb') as output:
                while chunk := source.read(1024 ** 2):
                    output.write(chunk)
                    guard()


def cmake_value(text, name):
    values = re.findall(r'^set\(\s*' + re.escape(name) + r'\s+([^\r\n)]*)\)', text, re.M)
    require(len(values) == 1, f'Absent/ambiguous SDK metadata: {name}')
    value = values[0].strip().strip('"')
    require(not any(c in value for c in '$;\\\n\r'), f'Unevaluated SDK metadata: {name}')
    return value


def sdk_metadata(sdk):
    config = sdk / 'lib/cmake/llvm/LLVMConfig.cmake'
    text = config.read_text(encoding='utf-8')
    names = ['LLVM_PACKAGE_VERSION', 'LLVM_BUILD_TYPE', 'CMAKE_MSVC_RUNTIME_LIBRARY',
             'LLVM_HOST_TRIPLE', 'LLVM_ENABLE_RTTI', 'LLVM_ENABLE_EH',
             'LLVM_ENABLE_ASSERTIONS', 'LLVM_ABI_BREAKING_CHECKS', 'LLVM_ENABLE_THREADS',
             'LLVM_ENABLE_LIBXML2', 'LLVM_ENABLE_ZLIB', 'LLVM_ENABLE_ZSTD',
             'LLVM_ENABLE_FFI', 'LLVM_ENABLE_LIBEDIT', 'LLVM_WITH_Z3']
    values = {name: cmake_value(text, name) for name in names}
    require(values['LLVM_PACKAGE_VERSION'] == '22.1.4', 'Wrong LLVM CMake version')
    require(values['LLVM_BUILD_TYPE'] == 'Release', 'Nonrelease LLVM SDK')
    require(values['CMAKE_MSVC_RUNTIME_LIBRARY'] == 'MultiThreaded', 'SDK CRT is not proven /MT')
    require(values['LLVM_HOST_TRIPLE'] == 'x86_64-pc-windows-msvc', 'Unknown SDK ABI/triple')
    for name in ['LLVM_ENABLE_RTTI', 'LLVM_ENABLE_EH', 'LLVM_ENABLE_ASSERTIONS', 'LLVM_ENABLE_THREADS']:
        require(values[name] in {'ON', 'OFF', '0', '1'}, f'Unknown SDK boolean: {name}')
    require(values['LLVM_ENABLE_ASSERTIONS'] in {'OFF', '0'} and
            values['LLVM_ABI_BREAKING_CHECKS'] in {'OFF', '0', 'WITH_ASSERTS', 'FORCE_OFF'}, 'Debug/ABI-breaking SDK unsupported')
    require(values['LLVM_ENABLE_THREADS'] in {'ON', '1'}, 'LLVM thread support absent')
    headers = ['llvm/Config/llvm-config.h', 'llvm/Config/abi-breaking.h',
               'llvm/ExecutionEngine/MCJIT.h', 'llvm/ExecutionEngine/ExecutionEngine.h',
               'llvm/IR/IRBuilder.h', 'llvm-c/Transforms/PassBuilder.h']
    values['headers'] = {name: sha(sdk / 'include' / name) for name in headers}
    abi_header = (sdk / 'include/llvm/Config/abi-breaking.h').read_text()
    require(re.search(r'^#define LLVM_ENABLE_ABI_BREAKING_CHECKS 0\s*$', abi_header, re.M),
            'Generated headers do not confirm ABI-breaking checks disabled')
    values['LLVMConfig.cmake_sha256'] = sha(config)
    values['LLVMExports.cmake_sha256'] = sha(sdk / 'lib/cmake/llvm/LLVMExports.cmake')
    return values


def selected_libraries(output, lock):
    names = output.split()
    require(0 < len(names) <= 180 and len(names) == len(set(names)), 'Invalid selected-library count')
    require(all(re.fullmatch(r'LLVM[A-Za-z0-9_]+\.lib', x) for x in names), 'Unknown llvm-config library syntax')
    targets = [x[:-4] for x in names]
    require(set(lock['required_libraries']) <= set(targets), 'Mesa required component library missing')
    require('LLVMWindowsManifest' not in targets, 'Selected closure needs WindowsManifest; stop for dependency review')
    return targets


def audit_static_library(path, guard=lambda: None):
    """Read COFF / bigobj sections without executing an SDK binary or loading .lib bytes wholesale."""
    defaults, runtime, objects, directive_objects = set(), set(), 0, 0
    size = path.stat().st_size
    require(size <= GIB, 'Static library exceeds per-file cap')
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'Not a regular COFF archive')
        pos = 8
        while pos < size:
            guard()
            stream.seek(pos)
            header = stream.read(60)
            require(len(header) == 60 and header[58:] == b'`\n', 'Invalid archive member header')
            number = header[48:58].strip()
            require(number.isdigit(), 'Invalid archive member length')
            length, start = int(number), pos + 60
            require(start + length <= size, 'Truncated static library member')
            name = header[:16].decode('ascii').strip()
            if name not in {'/', '//'}:
                head = stream.read(min(length, 56))
                require(not head.startswith((b'BC\xc0\xde', b'\xde\xc0\x17\x0b')),
                        'LLVM bitcode static library needs a separately reviewed linker/CRT plan')
                require(len(head) >= 20, 'Short COFF object')
                if head[:4] == b'\x00\x00\xff\xff':
                    require(len(head) >= 56 and head[12:28] == bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8'),
                            'Import/non-bigobj member is not a static code object')
                    machine, sections, section_offset = struct.unpack_from('<H', head, 6)[0], struct.unpack_from('<I', head, 44)[0], 56
                else:
                    machine, sections = struct.unpack_from('<HH', head)
                    optional = struct.unpack_from('<H', head, 16)[0]
                    require(optional == 0, 'Unexpected optional header in static COFF object')
                    section_offset = 20
                require(machine == 0x8664 and 0 < sections <= 200000, 'Wrong or unbounded COFF machine/sections')
                require(section_offset + sections * 40 <= length, 'Truncated COFF section table')
                stream.seek(start + section_offset)
                table = stream.read(sections * 40)
                for index in range(sections):
                    section = table[index * 40:(index + 1) * 40]
                    if section[:8] == b'.drectve':
                        count, offset = struct.unpack_from('<II', section, 16)
                        require(count <= 1024 ** 2 and offset + count <= length, 'Unbounded/truncated CRT directives')
                        stream.seek(start + offset)
                        text = stream.read(count).decode('ascii').replace('\x00', ' ')
                        require(not re.search(r'(?i)[/-](?:libpath|nodefaultlib|force)(?=[:\s"]|$)', text),
                                'Hidden library path, CRT suppression or unresolved-symbol override')
                        for match in re.finditer(r'(?i)[/-]defaultlib:(?:"([^"]+)"|([^\s]+))', text):
                            defaults.add((match[1] or match[2]).lower().removesuffix('.lib'))
                        runtime.update(re.findall(r'(?i)RuntimeLibrary=([^"\s]+)', text))
                        directive_objects += 1
                objects += 1
            pos = start + length + (length & 1)
        require(pos == size, 'Trailing static library bytes')
    require(objects > 0 and directive_objects > 0, 'No code/CRT directive evidence in library')
    require(defaults <= {'libcmt', 'libcpmt', 'libvcruntime', 'libucrt', 'oldnames'},
            f'Unreviewed implicit library/CRT dependency: {sorted(defaults)}')
    require('libcmt' in defaults or runtime == {'MT_StaticRelease'}, 'Library static release CRT identity absent')
    require(runtime <= {'MT_StaticRelease'}, f'Library CRT mismatch: {sorted(runtime)}')
    return {'coff_machine': 'x86_64', 'objects': objects, 'directive_objects': directive_objects,
            'default_libraries': sorted(defaults), 'runtime_mismatch_tags': sorted(runtime)}


def validate_closure(targets, graph, options, lock):
    """Every library edge must be selected or an exact reviewed system library."""
    require(set(graph) == set(targets) == set(options), 'Incomplete dependency metadata')
    systems, flags = set(), set()
    known_flags = set(lock['link_options'])
    for target in targets:
        for item in graph[target] + options[target]:
            if not item:
                continue
            require(not any(c in item for c in '$<>\\/"\r\n'), 'Unknown/unexpanded exported dependency')
            if item in targets:
                continue
            if item in lock['system_libraries']:
                systems.add(item)
            elif item in known_flags:
                flags.add(item)
            else:
                raise ValueError(f'Unresolved/unreviewed dependency: {target} -> {item}')
    # Required upstream allocator/delay-load semantics must not silently vanish.
    require(set(lock['system_libraries']) <= systems, 'Expected LLVMSupport system-library closure absent')
    require(set(lock['link_options']) <= flags, 'Expected LLVMSupport linker options absent')
    return sorted(systems), sorted(flags)


def parse_proof(output, code):
    lines = output.splitlines()
    require(code == 0 and len(lines) == 3, 'Probe exit or transcript shape failed')
    for n, (x, y) in enumerate(SEEDS):
        value = ((x * 6364136223846793005) ^ (y + 1442695040888963407)) & ((1 << 64) - 1)
        require(lines[n] == f'JIT seed={n} x={x} y={y} value={value}', 'Incorrect/missing/repeated JIT result')
    require(lines[-1] == 'PASS llvm=22.1.4 abi=msvc-x64 crt=MT pointer_bits=64 passes=O1 jit=MCJIT seeds=2 cleanup=complete',
            'Missing exact LLVM/ABI/pass/JIT/cleanup evidence')
    return {'seeds': 2, 'actual_native_code_executed': True, 'passes': 'default<O1>',
            'cpp_abi': 'MSVC x64', 'crt': 'MT', 'cleanup': 'complete'}


def install_job_limits():
    """Nested Windows job owns this interpreter and every later child process."""
    from ctypes import wintypes as w
    class Basic(ctypes.Structure):
        _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
                    ('LimitFlags', w.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', w.DWORD),
                    ('Affinity', ctypes.c_size_t), ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in ['ReadOperationCount', 'WriteOperationCount',
            'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount']]
    class Extended(ctypes.Structure):
        _fields_ = [('BasicLimitInformation', Basic), ('IoInfo', IO),
                    ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    require(job, 'Cannot create bounded Windows job')
    info = Extended()
    info.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x8  # kill on close, job memory, active processes
    info.BasicLimitInformation.ActiveProcessLimit = 16
    info.JobMemoryLimit = 10 * GIB
    require(kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)), 'Cannot set job resource limits')
    require(kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()), 'Cannot bind preflight process tree to limits')
    return job  # Deliberately live until process exit; closing kills this entire job.


class Run:
    def __init__(self, work):
        self.work, self.started, self.last_check = work, time.monotonic(), 0.0
        self.records = []
        self.lock = threading.Lock()

    def guard(self, force=False):
        with self.lock:
            now = time.monotonic()
            require(now - self.started <= MAX_SECONDS, '40-minute internal deadline reached')
            if force or now - self.last_check >= 10:
                self.last_check = now
                sizes = []
                for p in self.work.rglob('*'):
                    try:
                        if p.is_file():
                            sizes.append((p, p.stat().st_size))
                    except FileNotFoundError:
                        pass  # CMake/compiler transient files may disappear between stat calls.
                total = sum(size for p, size in sizes)
                logs = sum(size for p, size in sizes if p.suffix == '.log')
                require(total <= MAX_WORK, '8-GiB work cap exceeded')
                require(shutil.disk_usage(self.work).free >= MIN_FREE, '3-GiB free-space floor reached')
                require(logs <= MAX_ALL_LOGS, '64-MiB total log cap exceeded')
                require(all(size <= MAX_LOG for p, size in sizes if p.suffix == '.log'), '8-MiB log cap exceeded')

    def monitor(self):
        while True:
            time.sleep(2)
            try:
                self.guard()
            except Exception as exc:
                print(f'FAIL resource-guard={exc}', file=sys.stderr, flush=True)
                os._exit(2)  # Windows job termination also ends descendants.

    def command(self, name, argv, env, timeout, cwd=None, required=True):
        log = self.work / f'{name}.log'
        self.guard(True)
        start = time.monotonic()
        process = None
        try:
            with log.open('xb') as output:
                process = subprocess.Popen(list(map(str, argv)), env=env, cwd=cwd or self.work,
                                           stdout=output, stderr=subprocess.STDOUT)
                while process.poll() is None:
                    require(time.monotonic() - start <= timeout, f'{name} timed out')
                    require(log.stat().st_size <= MAX_LOG, f'{name} output cap exceeded')
                    self.guard()
                    time.sleep(0.2)
                require(log.stat().st_size <= MAX_LOG, f'{name} output cap exceeded')
        finally:
            if process is not None and process.poll() is None:
                subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'),
                                '/PID', str(process.pid), '/T', '/F'], timeout=15,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                process.wait(timeout=15)
        text = log.read_text(encoding='utf-8', errors='replace')
        print(f'STAGE {name} exit={process.returncode} seconds={time.monotonic()-start:.3f}', flush=True)
        if process.returncode or name.startswith('runtime'):
            print(text[-12000:], flush=True)
        self.records.append({'stage': name, 'argv': list(map(str, argv)), 'exit': process.returncode,
                             'log_sha256': sha(log), 'seconds': round(time.monotonic()-start, 3)})
        require(not required or process.returncode == 0, f'{name} failed; exact log retained under fresh work root')
        return process.returncode, text

    def fetch(self, item):
        path = self.work / item['filename']
        require(item['url'].startswith('https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.4/'),
                'Unapproved input URL')
        with urllib.request.urlopen(item['url'], timeout=40) as response, path.open('xb') as output:
            final = urllib.parse.urlparse(response.url)
            require(final.scheme == 'https' and final.hostname in {'github.com', 'release-assets.githubusercontent.com',
                    'objects.githubusercontent.com'}, 'Unapproved release redirect')
            while chunk := response.read(1024 ** 2):
                require(output.tell() + len(chunk) <= item['size'], 'Download exceeds pinned size')
                output.write(chunk)
                self.guard()
        require(path.stat().st_size == item['size'] and sha(path) == item['sha256'], 'SDK size/hash mismatch')
        print(f'INPUT verified bytes={item["size"]} sha256={item["sha256"]}', flush=True)
        return path


def tool_environment(run):
    win = Path(os.environ['SystemRoot'])
    program = Path(os.environ['ProgramFiles'])
    program32 = Path(os.environ['ProgramFiles(x86)'])
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432',
            'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}}
    env.update(TEMP=str(run.work / 'temp'), TMP=str(run.work / 'temp'),
               PATH=str(win / 'System32'), VSCMD_SKIP_SENDTELEMETRY='1',
               PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    vswhere = program32 / 'Microsoft Visual Studio/Installer/vswhere.exe'
    require(vswhere.is_file(), 'Preinstalled Visual Studio locator missing; no install fallback')
    _, result = run.command('vs-locate', [vswhere, '-latest', '-products', '*', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], env, 30)
    lines = result.strip().splitlines()
    require(len(lines) == 1, 'Expected one preinstalled Visual Studio installation')
    vs = Path(lines[0]).resolve()
    require(vs.is_relative_to(program) or vs.is_relative_to(program32), 'Unexpected Visual Studio location')
    devcmd = vs / 'Common7/Tools/VsDevCmd.bat'
    require(devcmd.is_file() and not any(c in str(devcmd) for c in '%!^&|<>"\r\n'), 'Unsafe/missing developer environment script')
    script = run.work / 'tool-environment.cmd'
    script.write_text('@echo off\ncall "' + str(devcmd) + '" -no_logo -arch=x64 -host_arch=x64 >nul\n'
                      'if errorlevel 1 exit /b 1\necho INCLUDE=%INCLUDE%\necho LIB=%LIB%\necho VC_TOOLS=%VCToolsInstallDir%\n'
                      'echo SDK_DIR=%WindowsSdkDir%\necho SDK_VERSION=%WindowsSDKVersion%\n', encoding='ascii')
    _, output = run.command('vs-environment', [win / 'System32/cmd.exe', '/d', '/c', script], env, 60)
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key.upper() in {'INCLUDE', 'LIB', 'VC_TOOLS', 'SDK_DIR', 'SDK_VERSION'} and key.upper() not in values,
                'Unexpected developer environment output')
        values[key.upper()] = value
    require({'INCLUDE', 'LIB', 'VC_TOOLS', 'SDK_DIR', 'SDK_VERSION'} == values.keys(), 'Incomplete developer tools environment')
    vc = Path(values.pop('VC_TOOLS')).resolve()
    require(vc.is_relative_to(vs) and (vc / 'bin/Hostx64/x64/cl.exe').is_file(), 'Unverified MSVC compiler path')
    sdkroot = program32 / 'Windows Kits'
    sdkdir = Path(values.pop('SDK_DIR')).resolve()
    sdkversion = values.pop('SDK_VERSION').rstrip('\\/')
    require(sdkdir.is_relative_to(sdkroot) and re.fullmatch(r'\d+\.\d+\.\d+\.\d+', sdkversion), 'Unknown Windows SDK identity')
    sdkbin = sdkdir / 'bin' / sdkversion / 'x64'
    for key, value in values.items():
        for element in value.split(';'):
            if element:
                path = Path(element).resolve()
                require(path.is_dir() and (path.is_relative_to(vs) or path.is_relative_to(sdkroot)),
                        f'Unexpected {key} search path')
    env.update(values)
    cmakes = [program / 'CMake/bin/cmake.exe', vs / 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe']
    cmake = next((p for p in cmakes if p.is_file()), None)
    require(cmake is not None, 'Preinstalled CMake unavailable; no package-manager fallback')
    toolbin = vc / 'bin/Hostx64/x64'
    env['PATH'] = os.pathsep.join(map(str, [toolbin, sdkbin, cmake.parent, win / 'System32', win]))
    tools = {name: toolbin / (name + '.exe') for name in ['cl', 'link', 'nmake', 'dumpbin']}
    tools['cmake'] = cmake
    tools.update({name: sdkbin / (name + '.exe') for name in ['rc', 'mt']})
    require(all(p.is_file() for p in tools.values()), 'Preinstalled compiler/linker/build tool missing')
    _, version = run.command('cmake-version', [cmake, '--version'], env, 20)
    match = re.search(r'cmake version (\d+)\.(\d+)\.(\d+)', version)
    require(match and tuple(map(int, match.groups())) >= (3, 25, 0), 'CMake >=3.25 required for exact export evaluation')
    return tools, env, {'visual_studio': str(vs), 'msvc': str(vc), 'windows_sdk': str(sdkdir),
                       'windows_sdk_version': sdkversion, 'cmake_version': version.strip(),
                       'tools': {n: {'path': str(p), 'sha256': sha(p)} for n, p in tools.items()}}


def validate_pe_dependencies(dependencies):
    for dependency in dependencies:
        name = dependency['module'].lower()
        require(name in SYSTEM_DLLS, f'Unreviewed dynamic dependency (including CRT/API-set): {name}')
        require(dependency['kind'] == 'import' or name in {'shell32.dll', 'ole32.dll'}, 'Unexpected delay import')


def audit_pe(path):
    require(path.is_file() and path.stat().st_size <= 128 * 1024 ** 2, 'Missing/oversized PE')
    sys.path.insert(0, str(ROOT / 'build/wine-pe'))
    from symbol_audit import PE, imports
    pe = PE(path.read_bytes())
    require(pe.architecture() == 'x86_64', 'Wrong PE architecture')
    dependencies = imports(pe)
    validate_pe_dependencies(dependencies)
    evidence = {'size': path.stat().st_size, 'sha256': sha(path), 'machine': f'0x{pe.machine:04x}',
                'architecture': pe.architecture(), 'pe_kind': 'PE32+' if pe.pe64 else 'PE32',
                'imports': dependencies, 'import_descriptor_count': len(dependencies),
                'import_symbol_count': sum(len(item['symbols']) for item in dependencies)}
    require(evidence['import_symbol_count'] <= 4096 and len(json.dumps(evidence).encode('utf-8')) <= 1024 ** 2,
            'Exact PE import evidence exceeds bounded log size')
    return evidence


def split_exported_properties(text):
    values = text.strip().split(';')
    require(values.count('MADEIRA_EXPORT_OPTIONS_BOUNDARY') == 1, 'Missing/ambiguous exported-property boundary')
    index = values.index('MADEIRA_EXPORT_OPTIONS_BOUNDARY')
    return values[:index], values[index + 1:]


def configure_exports(runner, tools, env, sdk, targets, name):
    source, build = runner.work / (name + '-source'), runner.work / (name + '-build')
    source.mkdir()
    target_file = source / 'selected-targets.txt'
    target_file.write_text('\n'.join(targets) + '\n')
    cmake_text = (HERE / 'inspect_exports.cmake.in').read_text()
    for key, value in {'SDK': sdk, 'TARGETS': target_file, 'PROBE': HERE / 'abi_jit_probe.cpp'}.items():
        value = value.as_posix()
        require(not any(c in value for c in '";\n\r$'), 'Unsafe generated CMake path')
        cmake_text = cmake_text.replace('@' + key + '@', value)
    (source / 'CMakeLists.txt').write_text(cmake_text)
    runner.command(name, [tools['cmake'], '-S', source, '-B', build,
        '-G', 'NMake Makefiles', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded',
        '-DCMAKE_CXX_COMPILER=' + str(tools['cl']), '-DCMAKE_MAKE_PROGRAM=' + str(tools['nmake']),
        '-DCMAKE_RC_COMPILER=' + str(tools['rc']), '-DCMAKE_MT=' + str(tools['mt']),
        '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
        '-DCMAKE_FIND_USE_PACKAGE_ROOT_PATH=OFF'], env, 180)
    return build


def export_evaluation_fixture(runner, tools, env):
    """Prove link-expression evaluation before downloading any SDK; no fixture is linked."""
    sdk = runner.work / 'export-evaluation-fixture'
    cmake = sdk / 'lib/cmake/llvm'
    cmake.mkdir(parents=True)
    for name in ['LLVMSupport', 'LLVMDemangle']:
        (sdk / 'lib' / (name + '.lib')).write_bytes(b'fixture-not-a-library')
    content = ''
    for name in ['LLVMSupport', 'LLVMDemangle']:
        content += f'add_library({name} STATIC IMPORTED)\n'
        content += f'set_target_properties({name} PROPERTIES IMPORTED_LOCATION "{sdk.as_posix()}/lib/{name}.lib")\n'
    content += r'''set_target_properties(LLVMSupport PROPERTIES
INTERFACE_LINK_LIBRARIES "LLVMDemangle;psapi;$<$<NOT:$<LINK_LANGUAGE:Swift>>:delayimp;$<$<OR:$<LINK_LANG_AND_ID:C,IntelLLVM>,$<LINK_LANG_AND_ID:CXX,IntelLLVM>,$<LINK_LANG_AND_ID:Fortran,IntelLLVM>>:-Qoption,link,>-delayload:shell32.dll;-delayload:ole32.dll>;$<LINK_ONLY:-INCLUDE:malloc>"
INTERFACE_LINK_OPTIONS "-delayload:shell32.dll")
'''
    (cmake / 'LLVMExports.cmake').write_text(content)
    build = configure_exports(runner, tools, env, sdk, ['LLVMSupport', 'LLVMDemangle'], 'export-fixture')
    deps, options = split_exported_properties((build / 'metadata/LLVMSupport.evaluated').read_text())
    require(deps == ['LLVMDemangle', 'psapi', 'delayimp', '-delayload:shell32.dll', '-delayload:ole32.dll', '-INCLUDE:malloc']
            and options == ['-delayload:shell32.dll'], 'Native CMake conditional link evaluation failed')
    empty, empty_options = split_exported_properties((build / 'metadata/LLVMDemangle.evaluated').read_text())
    require(not any(empty) and not any(empty_options), 'CMake invented absent dependencies')
    print('PASS export-evaluation-fixture link-language=MSVC-CXX conditional-options=preserved', flush=True)


def run_preflight(work):
    require(os.name == 'nt' and platform.machine().lower() in {'amd64', 'x86_64'}, 'Native x64 Windows required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'Mi-Yomi/Madeira' and
            os.environ.get('GITHUB_REF') == 'refs/heads/compatibility/desktop-apps' and
            os.environ.get('GITHUB_EVENT_NAME') in {'push', 'workflow_dispatch'}, 'Wrong Actions repository/ref/event')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    require(event.get('repository', {}).get('private') is False, 'Public repository guard missing')
    lock = json.loads((HERE / 'inputs.lock.json').read_text())
    require(platform.python_version() == lock['host_python'] and sys.maxsize > 2 ** 32, 'Pinned preinstalled Python 3.12.10 x64 required')
    temp = Path(os.environ['RUNNER_TEMP']).resolve()
    work = work.absolute()
    require(not work.exists() and not work.is_symlink() and work.resolve().is_relative_to(temp) and work.resolve() != temp,
            'Work root must be fresh and strictly under RUNNER_TEMP')
    require(not work.resolve().is_relative_to(ROOT) and not ROOT.is_relative_to(work.resolve()), 'Checkout/work roots overlap')
    work.mkdir(parents=True)
    for name in ['temp', 'runtime']:
        (work / name).mkdir()
    job = install_job_limits()
    runner = Run(work)
    runner.guard(True)
    threading.Thread(target=runner.monitor, daemon=True).start()
    tools, env, tool_record = tool_environment(runner)
    export_evaluation_fixture(runner, tools, env)
    archive = runner.fetch(lock['sdk'])
    members, expanded = inspect_archive(archive, lock['sdk']['archive_root'], guard=runner.guard)
    print(f'ARCHIVE inspected entries={len(members)} expanded_bytes={expanded} cap={MAX_SDK}', flush=True)
    extract_archive(archive, work, lock['sdk']['archive_root'], members, runner.guard)
    sdk = work / lock['sdk']['archive_root']
    licenses = {str(p.relative_to(sdk)): sha(p) for p in sdk.rglob('*') if p.is_file() and
                (p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')))}
    require(licenses, 'LLVM license/notices absent')
    metadata = sdk_metadata(sdk)
    print('SDK_METADATA ' + json.dumps(metadata, sort_keys=True), flush=True)
    config = sdk / 'bin/llvm-config.exe'
    config_pe = audit_pe(config)
    config_env = dict(env, PATH=os.pathsep.join([str(Path(os.environ['SystemRoot']) / 'System32'), os.environ['SystemRoot']]))
    queried = {}
    for name in ['version', 'host-target', 'has-rtti', 'shared-mode', 'targets-built', 'cxxflags']:
        _, result = runner.command('llvm-' + name, [config, '--' + name], config_env, 30)
        queried[name] = result.strip()
    require(queried['version'] == '22.1.4' and queried['host-target'] == 'x86_64-pc-windows-msvc', 'llvm-config identity mismatch')
    require(queried['shared-mode'] == 'static' and 'X86' in queried['targets-built'].split(), 'Missing static native backend')
    rtti = metadata['LLVM_ENABLE_RTTI'] in {'ON', '1'}
    require(queried['has-rtti'] == ('YES' if rtti else 'NO'), 'RTTI metadata disagreement')
    _, output = runner.command('llvm-selected-libs', [config, '--link-static', '--libnames'] + lock['components'], config_env, 30)
    targets = selected_libraries(output, lock)
    _, system_output = runner.command('llvm-global-system-libs', [config, '--link-static', '--system-libs'] + lock['components'], config_env, 30)
    print('LLVM_CONFIG ' + json.dumps(queried, sort_keys=True), flush=True)
    print('GLOBAL_SYSTEM_LIBS diagnostic_only=' + system_output.strip(), flush=True)
    build = configure_exports(runner, tools, env, sdk, targets, 'sdk-exports')
    graph, link_options, libraries = {}, {}, {}
    for name in targets:
        meta = build / 'metadata'
        path = Path((meta / (name + '.location')).read_text().strip()).resolve()
        require(path == (sdk / 'lib' / (name + '.lib')).resolve() and path.is_file(), 'Imported library escaped exact SDK path')
        graph[name], link_options[name] = split_exported_properties((meta / (name + '.evaluated')).read_text())
        libraries[name] = {'path': str(path), 'size': path.stat().st_size, 'sha256': sha(path),
                           'coff_crt': audit_static_library(path, runner.guard)}
    systems, flags = validate_closure(targets, graph, link_options, lock)
    for library in systems:
        matches = [Path(folder) / (library + '.lib') for folder in env['LIB'].split(';') if folder]
        matches = [p for p in matches if p.is_file()]
        require(matches, f'Expected preinstalled system import library absent: {library}')
    manifest = {'selected_components': lock['components'], 'selected_libraries': libraries,
                'dependency_edges': graph, 'exported_link_options': link_options,
                'system_libraries': systems, 'link_options': flags, 'global_system_libs_diagnostic': system_output.strip(),
                'windows_manifest_in_closure': False, 'third_party_dependency_removed': False,
                'config_sha256': metadata['LLVMConfig.cmake_sha256'], 'exports_sha256': metadata['LLVMExports.cmake_sha256']}
    (work / 'dependency-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('CLOSURE ' + json.dumps({'libraries': targets, 'system_libraries': systems, 'link_options': flags,
          'windows_manifest_in_closure': False, 'manifest_sha256': sha(work / 'dependency-manifest.json')}, sort_keys=True), flush=True)
    for name, row in libraries.items():
        print('LIBRARY ' + json.dumps({'name': name, **row}, sort_keys=True), flush=True)
    obj, exe = work / 'probe.obj', work / 'runtime/abi-jit-probe.exe'
    args = [tools['cl'], '/nologo', '/c', '/O2', '/MT', '/std:c++17', '/DNDEBUG', '/D_ITERATOR_DEBUG_LEVEL=0',
            '/DLLVM_BUILD_STATIC',
            '/GR' if rtti else '/GR-', '/I' + str(sdk / 'include'), '/Fo' + str(obj), HERE / 'abi_jit_probe.cpp']
    args += ['/EHsc'] if metadata['LLVM_ENABLE_EH'] in {'ON', '1'} else ['/EHs-c-', '/D_HAS_EXCEPTIONS=0']
    runner.command('compile-probe', args, env, 180)
    _, directives = runner.command('probe-crt-directives', [tools['dumpbin'], '/nologo', '/directives', obj], env, 30)
    require('LIBCMT' in directives.upper() and 'MSVCRT' not in directives.upper() and
            'MD_DYNAMIC' not in directives.upper() and 'MTD_STATICDEBUG' not in directives.upper(), 'Compiled probe does not prove release static CRT')
    response = ['/NOLOGO', '/MACHINE:X64', '/INCREMENTAL:NO', '/WX', '/OUT:' + str(exe), str(obj)]
    response += [str(sdk / 'lib' / (n + '.lib')) for n in targets]
    response += [n + '.lib' for n in systems] + flags
    require(all(not any(c in x for c in '"\r\n') for x in response), 'Unsafe linker response argument')
    (work / 'probe-link.rsp').write_text('\n'.join('"' + x + '"' for x in response) + '\n')
    runner.command('link-probe', [tools['link'], '@' + str(work / 'probe-link.rsp')], env, 300)
    binary = audit_pe(exe)
    # Persist exact imports in the job log before runtime, even if it later fails.
    print('PROBE_PE ' + json.dumps(binary, sort_keys=True), flush=True)
    from madeira_imports import assess
    madeira_comparison = assess(binary, ROOT, os.environ.get('GITHUB_SHA'), runner.guard)
    (work / 'madeira-import-assessment.json').write_text(json.dumps(madeira_comparison, indent=2) + '\n')
    print('MADEIRA_IMPORT_ASSESSMENT ' + json.dumps(madeira_comparison, sort_keys=True), flush=True)
    runtime_env = dict(config_env, PATH=os.pathsep.join([str(work / 'runtime'), str(Path(os.environ['SystemRoot']) / 'System32'), os.environ['SystemRoot']]))
    code, result = runner.command('runtime-jit', [exe], runtime_env, 30, work / 'runtime', required=False)
    proof = parse_proof(result, code)
    require(binary['sha256'] == sha(exe) and config_pe['sha256'] == sha(config), 'Runtime binary changed')
    runner.guard(True)
    receipt = {'schema_version': 1, 'status': 'native-windows-sdk-abi-jit-passed',
               'scope': 'LLVM SDK prerequisite only; no Mesa/Blender/Wine/FEX/ARM64EC/iOS test',
               'source_commit': os.environ.get('GITHUB_SHA'), 'runner_image': os.environ.get('ImageVersion'),
               'platform': platform.platform(), 'toolchain': tool_record, 'sdk_metadata': metadata,
               'sdk_archive': lock['sdk'], 'expanded_bytes': expanded, 'licenses': licenses,
               'dependency_manifest_sha256': sha(work / 'dependency-manifest.json'),
               'sdk_runtime': config_pe, 'source_probe': binary, 'proof': proof,
               'madeira_import_assessment': madeira_comparison,
               'commands': runner.records, 'seconds': round(time.monotonic() - runner.started, 3),
               'request': json.loads((HERE / 'preflight-request.json').read_text()),
               'job_limits': {'active_processes': 16, 'memory_bytes': 10 * GIB, 'compile_jobs': 1, 'link_jobs': 1}}
    (work / 'preflight-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    brief = {k: receipt[k] for k in ['status', 'scope', 'source_commit', 'runner_image',
             'expanded_bytes', 'dependency_manifest_sha256', 'proof', 'seconds']}
    brief['source_probe'] = {k: binary[k] for k in ['machine', 'architecture', 'size', 'sha256',
                             'import_descriptor_count', 'import_symbol_count']}
    brief['source_probe']['exact_import_evidence_record'] = 'PROBE_PE'
    brief['madeira_import_assessment'] = {k: madeira_comparison[k] for k in
        ['status', 'complete', 'checked_symbol_count', 'runtime_tested', 'abi_transition_verified']}
    print('PREFLIGHT ' + json.dumps(brief, sort_keys=True), flush=True)
    require(job is not None, 'Lost process-tree containment')


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--work-root', type=Path, required=True)
    options = parser.parse_args()
    try:
        run_preflight(options.work_root)
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f'FAIL LLVM SDK preflight stopped: {exc}', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
