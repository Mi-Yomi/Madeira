#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded, source-built Mesa softpipe reference on a standard public Windows job.

No installation, upload, fallback download, renderer override or Madeira runtime.
The sole target executable is the source-owned canary. Meson compiler sanity
execution is explicitly skipped for both machine kinds; target run checks require
an unavailable executable wrapper. Real compilation and linking must still pass.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

SOURCES = Path(__file__).resolve().parent
ROOT = SOURCES.parents[2]
MAX_LOG = 16 * 1024**2
MAX_WORK = 6 * 1024**3
MIN_FREE = 4 * 1024**3
MAX_SECONDS = 1320
OPTIONS = [
    '--buildtype=release', '--default-library=static', '--wrap-mode=nodownload',
    '-Db_lto=false', '-Dplatforms=windows', '-Dgallium-drivers=softpipe',
    '-Dllvm=disabled', '-Ddraw-use-llvm=false', '-Dvulkan-drivers=[]',
    '-Dvulkan-layers=[]', '-Degl=disabled', '-Dglx=disabled', '-Dgles1=disabled',
    '-Dgles2=disabled', '-Dgbm=disabled', '-Dglvnd=disabled', '-Dopengl=true',
    '-Dexpat=disabled', '-Dxmlconfig=disabled', '-Dzlib=disabled', '-Dzstd=disabled',
    '-Dshader-cache=disabled', '-Dgallium-va=disabled', '-Dgallium-rusticl=false',
    '-Dgallium-d3d12-video=disabled', '-Dmicrosoft-clc=disabled',
    '-Dvideo-codecs=[]', '-Dbuild-tests=false', '-Dtools=[]',
    '-Dvalgrind=disabled', '-Dlibunwind=disabled',
]
SYSTEM_DLLS = {'advapi32.dll', 'gdi32.dll', 'kernel32.dll', 'ntdll.dll',
              'user32.dll', 'version.dll', 'ws2_32.dll', 'ole32.dll',
              'shell32.dll', 'shlwapi.dll', 'bcrypt.dll', 'dbghelp.dll',
              'winmm.dll', 'ucrtbase.dll', 'msvcrt.dll'}
REQUIRED_EXPORTS = {'wglChoosePixelFormat', 'wglDescribePixelFormat',
                    'wglGetPixelFormat', 'wglSetPixelFormat', 'wglSwapBuffers',
                    'wglCreateContext', 'wglDeleteContext', 'wglMakeCurrent',
                    'wglGetProcAddress', 'glGetString', 'glGetIntegerv',
                    'glClearColor', 'glClear', 'glViewport', 'glReadPixels',
                    'glReadBuffer', 'glFinish', 'glGetError', 'glDrawArrays'}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_file(path, record):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record['size']:
        raise ValueError(f'Input size/type mismatch: {path.name}')
    if digest(path) != record['sha256']:
        raise ValueError(f'Input checksum mismatch: {path.name}')


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or '\\' in name or ':' in name
            or '..' in path.parts or '\x00' in name):
        raise ValueError(f'Unsafe archive path: {name!r}')
    return path


def unpack_zip(archive, destination, cap):
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if len(infos) > 100000 or sum(i.file_size for i in infos) > cap:
            raise ValueError('Expanded ZIP exceeds resource budget')
        seen = set()
        for i in infos:
            safe_name(i.filename)
            if i.filename.lower() in seen or stat.S_ISLNK(i.external_attr >> 16):
                raise ValueError('Duplicate ZIP entry or symlink')
            seen.add(i.filename.lower())
        z.extractall(destination)


def source_hashes(source):
    return {str(p.relative_to(source)).replace('\\', '/'): digest(p)
            for p in sorted(source.rglob('*')) if p.is_file() and not p.is_symlink()}


def parse_proof(output, code, stage, expected_dir):
    """Only explicit unsupported-context outcomes may become core43 unavailable."""
    rows = output.splitlines()
    if any(r.startswith('FAIL ') for r in rows):
        raise ValueError('Canary reported a failed checkpoint')
    required = ['window', 'gdi-memory', 'gdi-window']
    if stage != 'gdi':
        required += ['gl-load', 'pixel-format', 'legacy-context',
                     'legacy-clear-readback', 'legacy-swap', 'legacy-window-readback',
                     'legacy-second-readback', 'legacy-second-swap',
                     'legacy-second-window-readback']
    for item in required:
        if rows.count(f'PASS stage={item}') != 1:
            raise ValueError(f'Missing or repeated checkpoint: {item}')
    if rows.count(f'CANARY stage={stage} pointer_bits=64') != 1:
        raise ValueError('Missing canary stage/architecture identity')
    proof = {'stage': stage, 'status': 'passed', 'window_backing_pixels': True,
             'compositor_display_proven': False}
    if stage != 'gdi':
        for label, filename in [('opengl32', 'opengl32.dll'), ('gallium', 'libgallium_wgl.dll')]:
            paths = [r.removeprefix(f'MODULE {label}=') for r in rows
                     if r.startswith(f'MODULE {label}=')]
            if (len(paths) != 1 or ntpath.normcase(ntpath.normpath(paths[0])) !=
                    ntpath.normcase(ntpath.join(str(expected_dir), filename))):
                raise ValueError(f'Wrong loaded module identity: {label}')
        identity = [r for r in rows if r.startswith('GL renderer=')]
        if len(identity) != 1 or not re.fullmatch(r'GL renderer=softpipe version=.+ Mesa 26\.2\.4', identity[0]):
            raise ValueError('Wrong actual renderer/source version')
        version = [r for r in rows if r.startswith('LEGACY version=')]
        if len(version) != 1 or not re.fullmatch(r'LEGACY version=[3-9]\.[0-9]+ profile=0x[0-9a-f]+', version[0]):
            raise ValueError('Missing numeric GL version')
        proof.update(renderer=identity[0], actual_legacy_version=version[0])
        for tag, colors, window in [
                ('legacy-clear-readback', (64, 128, 191), False),
                ('legacy-window-readback', (64, 128, 191), True),
                ('legacy-second-readback', (191, 64, 128), False),
                ('legacy-second-window-readback', (191, 64, 128), True)]:
            pixel_proof(rows, tag, colors, window)
    if stage == 'core43' and code == 77:
        unsupported = [r for r in rows if r.startswith('UNAVAILABLE core43=')]
        accepted = {'UNAVAILABLE core43=missing-create-context-attribs',
                    'UNAVAILABLE core43=context-rejected win32_error=8341',
                    'UNAVAILABLE core43=context-rejected win32_error=8342'}
        if len(unsupported) != 1 or unsupported[0] not in accepted:
            raise ValueError('Unclassified context failure is not unavailability')
        if f'PASS requested-stage={stage}' in rows or 'PASS stage=core43-context' in rows:
            raise ValueError('Contradictory unsupported-context proof')
        proof.update(status='unavailable', reason=unsupported[0])
        return proof
    if code != 0 or rows.count(f'PASS requested-stage={stage}') != 1:
        raise ValueError(f'Canary failed or omitted final proof: {stage}, exit {code}')
    if any(r.startswith('UNAVAILABLE ') for r in rows):
        raise ValueError('Contradictory unavailability')
    if stage == 'core43':
        for tag in ['core43-context', 'core-shader-readback', 'core-swap', 'core-window-readback']:
            if rows.count(f'PASS stage={tag}') != 1:
                raise ValueError(f'Missing real core43 proof: {tag}')
        versions = [r for r in rows if r.startswith('CORE version=')]
        if len(versions) != 1:
            raise ValueError('Missing core version')
        m = re.fullmatch(r'CORE version=(\d+)\.(\d+) profile=0x([0-9a-f]+)', versions[0])
        if not m or (int(m[1]), int(m[2])) < (4, 3) or not (int(m[3], 16) & 1):
            raise ValueError('Core version/profile below the tested floor')
        pixel_proof(rows, 'core-shader-readback', (255, 0, 0), False)
        pixel_proof(rows, 'core-window-readback', (255, 0, 0), True)
    return proof


def pixel_proof(rows, stage, colors, window):
    prefix = ('WINDOW_PIXEL' if window else 'PIXEL') + f' stage={stage} '
    values = [r[len(prefix):] for r in rows if r.startswith(prefix)]
    pattern = r'rgb=(\d+),(\d+),(\d+)' if window else r'rgba=(\d+),(\d+),(\d+),(\d+) gl_error=0x0'
    match = re.fullmatch(pattern, values[0]) if len(values) == 1 else None
    if (not match or any(not 0 <= int(v) <= 255 for v in match.groups())
            or any(abs(int(match[i + 1]) - wanted) > 1 for i, wanted in enumerate(colors))):
        raise ValueError(f'Absent or incorrect pixel evidence: {stage}')


class Run:
    def __init__(self, work):
        self.work = work
        self.started = time.monotonic()
        self.last_disk_check = 0.0
        self.records = []

    def guard(self, force=False):
        now = time.monotonic()
        if now - self.started > MAX_SECONDS:
            raise TimeoutError('Reference exceeded its 22-minute internal deadline')
        if force or now - self.last_disk_check > 10:
            self.last_disk_check = now
            total = sum(p.stat().st_size for p in self.work.rglob('*')
                        if p.is_file() and not p.is_symlink())
            if total > MAX_WORK or shutil.disk_usage(self.work).free < MIN_FREE:
                raise ValueError('Reference disk budget exceeded')

    def command(self, name, argv, env, timeout, cwd=None):
        log = self.work / f'{name}.log'
        begin = time.monotonic()
        self.guard(force=True)
        process = None
        try:
            with log.open('xb') as out:
                process = subprocess.Popen(list(map(str, argv)), cwd=cwd or self.work,
                                           env=env, stdout=out, stderr=subprocess.STDOUT)
                while process.poll() is None:
                    if time.monotonic() - begin > timeout:
                        raise TimeoutError(f'{name} timed out')
                    if log.stat().st_size > MAX_LOG:
                        raise ValueError(f'{name} exceeded the log budget')
                    self.guard()
                    time.sleep(0.25)
                if log.stat().st_size > MAX_LOG:
                    raise ValueError(f'{name} exceeded the log budget')
        finally:
            if process is not None and process.poll() is None:
                # Kill descendants too, so compiler workers cannot escape a timeout.
                subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'),
                                '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                process.wait(timeout=15)
            if log.exists():
                with log.open('rb') as stream:
                    stream.seek(max(0, log.stat().st_size - 24000))
                    print(stream.read(24000).decode('utf-8', errors='replace'), flush=True)
        code = process.returncode
        self.records.append({'name': name, 'argv': list(map(str, argv)), 'exit': code,
                             'log_sha256': digest(log), 'seconds': round(time.monotonic() - begin, 3)})
        return code, log.read_text(encoding='utf-8', errors='replace')

    def required(self, name, argv, env, timeout, cwd=None):
        code, output = self.command(name, argv, env, timeout, cwd)
        if code:
            raise ValueError(f'{name} exited {code}')
        return output

    def fetch(self, item):
        self.guard(force=True)
        path = self.work / 'downloads' / item['filename']
        url = urllib.parse.urlparse(item['url'])
        if url.scheme != 'https' or url.hostname not in {'github.com', 'archive.mesa3d.org', 'files.pythonhosted.org'}:
            raise ValueError('Non-official or insecure input URL')
        with urllib.request.urlopen(item['url'], timeout=40) as response, path.open('xb') as out:
            while chunk := response.read(1024 * 1024):
                out.write(chunk)
                if out.tell() > item['size']:
                    raise ValueError('Download exceeds pinned size')
                self.guard()
        verify_file(path, item)
        print(f'INPUT verified {item["filename"]} sha256={item["sha256"]}', flush=True)
        return path


def audit_binaries(bundle, source):
    sys.path.insert(0, str(ROOT / 'build/wine-pe'))
    from symbol_audit import PE, imports, exports
    files = {p.name.lower(): p for p in bundle.iterdir() if p.suffix.lower() in {'.exe', '.dll'}}
    if set(files) != {'opengl32.dll', 'libgallium_wgl.dll', 'wgl-canary.exe'}:
        raise ValueError('Unexpected runtime file set')
    result = {}
    for name, path in files.items():
        if path.stat().st_size > 64 * 1024**2:
            raise ValueError('Unbounded runtime binary')
        pe = PE(path.read_bytes())
        if pe.architecture() != 'x86_64':
            raise ValueError(f'Unexpected architecture: {name}')
        result[name] = {'size': path.stat().st_size, 'sha256': digest(path),
                        'imports': imports(pe), 'exports': exports(pe)}
    opengl_names = {n for e in result['opengl32.dll']['exports'] for n in e['names']}
    if not REQUIRED_EXPORTS <= opengl_names:
        raise ValueError('Canary WGL/GL exports are absent')
    for name, item in result.items():
        for imp in item['imports']:
            dep = imp['module'].lower()
            if imp['kind'] != 'import':
                raise ValueError('Unexpected delayed dependency')
            if dep in files:
                names = {n for e in result[dep]['exports'] for n in e['names']}
                ordinals = {e['ordinal'] for e in result[dep]['exports']}
                for symbol in imp['symbols']:
                    if (symbol.get('name') not in names if 'name' in symbol else symbol.get('ordinal') not in ordinals):
                        raise ValueError('Package-internal symbol does not resolve')
            elif dep not in SYSTEM_DLLS and not dep.startswith(('api-ms-win-', 'ext-ms-win-')):
                raise ValueError(f'Unexpected dynamic runtime/backend: {name}: {dep}')
            if name == 'wgl-canary.exe' and dep in {'opengl32.dll', 'libgallium_wgl.dll'}:
                raise ValueError('Canary has an eager graphics import')
        for export in item['exports']:
            if 'forwarder' in export:
                module, symbol = export['forwarder'].rsplit('.', 1)
                dep = module.lower().removesuffix('.dll') + '.dll'
                if dep not in result or symbol not in {n for e in result[dep]['exports'] for n in e['names']}:
                    raise ValueError('Unresolved package export forwarder')
    gdi = [s.get('name') for i in result['libgallium_wgl.dll']['imports']
           if i['module'].lower() == 'gdi32.dll' for s in i['symbols']]
    if 'StretchDIBits' not in gdi:
        raise ValueError('Expected GDI presentation import is absent')
    return result


def run(work):
    if os.name != 'nt' or platform.machine().lower() not in {'amd64', 'x86_64'}:
        raise ValueError('Reference execution requires x64 Microsoft Windows')
    if (os.environ.get('GITHUB_REPOSITORY') != 'Mi-Yomi/Madeira'
            or os.environ.get('GITHUB_REF') != 'refs/heads/compatibility/desktop-apps'
            or os.environ.get('GITHUB_EVENT_NAME') not in {'push', 'workflow_dispatch'}):
        raise ValueError('Only the explicitly scoped Actions reference is supported')
    lock = json.loads((SOURCES / 'inputs.lock.json').read_text())
    if platform.python_version() != lock['host_python'] or sys.maxsize <= 2**32:
        raise ValueError('The preinstalled pinned CPython 3.12.10 x64 is required; no fallback download')
    work = work.absolute()
    temp = Path(os.environ['RUNNER_TEMP']).resolve()
    if work.exists() or work.is_symlink() or not work.resolve().is_relative_to(temp) or work.resolve() == temp:
        raise ValueError('Work root must be fresh and strictly beneath RUNNER_TEMP')
    if work.resolve().is_relative_to(ROOT) or ROOT.is_relative_to(work.resolve()):
        raise ValueError('Work root must be separate from the checkout')
    work.mkdir(parents=True)
    runner = Run(work)
    for name in ['downloads', 'host', 'parsers', 'bundle', 'runtime-temp', 'empty-pkgconfig']:
        (work / name).mkdir()
    env = dict(os.environ)
    for key in list(env):
        if (key.upper().startswith(('MESA_', 'GALLIUM_', 'LIBGL_', 'NIR_', 'TGSI_', 'LP_'))
                or key.upper() in {'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
                                   'CL', '_CL_', 'LINK', '_LINK_', 'PYTHONPATH', 'PYTHONHOME'}):
            env.pop(key, None)
    env.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
               PIP_DISABLE_PIP_VERSION_CHECK='1', PIP_NO_INDEX='1', PIP_NO_CACHE_DIR='1', PIP_CONFIG_FILE=os.devnull,
               SOURCE_DATE_EPOCH=str(lock['source_date_epoch']),
               TEMP=str(work / 'runtime-temp'), TMP=str(work / 'runtime-temp'),
               PKG_CONFIG_LIBDIR=str(work / 'empty-pkgconfig'), PKG_CONFIG_PATH='')
    for item in lock['inputs']:
        archive = runner.fetch(item)
        if item['kind'] == 'toolchain':
            unpack_zip(archive, work, 3 * 1024**3)
        elif item['kind'] == 'parser-tools':
            unpack_zip(archive, work / 'parsers', 16 * 1024**2)
        elif item['kind'] == 'source':
            with tarfile.open(archive) as tf:
                members = tf.getmembers()
                if len(members) > 20000 or sum(m.size for m in members) > 1024**3:
                    raise ValueError('Expanded source exceeds budget')
                for member in members:
                    if safe_name(member.name).parts[0] != 'mesa-26.2.4':
                        raise ValueError('Wrong source archive root')
                tf.extractall(work, filter='data')
        runner.guard(force=True)
    source = work / 'mesa-26.2.4'
    if (source / 'VERSION').read_text().strip() != '26.2.4':
        raise ValueError('Wrong source version')
    before = source_hashes(source)
    tc = work / 'llvm-mingw-20260421-ucrt-x86_64/bin'
    compiler = tc / 'x86_64-w64-mingw32-clang.exe'
    env['CC_FOR_BUILD'] = str(compiler)
    env['CXX_FOR_BUILD'] = str(tc / 'x86_64-w64-mingw32-clang++.exe')
    venv = work / 'host/Scripts'
    runner.required('venv', [sys.executable, '-m', 'venv', str(work / 'host')], env, 90)
    python = venv / 'python.exe'
    runner.required('wheels', [python, '-m', 'pip', 'install', '--no-index', '--no-cache-dir', '--no-deps',
        '--no-compile', '--require-hashes', '--only-binary=:all:', '--find-links', work / 'downloads',
        '-r', SOURCES / 'host-requirements.txt'], env, 120)
    env['PATH'] = os.pathsep.join(map(str, [venv, tc, work / 'parsers',
        Path(sys.executable).parent, Path(os.environ['SystemRoot']) / 'System32', Path(os.environ['SystemRoot'])]))
    cross = work / 'windows-x64.ini'
    def q(p):
        return str(p).replace('\\', '/')
    cross.write_text(f"""[binaries]
c = '{q(compiler)}'
cpp = '{q(tc / 'x86_64-w64-mingw32-clang++.exe')}'
ar = '{q(tc / 'llvm-ar.exe')}'
strip = '{q(tc / 'llvm-strip.exe')}'
windres = '{q(tc / 'llvm-windres.exe')}'
[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
[properties]
needs_exe_wrapper = true
skip_sanity_check = true
[built-in options]
c_link_args = ['-Wl,--no-insert-timestamp']
cpp_link_args = ['-static-libgcc', '-static-libstdc++', '-Wl,--no-insert-timestamp']
""")
    tool_versions = {}
    for name, tool in [('clang', compiler), ('meson', venv / 'meson.exe'),
                       ('ninja', venv / 'ninja.exe'), ('flex', work / 'parsers/win_flex.exe'),
                       ('bison', work / 'parsers/win_bison.exe')]:
        tool_versions[name] = runner.required(f'version-{name}', [tool, '--version'], env, 20)
    build = work / 'build'
    runner.required('configure', [venv / 'meson.exe', 'setup', build, source,
        '--cross-file', cross, '--prefix=' + str(work / 'inactive-install')] + OPTIONS, env, 180)
    runner.required('build', [venv / 'ninja.exe', '-C', build, '-j2',
        'src/gallium/targets/libgl-gdi/opengl32.dll'], env, 900)
    if source_hashes(source) != before:
        raise ValueError('Mesa source regular-file bytes changed during the build')
    bundle = work / 'bundle'
    for rel in ['libgl-gdi/opengl32.dll', 'wgl/libgallium_wgl.dll']:
        original = build / 'src/gallium/targets' / rel
        shutil.copyfile(original, bundle / original.name)
        if digest(original) != digest(bundle / original.name):
            raise ValueError('Staged DLL differs from this job output')
    runner.required('compile-canary', [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
        '-O2', '-static-libgcc', '-Wl,--no-insert-timestamp', SOURCES / 'wgl_canary.c',
        '-o', bundle / 'wgl-canary.exe', '-lgdi32', '-luser32'], env, 90)
    binaries = audit_binaries(bundle, source)
    # Keep only the bundle and system paths visible while running our target.
    env['PATH'] = os.pathsep.join([str(bundle), str(Path(os.environ['SystemRoot']) / 'System32'), os.environ['SystemRoot']])
    env['GALLIUM_DRIVER'] = 'softpipe'
    proof = []
    for stage in ['gdi', 'legacy', 'core43']:
        code, output = runner.command('runtime-' + stage,
            [bundle / 'wgl-canary.exe', '--stage', stage, '--source-built-reference'], env, 45, bundle)
        proof.append(parse_proof(output, code, stage, bundle))
    for name, item in binaries.items():
        if digest(bundle / name) != item['sha256']:
            raise ValueError('Runtime input changed during execution')
    receipt = {'schema_version': 1, 'status': 'gdi-and-legacy-reference-passed',
               'source_commit': os.environ.get('GITHUB_SHA'), 'source_modified': False,
               'scope': 'Microsoft Windows source-built Mesa softpipe reference only',
               'runner_image': os.environ.get('ImageVersion'), 'platform': platform.platform(),
               'python': platform.python_version(), 'inputs': lock, 'tools': tool_versions,
               'request': json.loads((SOURCES / 'reference-request.json').read_text()),
               'options': OPTIONS, 'commands': runner.records, 'binaries': binaries, 'proof': proof,
               'seconds': round(time.monotonic() - runner.started, 3),
               'madeira_runtime_tested': False, 'ios_display_tested': False,
               'blender_tested': False,
               'blender_5_2_2_requirements_unvalidated': ['GL_ARB_shader_draw_parameters',
                   'GL_ARB_clip_control', '12 SSBO bindings in vertex, fragment and compute stages',
                   'application initialization and actual display'],
               'product_installed': False, 'files_uploaded': False}
    (work / 'reference-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # Dependency details stay local; publish only a small verification summary to the job log.
    brief = {k: receipt[k] for k in ['status', 'scope', 'source_commit', 'runner_image', 'seconds', 'proof']}
    brief['binaries'] = {n: {k: d[k] for k in ['size', 'sha256']} for n, d in binaries.items()}
    print(json.dumps(brief, sort_keys=True), flush=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--work-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.work_root)
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'Mesa Windows reference stopped: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
