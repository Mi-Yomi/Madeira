#!/usr/bin/env python3
"""Isolated source/object probe; never executes a PE or copies a DLL to Madeira."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from source_phase import verify_source_phase

p = argparse.ArgumentParser()
p.add_argument('architecture', choices=['arm64ec', 'wow64'])
p.add_argument('phase', choices=['baseline', 'patched'])
a = p.parse_args()
verify_source_phase(a.phase)
w = Path(__file__).resolve().parent
s = w / 'FEX'
b = w / f'build-{a.architecture}-{a.phase}'
e = w / 'evidence'
cmake = w / 'build-tools/cmake/data/bin/cmake'
ninja = w / 'build-tools/bin/ninja'
tc = Path('/workspace/scratch/94ffb2b0bb2d/madeira-desktop-overlay-build/toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64')
triple = 'arm64ec-w64-mingw32' if a.architecture == 'arm64ec' else 'aarch64-w64-mingw32'
module = 'ARM64EC' if a.architecture == 'arm64ec' else 'WOW64'
target = 'arm64ecfex' if a.architecture == 'arm64ec' else 'wow64fex'
obj = f'Source/Windows/{module}/CMakeFiles/{target}.dir/Module.cpp.obj'
env = dict(os.environ, PATH=str(tc / 'bin') + os.pathsep + os.environ['PATH'])
configure = [str(cmake), '-S', str(s), '-B', str(b), '-G', 'Ninja',
             f'-DCMAKE_MAKE_PROGRAM={ninja}', '-DCMAKE_BUILD_TYPE=Release',
             f'-DCMAKE_TOOLCHAIN_FILE={s}/Data/CMake/toolchain_mingw.cmake',
             f'-DMINGW_TRIPLE={triple}', '-DFEX_IOS_HOST_BUILD=ON',
             '-DENABLE_GUEST_WINDOW=' + ('OFF' if a.architecture == 'arm64ec' else 'ON'),
             '-DCMAKE_C_FLAGS=-DFEX_IOS_HOST', '-DCMAKE_CXX_FLAGS=-DFEX_IOS_HOST',
             '-DCMAKE_ASM_FLAGS=-DFEX_IOS_HOST', '-DENABLE_LTO=OFF',
             '-DENABLE_ASSERTIONS=OFF', '-DENABLE_JEMALLOC_GLIBC_ALLOC=OFF',
             '-DENABLE_CCACHE=OFF', '-DBUILD_TESTING=OFF', '-DBUILD_THUNKS=OFF',
             '-DBUILD_FEXCONFIG=OFF', '-DTUNE_ARCH=generic', '-DTUNE_CPU=none',
             '-DCMAKE_POLICY_VERSION_MINIMUM=3.5']
build = [str(cmake), '--build', str(b), '--parallel', '2', '--target', obj, '--verbose']
record = {'scope': 'configure-and-single-production-object-only',
          'architecture': a.architecture, 'phase': a.phase,
          'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=s, text=True).strip(),
          'source_sha256': hashlib.sha256((s/f'Source/Windows/{module}/Module.cpp').read_bytes()).hexdigest(),
          'commands': []}
for step, args in [('configure', configure), ('object-compile', build)]:
    path = e / f'{a.architecture}-{a.phase}-{step}.log'
    started = time.time()
    with path.open('w') as out:
        proc = subprocess.run(args, cwd=w, env=env, stdout=out, stderr=subprocess.STDOUT)
    record['commands'].append({'step': step, 'argv': args, 'cwd': str(w),
                               'exit_code': proc.returncode, 'elapsed_seconds': time.time()-started,
                               'log': str(path)})
    print(f'{a.architecture} {a.phase} {step}: exit {proc.returncode}', flush=True)
    if proc.returncode:
        print(path.read_text()[-10000:], flush=True)
        break
    if step == 'configure':
        commands = json.loads((b/'compile_commands.json').read_text())
        selected = [c for c in commands if c['file'] == str(s/f'Source/Windows/{module}/Module.cpp')]
        assert len(selected) == 1
        command = selected[0]['command']
        assert '-DFEX_IOS_HOST' in command
        assert ('-DFEX_GUEST_WINDOW=1' in command) == (a.architecture == 'wow64')
        assert ('-DARCHITECTURE_arm64ec=1' in command) == (a.architecture == 'arm64ec')
        record['module_compile_command'] = selected[0]
        record['crt_ios_selected'] = any(c['file'].endswith('/CRT_iOS.cpp') for c in commands)
        assert record['crt_ios_selected']
if (b/obj).exists():
    record['object'] = {'path': str(b/obj), 'sha256': hashlib.sha256((b/obj).read_bytes()).hexdigest(),
                        'size': (b/obj).stat().st_size}
(e/f'{a.architecture}-{a.phase}-probe.json').write_text(json.dumps(record, indent=2)+'\n')
raise SystemExit(record['commands'][-1]['exit_code'])
