#!/usr/bin/env python3
"""Bounded local production link. Never installs or executes the output PE."""
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
verified_sources = verify_source_phase(a.phase)
w = Path(__file__).resolve().parent
e = w/'evidence'
b = w/f'build-{a.architecture}-{a.phase}'
probe = json.loads((e/f'{a.architecture}-{a.phase}-probe.json').read_text())
module = 'ARM64EC' if a.architecture == 'arm64ec' else 'WOW64'
src = w/f'FEX/Source/Windows/{module}/Module.cpp'
assert hashlib.sha256(src.read_bytes()).hexdigest() == probe['source_sha256']
tc = Path('/workspace/scratch/94ffb2b0bb2d/madeira-desktop-overlay-build/toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64')
target = 'arm64ecfex' if a.architecture == 'arm64ec' else 'wow64fex'
cmd = [str(w/'build-tools/cmake/data/bin/cmake'), '--build', str(b), '--parallel', '2', '--target', target, '--verbose']
log = e/f'{a.architecture}-{a.phase}-full-build.log'
env = dict(os.environ, PATH=str(tc/'bin') + os.pathsep + os.environ['PATH'])
start = time.time()
with log.open('w') as f:
    proc = subprocess.run(cmd, cwd=w, env=env, stdout=f, stderr=subprocess.STDOUT)
record = {'architecture': a.architecture, 'phase': a.phase, 'argv': cmd, 'cwd': str(w),
          'module_source_sha256': probe['source_sha256'], 'exit_code': proc.returncode,
          'elapsed_seconds': time.time()-start, 'log': str(log)}
record['verified_sources_sha256'] = verified_sources
output = b/f'Bin/lib{target}.dll'
if proc.returncode == 0:
    assert output.exists()
    record['dll'] = {'path': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(), 'size': output.stat().st_size}
    for name, args in [('pe', ['--file-headers', '--coff-imports', '--coff-exports']), ('load-config', ['--coff-load-config'])]:
        data = subprocess.check_output([str(tc/'bin/llvm-readobj'), *args, str(output)])
        (e/f'{a.architecture}-{a.phase}-{name}.txt').write_bytes(data)
(e/f'{a.architecture}-{a.phase}-full-build.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps(record, indent=2), flush=True)
if proc.returncode:
    print(log.read_text()[-14000:], flush=True)
raise SystemExit(proc.returncode)
