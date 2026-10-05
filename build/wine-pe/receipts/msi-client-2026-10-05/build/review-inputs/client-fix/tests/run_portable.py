#!/usr/bin/env python3
"""Compile exact production functions with deterministic Win32 fault injection.

LGPL-2.1-or-later. Generated production.inc retains functions byte for byte.
The shim tests control flow and ownership; it does not execute Wine or a guest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def extract(source, name):
    match = re.search(r'^static [^\n]*\b' + re.escape(name) + r'\s*\(', source, re.M)
    if not match:
        raise ValueError(name)
    start = match.start()
    opening = source.index('{', match.end())
    masked = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ' ' * len(m.group()), source, flags=re.S)
    depth, end = 1, opening + 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[start:end] + '\n'


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=root/'custom.c')
    parser.add_argument('--output', type=Path, default=root/'reports/patched')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = ['custom_get_thread_return', 'wait_thread_handle', 'custom_client_thread']
    extracted = '\n'.join(extract(source.read_text(), name) for name in names)
    (out/'production.inc').write_text(extracted)
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               '-Wno-error=maybe-uninitialized', '-O2', '-g', '-ftrivial-auto-var-init=pattern',
               '-I', str(out), str(root/'tests/portable_harness.c'), '-o', str(out/'client-tests')]
    if args.sanitize:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
    run = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out/'compile.log').write_text(run.stdout+run.stderr)
    if run.returncode:
        print(run.stdout+run.stderr)
        return run.returncode
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
    result = subprocess.run([str(out/'client-tests')], capture_output=True, text=True, timeout=30, env=env)
    (out/'test.log').write_text(result.stdout+result.stderr)
    manifest = {'source': str(source), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'extracted_functions': names, 'extracted_sha256': hashlib.sha256(extracted.encode()).hexdigest(),
                'compile_command': command, 'compiler_returncode': run.returncode,
                'test_returncode': result.returncode, 'sanitize': args.sanitize,
                'sanitizer_options': {k:env[k] for k in ('ASAN_OPTIONS','UBSAN_OPTIONS')} if args.sanitize else None,
                'limits': 'Host API doubles; no guest code, Windows ABI execution, real pipe/thread/COM, concurrency, or MSI installation.'}
    (out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(result.stdout+result.stderr, end='')
    return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
