#!/usr/bin/env python3
"""Compile complete candidate using existing trusted Wine build inputs, read-only.

LGPL-2.1-or-later. No make, configure, link, downloads or guest execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=root/'custom.c')
    parser.add_argument('--provider', type=Path, default=root.parent/'madeira-msi-patched-provider-build-20261005')
    parser.add_argument('--output', type=Path, default=root/'reports/cross-compile')
    args = parser.parse_args()
    provider, source, output = args.provider.resolve(), args.source.resolve(), args.output.resolve()
    if output.is_relative_to(provider):
        raise ValueError('Output must not be in sealed provider workspace')
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for arch in ('aarch64', 'arm64ec'):
        commands_path = provider/f'build-{arch}/compile_commands.json'
        matches = [e for e in json.loads(commands_path.read_text()) if e['file'].endswith('/msi/custom.c')]
        if len(matches) != 1:
            raise ValueError('Expected exactly one original translation-unit command')
        command = matches[0]
        argv = shlex.split(command['command'])
        original = provider/'wine/dlls/msi/custom.c'
        if argv.count('-o') != 1 or argv.count('-c') != 1 or argv.count(str(original)) != 1:
            raise ValueError('Unexpected compile command')
        obj = output/f'custom-{arch}.o'
        argv[argv.index(str(original))] = str(source)
        argv[argv.index('-o')+1] = str(obj)
        run = subprocess.run(argv, cwd=command['directory'], capture_output=True, text=True, timeout=90)
        (output/f'{arch}.log').write_text(run.stdout+run.stderr)
        inspect = [str(Path(argv[0]).with_name('llvm-readobj')), '--file-headers', str(obj)]
        inspected = subprocess.run(inspect, capture_output=True, text=True, timeout=30) if not run.returncode else None
        if inspected:
            (output/f'{arch}-file-headers.log').write_text(inspected.stdout+inspected.stderr)
        expected_machine = 'IMAGE_FILE_MACHINE_ARM64EC' if arch == 'arm64ec' else 'IMAGE_FILE_MACHINE_ARM64'
        machine_ok = inspected is not None and inspected.returncode == 0 and expected_machine in inspected.stdout
        results.append({'architecture':arch, 'source_sha256':sha(source), 'compile_command':argv,
                        'cwd': command['directory'], 'original_commands_sha256':sha(commands_path),
                        'compiler_sha256':sha(Path(argv[0]).resolve()), 'exit_code':run.returncode,
                        'object_sha256':sha(obj) if obj.exists() else None,
                        'machine_verified':machine_ok, 'inspection_command':inspect,
                        'linked':False, 'runtime_tested':False})
        (output/'manifest.json').write_text(json.dumps(results,indent=2)+'\n')
        print(f'{arch}: complete custom.c compile exit={run.returncode}; correct machine={machine_ok}')
        if run.returncode or not machine_ok:
            print(run.stdout+run.stderr)
            return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
