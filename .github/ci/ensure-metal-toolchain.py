#!/usr/bin/env python3
"""Bounded, fail-closed setup of Apple's optional Metal Toolchain.

Only --allow-install permits the official component downloader. It must only be
passed in the authorized temporary-runner workflow under the recorded Xcode
agreement. No account, license-accept, first-launch or other component action.

References:
https://developer.apple.com/documentation/xcode/downloading-and-installing-additional-xcode-components
https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements
https://developer.apple.com/library/archive/documentation/Miscellaneous/Conceptual/MetalProgrammingGuide/Dev-Technique/Dev-Technique.html
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time

OFFICIAL_SOURCE = 'https://developer.apple.com/documentation/xcode/downloading-and-installing-additional-xcode-components'
AGREEMENT = {'url': 'https://www.apple.com/legal/sla/docs/xcode.pdf',
             'identifier': 'EA2002', 'date': '2026-06-08'}
EXPECTED_XCODE_VERSION = '27.0'
EXPECTED_XCODE_BUILD = '27A266a'
EXPECTED_DEVELOPER_DIR = Path('/Applications/Xcode_27.app/Contents/Developer')
DOWNLOAD_SECONDS = 300
TOTAL_SECONDS = 420  # Included in, never added to, the 35-minute bootstrap budget.
COMMAND_SECONDS = 30
SMOKE_SECONDS = 60
OUTPUT_LIMIT = 16 * 1024
SYSTEM_TOOLS = {'select': '/usr/bin/xcode-select', 'xcrun': '/usr/bin/xcrun',
                'codesign': '/usr/bin/codesign'}
INTERACTION = re.compile(
    r'\b(?:license|agreement|terms|sign[ -]?in|log[ -]?in|password|payment|billing|purchase|subscription)\b'
    r'|\bApple\s+(?:ID|Account)\b|\bauthentication\s+required\b|\bverification\s+code\b', re.I)
MISSING = re.compile(r'missing Metal Toolchain|unable to find utility [\'\"]metal[\'\"]', re.I)
SHADER = '''#include <metal_stdlib>
using namespace metal;
kernel void madeira_setup_smoke(device uint *out [[buffer(0)]],
                               uint index [[thread_position_in_grid]]) {
    out[index] = index;
}
'''


class SetupFailure(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def stop_group(process):
    """Stop owned commands and children, including a child retaining stdout."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=2)


class Setup:
    def __init__(self, log_dir, allow_install):
        self.log_dir = Path(log_dir)
        self.allow_install = allow_install
        self.started = time.monotonic()
        self.deadline = self.started + TOTAL_SECONDS
        self.env = dict(os.environ, LC_ALL='C', LANG='C')
        self.data = {'schema': 1, 'status': 'running', 'official_source': OFFICIAL_SOURCE,
                     'approved_agreement': AGREEMENT, 'download_attempted': False,
                     'download_result': 'not-needed', 'installation_permitted': allow_install,
                     'limits_seconds': {'total': TOTAL_SECONDS, 'download': DOWNLOAD_SECONDS},
                     'started_utc': datetime.now(timezone.utc).isoformat(),
                     'commands': [], 'verified_executables': {},
                     'smoke_test': {'status': 'not-run', 'sdk': 'iphoneos'}}

    def command(self, label, argv, *, timeout=COMMAND_SECONDS, check=True, guard=True):
        argv = [str(arg) for arg in argv]
        print(f'Metal setup: {label}', flush=True)
        record = {'stage': label, 'argv': argv}
        self.data['commands'].append(record)
        start = time.monotonic()
        deadline = min(self.deadline, start + timeout)
        if start >= deadline:
            raise SetupFailure('timed-out', f'{label}: setup time budget exhausted')
        process = None
        output = bytearray()
        total_output = 0
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env=self.env, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SetupFailure('timed-out', f'{label}: exceeded bounded process lifetime')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total_output += len(chunk)
                        output.extend(chunk)
                        # Check each rolling chunk, even after the receipt log cap.
                        interaction = INTERACTION.search(output.decode('utf-8', errors='replace')) if guard else None
                        if interaction:
                            matched = interaction.group().lower()
                            category = ('terms' if matched in ('license', 'agreement', 'terms') else
                                        'payment' if matched in ('payment', 'billing', 'purchase', 'subscription') else
                                        'authentication')
                            # Unexpected prompts may contain credentials or one-time
                            # codes. Never emit their buffered text to public CI logs
                            # or persist it in the receipt, even on the failure path.
                            output.clear()
                            record.update({'interaction_category': category,
                                           'status': 'interaction-required', 'output_suppressed': True})
                            raise SetupFailure('interaction-required', f'{label}: {category} indication; stopped without responding')
                        del output[:-OUTPUT_LIMIT]
                record['returncode'] = process.wait()
            if check and record['returncode']:
                raise SetupFailure('command-failed', f'{label}: command exited {record["returncode"]}')
        finally:
            if process is not None:
                stop_group(process)
                process.stdout.close()
                record['returncode'] = process.returncode
            record['seconds'] = round(time.monotonic() - start, 3)
            record['output_tail'] = output.decode('utf-8', errors='replace')
            record['output_truncated'] = total_output > OUTPUT_LIMIT
            if output:
                print(record['output_tail'], flush=True)
        return record['returncode'], record['output_tail'].strip()

    def path(self, value):
        path = Path(value)
        if not path.is_absolute() or '\n' in value:
            raise SetupFailure('verification-failed', 'Tool discovery returned a non-absolute or multiline path')
        return path.resolve(strict=True)

    def verify_executable(self, label, path):
        path = self.path(str(path))
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SetupFailure('verification-failed', f'{label}: executable missing')
        code, _ = self.command(f'Verify Apple signature: {label}',
                               [SYSTEM_TOOLS['codesign'], '--verify', '--strict', '-R', '=anchor apple', path], check=False)
        if code:
            raise SetupFailure('verification-failed', f'{label}: Apple code signature verification failed')
        _, details = self.command(f'Record code signature: {label}',
                                  [SYSTEM_TOOLS['codesign'], '--display', '--verbose=4', path])
        self.data['verified_executables'][label] = {
            'path': str(path), 'sha256': sha256(path), 'requirement': 'anchor apple',
            'verification_passed': True, 'signature_details': details}
        return path

    def find(self, name, *, check=True):
        return self.command(f'Discover {name}',
                            [SYSTEM_TOOLS['xcrun'], '--no-cache', '--sdk', 'iphoneos', '--find', name], check=check)

    def probe(self):
        code, location = self.find('metal', check=False)
        if code:
            if MISSING.search(location):
                return None
            raise SetupFailure('probe-failed', 'Metal discovery failed without an explicit missing-toolchain diagnostic')
        entry = self.verify_executable('metal-entrypoint', self.path(location))
        code, version = self.command('Execute Metal compiler version',
                                     [SYSTEM_TOOLS['xcrun'], '--no-cache', '--sdk', 'iphoneos', 'metal', '--version'], check=False)
        if code:
            if MISSING.search(version):
                return None
            raise SetupFailure('probe-failed', 'Metal execution failed without an explicit missing-toolchain diagnostic')
        if not re.search(r'^Apple metal version\s+\S+', version, re.M):
            raise SetupFailure('verification-failed', 'Metal did not report an Apple compiler version')
        # A shim's hash is not the downloaded compiler's hash. InstalledDir is
        # emitted by the running compiler; resolve and verify that actual binary.
        matches = re.findall(r'^InstalledDir:\s*(.+)$', version, re.M)
        if len(matches) != 1:
            raise SetupFailure('verification-failed', 'Metal version did not identify one actual InstalledDir')
        real = self.path(str(Path(matches[0]) / 'metal'))
        roots = [p for p in real.parents if p.name == 'Metal.xctoolchain']
        if len(roots) != 1:
            raise SetupFailure('verification-failed', 'Actual compiler is outside the Metal component toolchain')
        actual = self.verify_executable('metal-compiler', real)
        _, real_version = self.command('Execute verified component compiler', [actual, '--version'])
        identity = re.findall(r'^Apple metal version[^\n]+', version, re.M)
        if re.findall(r'^Apple metal version[^\n]+', real_version, re.M) != identity:
            raise SetupFailure('verification-failed', 'Entrypoint and actual compiler versions differ')
        actual_dirs = re.findall(r'^InstalledDir:\s*(.+)$', real_version, re.M)
        if len(actual_dirs) != 1 or self.path(str(Path(actual_dirs[0]) / 'metal')) != actual:
            raise SetupFailure('verification-failed', 'Verified compiler reports a different executable location')
        _, linker_path = self.find('metallib')
        linker = self.verify_executable('metallib-entrypoint', self.path(linker_path))
        # Resolve the actual linker in the compiler's own advertised bin directory
        # if xcrun exposes a signed shim. Do not confuse a shim with component code.
        actual_linker = self.path(str(actual.parent / 'metallib'))
        if roots[0] not in actual_linker.parents:
            raise SetupFailure('verification-failed', 'Metal linker escapes the verified component root')
        actual_linker = self.verify_executable('metallib-linker', actual_linker)
        self.data.update({'compiler_version': real_version, 'component_root': str(roots[0]),
                          'entrypoints_are_component_binaries': entry == actual and linker == actual_linker})
        return actual, actual_linker

    def prepare(self):
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise SetupFailure('preflight-failed', 'Requires the native Apple ARM64 temporary runner')
        if self.env.get('TOOLCHAINS'):
            raise SetupFailure('preflight-failed', 'Custom TOOLCHAINS is not permitted for this Apple component setup')
        _, selected = self.command('Read selected Xcode', [SYSTEM_TOOLS['select'], '--print-path'])
        selected = self.path(selected)
        if selected != EXPECTED_DEVELOPER_DIR.resolve(strict=True):
            raise SetupFailure('preflight-failed', 'Selected developer directory differs from the audited Xcode installation')
        override = self.env.get('DEVELOPER_DIR')
        if override and self.path(override) != selected:
            raise SetupFailure('preflight-failed', 'DEVELOPER_DIR overrides the audited selected Xcode')
        self.env['DEVELOPER_DIR'] = str(selected)
        self.data['selected_developer_dir'] = str(selected)
        builder = self.verify_executable('xcodebuild', selected / 'usr/bin/xcodebuild')
        _, version = self.command('Verify selected Xcode version', [builder, '-version'])
        if version != f'Xcode {EXPECTED_XCODE_VERSION}\nBuild version {EXPECTED_XCODE_BUILD}':
            raise SetupFailure('preflight-failed', f'Only audited Xcode {EXPECTED_XCODE_VERSION} build {EXPECTED_XCODE_BUILD} is permitted')
        self.data['xcode_version'] = version
        _, help_text = self.command('Check xcrun discovery support', [SYSTEM_TOOLS['xcrun'], '--help'], guard=False)
        if '--no-cache' not in help_text:
            raise SetupFailure('preflight-failed', 'xcrun does not advertise uncached tool discovery')
        _, sdk = self.command('Verify iOS SDK version', [SYSTEM_TOOLS['xcrun'], '--sdk', 'iphoneos', '--show-sdk-version'])
        if sdk != '27.0':
            raise SetupFailure('preflight-failed', f'Expected approved iOS 27.0 SDK, found {sdk}')
        self.data['sdk_version'] = sdk
        _, sdk_path = self.command('Locate iOS SDK', [SYSTEM_TOOLS['xcrun'], '--sdk', 'iphoneos', '--show-sdk-path'])
        sdk_path = self.path(sdk_path)
        if selected not in sdk_path.parents or not sdk_path.is_dir():
            raise SetupFailure('verification-failed', 'iOS SDK is outside the selected Xcode')
        self.data['sdk_path'] = str(sdk_path)
        tools = self.probe()
        if tools is None:
            if not self.allow_install:
                self.data['download_result'] = 'not-authorized'
                raise SetupFailure('unavailable', 'Metal Toolchain missing; installation requires --allow-install under the recorded agreement')
            self.data['download_attempted'] = True
            self.data['download_result'] = 'started'
            # This is Apple's documented, component-specific install command.
            try:
                self.command('Download Apple Metal Toolchain', [builder, '-downloadComponent', 'metalToolchain'], timeout=DOWNLOAD_SECONDS)
            except (SetupFailure, OSError) as exc:
                self.data['download_result'] = getattr(exc, 'status', 'command-failed')
                raise
            self.data['download_result'] = 'command-succeeded'
            tools = self.probe()
            if tools is None:
                raise SetupFailure('verification-failed', 'Apple downloader returned success but the Metal compiler remains unavailable')
        compiler, linker = tools
        self.data['smoke_test']['status'] = 'running'
        with tempfile.TemporaryDirectory(prefix='madeira-metal-smoke-') as directory:
            directory = Path(directory)
            source, air, library = (directory / name for name in ('smoke.metal', 'smoke.air', 'smoke.metallib'))
            source.write_text(SHADER)
            try:
                self.command('Compile disposable iOS Metal shader',
                             [compiler, '-target', 'air64-apple-ios27.0', '-isysroot', sdk_path,
                              '-c', source, '-o', air], timeout=SMOKE_SECONDS)
                if not air.is_file() or air.stat().st_size == 0:
                    raise SetupFailure('smoke-failed', 'Metal compiler produced no AIR object')
                self.command('Link disposable Metal library', [linker, air, '-o', library], timeout=SMOKE_SECONDS)
                if not library.is_file() or library.stat().st_size == 0:
                    raise SetupFailure('smoke-failed', 'Metal linker produced no library')
            except SetupFailure as exc:
                self.data['smoke_test']['status'] = 'failed'
                if exc.status == 'command-failed':
                    raise SetupFailure('smoke-failed', str(exc)) from exc
                raise
            self.data['smoke_test'].update({'status': 'passed', 'target': 'air64-apple-ios27.0',
                'shader_sha256': sha256(source), 'air_bytes': air.stat().st_size,
                'library_bytes': library.stat().st_size, 'library_sha256': sha256(library),
                'outputs_disposable': True})
        self.data['status'] = 'available'

    def execute(self):
        self.log_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.prepare()
            return 0
        except (SetupFailure, OSError) as exc:
            self.data['status'] = getattr(exc, 'status', 'setup-failed')
            self.data['error'] = str(exc)
            print(f'Metal setup stopped: {exc}', file=sys.stderr, flush=True)
            return 1
        finally:
            self.data['finished_utc'] = datetime.now(timezone.utc).isoformat()
            self.data['seconds'] = round(time.monotonic() - self.started, 3)
            (self.log_dir / 'metal-toolchain-provenance.json').write_text(json.dumps(self.data, indent=2) + '\n')
            (self.log_dir / 'metal-toolchain-status.txt').write_text(self.data['status'] + '\n')
            print(f'Metal setup result: {self.data["status"]}; download: {self.data["download_result"]}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-install', action='store_true', help='Permit only the approved Apple Metal component install')
    parser.add_argument('--log-dir', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise SetupFailure('interrupted', f'Stopped by signal {signum}')
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    return Setup(args.log_dir, args.allow_install).execute()


if __name__ == '__main__':
    sys.exit(main())
