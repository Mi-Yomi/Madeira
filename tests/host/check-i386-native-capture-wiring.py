#!/usr/bin/env python3
"""Run the real shell routing and diagnostic dispatcher with tool doubles.

Clang/SDK/archive doubles make no claim of production native proof. The separate
contract tests compile real Mach-O fixtures. Frozen argument vectors were captured
from the reviewed pre-wiring compile_one functions, preserving token boundaries.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'build/app-ios'), str(ROOT / 'build/i386-native-contract')]
import link_diagnostic as link
import capture

SELECTED = {
    'ntdll': {'virtual': 'build/ntdll-unix/virtual_ios.c',
              'process': 'build/ntdll-unix/process_ios.c',
              'loader': 'build/ntdll-unix/loader_ios.c',
              'server': 'build/ntdll-unix/server_ios.c',
              'syscall': 'wine/dlls/ntdll/unix/syscall.c',
              'nsi_unixlib_ios': 'build/ntdll-unix/nsi_unixlib_ios.c',
              'nsi_network_ios': 'build/ntdll-unix/nsi_network_ios.c'},
    'win32u': {'syscall': 'build/win32u-unix/syscall_ios.c'},
}


def put(path, text='fixture\n'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='native-wiring-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root))
        self.env.pop('MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR', None)
        self.records = self.root / 'records with spaces'
        for owner, sources in SELECTED.items():
            build = self.root / f'build/{owner}-unix'
            build.mkdir(parents=True)
            shutil.copy2(ROOT / f'build/{owner}-unix/build.sh', build / 'build.sh')
            for path in sources.values():
                put(self.root / path, 'int fixture;\n')
            upstream = f'wine/dlls/{owner}' + ('/unix' if owner == 'ntdll' else '')
            for name in (*[name for name in sources if not name.startswith('nsi_')], 'file'):
                put(self.root / upstream / (name + '.c'), 'int fixture;\n')
        put(self.root / 'wine/dlls/win32u/dibdrv/bitblt.c')
        put(self.root / 'wine/dlls/win32u/freetype.c')
        put(self.root / 'wine/dlls/win32u/main.c')
        put(self.root / 'build/ntdll-unix/check-crypto-link-tables.py', '# Tool double; tested separately.\n')
        generator = put(self.root / 'build/crypto-unix/gen_gnutls_symtab.sh', '#!/bin/sh\nexit 0\n')
        generator.chmod(0o755)
        for owner in SELECTED:
            put(self.root / f'app/Madeira/lib{owner}_unix.a', 'previous archive\n')
        wrapper = self.root / 'build/i386-native-contract/capture.py'
        wrapper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / 'build/i386-native-contract/capture.py', wrapper)
        self.tool('xcrun', r'''
args = sys.argv[1:]
if '--show-sdk-path' in args: print('/fixture iPhoneOS.sdk'); sys.exit(0)
if '--find' in args:
    with (root / 'resolutions.jsonl').open('a') as log: log.write(json.dumps(args) + '\n')
    if os.getenv('FAIL_RESOLVE'): sys.exit(7)
    print(root / 'bin/clang-real'); sys.exit(0)
if '-f' in args and args[-1] == 'nm': print('/usr/bin/nm'); sys.exit(0)
assert args[:3] == ['-sdk', 'iphoneos', 'clang'], args
with (root / 'ordinary.jsonl').open('a') as log: log.write(json.dumps(args) + '\n')
os.execv(str(root / 'bin/clang-real'), [str(root / 'bin/clang-real'), *args[3:]])
''')
        self.tool('clang-real', r'''
args = sys.argv[1:]
with (root / 'compiles.jsonl').open('a') as log: log.write(json.dumps(args) + '\n')
source = Path(next(a for a in reversed(args) if a.endswith('.c')))
if '-MF' in args:
    dep = Path(args[args.index('-MF') + 1])
    dep.write_text('madeira_contract: ' + str(source).replace(' ', '\\ ') + '\n')
if '-c' not in args: sys.exit(0)
out = Path(args[args.index('-o') + 1])
if out.stem == os.getenv('FAIL_COMPILE'): sys.exit('fixture compiler failed')
if out.stem != os.getenv('OMIT_OBJECT'): out.write_text('object:' + source.name)
''')
        self.tool('ar', r'''
assert sys.argv[1] == 'rcs'
Path(sys.argv[2]).write_text('new fixture archive')
''')

    def tool(self, name, body):
        path = put(self.bin / name, '#!/usr/bin/env python3\nimport json, os, sys\nfrom pathlib import Path\n'
                   'root = Path(os.environ["FIXTURE_ROOT"])\n' + body)
        path.chmod(0o755)

    def rows(self, name):
        path = self.root / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run_build(self, owner, enabled=False, success=True, **extra):
        env = dict(self.env, **extra)
        if enabled: env['MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR'] = str(self.records)
        result = subprocess.run(['bash', str(self.root / f'build/{owner}-unix/build.sh')],
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def normalized(self, args):
        args = list(args)
        args[args.index('-c') + 1] = '<SOURCE>'
        args[args.index('-o') + 1] = '<OBJECT>'
        return [a.replace(str(self.root), '<ROOT>') for a in args]

    def test_default_off_matches_reviewed_ordinary_commands(self):
        expected = json.loads((ROOT / 'tests/host/fixtures/i386-native-compile-arguments.json').read_text())
        for owner in SELECTED:
            self.run_build(owner)
        self.assertFalse(self.records.exists())
        self.assertEqual(self.rows('resolutions.jsonl'), [])
        for owner, sources in SELECTED.items():
            for name in sources:
                out = str(self.root / f'build/{owner}-unix/obj/{name}.o')
                commands = [a for a in self.rows('ordinary.jsonl') if out in a]
                self.assertEqual(len(commands), 1)
                self.assertEqual(self.normalized(commands[0][3:]), expected[owner])
        # Existing per-file extra arguments retain boundaries/order as well.
        ft = next(a for a in self.rows('ordinary.jsonl') if 'freetype.o' in a[-1])
        self.assertEqual(ft[-6:-4], ['-I' + str(self.root / 'build/freetype-ios/build/include'),
                                   '-I' + str(self.root / 'research/freetype/include')])

    def test_exactly_eight_captures_keep_command_and_compiler_identity(self):
        for owner in SELECTED:
            self.run_build(owner)
        ordinary = {a[-1]: a[3:] for a in self.rows('ordinary.jsonl')}
        (self.root / 'ordinary.jsonl').unlink()
        for owner in SELECTED:
            self.run_build(owner, enabled=True)
        expected = {f'{owner}-{name}.o.json' for owner, sources in SELECTED.items() for name in sources}
        self.assertEqual({p.name for p in self.records.iterdir()}, expected)
        self.assertEqual(len(self.rows('resolutions.jsonl')), 8)
        routed = set()
        for owner, sources in SELECTED.items():
            for name, source in sources.items():
                record = json.loads((self.records / f'{owner}-{name}.o.json').read_text())
                output = f'build/{owner}-unix/obj/{name}.o'
                self.assertEqual(record['source'], source)
                self.assertEqual(record['object'], output)
                self.assertEqual(record['compiler'], str(self.bin / 'clang-real'))
                self.assertEqual(record['compiler_sha256'], hashlib.sha256((self.bin / 'clang-real').read_bytes()).hexdigest())
                self.assertEqual(record['arguments'], ordinary[str(self.root / output)])
                self.assertEqual(record['object_sha256'], hashlib.sha256((self.root / output).read_bytes()).hexdigest())
                routed.add(str(self.root / output))
        self.assertTrue(all(a[-1] not in routed for a in self.rows('ordinary.jsonl')))
        self.assertTrue(self.rows('ordinary.jsonl'))

    def test_capture_failure_stops_archive_and_removes_stale_selected_object(self):
        for owner in SELECTED:
            for failure in ('FAIL_COMPILE', 'OMIT_OBJECT'):
                with self.subTest(owner=owner, failure=failure):
                    shutil.rmtree(self.records, ignore_errors=True)
                    obj = put(self.root / f'build/{owner}-unix/obj/syscall.o', 'stale')
                    app = self.root / f'app/Madeira/lib{owner}_unix.a'
                    before = app.read_bytes()
                    self.run_build(owner, enabled=True, success=False, **{failure: 'syscall'})
                    self.assertFalse(obj.exists())
                    self.assertFalse((self.records / f'{owner}-syscall.o.json').exists())
                    self.assertEqual(app.read_bytes(), before)

    def test_real_clang_resolution_and_stale_record_fail_closed(self):
        for owner in SELECTED:
            with self.subTest(owner=owner):
                self.run_build(owner, enabled=True, success=False, FAIL_RESOLVE='1')
                self.assertEqual((self.root / f'app/Madeira/lib{owner}_unix.a').read_text(), 'previous archive\n')
        self.records.mkdir(exist_ok=True)
        put(self.records / 'win32u-syscall.o.json', 'old capture')
        self.run_build('win32u', enabled=True, success=False)
        self.assertEqual((self.records / 'win32u-syscall.o.json').read_text(), 'old capture')

    def test_failure_report_bounds_both_streams_for_bytes_and_text(self):
        for payload in (b"\xff" * 100000 + b"BYTE_TAIL", "\u2603" * 100000 + "TEXT_TAIL"):
            with self.subTest(kind=type(payload).__name__), contextlib.redirect_stderr(io.StringIO()) as stream:
                failure = subprocess.CalledProcessError(7, ["COMMAND_MUST_NOT_BE_PRINTED"],
                                                        output=payload, stderr=payload)
                capture.report_failure_output(failure)
            result = stream.getvalue()
            self.assertNotIn("COMMAND_MUST_NOT_BE_PRINTED", result)
            self.assertLessEqual(len(result.encode("utf-8")), 2 * 32 * 1024 + 256)
            self.assertEqual(result.count("TAIL"), 2)
            self.assertIn("compiler stdout", result)
            self.assertIn("compiler stderr", result)
        failure = subprocess.TimeoutExpired(["COMMAND_MUST_NOT_BE_PRINTED"], 120, output=b"TIMEOUT_TAIL")
        with contextlib.redirect_stderr(io.StringIO()) as stream:
            capture.report_failure_output(failure)
        self.assertIn("TIMEOUT_TAIL", stream.getvalue())
        self.assertNotIn("COMMAND_MUST_NOT_BE_PRINTED", stream.getvalue())

    def test_wrapper_rejects_response_dependencies_and_source_output_mismatch(self):
        source = self.root / SELECTED['ntdll']['virtual']
        output = put(self.root / 'object.o', 'old object')
        args = [str(self.bin / 'clang-real'), '-c', str(source), '-o', str(output)]
        for bad in (['@args'], ['-MMD'], ['-MF', 'deps'], ['-flto'], ['-MD']):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                capture.capture(self.root, self.records / 'bad.json', source, output, args + bad)
        for changed in (args[:-1] + [str(self.root / 'other.o')],
                        [args[0], '-c', str(self.root / 'different.c'), '-o', str(output)]):
            with self.assertRaises(ValueError):
                capture.capture(self.root, self.records / 'bad.json', source, output, changed)
        self.assertEqual(output.read_text(), 'old object')
        self.assertFalse(self.records.exists())


class DispatchTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, enabled=False):
        with tempfile.TemporaryDirectory(prefix='native-dispatch-') as tmp:
            root = Path(tmp)
            request = put(root / 'request.json', json.dumps(dict(link.EXPECTED_REQUEST, native_archive_contract=enabled)))
            with mock.patch.object(link, 'ROOT', root), mock.patch.object(link, 'REQUEST', request), \
                    contextlib.redirect_stdout(io.StringIO()):
                yield root, root / 'logs', root / 'artifacts'

    def test_default_request_is_off_and_strict_boolean_is_the_only_new_option(self):
        # A reviewed diagnostic may explicitly select true. The code default
        # stays off; validate the current request rather than forbidding opt-in.
        self.assertIs(link.EXPECTED_REQUEST['native_archive_contract'], False)
        link.request()
        for value in (False, True):
            with self.fixture(value): link.request()
        for value in (None, 0, 1, 'true', {}, []):
            with self.fixture(value), self.assertRaises(ValueError): link.request()
        with self.fixture() as (root, *_):
            data = json.loads(link.REQUEST.read_text()); del data['native_archive_contract']
            link.REQUEST.write_text(json.dumps(data))
            with self.assertRaises(ValueError): link.request()

    def test_default_dispatch_clears_inherited_capture_and_runs_only_native_stage(self):
        with self.fixture() as (root, logs, artifacts), \
                mock.patch.dict(os.environ, MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR='/injected'), \
                mock.patch.object(link.subprocess, 'run') as run:
            link.native(logs, artifacts)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], ['bash', '.github/ci/native-bootstrap.sh'])
            self.assertNotIn('MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR', run.call_args.kwargs['env'])
            self.assertTrue(run.call_args.kwargs['check'])
            self.assertFalse((logs / 'i386-native-contract').exists())

    def test_enabled_dispatch_runs_archive_check_after_success_with_no_final_inputs(self):
        with self.fixture(True) as (root, logs, artifacts):
            events = []
            def run(command, **kwargs):
                self.assertTrue(kwargs['check'])
                events.append(command)
                captures = logs / 'i386-native-contract/captures'
                self.assertEqual(kwargs['env']['MADEIRA_NATIVE_CONTRACT_CAPTURE_DIR'], str(captures))
                if len(events) == 1:
                    self.assertTrue(captures.is_dir())
                    put(artifacts / 'provenance.json', 'native passed fixture')
                else:
                    self.assertTrue((artifacts / 'provenance.json').exists())
                    self.assertEqual(command, [sys.executable, 'build/i386-native-contract/check.py',
                        '--root', str(root), '--native-receipt', str(artifacts / 'provenance.json'),
                        '--captures', str(captures), '--output', str(captures.parent / 'archive-contract.json')])
                    put(captures.parent / 'archive-contract.json', json.dumps({
                        'status': 'bounded_archive_contract_passed', 'final_link': None,
                        'runtime': 'not_run', 'application_support': 'not_established',
                        'captures': {str(n): {} for n in range(8)}}))
            with mock.patch.object(link.subprocess, 'run', side_effect=run): link.native(logs, artifacts)
            self.assertEqual(len(events), 2)
            with mock.patch.object(link.subprocess, 'run') as runner, self.assertRaises(FileExistsError):
                link.native(logs, artifacts)
            runner.assert_not_called()

    def test_native_or_archive_failure_cannot_continue_to_success(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at), self.fixture(True) as (root, logs, artifacts):
                calls = []
                def fail(command, **kwargs):
                    calls.append(command)
                    if len(calls) == fail_at: raise subprocess.CalledProcessError(1, command)
                with mock.patch.object(link.subprocess, 'run', side_effect=fail), self.assertRaises(subprocess.CalledProcessError):
                    link.native(logs, artifacts)
                self.assertEqual(len(calls), fail_at)
                self.assertFalse((logs / 'i386-native-contract/archive-contract.json').exists())

    def test_native_cli_has_no_final_link_packaging_or_compiler_passthrough(self):
        base = ['native', '--native-log-dir', 'logs', '--native-artifact-dir', 'artifacts']
        for extra in (['--executable', 'app'], ['--fex-bridge-capture', 'bridge.json'],
                      ['--package'], ['--jobs', '3'], ['--', '-flto']):
            with self.subTest(extra=extra), mock.patch.object(link, 'native') as native, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                link.main(base + extra)
            self.assertEqual(exc.exception.code, 2)
            native.assert_not_called()
        with mock.patch.object(link, 'native') as native:
            link.main(base)
            native.assert_called_once_with(Path('logs'), Path('artifacts'))

    def test_enabled_success_without_archive_receipt_fails(self):
        with self.fixture(True) as (root, logs, artifacts), mock.patch.object(link.subprocess, 'run'), \
                self.assertRaises((FileNotFoundError, ValueError)):
            link.native(logs, artifacts)


if __name__ == '__main__':
    unittest.main(verbosity=2)
