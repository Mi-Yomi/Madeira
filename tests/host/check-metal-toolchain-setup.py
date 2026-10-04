#!/usr/bin/env python3
"""Portable subprocess fixtures. Never downloads or executes any Apple binary."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('metal_setup', ROOT / '.github/ci/ensure-metal-toolchain.py')
METAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METAL)
HEADER = '''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
from pathlib import Path
root = Path(os.environ['FIXTURE_ROOT'])
mode = os.environ.get('FIXTURE_MODE', 'missing')
args = sys.argv[1:]
with (root / 'trace.jsonl').open('a') as stream:
    stream.write(json.dumps([Path(sys.argv[0]).name, *args]) + '\\n')
dev = root / 'Xcode_27.app/Contents/Developer'
component = root / 'official component/Metal.xctoolchain/usr/metal/current/bin'
stub = dev / 'Toolchains/XcodeDefault.xctoolchain/usr/bin/metal'
installed = (root / 'installed').exists()
'''


class MetalSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='metal fixture ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dev = self.root / 'Xcode_27.app/Contents/Developer'
        self.component = self.root / 'official component/Metal.xctoolchain/usr/metal/current/bin'
        self.sdk = self.dev / 'Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.sdk'
        self.sdk.mkdir(parents=True)
        self.logs = self.root / 'logs'
        self.tools = {name: str(self.root / 'tools' / name) for name in METAL.SYSTEM_TOOLS}
        self.write_tool(Path(self.tools['select']), "print(dev if mode != 'wrong-path' else root)\n")
        self.write_tool(self.dev / 'usr/bin/xcodebuild', '''
if args == ['-version']:
    print('Xcode ' + ('27.1' if mode == 'wrong-version' else '27.0'))
    print('Build version ' + ('27A999' if mode == 'wrong-build' else '27A266a'))
    sys.exit(0)
if args != ['-downloadComponent', 'metalToolchain']: sys.exit('unexpected xcodebuild arguments')
if mode == 'download-failure': sys.exit('fixture official download failed')
if mode == 'login': print('Sign in with your Apple Account; verification code: 919191; token=MDA_FIXTURE_AUTH_SECRET_8cbd3', flush=True); time.sleep(30)
if mode == 'terms': print('You must accept the new license agreement', flush=True); time.sleep(30)
if mode == 'payment': print('Payment information required', flush=True); time.sleep(30)
if mode == 'download-timeout': time.sleep(30)
if mode != 'success-but-missing': (root / 'installed').touch()
print('Done downloading: Metal Toolchain (fixture).')
''')
        self.write_tool(Path(self.tools['codesign']), '''
if '--verify' in args:
    if mode == 'bad-downloader-signature' and args[-1].endswith('xcodebuild'): sys.exit(8)
    if mode == 'verification-failure' and 'Metal.xctoolchain' in args[-1]: sys.exit(8)
    if mode == 'bad-linker-signature' and args[-1].endswith('/metallib'): sys.exit(8)
    print('explicit requirement satisfied')
else: print('Authority=Software Signing\\nAuthority=Apple Root CA\\nIdentifier=fixture')
''')
        self.write_tool(Path(self.tools['xcrun']), '''
if args == ['--help']: print('--no-cache --find --sdk'); sys.exit(0)
if '--show-sdk-version' in args: print('26.0' if mode == 'wrong-sdk' else '27.0'); sys.exit(0)
if '--show-sdk-path' in args: print(dev / 'Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.sdk'); sys.exit(0)
if '--find' in args:
    tool = args[-1]
    if tool == 'metal' and mode == 'missing-discovery' and not installed:
        sys.exit('xcrun: unable to find utility "metal"')
    if tool == 'metallib' and mode == 'missing-linker': sys.exit('missing metallib')
    if not installed or mode == 'shim': print(stub if tool == 'metal' else stub.with_name('metallib'))
    else: print(component / tool)
    sys.exit(0)
if args[-2:] == ['metal', '--version']:
    if mode == 'probe-error': sys.exit('fixture compiler crashed')
    if not installed: sys.exit("error: cannot execute tool 'metal' due to missing Metal Toolchain; use: xcodebuild -downloadComponent MetalToolchain")
    sys.exit(subprocess.run([component / 'metal', '--version']).returncode)
sys.exit('unexpected xcrun arguments')
''')
        compiler = '''
if args == ['--version']:
    print('Apple metal version 33000.1 (fixture)\\nTarget: air64-apple-darwin26.0\\nThread model: posix')
    print('InstalledDir: ' + str(root if mode == 'wrong-component-path' else component))
    sys.exit(0)
if mode == 'compile-failure': sys.exit('fixture Metal compilation failed')
assert args[:4] == ['-target', 'air64-apple-ios27.0', '-isysroot', str(dev / 'Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.sdk')]
source = Path(args[args.index('-c') + 1])
assert '#include <metal_stdlib>' in source.read_text()
if mode != 'missing-air': Path(args[args.index('-o') + 1]).write_bytes(b'fixture AIR')
'''
        linker = '''
if mode == 'link-failure': sys.exit('fixture Metal link failed')
assert Path(args[0]).read_bytes() == b'fixture AIR'
if mode != 'missing-library': Path(args[args.index('-o') + 1]).write_bytes(b'MTLB fixture library')
'''
        self.write_tool(self.component / 'metal', compiler)
        self.write_tool(self.component / 'metallib', linker)
        stub = self.dev / 'Toolchains/XcodeDefault.xctoolchain/usr/bin/metal'
        self.write_tool(stub, "sys.exit('fixture stub must be invoked through xcrun')\n")
        self.write_tool(stub.with_name('metallib'), "sys.exit('fixture stub not the actual linker')\n")
        self.env = {'FIXTURE_ROOT': str(self.root), 'DEVELOPER_DIR': '', 'TOOLCHAINS': ''}

    def write_tool(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(HEADER + body)
        path.chmod(0o755)

    def run_setup(self, mode='missing', *, allow=True, installed=False, **overrides):
        if installed: (self.root / 'installed').touch()
        else: (self.root / 'installed').unlink(missing_ok=True)
        (self.root / 'trace.jsonl').unlink(missing_ok=True)
        console = io.StringIO()
        with mock.patch.dict(os.environ, dict(self.env, FIXTURE_MODE=mode)), \
             mock.patch.object(METAL, 'SYSTEM_TOOLS', self.tools), \
             mock.patch.object(METAL, 'EXPECTED_DEVELOPER_DIR', self.dev), \
             mock.patch.object(METAL.platform, 'system', return_value='Darwin'), \
             mock.patch.object(METAL.platform, 'machine', return_value='arm64'), \
             (mock.patch.multiple(METAL, **overrides) if overrides else contextlib.nullcontext()), \
             contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
            result = METAL.Setup(self.logs, allow).execute()
        self.console_output = console.getvalue()
        self.data = json.loads((self.logs / 'metal-toolchain-provenance.json').read_text())
        self.trace = [json.loads(line) for line in (self.root / 'trace.jsonl').read_text().splitlines()]
        self.assertEqual((self.logs / 'metal-toolchain-status.txt').read_text().strip(), self.data['status'])
        return result

    def downloads(self):
        return [entry for entry in self.trace if '-downloadComponent' in entry]

    def test_present_compiler_does_not_download_and_has_real_evidence(self):
        self.assertEqual(self.run_setup(installed=True, allow=False), 0)
        self.assertEqual(self.downloads(), [])
        self.assertEqual(self.data['status'], 'available')
        self.assertEqual(self.data['download_result'], 'not-needed')
        self.assertEqual(self.data['smoke_test']['status'], 'passed')
        self.assertEqual(self.data['approved_agreement']['identifier'], 'EA2002')
        for evidence in self.data['verified_executables'].values():
            self.assertTrue(evidence['verification_passed'])
            self.assertEqual(evidence['requirement'], 'anchor apple')
            self.assertEqual(len(evidence['sha256']), 64)
        compiled = [e for e in self.trace if e[0] == 'metal' and '-c' in e]
        self.assertEqual(len(compiled), 1)
        self.assertFalse(Path(compiled[0][compiled[0].index('-c') + 1]).exists())

    def test_missing_without_explicit_permission_does_not_install(self):
        self.assertEqual(self.run_setup(allow=False), 1)
        self.assertEqual(self.downloads(), [])
        self.assertEqual(self.data['status'], 'unavailable')

    def test_missing_component_downloads_once_then_reprobes_and_smokes(self):
        self.assertEqual(self.run_setup(), 0)
        self.assertEqual(self.downloads(), [['xcodebuild', '-downloadComponent', 'metalToolchain']])
        self.assertTrue(self.data['download_attempted'])
        self.assertEqual(self.data['download_result'], 'command-succeeded')
        self.assertEqual(self.data['smoke_test']['status'], 'passed')
        self.assertEqual(sum(e[0] == 'xcrun' and e[-2:] == ['metal', '--version'] for e in self.trace), 2)

    def test_missing_discovery_is_supported(self):
        self.assertEqual(self.run_setup('missing-discovery'), 0)
        self.assertEqual(len(self.downloads()), 1)

    def test_signed_shim_is_not_mislabeled_as_component(self):
        self.assertEqual(self.run_setup('shim', installed=True), 0)
        self.assertFalse(self.data['entrypoints_are_component_binaries'])
        evidence = self.data['verified_executables']
        self.assertNotEqual(evidence['metal-entrypoint']['path'], evidence['metal-compiler']['path'])
        self.assertIn('Metal.xctoolchain', evidence['metal-compiler']['path'])

    def test_download_failure_is_fatal(self):
        self.assertEqual(self.run_setup('download-failure'), 1)
        self.assertEqual(len(self.downloads()), 1)
        self.assertEqual(self.data['download_result'], 'command-failed')
        self.assertEqual(self.data['smoke_test']['status'], 'not-run')

    def test_download_success_without_compiler_is_fatal(self):
        self.assertEqual(self.run_setup('success-but-missing'), 1)
        self.assertEqual(self.data['status'], 'verification-failed')
        self.assertEqual(len(self.downloads()), 1)

    def test_verification_failure_never_executes_unverified_component(self):
        self.assertEqual(self.run_setup('verification-failure'), 1)
        self.assertEqual(self.data['status'], 'verification-failed')
        self.assertFalse(any(e[0] == 'metal' for e in self.trace))
        self.assertEqual(self.data['smoke_test']['status'], 'not-run')

    def test_downloader_signature_failure_prevents_install(self):
        self.assertEqual(self.run_setup('bad-downloader-signature'), 1)
        self.assertEqual(self.downloads(), [])
        self.assertEqual(self.data['status'], 'verification-failed')

    def test_linker_signature_failure_prevents_smoke(self):
        self.assertEqual(self.run_setup('bad-linker-signature', installed=True), 1)
        self.assertEqual(self.data['status'], 'verification-failed')
        self.assertEqual(self.data['smoke_test']['status'], 'not-run')

    def test_generic_probe_error_does_not_trigger_install(self):
        self.assertEqual(self.run_setup('probe-error'), 1)
        self.assertEqual(self.downloads(), [])
        self.assertEqual(self.data['status'], 'probe-failed')

    def test_compile_and_link_failures_are_fatal(self):
        for mode in ('compile-failure', 'link-failure', 'missing-air', 'missing-library'):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_setup(mode, installed=True), 1)
                self.assertEqual(self.data['status'], 'smoke-failed')
                self.assertEqual(self.data['smoke_test']['status'], 'failed')
                self.assertEqual(self.downloads(), [])

    def test_wrong_xcode_build_version_path_or_sdk_prevents_install(self):
        for mode in ('wrong-version', 'wrong-build', 'wrong-path', 'wrong-sdk'):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_setup(mode), 1)
                self.assertEqual(self.data['status'], 'preflight-failed')
                self.assertEqual(self.downloads(), [])

    def test_custom_toolchain_is_rejected(self):
        self.env['TOOLCHAINS'] = 'unreviewed'
        with mock.patch.dict(os.environ, dict(self.env, FIXTURE_MODE='missing')), \
             mock.patch.object(METAL.platform, 'system', return_value='Darwin'), \
             mock.patch.object(METAL.platform, 'machine', return_value='arm64'), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(METAL.Setup(self.logs, True).execute(), 1)
        self.assertFalse((self.root / 'trace.jsonl').exists())

    def test_new_terms_login_and_payment_stop_without_responding(self):
        for mode in ('terms', 'login', 'payment'):
            with self.subTest(mode=mode):
                started = time.monotonic()
                self.assertEqual(self.run_setup(mode), 1)
                self.assertLess(time.monotonic() - started, 10)
                self.assertEqual(self.data['status'], 'interaction-required')
                self.assertEqual(self.data['download_result'], 'interaction-required')

    def test_auth_prompt_secret_and_code_are_not_logged_or_persisted(self):
        self.assertEqual(self.run_setup('login'), 1)
        receipt = (self.logs / 'metal-toolchain-provenance.json').read_text()
        for secret in ('919191', 'MDA_FIXTURE_AUTH_SECRET_8cbd3', 'Sign in with your Apple Account'):
            self.assertNotIn(secret, self.console_output)
            self.assertNotIn(secret, receipt)
        record = next(item for item in self.data['commands'] if item['stage'] == 'Download Apple Metal Toolchain')
        self.assertEqual(record['interaction_category'], 'authentication')
        self.assertEqual(record['status'], 'interaction-required')
        self.assertTrue(record['output_suppressed'])
        self.assertEqual(record['output_tail'], '')
        self.assertIn('explicit requirement satisfied', self.console_output)
        self.assertIn('Xcode 27.0', receipt)

    def test_download_time_limit_stops_owned_process(self):
        self.assertEqual(self.run_setup('download-timeout', DOWNLOAD_SECONDS=0.15), 1)
        self.assertEqual(self.data['status'], 'timed-out')
        self.assertEqual(self.data['download_result'], 'timed-out')
        self.assertEqual(self.data['smoke_test']['status'], 'not-run')

    def test_real_component_path_is_required(self):
        self.assertEqual(self.run_setup('wrong-component-path', installed=True), 1)
        self.assertEqual(self.data['status'], 'setup-failed')
        self.assertEqual(self.downloads(), [])

    def test_output_capture_is_bounded(self):
        with contextlib.redirect_stdout(io.StringIO()):
            setup = METAL.Setup(self.logs, False)
            code, output = setup.command('output fixture', [sys.executable, '-c', "print('x' * 100000)"])
        self.assertEqual(code, 0)
        self.assertLessEqual(len(output), METAL.OUTPUT_LIMIT)
        self.assertTrue(setup.data['commands'][0]['output_truncated'])

    def test_process_group_timeout_kills_child_with_inherited_pipe(self):
        marker = self.root / 'escaped-child'
        child = f'import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()'
        parent = f'import subprocess, sys; subprocess.Popen([sys.executable, "-c", {child!r}])'
        with contextlib.redirect_stdout(io.StringIO()):
            setup = METAL.Setup(self.logs, False)
            with self.assertRaises(METAL.SetupFailure) as failure:
                setup.command('child timeout fixture', [sys.executable, '-c', parent], timeout=0.15)
        self.assertEqual(failure.exception.status, 'timed-out')
        time.sleep(1.1)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
