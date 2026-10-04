#!/usr/bin/env python3
"""Exercise native build orchestration without an Apple SDK or Wine checkout.

Mock only SDK/compiler/CMake discovery; use real host objects, ar, objcopy and
nm to test complete replacement/rename, stale-output rejection and failure
propagation. This is not an iOS compilation or architecture test.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = [
    'FEXCore/Source/libFEXCore.a', 'FEXCore/Source/libFEXCore_Base.a',
    'FEXCore/Source/libJemallocLibs.a', 'External/cephes/libcephes_128bit.a',
    'External/fmt/libfmt.a', 'External/SoftFloat-3e/libsoftfloat_3e.a',
    'External/xxhash/cmake_unofficial/libxxhash.a',
]
SERVER_SOURCES = '''async atom change class clipboard completion console d3dkmt
debugger device directory event fd file handle hook inproc_sync mach mailslot
main mapping mutex named_pipe object process procfs ptrace queue region registry
request semaphore serial signal sock symlink thread timer token trace unicode
user window winstation'''.split()
OVERLAYS = re.findall(r'^\s*"([^:"]+):([^:"]+):([^:"]+)"',
                      (ROOT / 'build/wineserver/build.sh').read_text(), re.M)


class NativeBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='native bootstrap ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.build = self.root / 'build/wineserver'
        self.build.mkdir(parents=True)
        for name in ('build.sh', 'build-base.sh'):
            shutil.copy2(ROOT / 'build/wineserver' / name, self.build / name)
        fex = self.root / 'build/fex-ios'
        fex.mkdir()
        shutil.copy2(ROOT / 'build/fex-ios/build.sh', fex / 'build.sh')
        # The real patch/revision gate is exercised in check-fex-source-repairs.py.
        # This synthetic tree mocks only that subprocess, while proving ordering
        # and failure propagation in the actual build.sh orchestration.
        (fex / 'apply-source-repairs.py').write_text('''import os, sys
from pathlib import Path
root = Path(os.environ['FIXTURE_ROOT'])
with (root / 'fex-events').open('a') as out: out.write('repair\\n')
if os.getenv('FAIL_REPAIR'): sys.exit('fixture source repair rejected')
''')
        (self.root / 'wine/build-macos/include').mkdir(parents=True)
        (self.root / 'wine/build-macos/include/config.h').touch()
        (self.root / 'wine/server').mkdir()
        (self.root / 'app/Madeira').mkdir(parents=True)
        for name in SERVER_SOURCES:
            (self.root / 'wine/server' / (name + '.c')).touch()
        for _, source, _ in OVERLAYS:
            source = source.replace('$WINE_SRC', str(self.root / 'wine'))
            source = source.replace('$BUILD_DIR', str(self.build))
            source = source.replace('$REPO_ROOT', str(self.root))
            path = Path(source) if source.startswith('/') else self.build / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        (self.build / 'wineserver_ios_kill.c').touch()
        for name, code in (
            ('definition', 'int shared __asm__("_shared_session");\n'
             'int notify(void) __asm__("_send_notify_message");\n'
             'int notify(void) { return shared; }\n'),
            ('reference', 'extern int notify(void) __asm__("_send_notify_message");\n'
             'int caller(void) { return notify(); }\n'),
        ):
            subprocess.run(['cc', '-x', 'c', '-c', '-o', str(self.root / (name + '.o')), '-'],
                           input=code, text=True, check=True, capture_output=True)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root), BUILD_JOBS='2',
                        REAL_AR=shutil.which('ar'), REAL_OBJCOPY=shutil.which('objcopy') or
                        shutil.which('llvm-objcopy'), AR=str(self.bin / 'ar'),
                        OBJCOPY=str(self.bin / 'llvm-objcopy'))
        self.assertTrue(self.env['REAL_OBJCOPY'], 'Host objcopy or llvm-objcopy is required')
        self.tool('xcrun', '''
args = sys.argv[1:]
if '--show-sdk-path' in args:
    print('/mock iPhoneOS.sdk'); sys.exit(0)
src = Path(args[args.index('-c') + 1]); out = Path(args[args.index('-o') + 1])
with (root / 'compiles.jsonl').open('a') as log: log.write(json.dumps(args) + '\\n')
if not src.is_file(): sys.exit('missing source: ' + str(src))
if src.stem == os.getenv('FAIL_COMPILE'):
    print('fixture compiler diagnostic: ' + src.name, file=sys.stderr); sys.exit(7)
if src.stem == os.getenv('OMIT_OBJECT'): sys.exit(0)
shutil.copyfile(root / ('definition.o' if src.stem == 'atom' else 'reference.o'), out)
''')
        self.tool('ar', '''
args = sys.argv[1:]
if args[0] == os.getenv('FAIL_AR'): sys.exit(8)
if args[0] == 't' and os.getenv('APPLE_INDEX'): print('__.SYMDEF SORTED', flush=True)
if args[0] == 'rcs' and os.getenv('DROP_ARCHIVE_MEMBER'): args = args[:-1]
sys.exit(subprocess.run([os.environ['REAL_AR'], *args]).returncode)
''')
        self.tool('llvm-objcopy', '''
if os.getenv('FAIL_OBJCOPY'): sys.exit(9)
if os.getenv('NOOP_OBJCOPY'): sys.exit(0)
sys.exit(subprocess.run([os.environ['REAL_OBJCOPY'], *sys.argv[1:]]).returncode)
''')
        self.tool('cmake', '''
args = sys.argv[1:]
with (root / 'cmake.jsonl').open('a') as log: log.write(json.dumps(args) + '\\n')
with (root / 'fex-events').open('a') as log: log.write(('build' if '--build' in args else 'configure') + '\\n')
if '--build' not in args:
    if os.getenv('FAIL_CONFIGURE'): sys.exit(6)
    build = Path(args[args.index('-B') + 1]); build.mkdir(parents=True, exist_ok=True)
    (build / 'CMakeCache.txt').write_text('fixture cache')
else:
    if os.getenv('FAIL_BUILD'): sys.exit(7)
    build = Path(args[args.index('--build') + 1])
    for archive in json.loads(os.environ['FEX_ARCHIVES']):
        if archive.endswith(os.getenv('OMIT_ARCHIVE', 'never matches')): continue
        out = build / archive; out.parent.mkdir(parents=True, exist_ok=True); out.write_text('archive')
''')
        self.env['FEX_ARCHIVES'] = json.dumps(ARCHIVES)

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!/usr/bin/env python3\nimport json, os, shutil, subprocess, sys\n'
                        'from pathlib import Path\nroot = Path(os.environ["FIXTURE_ROOT"])\n' + body)
        path.chmod(0o755)

    def run_script(self, script='build/wineserver/build.sh', args=(), success=True, **env):
        result = subprocess.run(['bash', str(self.root / script), *args],
                                env=dict(self.env, **env), text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def seed_app(self):
        app = self.root / 'app/Madeira/libwineserver.a'
        app.write_bytes(b'old app archive must stay untouched')
        return app, app.read_bytes()

    def test_clean_build_and_cross_object_symbol_renames(self):
        self.seed_app()
        self.run_script(APPLE_INDEX='1')
        app = self.root / 'app/Madeira/libwineserver.a'
        members = subprocess.check_output([self.env['REAL_AR'], 't', str(app)], text=True).splitlines()
        expected = set(s + '.o' for s in SERVER_SOURCES)
        for name, _, old in OVERLAYS:
            expected.discard(old)
            expected.add(name + '.o')
        expected.add('wineserver_ios_kill.o')
        self.assertEqual(set(members), expected)
        self.assertEqual(len(members), len(expected))
        symbols = subprocess.check_output(['nm', str(app)], text=True)
        self.assertRegex(symbols, r'U _ws_send_notify_message\b')
        self.assertRegex(symbols, r'T _ws_send_notify_message\b')
        self.assertNotRegex(symbols, r'\b[UT] _send_notify_message\b')
        self.assertNotRegex(symbols, r'\b[BC] _shared_session\b')
        self.run_script(args=('request',))
        self.assertTrue(app.stat().st_size)
        # An interrupted later full rebuild cannot damage the last good output.
        before = app.read_bytes()
        self.run_script(success=False, FAIL_COMPILE='atom')
        self.assertEqual(app.read_bytes(), before)

    def test_base_failure_is_fatal_and_prints_diagnostic(self):
        app, before = self.seed_app()
        result = self.run_script(success=False, FAIL_COMPILE='atom')
        self.assertIn('fixture compiler diagnostic: atom.c', result.stderr)
        self.assertFalse((self.build / 'libwineserver_base.a').exists())
        self.assertEqual(app.read_bytes(), before)

    def test_missing_base_object_cannot_reuse_stale_object(self):
        stale = self.build / 'obj/base/atom.o'
        stale.parent.mkdir(parents=True)
        stale.write_text('stale')
        result = self.run_script(success=False, OMIT_OBJECT='atom')
        self.assertIn('Missing Wine base object: atom.o', result.stderr)

    def test_missing_overlay_and_compiler_error_are_fatal(self):
        app, before = self.seed_app()
        for failure in ({'OMIT_OBJECT': 'request_ios'}, {'FAIL_COMPILE': 'request_ios'},
                        {'OMIT_OBJECT': 'wineserver_ios_kill'}):
            with self.subTest(failure=failure):
                self.run_script(success=False, **failure)
                self.assertEqual(app.read_bytes(), before)

    def test_archive_and_symbol_rewrite_failures_do_not_publish(self):
        app, before = self.seed_app()
        for failure in ({'FAIL_AR': 'rcs'}, {'FAIL_OBJCOPY': '1'},
                        {'NOOP_OBJCOPY': '1'}, {'DROP_ARCHIVE_MEMBER': '1'}):
            with self.subTest(failure=failure):
                self.run_script(success=False, **failure)
                self.assertEqual(app.read_bytes(), before)

    def test_partial_build_requires_complete_local_archive(self):
        app, before = self.seed_app()
        result = self.run_script(args=('request',), success=False)
        self.assertIn('run ', result.stderr)
        self.assertEqual(app.read_bytes(), before)

    def test_deletion_error_is_not_suppressed(self):
        self.run_script()
        app = self.root / 'app/Madeira/libwineserver.a'
        before = app.read_bytes()
        self.run_script(args=('request',), success=False, FAIL_AR='d')
        self.assertEqual(app.read_bytes(), before)

    def test_base_direct_build_and_missing_headers(self):
        self.run_script('build/wineserver/build-base.sh')
        base = self.build / 'libwineserver_base.a'
        before = base.read_bytes()
        (self.root / 'wine/build-macos/include/config.h').unlink()
        self.run_script('build/wineserver/build-base.sh', success=False)
        self.assertEqual(base.read_bytes(), before)

    def test_fex_repairs_failed_cache_and_builds_only_static_targets(self):
        cache = self.root / 'FEX/build-ios/CMakeCache.txt'
        cache.parent.mkdir(parents=True)
        cache.write_text('old incomplete configure')
        self.run_script('build/fex-ios/build.sh')
        self.assertEqual((self.root / 'fex-events').read_text().splitlines(),
                         ['repair', 'configure', 'build'])
        configure, build = map(json.loads, (self.root / 'cmake.jsonl').read_text().splitlines())
        self.assertIn('-DCMAKE_SYSTEM_PROCESSOR=arm64', configure)
        self.assertIn('-DTUNE_CPU=none', configure)
        for dependency in ('fmt', 'unordered_dense', 'range-v3'):
            self.assertIn('-DCMAKE_DISABLE_FIND_PACKAGE_' + dependency + '=TRUE', configure)
        self.assertEqual(build[build.index('--target') + 1:],
                         ['FEXCore', 'FEXCore_Base', 'JemallocLibs', 'softfloat_3e'])
        self.assertEqual(build[build.index('--parallel') + 1], '2')
        for archive in ARCHIVES:
            self.assertTrue((cache.parent / archive).is_file())

    def test_fex_missing_archive_or_failed_tool_is_fatal(self):
        for failure in ({'OMIT_ARCHIVE': 'libJemallocLibs.a'}, {'FAIL_CONFIGURE': '1'},
                        {'FAIL_BUILD': '1'}, {'BUILD_JOBS': '0'}):
            with self.subTest(failure=failure):
                self.run_script('build/fex-ios/build.sh', success=False, **failure)

    def test_fex_source_repair_failure_stops_before_configure(self):
        result = self.run_script('build/fex-ios/build.sh', success=False, FAIL_REPAIR='1')
        self.assertIn('fixture source repair rejected', result.stderr)
        self.assertEqual((self.root / 'fex-events').read_text().splitlines(), ['repair'])
        self.assertFalse((self.root / 'cmake.jsonl').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
