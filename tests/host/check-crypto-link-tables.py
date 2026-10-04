#!/usr/bin/env python3
"""Exercise target crypto feature flags and fail-closed link contracts on a host.

Uses the real build.sh, flag handling, shim header, compiler, nm and ar. Only
Apple SDK/tool discovery and unrelated compilation are mocked. Small guarded
C fixtures model the pinned Wine 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f
bcrypt/secur32/crypt32 preprocessor boundaries; this is not a full Wine/iOS
compile, TLS handshake, certificate validation or cryptographic correctness test.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'build/ntdll-unix/build.sh'
CHECKER = ROOT / 'build/ntdll-unix/check-crypto-link-tables.py'
spec = importlib.util.spec_from_file_location('crypto_link_tables', CHECKER)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def symbol_listing(prefix):
    return (f'0000000000000000 S _{prefix}_unix_call_funcs\n'
            f'0000000000000010 D _{prefix}_unix_call_wow64_funcs\n'
            '                 U _ios_gnutls_dlopen\n'
            '                 U _ios_gnutls_dlsym\n'
            '                 U _ios_gnutls_dlclose\n')


class SymbolTests(unittest.TestCase):
    def test_all_table_definitions_are_required(self):
        for prefix in ('bcrypt', 'secur32', 'crypt32'):
            good = symbol_listing(prefix)
            checker.check_symbols(good, prefix)
            for suffix in ('unix_call_funcs', 'unix_call_wow64_funcs'):
                name = f'_{prefix}_{suffix}'
                for kind in ('U', 's', 'd', 'T', 'A', 'B', '?'):
                    with self.subTest(prefix=prefix, suffix=suffix, kind=kind):
                        bad = re.sub(rf'^.*\b{re.escape(name)}$', f'                 {kind} {name}', good, flags=re.M)
                        with self.assertRaisesRegex(ValueError, 'missing external data definition'):
                            checker.check_symbols(bad, prefix)

    def test_near_matches_and_diagnostics_are_not_definitions(self):
        good = symbol_listing('bcrypt')
        for replacement in ('_bcrypt_unix_call_funcs_old', '_not_bcrypt_unix_call_funcs',
                            '_bcrypt_unix_call_funcs extra text'):
            with self.assertRaises(ValueError):
                checker.check_symbols(good.replace('_bcrypt_unix_call_funcs', replacement), 'bcrypt')
        with self.assertRaises(ValueError):
            checker.check_symbols('diagnostic: 000 S _bcrypt_unix_call_funcs\n', 'bcrypt')
        with self.assertRaises(ValueError):
            checker.check_symbols(good.replace('0000000000000000 S', 'S'), 'bcrypt')
        with self.assertRaises(ValueError):
            checker.check_symbols(good + ' U _bcrypt_unix_call_funcs\n', 'bcrypt')

    def test_no_backend_and_unrenamed_tables_are_rejected(self):
        good = symbol_listing('crypt32')
        with self.assertRaisesRegex(ValueError, 'static GnuTLS shim'):
            checker.check_symbols('\n'.join(good.splitlines()[:2]), 'crypt32')
        with self.assertRaisesRegex(ValueError, 'unrenamed unixlib table'):
            checker.check_symbols(good + '0000000000000000 S ___wine_unix_call_funcs\n', 'crypt32')


FIXTURE = r'''
#include "config.h"
#include <dlfcn.h>
/* Explicit assembler labels model Mach-O's leading underscore on any host. */
extern void *ios_gnutls_dlopen(const char *, int) __asm__("_ios_gnutls_dlopen");
extern void *ios_gnutls_dlsym(void *, const char *) __asm__("_ios_gnutls_dlsym");
extern int ios_gnutls_dlclose(void *) __asm__("_ios_gnutls_dlclose");
#define STR1(x) #x
#define STR(x) STR1(x)
typedef int (*unixlib_entry_t)(void *);
#if BACKEND_GUARD
static int process_attach(void *args)
{
    void *handle = dlopen(SONAME_LIBGNUTLS, RTLD_NOW);
    void *symbol = dlsym(handle, "gnutls_global_init");
    dlclose(handle);
    return symbol ? 0 : -1;
}
#elif defined(CRYPT32_FIXTURE)
static int process_attach(void *args) { return -1; }
#endif
#if BACKEND_GUARD || defined(CRYPT32_FIXTURE)
#ifndef OMIT_NATIVE_TABLE
const unixlib_entry_t __wine_unix_call_funcs[]
    __asm__("_" STR(__wine_unix_call_funcs)) = {process_attach};
#endif
#if defined(_WIN64) && !defined(OMIT_WOW64_TABLE)
const unixlib_entry_t __wine_unix_call_wow64_funcs[]
    __asm__("_" STR(__wine_unix_call_wow64_funcs)) = {process_attach};
#endif
#endif
'''


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='crypto link tables ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.build = self.root / 'build/ntdll-unix'
        (self.build / 'shims').mkdir(parents=True)
        (self.build / 'shims/wine_ios_exit.h').touch()
        shutil.copy2(BUILD, self.build / 'build.sh')
        shutil.copy2(CHECKER, self.build / CHECKER.name)
        config = self.root / 'wine/build-macos/include/config.h'
        config.parent.mkdir(parents=True)
        # Autoconf --without-gnutls uses commented #undef, not a real #undef.
        config.write_text('/* #undef HAVE_GNUTLS_CIPHER_INIT */\n'
                          '/* #undef SONAME_LIBGNUTLS */\n#define _WIN64 1\n')
        crypto = self.root / 'build/crypto-unix'
        crypto.mkdir()
        shutil.copy2(ROOT / 'build/crypto-unix/ios_gnutls_shim.h', crypto)
        generator = crypto / 'gen_gnutls_symtab.sh'
        generator.write_text('#!/bin/sh\nexit 0\n')
        generator.chmod(0o755)
        for prefix, path, guard in (
            ('bcrypt', 'wine/dlls/bcrypt/gnutls.c', 'defined(HAVE_GNUTLS_CIPHER_INIT)'),
            ('secur32', 'wine/dlls/secur32/schannel_gnutls.c', 'defined(SONAME_LIBGNUTLS)'),
            ('crypt32', 'build/crypto-unix/crypt32_unixlib_ios.c', 'defined(SONAME_LIBGNUTLS)'),
        ):
            source = self.root / path
            source.parent.mkdir(parents=True, exist_ok=True)
            code = FIXTURE.replace('BACKEND_GUARD', guard)
            source.write_text(('#define CRYPT32_FIXTURE\n' if prefix == 'crypt32' else '') + code)
        native = self.root / 'wine/dlls/ntdll/unix'
        native.mkdir(parents=True)
        archive_tail = BUILD.read_text().split('"$OBJ_DIR/cdrom.o"', 1)[1]
        for name in ['cdrom', *re.findall(r'"\$OBJ_DIR/(\w+)\.o"', archive_tail)]:
            (native / f'{name}.c').touch()
        self.app = self.root / 'app/Madeira/libntdll_unix.a'
        self.app.parent.mkdir(parents=True)
        self.app.write_bytes(b'previous good archive')
        self.cc = shutil.which('cc')
        self.nm = shutil.which('nm')
        self.assertTrue(self.cc and self.nm and shutil.which('ar'))
        subprocess.run([self.cc, '-x', 'c', '-c', '-o', str(self.root / 'unrelated.o'), '-'],
                       input='static int unrelated;\n', text=True, check=True, capture_output=True)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root), REAL_CC=self.cc, REAL_NM=self.nm)
        self.tool('nm', '''
if os.getenv('FAIL_NM'): sys.exit('fixture nm failure')
sys.exit(subprocess.run([os.environ['REAL_NM'], *sys.argv[1:]]).returncode)
''')
        self.tool('xcrun', '''
args = sys.argv[1:]
if '--show-sdk-path' in args: print('/fixture iPhoneOS.sdk'); sys.exit(0)
if '-f' in args and args[-1] == 'nm': print(root / 'bin/nm'); sys.exit(0)
with (root / 'compiles.jsonl').open('a') as log: log.write(json.dumps(args) + '\\n')
out = Path(args[args.index('-o') + 1])
if out.stem not in ('bcrypt_unixlib', 'secur32_unixlib', 'crypt32_unixlib'):
    shutil.copyfile(root / 'unrelated.o', out); sys.exit(0)
if out.stem == os.getenv('OMIT_OBJECT'): sys.exit(0)
# Keep real include/define options; remove only Apple target selection.
args = args[3:]  # -sdk iphoneos clang
filtered = []
i = 0
while i < len(args):
    if args[i] in ('-arch', '-isysroot'): i += 2; continue
    if args[i].startswith('-miphoneos-version-min='): i += 1; continue
    if out.stem == os.getenv('DROP_FEATURE_FOR') and args[i].startswith(('-DHAVE_GNUTLS_CIPHER_INIT=', '-DSONAME_LIBGNUTLS=')):
        i += 1; continue
    filtered.append(args[i]); i += 1
if out.stem == os.getenv('OMIT_NATIVE'): filtered.append('-DOMIT_NATIVE_TABLE=1')
if out.stem == os.getenv('OMIT_WOW64'): filtered.append('-DOMIT_WOW64_TABLE=1')
sys.exit(subprocess.run([os.environ['REAL_CC'], *filtered]).returncode)
''')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!/usr/bin/env python3\nimport json, os, shutil, subprocess, sys\n'
                        'from pathlib import Path\nroot = Path(os.environ["FIXTURE_ROOT"])\n' + body)
        path.chmod(0o755)

    def run_build(self, success=True, **env):
        before = self.app.read_bytes()
        result = subprocess.run(['bash', str(self.build / 'build.sh')],
                                env=dict(self.env, **env), text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.app.read_bytes(), before)
            self.assertNotIn('=== Building libntdll_unix.a ===', result.stdout)
        return result

    def test_without_host_gnutls_all_three_real_backends_are_selected(self):
        self.run_build()
        for prefix in ('bcrypt', 'secur32', 'crypt32'):
            obj = self.build / f'obj/{prefix}_unixlib.o'
            checker.check_symbols(subprocess.check_output([self.nm, '-g', str(obj)], text=True), prefix)
        # Crypto target overrides cannot leak into other Wine unixlibs or ntdll.
        invocations = [json.loads(line) for line in (self.root / 'compiles.jsonl').read_text().splitlines()]
        for args in invocations:
            out = Path(args[args.index('-o') + 1]).stem
            flags = [arg for arg in args if arg.startswith('-DSONAME_LIBGNUTLS=')]
            self.assertEqual(bool(flags), out in ('bcrypt_unixlib', 'secur32_unixlib', 'crypt32_unixlib'))
        members = subprocess.check_output(['ar', 't', str(self.app)], text=True).splitlines()
        self.assertTrue({'bcrypt_unixlib.o', 'secur32_unixlib.o', 'crypt32_unixlib.o'} <= set(members))

    def test_missing_bcrypt_feature_reproduces_empty_successful_compile(self):
        result = self.run_build(success=False, DROP_FEATURE_FOR='bcrypt_unixlib')
        self.assertIn('missing external data definition: _bcrypt_unix_call_funcs', result.stderr)

    def test_missing_schannel_feature_reproduces_empty_successful_compile(self):
        result = self.run_build(success=False, DROP_FEATURE_FOR='secur32_unixlib')
        self.assertIn('missing external data definition: _secur32_unix_call_funcs', result.stderr)

    def test_crypt32_no_backend_tables_cannot_pass(self):
        result = self.run_build(success=False, DROP_FEATURE_FOR='crypt32_unixlib')
        self.assertIn('crypt32_unixlib.o: missing static GnuTLS shim reference', result.stderr)

    def test_missing_native_table_stops_before_archive_staging(self):
        result = self.run_build(success=False, OMIT_NATIVE='secur32_unixlib')
        self.assertIn('missing external data definition: _secur32_unix_call_funcs', result.stderr)

    def test_missing_wow64_table_stops_before_archive_staging(self):
        result = self.run_build(success=False, OMIT_WOW64='bcrypt_unixlib')
        self.assertIn('missing external data definition: _bcrypt_unix_call_wow64_funcs', result.stderr)

    def test_nm_error_is_fatal(self):
        result = self.run_build(success=False, FAIL_NM='1')
        self.assertIn('nm failed', result.stderr)

    def test_stale_crypto_object_cannot_hide_missing_output(self):
        self.run_build()
        result = self.run_build(success=False, OMIT_OBJECT='bcrypt_unixlib')
        self.assertIn('missing or empty crypto object', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
