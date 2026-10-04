#!/usr/bin/env python3
"""Exercise Madeira's actual GL-absent Unix-call tables; no Wine or GL runs.

wglGetProcAddress has an unusual failure ABI: its PE wrapper expects an
all-ones extension index, not zero.  Compile the production table and handlers
with ASan/UBSan and test both pointer widths, guards, lifecycle and other slots.
If the Wine submodule is present, also cross-check its slot/layout/PE contract.
Use --wine-source PATH --require-wine to require that additional source check.
"""
from pathlib import Path
import argparse
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--wine-source', type=Path, default=ROOT / 'wine')
parser.add_argument('--require-wine', action='store_true')
options = parser.parse_args()
source = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()
start = source.index('static NTSTATUS ios_stub_unix_call(void *args)')
end = source.index("/* DXMT's unix call table", start)
production = source[start:end]
assert 'funcs64 = (const void *)ios_gl_stub_unix_call_table;' in source
assert 'funcs_wow64 = (const void *)ios_gl_stub_unix_call_wow64_table;' in source
assert 'funcs64 = funcs_wow64 = (const void *)ios_gl_stub_unix_call_table;' not in source

slot = int(re.search(r'#define IOS_GL_GET_PROC_ADDRESS\s+(\d+)', production)[1])
table_size = int(re.search(r'#define IOS_STUB_TABLE_SIZE\s+(\d+)', production)[1])
wine_header = options.wine_source / 'dlls/opengl32/unixlib.h'
wine_pe = options.wine_source / 'dlls/opengl32/wgl.c'
if wine_header.is_file() and wine_pe.is_file():
    header = wine_header.read_text()
    enum = re.search(r'enum unix_funcs\s*\{([^}]+)\}', header, re.S)[1]
    names = [name.strip() for name in enum.split(',') if name.strip()]
    assert names[:3] == ['unix_process_attach', 'unix_thread_attach', 'unix_process_detach']
    assert names[slot] == 'unix_wglGetProcAddress', names[slot]
    assert names.index('funcs_count') <= table_size
    params = re.search(r'struct wglGetProcAddress_params\s*\{([^}]+)\}', header, re.S)[1]
    assert re.sub(r'\s+', ' ', params).strip() == 'TEB *teb; LPCSTR lpszProc; PROC ret;'
    pe = wine_pe.read_text()
    function = pe.split('PROC WINAPI wglGetProcAddress(', 1)[1].split('\n}', 1)[0]
    sentinel = function.index('if (args.ret == (void *)-1) return NULL;')
    assert sentinel < function.index('extension_procs[(UINT_PTR)args.ret]')
    print('PASS: Wine source matches the lifecycle slots, lookup slot, argument layout and failure sentinel', flush=True)
elif options.require_wine:
    parser.error('Wine source cross-check requested, but unixlib.h or wgl.c is missing')
else:
    print('NOT RUN: Wine source ABI cross-check (submodule absent; audited at 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f)', flush=True)

harness = r'''
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef int32_t NTSTATUS;
typedef NTSTATUS (*unixlib_entry_t)(void *);
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
''' + production + r'''

_Static_assert(sizeof(void *) == 8, "the iOS Unix side is 64-bit");
_Static_assert(offsetof(struct ios_gl_get_proc_address_params, ret) == 16, "native ret offset");
_Static_assert(sizeof(struct ios_gl_get_proc_address_params) == 24, "native argument size");
_Static_assert(offsetof(struct ios_gl_get_proc_address_params32, ret) == 8, "WoW64 ret offset");
_Static_assert(sizeof(struct ios_gl_get_proc_address_params32) == 12, "WoW64 argument size");

/* Build the PE argument blocks independently as bytes.  Poisoned embedded
 * pointers must never be followed, and only the caller-width ret may change. */
static void check_lookup(unixlib_entry_t entry, size_t width, unsigned char fill)
{
    unsigned char *storage = malloc(40), expected[40];
    assert(storage);
    unsigned char *args = storage + 8;
    memset(storage, fill, 40);
    memcpy(expected, storage, 40);
    memset(expected + 8 + 2 * width, 0xff, width);
    assert(entry(args) == STATUS_NOT_SUPPORTED);
    assert(!memcmp(storage, expected, 40));

    /* Model the PE-side sentinel check: zero falsely selects extension 0. */
    if (width == 8) {
        uint64_t index;
        memcpy(&index, args + 16, sizeof(index));
        assert(index == UINT64_MAX);
    } else {
        uint32_t index;
        memcpy(&index, args + 8, sizeof(index));
        assert(index == UINT32_MAX);
    }
    free(storage);
}

static void *check_tables(void *unused)
{
    (void)unused;
    pthread_once(&ios_stub_tables_once, ios_init_stub_tables);
    for (unsigned int i = 0; i < IOS_STUB_TABLE_SIZE; ++i) {
        unsigned char untouched[32], expected[32];
        memset(untouched, 0x5a, sizeof(untouched));
        memcpy(expected, untouched, sizeof(expected));
        assert(ios_stub_unix_call_table[i](untouched) == STATUS_NOT_SUPPORTED);
        if (i == IOS_GL_GET_PROC_ADDRESS) continue;
        NTSTATUS status = i < 3 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
        assert(ios_gl_stub_unix_call_table[i](untouched) == status);
        assert(ios_gl_stub_unix_call_wow64_table[i](untouched) == status);
        assert(!memcmp(untouched, expected, sizeof(untouched)));
        /* Lifecycle entrypoints intentionally accept a NULL argument. */
        if (i < 3) {
            assert(ios_gl_stub_unix_call_table[i](NULL) == STATUS_SUCCESS);
            assert(ios_gl_stub_unix_call_wow64_table[i](NULL) == STATUS_SUCCESS);
        }
    }
    for (unsigned int n = 0; n < 256; ++n) {
        check_lookup(ios_gl_stub_unix_call_table[IOS_GL_GET_PROC_ADDRESS], 8, n);
        check_lookup(ios_gl_stub_unix_call_wow64_table[IOS_GL_GET_PROC_ADDRESS], 4, n);
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[8];
    for (unsigned int i = 0; i < 8; ++i) assert(!pthread_create(threads + i, NULL, check_tables, NULL));
    for (unsigned int i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
    puts("PASS: native/WoW64 lookups return unavailable; guards and inputs intact; lifecycle/unsupported slots preserved");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-gl-absent-') as tmp:
    c_file = Path(tmp) / 'gl-absent.c'
    executable = Path(tmp) / 'gl-absent'
    c_file.write_text(harness)
    flags = shlex.split(os.environ.get('CFLAGS', '-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'))
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
        '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
        '-pthread', *flags, str(c_file), '-o', str(executable)
    ], check=True)
    subprocess.run([str(executable)], check=True)
