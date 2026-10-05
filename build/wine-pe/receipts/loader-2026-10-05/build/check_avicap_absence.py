#!/usr/bin/env python3
"""Host-only tests of extracted pristine AVICAP absence handling. No guest runs."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
av = (ROOT/'wine/dlls/avicap32/avicap32_main.c').read_text()
unix = (ROOT/'wine/dlls/avicap32/unixlib.h').read_text()
virtual = (ROOT/'reference-inputs/virtual_ios.c').read_text()
signal = (ROOT/'reference-inputs/signal_arm64_ios.c').read_text()

def function(source, signature):
    start = source.index(signature)
    pos = source.index('{', start)
    depth = 1
    end = pos + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

bind = function(virtual, 'static NTSTATUS ios_bind_unixlib_table(')
stub = function(virtual, 'static NTSTATUS ios_stub_unix_call(')
w = function(av, 'BOOL VFWAPI capGetDriverDescriptionW(')
a = function(av, 'BOOL VFWAPI capGetDriverDescriptionA(')
start = unix.index('#define CAP_DESC_MAX')
layout = unix[start:]
chain = function(virtual, 'static NTSTATUS load_builtin_unixlib(')
assert 'avicap' not in chain
assert 'funcs64 = (const void *)ios_stub_unix_call_table;' in chain
initialization = function(virtual, 'static void ios_init_stub_tables(')
assert 'ios_stub_unix_call_table[i] = ios_gl_stub_unix_call_table[i] =' in initialization
assert 'ios_gl_stub_unix_call_wow64_table[i] = ios_stub_unix_call;' in initialization
# The failure branch must precede any table dereference. This is a source-order
# check of ARM64 assembly, not an executed architecture/ABI test.
dispatcher = signal[signal.index('__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,'):]
assert dispatcher.index('"cbz x0, ') < dispatcher.index('"ldr x16, [x0, x1, lsl 3]')
assert '"bl " __ASM_NAME("ios_unixlib_null_call")' in dispatcher
null = function(signal, 'NTSTATUS __attribute__((used)) ios_unixlib_null_call(')
assert 'return STATUS_NOT_IMPLEMENTED;' in null

harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t WORD, WCHAR;
typedef int32_t NTSTATUS;
typedef int BOOL, INT;
typedef char *LPSTR;
#define VFWAPI
#define FALSE 0
#define TRUE 1
#define CP_ACP 0
#define STATUS_SUCCESS 0
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xc0000002)
#define STATUS_DLL_NOT_FOUND ((NTSTATUS)0xc0000135)
#define TRACE(...) ((void)0)
static int copies, conversions, calls;
static NTSTATUS injected_status;
static WORD last_index;
static WCHAR *lstrcpynW(WCHAR *a, const WCHAR *b, int n) {
    (void)b; (void)n; copies++; return a;
}
static int WideCharToMultiByte(unsigned cp, unsigned flags, const WCHAR *src,
  int src_len, char *dest, int len, const char *default_char, int *used) {
    (void)cp;(void)flags;(void)src;(void)src_len;(void)dest;(void)len;
    (void)default_char;(void)used;conversions++;return 0;
}
''' + layout + '\n' + stub + '\n' + bind + r'''
static NTSTATUS call(unsigned code, void *arg) {
    struct get_device_desc_params *p = arg;
    assert(code == unix_get_device_desc);
    last_index = p->index; calls++;
    return injected_status == STATUS_NOT_SUPPORTED ? ios_stub_unix_call(arg) : injected_status;
}
#define WINE_UNIX_CALL(code,args) call(code,args)
''' + w + '\n' + a + r'''
int main(void) {
    const NTSTATUS errors[] = {STATUS_NOT_SUPPORTED, STATUS_NOT_IMPLEMENTED, STATUS_DLL_NOT_FOUND};
    const WORD indices[] = {0, 1, 9, 65535};
    WCHAR name[32], version[32], before[32];
    char aname[32], aversion[32], abefore[32];
    const void *table = NULL;
    const void *sentinel = (void *)(uintptr_t)0x1000;
    assert(ios_bind_unixlib_table(NULL,"avicap32.dll",0,sentinel,NULL,&table)==STATUS_SUCCESS);
    assert(table == sentinel);
    table = NULL;
    assert(ios_bind_unixlib_table(NULL,"avicap32.dll",0,NULL,NULL,&table)==STATUS_NOT_SUPPORTED);
    assert(table == NULL);
    memset(before,0xa5,sizeof before);memset(abefore,0x5a,sizeof abefore);
    for(unsigned e=0;e<sizeof errors/sizeof errors[0];e++)
      for(unsigned i=0;i<sizeof indices/sizeof indices[0];i++) {
        injected_status=errors[e];
        memcpy(name,before,sizeof name);memcpy(version,before,sizeof version);
        memcpy(aname,abefore,sizeof aname);memcpy(aversion,abefore,sizeof aversion);
        assert(capGetDriverDescriptionW(indices[i],name,32,version,32)==FALSE);
        assert(last_index==indices[i]);
        assert(!memcmp(name,before,sizeof name)&&!memcmp(version,before,sizeof version));
        assert(capGetDriverDescriptionA(indices[i],aname,32,aversion,32)==FALSE);
        assert(last_index==indices[i]);
        assert(!memcmp(aname,abefore,sizeof aname)&&!memcmp(aversion,abefore,sizeof aversion));
      }
    assert(calls==24 && copies==0 && conversions==0);
    puts("PASS: 24 A/W unavailable-backend calls return FALSE, leave output buffers unchanged, and never copy uninitialized device fields");
    return 0;
}
'''
c = ROOT/'evidence/avicap-host-harness.c'
exe = ROOT/'evidence/avicap-host-harness'
c.write_text(harness)
subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Wno-unused-parameter',
                '-fsanitize=address,undefined','-g',str(c),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True)
print('PASS: production generic table initializes with failure; production ARM64 zero-handle guard precedes table dereference (static source check)')
