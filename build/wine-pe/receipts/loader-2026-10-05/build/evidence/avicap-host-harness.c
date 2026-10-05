
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
#define CAP_DESC_MAX 32

struct get_device_desc_params
{
    WORD index;
    WCHAR name[CAP_DESC_MAX];
    WCHAR version[CAP_DESC_MAX];
};

enum unix_funcs
{
    unix_get_device_desc,
};

static NTSTATUS ios_stub_unix_call(void *args) {
    return STATUS_NOT_SUPPORTED;
}
static NTSTATUS ios_bind_unixlib_table( void *module, const char *libname, BOOL wow,
                                        const void *funcs64, const void *funcs_wow64,
                                        const void **funcs )
{
    const void *table = wow ? funcs_wow64 : funcs64;

    if (!table)
    {
        /* MADEIRA 2026-09-15: dprintf, not ERR.  This file's debug channel is
         * `virtual`, and the app runs with WINEDEBUG=err+all,err-virtual
         * (WineProcessBridge.m:505) — so every refusal logged here has been
         * INVISIBLE, which is why log n60 shows dnsapi's DllMain complaining
         * and no [unixlib] line for it at all.  A library losing its unix side
         * is the first half of every NULL-handle crash and has to be loud. */
        dprintf( 2, "[unixlib] %s (module %p) has no unix side on this port: no %s unix call "
                 "table — failing the load rather than binding the %s table to a %s caller\n",
                 libname, module, wow ? "wow64" : "64-bit", wow ? "64-bit" : "wow64",
                 wow ? "32-bit" : "64-bit" );
        return STATUS_NOT_SUPPORTED;
    }
    dprintf( 2, "[unixlib] %s (module %p) -> %s table (%p)\n",
             libname, module, wow ? "wow64" : "64-bit", table );
    *funcs = table;
    return STATUS_SUCCESS;
}
static NTSTATUS call(unsigned code, void *arg) {
    struct get_device_desc_params *p = arg;
    assert(code == unix_get_device_desc);
    last_index = p->index; calls++;
    return injected_status == STATUS_NOT_SUPPORTED ? ios_stub_unix_call(arg) : injected_status;
}
#define WINE_UNIX_CALL(code,args) call(code,args)
BOOL VFWAPI capGetDriverDescriptionW(WORD index, WCHAR *name, int name_len, WCHAR *version, int version_len)
{
    struct get_device_desc_params params;

    params.index = index;
    if (WINE_UNIX_CALL(unix_get_device_desc, &params)) return FALSE;

    TRACE("Found device name %s, version %s.\n", debugstr_w(params.name), debugstr_w(params.version));
    lstrcpynW(name, params.name, name_len);
    lstrcpynW(version, params.version, version_len);
    return TRUE;
}
BOOL VFWAPI capGetDriverDescriptionA(WORD wDriverIndex, LPSTR lpszName,
                                     INT cbName, LPSTR lpszVer, INT cbVer)
{
   BOOL retval;
   WCHAR devname[CAP_DESC_MAX], devver[CAP_DESC_MAX];
   TRACE("--> capGetDriverDescriptionW\n");
   retval = capGetDriverDescriptionW(wDriverIndex, devname, CAP_DESC_MAX, devver, CAP_DESC_MAX);
   if (retval) {
      WideCharToMultiByte(CP_ACP, 0, devname, -1, lpszName, cbName, NULL, NULL);
      WideCharToMultiByte(CP_ACP, 0, devver, -1, lpszVer, cbVer, NULL, NULL);
   }
   return retval;
}
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
