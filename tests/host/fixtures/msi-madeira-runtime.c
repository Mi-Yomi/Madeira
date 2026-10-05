/* SPDX-License-Identifier: GPL-3.0-or-later
 * Source-owned host test of the real helper using controlled Windows API
 * results. No emulator, Wine code, installer or Windows guest executes. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

#define WINAPI
typedef int32_t LONG;
typedef uint32_t ULONG, DWORD, UINT;
typedef uintptr_t ULONG_PTR;
typedef wchar_t WCHAR;
typedef void *HANDLE, *HMODULE;
typedef intptr_t (*FARPROC)(void);
#define MAX_PATH 260
#define FALSE 0
#define PROCESS_QUERY_INFORMATION 0x400
#define SYNCHRONIZE 0x100000
#define ERROR_SUCCESS 0
#define ERROR_INSTALL_FAILURE 1603
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define STILL_ACTIVE 259

static int missing_module, missing_query, open_fails, name_fails, path_wrong;
static int length_wrong, close_fails, exit_query_fails;
static ULONG returned_length;
static LONG query_status;
static ULONG_PTR parent_base, child_base;
static DWORD live_wait, exit_wait, exit_code, last_error;
static DWORD seen_rights, seen_pid, opens, closes, logged_passes, logged_failures;
static HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)1; }
static HMODULE GetModuleHandleW(const WCHAR *name) { assert(!wcscmp(name,L"ntdll.dll")); return missing_module ? NULL : (HMODULE)(uintptr_t)2; }
static DWORD GetLastError(void) { return last_error; }
static HANDLE OpenProcess(DWORD rights, int inherit, DWORD pid) {
    assert(!inherit); seen_rights=rights; seen_pid=pid; ++opens;
    return open_fails ? NULL : (HANDLE)(uintptr_t)3;
}
static LONG fake_query(HANDLE process, ULONG cls, void *out, ULONG size, ULONG *returned) {
    assert(cls == 1010 && size == 8);
    *(ULONG_PTR *)out = process == GetCurrentProcess() ? parent_base : child_base;
    *returned=returned_length; return query_status;
}
static FARPROC GetProcAddress(HMODULE module, const char *name) {
    union { FARPROC generic; LONG (*query)(HANDLE,ULONG,void*,ULONG,ULONG*); } symbol;
    (void)name; assert(module); symbol.query=fake_query;
    return missing_query ? NULL : symbol.generic;
}
static DWORD WaitForSingleObject(HANDLE process, DWORD delay) {
    assert(process == (HANDLE)(uintptr_t)3 && (delay == 0 || delay == 5000));
    return delay ? exit_wait : live_wait;
}
static DWORD GetSystemWow64DirectoryW(WCHAR *out, DWORD length) {
    assert(length == MAX_PATH); wcscpy(out,L"C:\\windows\\syswow64");
    return length_wrong ? MAX_PATH : (DWORD)wcslen(out);
}
static int QueryFullProcessImageNameW(HANDLE process,DWORD flags,WCHAR *out,DWORD *length) {
    assert(process && !flags && *length == MAX_PATH);
    wcscpy(out,path_wrong ? L"C:\\windows\\system32\\msiexec.exe" : L"C:\\windows\\syswow64\\msiexec.exe");
    *length=(DWORD)wcslen(out); return !name_fails;
}
static int lstrcmpiW(const WCHAR *a,const WCHAR *b) { return wcscmp(a,b); }
static int GetExitCodeProcess(HANDLE process, DWORD *code) { assert(process); *code=exit_code; return !exit_query_fails; }
static int CloseHandle(HANDLE process) { assert(process); ++closes; return !close_fails; }
static void probe_log(const char *stage,DWORD code) {
    (void)code; if (stage[0] == 'P') ++logged_passes; else ++logged_failures;
}
#include "madeira_runtime_probe.h"

static void reset(void) {
    missing_module=missing_query=open_fails=name_fails=path_wrong=length_wrong=close_fails=exit_query_fails=0;
    returned_length=8; query_status=0; parent_base=0; child_base=(ULONG_PTR)10<<32;
    live_wait=WAIT_TIMEOUT; exit_wait=WAIT_OBJECT_0; exit_code=0; last_error=5;
    seen_rights=seen_pid=opens=closes=logged_passes=logged_failures=0;
    madeira_query_process=NULL; madeira_child=NULL; madeira_child_pid=0; madeira_child_base=0;
}

int main(void) {
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); assert(!madeira_probe_child(202));
    assert(opens == 1 && seen_pid == 202 && seen_rights == (PROCESS_QUERY_INFORMATION|SYNCHRONIZE));
    assert(!madeira_probe_child_exit()); assert(closes == 1 && !madeira_child && !logged_failures && logged_passes == 8);
    reset(); missing_module=1; assert(madeira_probe_parent());
    reset(); missing_query=1; assert(madeira_probe_parent());
    reset(); parent_base=0x100000000; assert(madeira_probe_parent());
    reset(); query_status=-1; assert(madeira_probe_parent());
    reset(); returned_length=4; assert(madeira_probe_parent());
    reset(); assert(!madeira_probe_parent()); open_fails=1; assert(madeira_probe_child(202)); assert(!madeira_child);
    reset(); assert(!madeira_probe_parent()); live_wait=WAIT_OBJECT_0; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); live_wait=0xffffffff; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); length_wrong=1; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); name_fails=1; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); path_wrong=1; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); child_base=0; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); child_base=0xffffffff; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); child_base=0xa00000001; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); child_base=UINTPTR_MAX; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); child_base += (ULONG_PTR)1 << 32; assert(madeira_probe_child(202));
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); assert(madeira_probe_child(303)); assert(opens == 1);
    reset(); assert(!madeira_probe_parent()); assert(madeira_probe_child_exit());
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); exit_wait=WAIT_TIMEOUT; assert(madeira_probe_child_exit()); assert(closes == 1);
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); exit_code=STILL_ACTIVE; assert(madeira_probe_child_exit());
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); exit_code=1; assert(madeira_probe_child_exit());
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); exit_query_fails=1; assert(madeira_probe_child_exit());
    reset(); assert(!madeira_probe_parent()); assert(!madeira_probe_child(202)); close_fails=1; assert(madeira_probe_child_exit());
    return 0;
}
