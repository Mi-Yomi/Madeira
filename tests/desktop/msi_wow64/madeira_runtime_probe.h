/* SPDX-License-Identifier: GPL-3.0-or-later
 * Optional Madeira-only evidence. Include after canary_common.h, only when
 * MADEIRA_I386_DIAGNOSTIC=1. Native Windows rejects private class 1010.
 * No platform inference, persistent success flag or launcher enablement. */
#ifndef MADEIRA_RUNTIME_PROBE_H
#define MADEIRA_RUNTIME_PROBE_H

typedef LONG (WINAPI *madeira_query_process_fn)(HANDLE, ULONG, void *, ULONG, ULONG *);
static madeira_query_process_fn madeira_query_process;
static HANDLE madeira_child;
static DWORD madeira_child_pid;
static ULONG_PTR madeira_child_base;

static UINT madeira_query_base(HANDLE process, ULONG_PTR *base)
{
    ULONG returned = 0;
    LONG status = madeira_query_process(process, 1010, base, sizeof(*base), &returned);
    if (status || returned != sizeof(*base)) {
        probe_log("FAIL guest-base-query", (DWORD)status);
        return ERROR_INSTALL_FAILURE;
    }
    return ERROR_SUCCESS;
}

static UINT madeira_probe_parent(void)
{
    ULONG_PTR base = ~(ULONG_PTR)0;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    /* FARPROC -> exact NT ABI through a union avoids incompatible-function
     * cast diagnostics on MSVC/GNU toolchains. The symbol is never invoked
     * through FARPROC's unrelated prototype. */
    union { FARPROC generic; madeira_query_process_fn query; } symbol;
    symbol.generic = ntdll ? GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;
    madeira_query_process = symbol.query;
    if (!madeira_query_process || madeira_query_base(GetCurrentProcess(), &base) || base) {
        probe_log("FAIL parent-guest-base-zero", 1);
        return ERROR_INSTALL_FAILURE;
    }
    probe_log("PASS parent-guest-base-zero", 0);
    return ERROR_SUCCESS;
}

static UINT madeira_probe_child(DWORD pid)
{
    WCHAR actual[MAX_PATH], expected[MAX_PATH];
    static const WCHAR suffix[] = L"\\msiexec.exe";
    DWORD length = MAX_PATH, directory_length, i;
    ULONG_PTR base = 0;
    if (madeira_child && pid != madeira_child_pid) {
        probe_log("FAIL child-session-changed", pid);
        return ERROR_INSTALL_FAILURE;
    }
    if (!madeira_child) {
        madeira_child = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pid);
        if (!madeira_child) {
            probe_log("FAIL child-open", GetLastError());
            return ERROR_INSTALL_FAILURE;
        }
        madeira_child_pid = pid;
    }
    if (WaitForSingleObject(madeira_child, 0) != WAIT_TIMEOUT) {
        probe_log("FAIL child-not-live", pid);
        return ERROR_INSTALL_FAILURE;
    }
    directory_length = GetSystemWow64DirectoryW(expected, MAX_PATH);
    if (!directory_length || directory_length > MAX_PATH - sizeof(suffix) / sizeof(suffix[0]) ||
        !QueryFullProcessImageNameW(madeira_child, 0, actual, &length) || !length || length >= MAX_PATH) {
        probe_log("FAIL child-image-query", GetLastError());
        return ERROR_INSTALL_FAILURE;
    }
    for (i = 0; i < sizeof(suffix) / sizeof(suffix[0]); ++i) expected[directory_length + i] = suffix[i];
    actual[length] = 0;
    if (lstrcmpiW(actual, expected)) {
        probe_log("FAIL child-image-mismatch", pid);
        return ERROR_INSTALL_FAILURE;
    }
    if (madeira_query_base(madeira_child, &base) || base < ((ULONG_PTR)1 << 32) || (DWORD)base != 0 ||
        base > ~(ULONG_PTR)0 - (((ULONG_PTR)1 << 32) - 1) ||
        (madeira_child_base && madeira_child_base != base)) {
        probe_log("FAIL child-guest-window", pid);
        return ERROR_INSTALL_FAILURE;
    }
    madeira_child_base = base;
    probe_log("PASS child-syswow64-image", pid);
    probe_log("PASS child-guest-base-high", (DWORD)(base >> 32));
    probe_log("PASS child-guest-base-low", (DWORD)base);
    return ERROR_SUCCESS;
}

static UINT madeira_probe_child_exit(void)
{
    UINT result = ERROR_SUCCESS;
    DWORD code = STILL_ACTIVE, waited;
    if (!madeira_child) {
        probe_log("FAIL child-exit-missing-handle", 1);
        return ERROR_INSTALL_FAILURE;
    }
    /* Wine closes its custom-action server on package destruction. Keep our
     * own process handle before close, so PID reuse cannot satisfy this check.
     * A hung MsiCloseHandle is still bounded by the existing 60-second watchdog. */
    waited = WaitForSingleObject(madeira_child, 5000);
    if (waited != WAIT_OBJECT_0 || !GetExitCodeProcess(madeira_child, &code) || code != 0) {
        probe_log("FAIL child-exit", waited == WAIT_OBJECT_0 ? code : waited);
        result = ERROR_INSTALL_FAILURE;
    } else probe_log("PASS child-exit", madeira_child_pid);
    if (!CloseHandle(madeira_child)) {
        probe_log("FAIL child-handle-close", GetLastError());
        result = ERROR_INSTALL_FAILURE;
    }
    madeira_child = NULL;
    return result;
}
#endif
