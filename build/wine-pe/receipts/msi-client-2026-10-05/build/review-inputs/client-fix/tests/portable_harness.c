/* LGPL-2.1-or-later. Host fault-injection tests for extracted Wine MSI functions. */
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>

typedef uint32_t DWORD, UINT;
typedef uint64_t DWORD64;
typedef uintptr_t DWORD_PTR;
typedef int32_t HRESULT;
typedef int BOOL, INT, CRITICAL_SECTION;
typedef void *HANDLE;
typedef uint16_t *LPWSTR;
typedef struct { uint32_t word[4]; } GUID;
#define WINAPI
#define FALSE 0
#define TRUE 1
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_OUTOFMEMORY ((HRESULT)0x8007000e)
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106)
#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
#define FAILED(hr) ((HRESULT)(hr) < 0)
#define COINIT_MULTITHREADED 0
#define SCS_32BIT_BINARY 0
#define SCS_64BIT_BINARY 6
#define ERROR_SUCCESS 0
#define ERROR_FUNCTION_FAILED 1627
#define ERROR_FUNCTION_NOT_CALLED 1626
#define ERROR_INSTALL_FAILURE 1603
#define ERROR_INSTALL_USEREXIT 1602
#define ERROR_INSTALL_SUSPEND 1604
#define ERROR_NO_MORE_ITEMS 259
#define ERROR_ACCESS_DENIED 5
#define ERROR_BROKEN_PIPE 109
#define ERROR_INVALID_HANDLE 6
#define WAIT_OBJECT_0 0
#define WAIT_FAILED UINT32_MAX
#define WAIT_TIMEOUT 258
#define WAIT_ABANDONED 128
#define INFINITE UINT32_MAX
#define DUPLICATE_SAME_ACCESS 2
#define DUPLICATE_CLOSE_SOURCE 1
#define msidbCustomActionTypeContinue 0x40
#define msidbCustomActionTypeAsync 0x80
#define H(n) ((HANDLE)(uintptr_t)(n))

typedef struct {
    HANDLE custom_server_32_process, custom_server_64_process;
    HANDLE custom_server_32_pipe, custom_server_64_pipe;
} MSIPACKAGE;
typedef struct {
    MSIPACKAGE *package;
    HANDLE handle;
    LPWSTR action;
    INT type;
    GUID guid;
    DWORD arch;
} custom_action_info;
static CRITICAL_SECTION custom_action_cs;

struct scenario {
    const char *name;
    HRESULT hr;
    int write_mode, read_mode, duplicate_fail, query_fail;
    DWORD write_error, read_error, duplicate_error, wait_result, wait_error, query_error;
    DWORD action_result, initial_error, err_clobber, leave_clobber, close_clobber, com_clobber;
    DWORD expected;
    int short_write_count, short_read_count;
};
static struct scenario s;
static struct {
    DWORD last_error, outer_result;
    int init, uninit, lock_depth, enters, leaves, write, read, duplicate, wait, query, close;
    int bad_api, dialogs, freed, reboot, outer_queries;
    DWORD arch;
    custom_action_info *info;
} seen;
static int failures, total;

static DWORD GetLastError(void) { return seen.last_error; }
static HRESULT CoInitializeEx(void *unused, DWORD mode) {
    seen.init++;
    if (unused || mode != COINIT_MULTITHREADED) seen.bad_api++;
    return s.hr;
}
static void CoUninitialize(void) {
    seen.uninit++;
    if (seen.lock_depth || (seen.duplicate && !s.duplicate_fail && seen.close != 1)) seen.bad_api++;
    seen.last_error = s.com_clobber;
}
static void EnterCriticalSection(CRITICAL_SECTION *cs) {
    seen.enters++;
    if (cs != &custom_action_cs || seen.lock_depth++) seen.bad_api++;
}
static void LeaveCriticalSection(CRITICAL_SECTION *cs) {
    seen.leaves++;
    if (cs != &custom_action_cs || --seen.lock_depth) seen.bad_api++;
    seen.last_error = s.leave_clobber;
}
static void log_error(const char *fmt, ...) { seen.last_error = s.err_clobber; }
#define ERR(...) log_error(__VA_ARGS__)
#define TRACE(...) ((void)0)
#define debugstr_w(x) (x)
static HANDLE GetCurrentProcess(void) { return H(100); }
static HANDLE expected_pipe(void) { return seen.arch == SCS_32BIT_BINARY ? H(32) : H(64); }
static HANDLE expected_process(void) { return seen.arch == SCS_32BIT_BINARY ? H(132) : H(164); }
static BOOL WriteFile(HANDLE pipe, const void *data, DWORD count, DWORD *size, void *overlapped) {
    seen.write++;
    if (pipe != expected_pipe() || data != &seen.info->guid || count != sizeof(GUID) || overlapped || seen.lock_depth != 1) seen.bad_api++;
    *size = 0;
    if (s.write_mode == 1) { seen.last_error = s.write_error; return FALSE; }
    *size = s.write_mode == 2 ? (DWORD)s.short_write_count : count;
    return TRUE;
}
static BOOL ReadFile(HANDLE pipe, void *data, DWORD count, DWORD *size, void *overlapped) {
    DWORD64 value = 0x1234;
    seen.read++;
    if (pipe != expected_pipe() || count != sizeof(DWORD64) || overlapped || seen.lock_depth != 1) seen.bad_api++;
    *size = 0;
    if (s.read_mode == 1) { seen.last_error = s.read_error; return FALSE; }
    *size = s.read_mode == 2 ? (DWORD)s.short_read_count : count;
    memcpy(data, &value, *size);
    return TRUE;
}
static BOOL DuplicateHandle(HANDLE src, HANDLE handle, HANDLE dest, HANDLE *output, DWORD access, BOOL inherit, DWORD options) {
    seen.duplicate++;
    if (src != expected_process() || handle != H(0x1234) || dest != H(100) || access || inherit || options != (DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE) || seen.lock_depth) seen.bad_api++;
    if (s.duplicate_fail) { seen.last_error = s.duplicate_error; return FALSE; }
    *output = H(200);
    return TRUE;
}
static DWORD WaitForSingleObject(HANDLE thread, DWORD timeout) {
    seen.wait++;
    if (thread != H(200) || timeout != INFINITE || seen.lock_depth) seen.bad_api++;
    if (s.wait_result == WAIT_FAILED) seen.last_error = s.wait_error;
    return s.wait_result;
}
static BOOL GetExitCodeThread(HANDLE thread, DWORD *result) {
    if (thread == H(201)) { seen.outer_queries++; *result = seen.outer_result; return TRUE; }
    seen.query++;
    if (thread != H(200) || seen.lock_depth) seen.bad_api++;
    if (s.query_fail) { seen.last_error = s.query_error; return FALSE; }
    *result = s.action_result;
    return TRUE;
}
static BOOL CloseHandle(HANDLE thread) {
    seen.close++;
    if (thread != H(200) || seen.lock_depth) seen.bad_api++;
    seen.last_error = s.close_clobber;
    return TRUE;
}
static void ACTION_ForceReboot(MSIPACKAGE *package) { seen.reboot++; }
static void free_custom_action_data(custom_action_info *info) { seen.freed++; }
static DWORD WINAPI custom_client_thread(void *arg);
static void msi_dialog_check_messages(HANDLE thread) {
    seen.dialogs++;
    if (thread != H(201)) seen.bad_api++;
    seen.outer_result = custom_client_thread(seen.info);
}
#include "production.inc"

#define CHECK(cond, text) do { if (!(cond)) { printf("  %s\n", text); bad++; } } while (0)
static void reset(custom_action_info *info, DWORD arch) {
    memset(&seen, 0, sizeof(seen));
    seen.last_error = s.initial_error;
    seen.arch = arch;
    seen.info = info;
    info->arch = arch;
}
static void run_case(custom_action_info *info, DWORD arch) {
    int bad = 0;
    reset(info, arch);
    DWORD rc = custom_client_thread(info);
    if (rc != s.expected) { printf("  result expected=%" PRIu32 " actual=%" PRIu32 "\n", s.expected, rc); bad++; }
    CHECK(seen.init == 1, "CoInitializeEx called once");
    CHECK(seen.uninit == (SUCCEEDED(s.hr) ? 1 : 0), "COM initialization must be balanced only on success/S_FALSE");
    CHECK(seen.lock_depth == 0 && seen.enters == seen.leaves, "critical section balanced");
    CHECK(!seen.bad_api, "API arguments, handle ownership, architecture, or lock boundaries changed");
    if (FAILED(s.hr)) {
        CHECK(!seen.enters && !seen.write && !seen.read && !seen.duplicate && !seen.wait && !seen.query && !seen.close, "failed COM initialization must not start IPC");
    } else if (s.write_mode) {
        CHECK(seen.write == 1 && !seen.read && !seen.duplicate && !seen.wait && !seen.query && !seen.close, "failed/short write must stop before read");
    } else if (s.read_mode) {
        CHECK(seen.write == 1 && seen.read == 1 && !seen.duplicate && !seen.wait && !seen.query && !seen.close, "failed/short read must stop before handle use");
    } else if (s.duplicate_fail) {
        CHECK(seen.duplicate == 1 && !seen.wait && !seen.query && !seen.close, "failed duplicate must not use/close an unowned thread");
    } else {
        CHECK(seen.duplicate == 1 && seen.wait == 1 && seen.close == 1, "owned thread must be waited and closed exactly once");
        CHECK(seen.query == (s.wait_result == WAIT_OBJECT_0), "exit status queried only after a completed wait");
    }
    total++;
    failures += !!bad;
    printf("%s arch=%u %s\n", s.name, arch == SCS_32BIT_BINARY ? 32 : 64, bad ? "FAIL" : "PASS");
}
static void run_policy(custom_action_info *info, DWORD arch, int type, DWORD expected) {
    int bad = 0;
    reset(info, arch);
    info->type = type;
    DWORD rc = wait_thread_handle(info);
    CHECK(rc == expected, "outer Continue/Async MSI result");
    CHECK(seen.dialogs == !(type & msidbCustomActionTypeAsync), "outer async wait policy");
    CHECK(seen.freed == !(type & msidbCustomActionTypeAsync), "outer action ownership policy");
    CHECK(seen.outer_queries == (!(type & (msidbCustomActionTypeAsync | msidbCustomActionTypeContinue))), "outer Continue status-query policy");
    CHECK(seen.reboot == (!(type & (msidbCustomActionTypeAsync | msidbCustomActionTypeContinue)) && s.action_result == ERROR_INSTALL_SUSPEND), "outer reboot mapping policy");
    if (!(type & msidbCustomActionTypeAsync)) CHECK(seen.uninit == 1, "synchronous policy retains balanced COM");
    total++;
    failures += !!bad;
    printf("policy-%s-type=%d arch=%u %s\n", s.name, type, arch == SCS_32BIT_BINARY ? 32 : 64, bad ? "FAIL" : "PASS");
}

int main(void) {
    MSIPACKAGE package = { H(132), H(164), H(32), H(64) };
    custom_action_info info = { .package = &package, .handle = H(201) };
    const struct scenario cases[] = {
        { .name="success", .expected=ERROR_SUCCESS },
        { .name="success-S_FALSE", .hr=S_FALSE, .expected=ERROR_SUCCESS },
        { .name="action-failure", .action_result=ERROR_INSTALL_FAILURE, .expected=ERROR_INSTALL_FAILURE },
        { .name="action-cancel", .action_result=ERROR_INSTALL_USEREXIT, .expected=ERROR_INSTALL_USEREXIT },
        { .name="action-arbitrary", .action_result=0x12345678, .expected=0x12345678 },
        { .name="action-no-more-items", .action_result=ERROR_NO_MORE_ITEMS, .expected=ERROR_NO_MORE_ITEMS },
        { .name="action-suspend", .action_result=ERROR_INSTALL_SUSPEND, .expected=ERROR_INSTALL_SUSPEND },
        { .name="COM-out-of-memory", .hr=E_OUTOFMEMORY, .expected=ERROR_FUNCTION_FAILED },
        { .name="COM-changed-mode", .hr=RPC_E_CHANGED_MODE, .expected=ERROR_FUNCTION_FAILED },
        { .name="write-broken-pipe-clobber-zero", .write_mode=1, .write_error=ERROR_BROKEN_PIPE, .expected=ERROR_BROKEN_PIPE },
        { .name="write-denied-clobber-other", .write_mode=1, .write_error=ERROR_ACCESS_DENIED, .err_clobber=87, .leave_clobber=123, .com_clobber=4321, .expected=ERROR_ACCESS_DENIED },
        { .name="write-false-zero-error", .write_mode=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="write-zero-count-zero-error", .write_mode=2, .expected=ERROR_FUNCTION_FAILED },
        { .name="write-short-stale-error", .write_mode=2, .short_write_count=15, .initial_error=7654, .expected=ERROR_FUNCTION_FAILED },
        { .name="write-short-S_FALSE", .hr=S_FALSE, .write_mode=2, .short_write_count=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="read-broken-pipe-clobber-zero", .read_mode=1, .read_error=ERROR_BROKEN_PIPE, .expected=ERROR_BROKEN_PIPE },
        { .name="read-denied-clobber-other", .read_mode=1, .read_error=ERROR_ACCESS_DENIED, .err_clobber=87, .leave_clobber=123, .com_clobber=4321, .expected=ERROR_ACCESS_DENIED },
        { .name="read-false-zero-error", .read_mode=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="read-zero-count-zero-error", .read_mode=2, .expected=ERROR_FUNCTION_FAILED },
        { .name="read-short-stale-error", .read_mode=2, .short_read_count=7, .initial_error=7654, .expected=ERROR_FUNCTION_FAILED },
        { .name="read-short-S_FALSE", .hr=S_FALSE, .read_mode=2, .short_read_count=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="duplicate-error-clobber", .duplicate_fail=1, .duplicate_error=ERROR_INVALID_HANDLE, .com_clobber=4321, .expected=ERROR_INVALID_HANDLE },
        { .name="duplicate-zero-error", .duplicate_fail=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="wait-failed-error-clobber", .wait_result=WAIT_FAILED, .wait_error=ERROR_INVALID_HANDLE, .close_clobber=4321, .com_clobber=7654, .expected=ERROR_INVALID_HANDLE },
        { .name="wait-failed-zero-error", .wait_result=WAIT_FAILED, .expected=ERROR_FUNCTION_FAILED },
        { .name="wait-unexpected-timeout-stale-error", .wait_result=WAIT_TIMEOUT, .initial_error=ERROR_ACCESS_DENIED, .expected=ERROR_FUNCTION_FAILED },
        { .name="wait-unexpected-abandoned", .wait_result=WAIT_ABANDONED, .expected=ERROR_FUNCTION_FAILED },
        { .name="query-failed-error-clobber", .query_fail=1, .query_error=ERROR_INVALID_HANDLE, .close_clobber=4321, .com_clobber=7654, .expected=ERROR_INVALID_HANDLE },
        { .name="query-failed-zero-error", .query_fail=1, .expected=ERROR_FUNCTION_FAILED },
        { .name="success-cleanup-clobber", .initial_error=ERROR_BROKEN_PIPE, .leave_clobber=123, .close_clobber=456, .com_clobber=789, .expected=ERROR_SUCCESS },
        { .name="failure-cleanup-clobber", .action_result=ERROR_INSTALL_FAILURE, .leave_clobber=123, .close_clobber=456, .com_clobber=789, .expected=ERROR_INSTALL_FAILURE }
    };
    for (unsigned arch_index = 0; arch_index < 2; arch_index++) {
        DWORD arch = arch_index ? SCS_64BIT_BINARY : SCS_32BIT_BINARY;
        for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) { s = cases[i]; run_case(&info, arch); }
        for (unsigned mode = 0; mode < 4; mode++) {
            int type = (mode & 1 ? msidbCustomActionTypeContinue : 0) | (mode & 2 ? msidbCustomActionTypeAsync : 0);
            s = (struct scenario){ .name="write-failure", .write_mode=1, .write_error=ERROR_BROKEN_PIPE };
            run_policy(&info, arch, type, type ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE);
            s = (struct scenario){ .name="action-success" };
            run_policy(&info, arch, type, ERROR_SUCCESS);
            s = (struct scenario){ .name="action-cancel", .action_result=ERROR_INSTALL_USEREXIT };
            run_policy(&info, arch, type, type ? ERROR_SUCCESS : ERROR_INSTALL_USEREXIT);
            s = (struct scenario){ .name="action-no-more-items", .action_result=ERROR_NO_MORE_ITEMS };
            run_policy(&info, arch, type, ERROR_SUCCESS);
            s = (struct scenario){ .name="action-suspend", .action_result=ERROR_INSTALL_SUSPEND };
            run_policy(&info, arch, type, ERROR_SUCCESS);
        }
    }
    printf("RESULT: %d/%d passed; %d failed\n", total-failures, total, failures);
    return failures ? 1 : 0;
}
