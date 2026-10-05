/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Real Win32 reference fixture. Only the outer supervisor has a time limit. */
#include "fixture_common.h"
#include <stdarg.h>

#define CASE_WATCHDOG_MS 20000
#define CLEANUP_WATCHDOG_MS 5000
#define RACE_ITERATIONS 64
#define EXCHANGE_ITERATIONS 256

static FILE *case_log;
static struct
{
    HANDLE pipe, process, gate, opened, release;
    BOOL release_on_pending, both_before_wait, release_on_read;
    DWORD serial;
    unsigned pending_connects, early_connects, process_wins, event_wins;
    unsigned both_signaled, cancellation_requests, cancellation_not_found;
    unsigned pending_reads, exchanges, stops, races_success, races_failure;
} state;

static void log_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(case_log, format, args);
    va_end(args);
}

/* These scheduling/observation adapters always call the real Win32 API and
 * return its unchanged result/error. No API outcome or completion is mocked. */
static BOOL observed_connect(HANDLE pipe, LPOVERLAPPED ov)
{
    BOOL result = ConnectNamedPipe(pipe, ov);
    DWORD error = GetLastError();
    if (!result && error == ERROR_IO_PENDING)
    {
        ++state.pending_connects;
        if (state.release_on_pending && !SetEvent(state.gate))
            log_error("failed to release own child: %lu\n", GetLastError());
    }
    if (!result && error == ERROR_PIPE_CONNECTED) ++state.early_connects;
    SetLastError(error);
    return result;
}

static DWORD observed_wait(DWORD count, const HANDLE *handles, BOOL all, DWORD timeout)
{
    DWORD result, error;
    if (state.both_before_wait && count == 2)
    {
        /* Hold only the test thread until our own child has connected and
         * exited. Then make the production wait with both real objects set. */
        if (WaitForSingleObject(handles[0], INFINITE) == WAIT_OBJECT_0 &&
            WaitForSingleObject(handles[1], 0) == WAIT_OBJECT_0)
            ++state.both_signaled;
    }
    result = WaitForMultipleObjects(count, handles, all, timeout);
    error = GetLastError();
    if (result == WAIT_OBJECT_0) ++state.process_wins;
    if (result == WAIT_OBJECT_0 + 1) ++state.event_wins;
    SetLastError(error);
    return result;
}

static BOOL observed_cancel(HANDLE handle, LPOVERLAPPED ov)
{
    BOOL result = CancelIoEx(handle, ov);
    DWORD error = GetLastError();
    ++state.cancellation_requests;
    if (!result && error == ERROR_NOT_FOUND) ++state.cancellation_not_found;
    SetLastError(error);
    return result;
}

static BOOL observed_read(HANDLE handle, LPVOID buffer, DWORD count,
                          LPDWORD size, LPOVERLAPPED ov)
{
    BOOL result = ReadFile(handle, buffer, count, size, ov);
    DWORD error = GetLastError();
    if (!result && error == ERROR_IO_PENDING)
    {
        ++state.pending_reads;
        if (state.release_on_read && !SetEvent(state.release))
            log_error("failed to release own child's reply: %lu\n", GetLastError());
    }
    SetLastError(error);
    return result;
}

#define ERR log_error
#define ConnectNamedPipe observed_connect
#define WaitForMultipleObjects observed_wait
#define CancelIoEx observed_cancel
#define ReadFile observed_read
#include "production_helpers.inc"
#undef ReadFile
#undef CancelIoEx
#undef WaitForMultipleObjects
#undef ConnectNamedPipe
#undef ERR

#define CHECK(condition, description) do { if (!(condition)) { \
    log_error("FAIL: %s (line %d, last error %lu)\n", description, __LINE__, GetLastError()); \
    return FALSE; } } while (0)

static BOOL module_sibling(wchar_t *path, size_t capacity, const wchar_t *name)
{
    wchar_t *slash;
    DWORD length = GetModuleFileNameW(NULL, path, (DWORD)capacity);
    if (!length || length >= capacity) return FALSE;
    slash = wcsrchr(path, L'\\');
    if (!slash || (size_t)(slash - path) + 1 + wcslen(name) >= capacity) return FALSE;
    wcscpy(slash + 1, name);
    return TRUE;
}

static BOOL close_session(void)
{
    BOOL clean = TRUE;
    if (state.process)
    {
        if (WaitForSingleObject(state.process, 0) != WAIT_OBJECT_0)
        {
            log_error("cleanup: terminating only this test's own live child\n");
            clean = FALSE;
            TerminateProcess(state.process, 100);
            WaitForSingleObject(state.process, INFINITE);
        }
        CloseHandle(state.process);
    }
    if (state.pipe && state.pipe != INVALID_HANDLE_VALUE) CloseHandle(state.pipe);
    if (state.gate) CloseHandle(state.gate);
    if (state.opened) CloseHandle(state.opened);
    if (state.release) CloseHandle(state.release);
    state.process = state.pipe = state.gate = state.opened = state.release = NULL;
    state.release_on_pending = state.both_before_wait = state.release_on_read = FALSE;
    return clean;
}

static BOOL create_session(const wchar_t *mode)
{
    wchar_t pipe_name[160], gate_name[160], opened_name[160], release_name[160];
    wchar_t child_path[32768], command[34000];
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD pid = GetCurrentProcessId();
    ++state.serial;
    _snwprintf(pipe_name, 160, L"\\\\.\\pipe\\msi-source-fixture-%lu-%lu", pid, state.serial);
    _snwprintf(gate_name, 160, L"Local\\msi-source-fixture-%lu-%lu-gate", pid, state.serial);
    _snwprintf(opened_name, 160, L"Local\\msi-source-fixture-%lu-%lu-opened", pid, state.serial);
    _snwprintf(release_name, 160, L"Local\\msi-source-fixture-%lu-%lu-release", pid, state.serial);
    state.gate = CreateEventW(NULL, TRUE, FALSE, gate_name);
    state.opened = CreateEventW(NULL, TRUE, FALSE, opened_name);
    state.release = CreateEventW(NULL, FALSE, FALSE, release_name);
    CHECK(state.gate && state.opened && state.release, "create private fixture events");
    state.pipe = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                                  FILE_FLAG_FIRST_PIPE_INSTANCE, 0, 1,
                                  sizeof(DWORD64), sizeof(GUID), 0, NULL);
    CHECK(state.pipe != INVALID_HANDLE_VALUE, "create private overlapped pipe");
    CHECK(module_sibling(child_path, 32768, L"own_child.exe"), "locate own compiled child");
    CHECK(_snwprintf(command, 34000, L"\"%ls\" %ls \"%ls\" \"%ls\" \"%ls\" \"%ls\"",
                      child_path, mode, pipe_name, gate_name, opened_name, release_name) > 0,
          "format own child command");
    startup.cb = sizeof(startup);
    CHECK(CreateProcessW(child_path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &startup, &process), "start own compiled child");
    state.process = process.hProcess;
    CloseHandle(process.hThread);
    return TRUE;
}

static BOOL wait_child_success(void)
{
    DWORD code;
    CHECK(WaitForSingleObject(state.process, INFINITE) == WAIT_OBJECT_0, "wait own child");
    CHECK(GetExitCodeProcess(state.process, &code) && code == 0, "own child exited cleanly");
    return TRUE;
}

static BOOL stop_child(void)
{
    GUID stop = {0};
    DWORD count;
    CHECK(custom_pipe_io(state.pipe, &stop, sizeof(stop), &count, TRUE), "write stop GUID");
    CHECK(count == sizeof(stop), "full stop GUID byte count");
    CHECK(wait_child_success(), "child observed stop and exited");
    ++state.stops;
    return TRUE;
}

static BOOL run_test(unsigned index)
{
    DWORD result, count, error;
    DWORD64 reply;
    unsigned i;
    GUID guid = {0};
    if (index == 0 || index == 1)
    {
        CHECK(create_session(L"exit"), "create early-exit session");
        if (index == 1)
        {
            CHECK(SetEvent(state.gate), "release child before connect");
            CHECK(wait_child_success(), "child already dead before helper");
        }
        else state.release_on_pending = TRUE;
        result = custom_connect_server(state.pipe, state.process);
        CHECK(result == ERROR_FUNCTION_FAILED, "dead child rejects startup even with exit zero");
        CHECK(state.pending_connects == 1 && state.process_wins == 1,
              "real pending connect waited on dead child");
        CHECK(state.cancellation_requests >= 1, "pending startup cancellation requested");
        CHECK(wait_child_success(), "early child exit is clean");
    }
    else if (index == 2 || index == 3 || index == 7)
    {
        CHECK(create_session(L"exchange"), "create exchange session");
        state.release_on_read = TRUE;
        if (index == 2)
        {
            CHECK(SetEvent(state.gate), "release immediate child");
            CHECK(WaitForSingleObject(state.opened, INFINITE) == WAIT_OBJECT_0,
                  "child opened pipe before ConnectNamedPipe");
        }
        else state.release_on_pending = TRUE;
        CHECK(custom_connect_server(state.pipe, state.process) == ERROR_SUCCESS,
              "live child connected successfully");
        CHECK(WaitForSingleObject(state.process, 0) == WAIT_TIMEOUT, "connected child is alive");
        if (index == 2) CHECK(state.early_connects == 1, "real ERROR_PIPE_CONNECTED observed");
        else CHECK(state.pending_connects == 1 && state.event_wins == 1,
                   "real pending connect completed on event");
        for (i = 1; i <= (index == 7 ? EXCHANGE_ITERATIONS : 1); ++i)
        {
            guid.Data1 = i;
            CHECK(custom_pipe_io(state.pipe, &guid, sizeof(guid), &count, TRUE), "write action GUID");
            CHECK(count == sizeof(guid), "full 16-byte action GUID");
            CHECK(custom_pipe_io(state.pipe, &reply, sizeof(reply), &count, FALSE), "read thread-sized reply");
            CHECK(count == sizeof(reply), "full 8-byte DWORD64 thread-handle-size reply");
            CHECK(reply == fixture_reply(&guid), "reply content matches this action GUID");
            ++state.exchanges;
        }
        CHECK(state.pending_reads == state.exchanges, "each eventless reply read really was pending");
        CHECK(stop_child(), "clean GUID_NULL stop");
    }
    else if (index == 4 || index == 5)
    {
        for (i = 0; i < (index == 4 ? 1u : RACE_ITERATIONS); ++i)
        {
            CHECK(create_session(L"connect_exit"), "create connection/death race session");
            state.release_on_pending = TRUE;
            state.both_before_wait = index == 4;
            result = custom_connect_server(state.pipe, state.process);
            /* An uncontrolled race may succeed while the child is still alive.
             * Success is NOT evidence it remains alive after the helper returns. */
            if (result == ERROR_SUCCESS) ++state.races_success;
            else if (result == ERROR_FUNCTION_FAILED) ++state.races_failure;
            else { log_error("unexpected startup race error %lu\n", result); return FALSE; }
            CHECK(wait_child_success(), "racing child really opened and exited");
            if (index == 4)
            {
                CHECK(state.both_signaled == 1 && state.process_wins == 1,
                      "both real objects set; process index won");
                CHECK(result == ERROR_FUNCTION_FAILED, "both-signaled child cannot be accepted");
                CHECK(state.cancellation_not_found == 1,
                      "completed connection produced real cancellation ERROR_NOT_FOUND");
            }
            CHECK(close_session(), "race session had no live child to kill");
        }
    }
    else if (index == 6)
    {
        CHECK(create_session(L"break"), "create broken-pipe session");
        state.release_on_pending = TRUE;
        CHECK(custom_connect_server(state.pipe, state.process) == ERROR_SUCCESS, "connect before break");
        state.release_on_read = TRUE;
        /* Queue a real read first; the observation adapter then permits the
         * client to disconnect. This also exercises an error after full drain. */
        CHECK(!custom_pipe_io(state.pipe, &reply, sizeof(reply), &count, FALSE), "broken read fails");
        error = GetLastError();
        CHECK(error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_NO_DATA,
              "broken read reports pipe error");
        CHECK(count == 0, "broken read supplies zero bytes");
        CHECK(state.pending_reads == 1, "disconnect completed a genuinely pending read");
        CHECK(wait_child_success(), "client pipe closed and child exited");
        state.release_on_read = FALSE;
        CHECK(!custom_pipe_io(state.pipe, &reply, sizeof(reply), &count, FALSE), "already broken read fails");
        CHECK(count == 0, "already broken read supplies zero bytes");
        CHECK(!custom_pipe_io(state.pipe, &guid, sizeof(guid), &count, TRUE), "broken write fails");
        error = GetLastError();
        CHECK(error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_NO_DATA,
              "broken write reports pipe error");
        CHECK(count == 0, "broken write supplies zero bytes");
    }
    else return FALSE;
    return TRUE;
}

static const wchar_t *case_names[] = {
    L"exit-before-open-pending", L"already-dead-child", L"immediate-connect",
    L"event-delayed-connect", L"both-signaled-connect-death", L"connect-death-race-64",
    L"broken-post-connect-pipe", L"guid-thread64-exchange-256-clean-stop"
};

static int case_main(unsigned index, const wchar_t *log_path)
{
    BOOL passed, clean;
    case_log = _wfopen(log_path, L"w");
    if (!case_log || index >= sizeof(case_names) / sizeof(case_names[0])) return 101;
    setvbuf(case_log, NULL, _IONBF, 0);
    fprintf(case_log, "START %ls; real Windows process/pipe APIs\n", case_names[index]);
    passed = run_test(index);
    clean = close_session();
    fprintf(case_log,
        "METRICS {\"pending_connects\":%u,\"early_connects\":%u,\"process_wins\":%u,"
        "\"event_wins\":%u,\"both_signaled\":%u,\"cancellation_requests\":%u,"
        "\"cancellation_not_found\":%u,\"pending_reads\":%u,\"exchanges\":%u,"
        "\"clean_stops\":%u,\"race_success\":%u,\"race_failure\":%u}\n",
        state.pending_connects, state.early_connects, state.process_wins, state.event_wins,
        state.both_signaled, state.cancellation_requests, state.cancellation_not_found,
        state.pending_reads, state.exchanges, state.stops, state.races_success, state.races_failure);
    fprintf(case_log, "%s %ls\n", passed && clean ? "PASS" : "FAIL", case_names[index]);
    fclose(case_log);
    return passed && clean ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t self[32768], command[34000], log_path[256];
    unsigned i, passed = 0, ran = 0;
    const unsigned total = (unsigned)(sizeof(case_names) / sizeof(case_names[0]));
    FILE *report;
    if (argc == 4 && !wcscmp(argv[1], L"--case"))
        return case_main((unsigned)_wtoi(argv[2]), argv[3]);
    if (argc != 1) return 102;
    if (!GetModuleFileNameW(NULL, self, 32768)) return 103;
    report = fopen("windows-results.json", "w");
    if (!report) return 104;
    fprintf(report, "{\n  \"schema\": 1, \"execution\": \"real-windows-api\", "
                    "\"case_watchdog_ms\": %u,\n  \"cases\": [\n", CASE_WATCHDOG_MS);
    for (i = 0; i < total; ++i)
    {
        HANDLE job = NULL;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
        STARTUPINFOW startup = {0};
        PROCESS_INFORMATION process = {0};
        DWORD wait = WAIT_FAILED, code = 105;
        ULONGLONG start = GetTickCount64(), duration;
        BOOL started = FALSE, watchdog = FALSE, setup_ok = FALSE, cleanup_ok = TRUE;
        const char *status = "not_run";
        _snwprintf(log_path, 256, L"case-%02u.log", i + 1);
        _snwprintf(command, 34000, L"\"%ls\" --case %u \"%ls\"", self, i, log_path);
        job = CreateJobObjectW(NULL, NULL);
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        startup.cb = sizeof(startup);
        if (job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) &&
            CreateProcessW(self, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                           NULL, NULL, &startup, &process))
        {
            started = TRUE;
            if (AssignProcessToJobObject(job, process.hProcess) && ResumeThread(process.hThread) != (DWORD)-1)
            {
                setup_ok = TRUE;
                ++ran;
                wait = WaitForSingleObject(process.hProcess, CASE_WATCHDOG_MS);
                watchdog = wait == WAIT_TIMEOUT;
                if (wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &code))
                {
                    status = code == 0 ? "passed" : "failed";
                    if (code == 0) ++passed;
                }
                else status = watchdog ? "watchdog_timeout" : "wait_failed";
            }
        }
        if (started && (!setup_ok || wait != WAIT_OBJECT_0))
        {
            /* These are only handles created by this fixture. Never enumerate
             * PIDs or invoke taskkill. A suspended case is killed before run if
             * job assignment failed; no uncontained child can be spawned. */
            if (setup_ok) TerminateJobObject(job, 106);
            else TerminateProcess(process.hProcess, 107);
            if (WaitForSingleObject(process.hProcess, CLEANUP_WATCHDOG_MS) != WAIT_OBJECT_0)
                cleanup_ok = FALSE;
            GetExitCodeProcess(process.hProcess, &code);
        }
        if (job && setup_ok)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
            ULONGLONG cleanup_start = GetTickCount64();
            for (;;)
            {
                if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                               &accounting, sizeof(accounting), NULL))
                { cleanup_ok = FALSE; break; }
                if (!accounting.ActiveProcesses) break;
                if (GetTickCount64() - cleanup_start >= CLEANUP_WATCHDOG_MS)
                { cleanup_ok = FALSE; break; }
                Sleep(10);
            }
        }
        if (!cleanup_ok)
        {
            if (!strcmp(status, "passed")) --passed;
            status = "cleanup_failed";
        }
        if (process.hThread) CloseHandle(process.hThread);
        if (process.hProcess) CloseHandle(process.hProcess);
        if (job) CloseHandle(job); /* Also reaps any fixture descendant on failure. */
        duration = GetTickCount64() - start;
        fprintf(report, "    {\"name\":\"%ls\",\"status\":\"%s\",\"ran\":%s,"
                        "\"exit_code\":%lu,\"watchdog_fired\":%s,\"cleanup_confirmed\":%s,\"duration_ms\":%llu,"
                        "\"log\":\"%ls\"}%s\n",
                case_names[i], status, setup_ok ? "true" : "false", code,
                watchdog ? "true" : "false", cleanup_ok ? "true" : "false", (unsigned long long)duration,
                log_path, i + 1 == total ? "" : ",");
        fflush(report);
        printf("%s %ls (%llu ms)\n", status, case_names[i], (unsigned long long)duration);
        fflush(stdout);
    }
    fprintf(report, "  ],\n  \"planned\":%u,\"ran\":%u,\"passed\":%u,\"failed_or_not_run\":%u\n}\n",
            total, ran, passed, total - passed);
    fclose(report);
    return passed == total && ran == total ? 0 : 1;
}
