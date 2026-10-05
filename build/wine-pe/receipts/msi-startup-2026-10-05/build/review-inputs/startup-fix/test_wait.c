#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { uintptr_t Internal, InternalHigh; DWORD Offset, OffsetHigh; HANDLE hEvent; } OVERLAPPED;
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_BROKEN_PIPE 109u
#define ERROR_PIPE_CONNECTED 535u
#define ERROR_OPERATION_ABORTED 995u
#define ERROR_IO_INCOMPLETE 996u
#define ERROR_IO_PENDING 997u
#define ERROR_NOT_FOUND 1168u
#define ERROR_FUNCTION_FAILED 1627u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
#define INFINITE 0xffffffffu
#define STATUS_PENDING 0x103u
#define ERR(...) ((void)0)

static const HANDLE pipe_handle = (HANDLE)(uintptr_t)1;
static const HANDLE process_handle = (HANDLE)(uintptr_t)2;
static const HANDLE event_handle = (HANDLE)(uintptr_t)3;
enum issue_kind { IMMEDIATE_SUCCESS, ALREADY_CONNECTED, PENDING, ISSUE_ERROR };
static struct {
    enum issue_kind issue;
    BOOL event_failure, result_success, cancel_success;
    DWORD issue_error, event_error, result_error, cancel_error;
    DWORD multi_wait, multi_error, single_wait, single_error, result_size;
    DWORD last_error;
    OVERLAPPED *active;
    BOOL pending, canceled, terminal;
    unsigned issued, waits, single_waits, cancels, results, probes, sleeps, closes, reads, writes;
    BOOL result_wait_failure, result_true_pending;
    DWORD result_wait_error;
    unsigned pending_probes;
} s;

static DWORD GetLastError(void) { return s.last_error; }
static void SetLastError(DWORD error) { s.last_error = error; }
static void Sleep(DWORD ms)
{
    assert(ms == 1 && s.pending && !s.closes);
    assert(++s.sleeps < 20); /* Harness bound only; production has no deadline. */
}
static HANDLE CreateEventW(void *attrs, BOOL manual, BOOL initial, const void *name)
{
    assert(!attrs && manual && !initial && !name);
    if (s.event_failure) { s.last_error = s.event_error; return NULL; }
    return event_handle;
}
static BOOL ConnectNamedPipe(HANDLE pipe, OVERLAPPED *ov)
{
    assert(pipe == pipe_handle && ov && ov->hEvent == event_handle);
    assert(!ov->Internal && !ov->InternalHigh && !ov->Offset && !ov->OffsetHigh);
    s.issued++;
    s.active = ov;
    ov->Internal = STATUS_PENDING; /* Real Wine sets this before synchronous failure too. */
    if (s.issue == IMMEDIATE_SUCCESS) { s.terminal = TRUE; return TRUE; }
    if (s.issue == ALREADY_CONNECTED) { s.last_error = ERROR_PIPE_CONNECTED; return FALSE; }
    if (s.issue == ISSUE_ERROR) { s.last_error = s.issue_error; return FALSE; }
    s.pending = TRUE;
    ov->Internal = STATUS_PENDING;
    s.last_error = ERROR_IO_PENDING;
    return FALSE;
}
static DWORD WaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL all, DWORD timeout)
{
    assert(count == 2 && handles[0] == process_handle && handles[1] == event_handle);
    assert(!all && timeout == INFINITE && s.pending && !s.closes);
    s.waits++;
    s.last_error = s.multi_error;
    return s.multi_wait;
}
static DWORD WaitForSingleObject(HANDLE handle, DWORD timeout)
{
    assert(handle == process_handle && timeout == 0 && !s.pending);
    s.single_waits++;
    s.last_error = s.single_error;
    return s.single_wait;
}
static BOOL CancelIoEx(HANDLE pipe, OVERLAPPED *ov)
{
    assert(pipe == pipe_handle && ov == s.active && s.pending && !s.closes);
    s.cancels++;
    s.canceled = TRUE;
    /* Deliberately leave the operation pending: cancellation is only a request. */
    s.last_error = s.cancel_error;
    return s.cancel_success;
}
static BOOL GetOverlappedResult(HANDLE pipe, OVERLAPPED *ov, DWORD *size, BOOL wait)
{
    assert(pipe == pipe_handle && ov == s.active && size && !s.closes);
    assert(s.pending || s.terminal);
    if (wait)
    {
        s.results++;
        if (s.result_wait_failure)
        {
            assert(s.pending);
            s.last_error = s.result_wait_error;
            return FALSE;
        }
        if (s.result_true_pending) { assert(s.pending); return TRUE; }
    }
    else
    {
        s.probes++;
        if (s.pending && s.pending_probes)
        {
            s.pending_probes--;
            s.last_error = ERROR_IO_INCOMPLETE;
            return FALSE;
        }
    }
    s.pending = FALSE;
    s.terminal = TRUE;
    ov->Internal = s.result_success ? 0 : s.result_error;
    ov->InternalHigh = s.result_size;
    *size = s.result_size;
    s.last_error = s.result_error;
    return s.result_success;
}
static BOOL CloseHandle(HANDLE handle)
{
    assert(handle == event_handle && !s.pending && !s.closes);
    s.closes++;
    /* Closing a handle may clobber last-error; the returned error must survive. */
    s.last_error = 123456;
    return TRUE;
}
static BOOL issue_io(HANDLE pipe, void *buffer, DWORD count, DWORD *size, OVERLAPPED *ov)
{
    assert(pipe == pipe_handle && buffer && count == 16 && !size && ov);
    assert(!ov->hEvent && !ov->Internal && !ov->InternalHigh && !ov->Offset && !ov->OffsetHigh);
    s.issued++;
    s.active = ov;
    if (s.issue == ISSUE_ERROR) { s.last_error = s.issue_error; return FALSE; }
    if (s.issue == IMMEDIATE_SUCCESS) { s.terminal = TRUE; return TRUE; }
    assert(s.issue == PENDING);
    s.pending = TRUE;
    ov->Internal = STATUS_PENDING;
    s.last_error = ERROR_IO_PENDING;
    return FALSE;
}
static BOOL WriteFile(HANDLE pipe, const void *buffer, DWORD count, DWORD *size, OVERLAPPED *ov)
{ s.writes++; return issue_io(pipe, (void *)buffer, count, size, ov); }
static BOOL ReadFile(HANDLE pipe, void *buffer, DWORD count, DWORD *size, OVERLAPPED *ov)
{ s.reads++; return issue_io(pipe, buffer, count, size, ov); }

#include "proposal_helpers.inc"

static unsigned tests;
static void reset(void)
{
    memset(&s, 0, sizeof(s));
    s.issue = PENDING;
    s.event_error = ERROR_NOT_ENOUGH_MEMORY;
    s.issue_error = ERROR_ACCESS_DENIED;
    s.multi_wait = WAIT_OBJECT_0 + 1;
    s.multi_error = ERROR_INVALID_HANDLE;
    s.single_wait = WAIT_TIMEOUT;
    s.single_error = ERROR_INVALID_HANDLE;
    s.result_success = TRUE;
    s.result_size = 16;
    s.cancel_success = TRUE;
    s.cancel_error = ERROR_NOT_FOUND;
    s.result_wait_error = ERROR_INVALID_HANDLE;
}
static void connect_case(const char *name, DWORD expected, unsigned cancels, unsigned results)
{
    DWORD actual = custom_connect_server(pipe_handle, process_handle);
    assert(actual == expected && s.cancels == cancels && s.results == results);
    assert(!s.pending && s.closes == !s.event_failure);
    tests++;
    printf("PASS %s\n", name);
}
static void io_case(const char *name, BOOL write, BOOL expected, DWORD expected_size)
{
    char buffer[16]; DWORD size = 999;
    assert(custom_pipe_io(pipe_handle, buffer, sizeof(buffer), &size, write) == expected);
    assert(size == expected_size && !s.pending && !s.closes);
    assert(s.writes == !!write && s.reads == !write);
    tests++;
    printf("PASS %s\n", name);
}
int main(void)
{
    reset(); s.event_failure = TRUE;
    connect_case("event allocation failure before I/O", ERROR_NOT_ENOUGH_MEMORY, 0, 0);
    assert(!s.issued);
    reset(); s.event_failure = TRUE; s.event_error = 0;
    connect_case("event failure never maps to success", ERROR_FUNCTION_FAILED, 0, 0);
    reset(); s.issue = IMMEDIATE_SUCCESS;
    connect_case("synchronous connection completion", 0, 0, 0);
    reset(); s.issue = ALREADY_CONNECTED;
    connect_case("ERROR_PIPE_CONNECTED has no pending I/O", 0, 0, 0);
    reset(); s.issue = ISSUE_ERROR;
    connect_case("immediate connect error preserved", ERROR_ACCESS_DENIED, 0, 0);
    reset(); s.issue = ISSUE_ERROR; s.issue_error = 0;
    connect_case("connect failure never maps to success", ERROR_FUNCTION_FAILED, 0, 0);
    reset();
    connect_case("pending connection completes", 0, 0, 1);
    reset(); s.result_success = FALSE; s.result_error = ERROR_BROKEN_PIPE;
    connect_case("pending connection failure preserved", ERROR_BROKEN_PIPE, 0, 1);
    reset(); s.multi_wait = WAIT_OBJECT_0; s.result_success = FALSE; s.result_error = ERROR_OPERATION_ABORTED;
    connect_case("child death cancels then drains", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.multi_wait = WAIT_OBJECT_0;
    connect_case("child death racing successful connection still fails", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.multi_wait = WAIT_OBJECT_0; s.cancel_success = FALSE;
    connect_case("cancel ERROR_NOT_FOUND race still drains", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.multi_wait = WAIT_OBJECT_0; s.cancel_success = FALSE; s.cancel_error = ERROR_ACCESS_DENIED;
    connect_case("unexpected cancellation error retains operation until completion", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.multi_wait = WAIT_FAILED; s.result_success = FALSE; s.result_error = ERROR_OPERATION_ABORTED;
    connect_case("wait failure preserved across cancellation and close", ERROR_INVALID_HANDLE, 1, 1);
    reset(); s.multi_wait = WAIT_FAILED; s.multi_error = 0;
    connect_case("wait failure never maps to success", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.multi_wait = WAIT_TIMEOUT;
    connect_case("unexpected wait result cancels then drains", ERROR_FUNCTION_FAILED, 1, 1);
    reset(); s.issue = IMMEDIATE_SUCCESS; s.single_wait = WAIT_OBJECT_0;
    connect_case("dead child after immediate completion rejected", ERROR_FUNCTION_FAILED, 0, 0);
    reset(); s.issue = ALREADY_CONNECTED; s.single_wait = WAIT_OBJECT_0;
    connect_case("dead child on already-connected path rejected", ERROR_FUNCTION_FAILED, 0, 0);
    reset(); s.single_wait = WAIT_OBJECT_0;
    connect_case("child dies while pending completion is collected", ERROR_FUNCTION_FAILED, 0, 1);
    reset(); s.single_wait = WAIT_FAILED;
    connect_case("post-connect process check failure preserved", ERROR_INVALID_HANDLE, 0, 1);
    reset(); s.result_wait_failure = TRUE; s.pending_probes = 3;
    connect_case("connect result wait failure cancels and polls to terminal", ERROR_INVALID_HANDLE, 1, 1);
    assert(s.sleeps == 3 && s.probes == 4);
    reset(); s.multi_wait = WAIT_OBJECT_0; s.result_wait_failure = TRUE; s.pending_probes = 3;
    s.result_success = FALSE; s.result_error = ERROR_OPERATION_ABORTED;
    connect_case("failed cancellation drain wait retains stack until terminal", ERROR_FUNCTION_FAILED, 2, 1);
    assert(s.sleeps == 3 && s.probes == 4);
    reset(); s.result_true_pending = TRUE; s.pending_probes = 3;
    connect_case("TRUE result with pending status still waits for terminal status", 0, 0, 1);
    assert(s.sleeps == 3 && s.probes == 4);
    reset(); s.issue = IMMEDIATE_SUCCESS; io_case("immediate write", TRUE, TRUE, 16);
    reset(); io_case("pending write drained synchronously", TRUE, TRUE, 16);
    reset(); s.issue = IMMEDIATE_SUCCESS; s.result_size = 8; io_case("short write size retained for caller", TRUE, TRUE, 8);
    reset(); s.issue = ISSUE_ERROR; s.issue_error = ERROR_BROKEN_PIPE; io_case("immediate write failure", TRUE, FALSE, 0);
    assert(s.last_error == ERROR_BROKEN_PIPE);
    reset(); s.result_wait_failure = TRUE; s.pending_probes = 3;
    io_case("read result wait failure cancels and retains buffer until terminal", FALSE, FALSE, 16);
    assert(s.last_error == ERROR_INVALID_HANDLE && s.cancels == 1 && s.sleeps == 3);
    reset(); s.result_wait_failure = TRUE; s.pending_probes = 2;
    io_case("write result wait failure cancels and retains buffer until terminal", TRUE, FALSE, 16);
    assert(s.last_error == ERROR_INVALID_HANDLE && s.cancels == 1 && s.sleeps == 2);
    reset(); s.result_true_pending = TRUE; s.pending_probes = 3;
    io_case("TRUE read result with pending status is fully drained", FALSE, TRUE, 16);
    assert(s.cancels == 0 && s.sleeps == 3);
    reset(); s.issue = IMMEDIATE_SUCCESS; io_case("immediate read", FALSE, TRUE, 16);
    reset(); io_case("pending read drained synchronously", FALSE, TRUE, 16);
    reset(); s.result_size = 8; io_case("short read size retained for caller", FALSE, TRUE, 8);
    reset(); s.result_success = FALSE; s.result_error = ERROR_BROKEN_PIPE; s.result_size = 0;
    io_case("pending read error retains error and drains", FALSE, FALSE, 0);
    assert(s.last_error == ERROR_BROKEN_PIPE);
    printf("%u deterministic API-model tests passed; no OS/Wine runtime claim\n", tests);
    return 0;
}
