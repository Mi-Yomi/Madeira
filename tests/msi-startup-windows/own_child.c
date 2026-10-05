/* SPDX-License-Identifier: LGPL-2.1-or-later
 * This fixture child is the only client executable the tests may start. */
#include "fixture_common.h"

int wmain(int argc, wchar_t **argv)
{
    HANDLE gate, opened, release, pipe;
    GUID guid, zero = {0};
    DWORD count;
    DWORD64 reply;
    int status = 0;

    if (argc != 6) return 90;
    gate = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);
    opened = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[4]);
    release = OpenEventW(SYNCHRONIZE, FALSE, argv[5]);
    if (!gate || !opened || !release) return 91;
    if (WaitForSingleObject(gate, INFINITE) != WAIT_OBJECT_0) return 92;
    if (!wcscmp(argv[1], L"exit")) return 0;

    pipe = CreateFileW(argv[2], GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) return 93;
    if (!SetEvent(opened)) return 94;
    if (!wcscmp(argv[1], L"connect_exit")) goto done;
    if (!wcscmp(argv[1], L"break"))
    {
        if (WaitForSingleObject(release, INFINITE) != WAIT_OBJECT_0) status = 95;
        goto done;
    }
    if (wcscmp(argv[1], L"exchange")) { status = 96; goto done; }

    for (;;)
    {
        if (!ReadFile(pipe, &guid, sizeof(guid), &count, NULL) || count != sizeof(guid))
        { status = 97; break; }
        if (!memcmp(&guid, &zero, sizeof(guid))) break;
        /* Make each server reply-read genuinely pending without a timed sleep. */
        if (WaitForSingleObject(release, INFINITE) != WAIT_OBJECT_0)
        { status = 98; break; }
        reply = fixture_reply(&guid);
        if (!WriteFile(pipe, &reply, sizeof(reply), &count, NULL) || count != sizeof(reply))
        { status = 99; break; }
    }
done:
    CloseHandle(pipe);
    CloseHandle(release);
    CloseHandle(opened);
    CloseHandle(gate);
    return status;
}
