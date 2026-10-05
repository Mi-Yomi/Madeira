/* Finish server-pipe operations before releasing their caller-owned storage. */
static BOOL custom_pipe_result( HANDLE pipe, OVERLAPPED *overlapped, DWORD *size )
{
    BOOL waited, success;
    DWORD error = ERROR_SUCCESS;

    waited = GetOverlappedResult( pipe, overlapped, size, TRUE );
    if (!waited)
    {
        error = GetLastError();
        if (!error) error = ERROR_FUNCTION_FAILED;
    }

    /* A failed wait need not complete the I/O. Probe its actual status before
     * releasing the caller's OVERLAPPED/buffer, including after cancellation.
     * A private handle remains valid throughout. No installer timeout is set. */
    success = GetOverlappedResult( pipe, overlapped, size, FALSE );
    if (!success && GetLastError() == ERROR_IO_INCOMPLETE)
    {
        if (!waited) CancelIoEx( pipe, overlapped );
        do
        {
            Sleep( 1 );
            success = GetOverlappedResult( pipe, overlapped, size, FALSE );
        } while (!success && GetLastError() == ERROR_IO_INCOMPLETE);
    }
    if (!waited) SetLastError( error );
    return waited && success;
}

static DWORD custom_connect_server( HANDLE pipe, HANDLE process )
{
    OVERLAPPED overlapped = {0};
    HANDLE handles[2];
    DWORD ret = ERROR_SUCCESS, size, wait, error;

    if (!(overlapped.hEvent = CreateEventW( NULL, TRUE, FALSE, NULL )))
    {
        ret = GetLastError();
        return ret ? ret : ERROR_FUNCTION_FAILED;
    }

    if (!ConnectNamedPipe( pipe, &overlapped ))
    {
        ret = GetLastError();
        if (ret == ERROR_IO_PENDING)
        {
            /* A dead child wins when both objects are already signaled. */
            handles[0] = process;
            handles[1] = overlapped.hEvent;
            wait = WaitForMultipleObjects( 2, handles, FALSE, INFINITE );
            if (wait == WAIT_OBJECT_0 + 1)
            {
                ret = ERROR_SUCCESS;
                if (!custom_pipe_result( pipe, &overlapped, &size ))
                {
                    ret = GetLastError();
                    if (!ret) ret = ERROR_FUNCTION_FAILED;
                }
            }
            else
            {
                ret = wait == WAIT_FAILED ? GetLastError() : ERROR_FUNCTION_FAILED;
                if (!ret) ret = ERROR_FUNCTION_FAILED;
                if (!CancelIoEx( pipe, &overlapped ) && (error = GetLastError()) != ERROR_NOT_FOUND)
                    ERR( "failed to cancel custom action server connection: %lu\n", error );
                /* CancelIoEx only requests cancellation. Also drain a racing
                 * successful completion before closing the event or returning
                 * past this stack OVERLAPPED. The handle/event remain private. */
                custom_pipe_result( pipe, &overlapped, &size );
            }
        }
        else if (ret == ERROR_PIPE_CONNECTED)
            ret = ERROR_SUCCESS;
        else if (!ret)
            ret = ERROR_FUNCTION_FAILED;
    }

    if (!ret)
    {
        /* Also reject a child already dead on an immediate connection path. */
        wait = WaitForSingleObject( process, 0 );
        if (wait != WAIT_TIMEOUT)
        {
            ret = wait == WAIT_FAILED ? GetLastError() : ERROR_FUNCTION_FAILED;
            if (!ret) ret = ERROR_FUNCTION_FAILED;
        }
    }

    CloseHandle( overlapped.hEvent );
    return ret;
}

/* The connection operation is drained before the handle is published. The
 * action GUID write / thread-handle read are serialized by custom_action_cs.
 * Package references keep destruction/stop after all action users are gone.
 * Thus there is exactly one outstanding operation on this handle, allowing
 * its own completion signal to be used without allocating another event. */
static BOOL custom_pipe_io( HANDLE pipe, void *buffer, DWORD count, DWORD *size, BOOL write )
{
    OVERLAPPED overlapped = {0};
    BOOL success;

    *size = 0;
    if (write)
        success = WriteFile( pipe, buffer, count, NULL, &overlapped );
    else
        success = ReadFile( pipe, buffer, count, NULL, &overlapped );
    if (!success && GetLastError() != ERROR_IO_PENDING) return FALSE;
    return custom_pipe_result( pipe, &overlapped, size );
}
