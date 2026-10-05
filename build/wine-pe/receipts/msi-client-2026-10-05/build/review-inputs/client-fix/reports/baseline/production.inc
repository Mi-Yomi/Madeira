static UINT custom_get_thread_return( MSIPACKAGE *package, HANDLE thread )
{
    DWORD rc = 0;

    GetExitCodeThread( thread, &rc );

    switch (rc)
    {
    case ERROR_FUNCTION_NOT_CALLED:
    case ERROR_SUCCESS:
    case ERROR_INSTALL_USEREXIT:
    case ERROR_INSTALL_FAILURE:
        return rc;
    case ERROR_NO_MORE_ITEMS:
        return ERROR_SUCCESS;
    case ERROR_INSTALL_SUSPEND:
        ACTION_ForceReboot( package );
        return ERROR_SUCCESS;
    default:
        ERR( "invalid Return Code %lu\n", rc );
        return ERROR_INSTALL_FAILURE;
    }
}

static UINT wait_thread_handle( custom_action_info *info )
{
    UINT rc = ERROR_SUCCESS;

    if (!(info->type & msidbCustomActionTypeAsync))
    {
        TRACE("waiting for %s\n", debugstr_w( info->action ));

        msi_dialog_check_messages( info->handle );

        if (!(info->type & msidbCustomActionTypeContinue))
            rc = custom_get_thread_return( info->package, info->handle );

        free_custom_action_data( info );
    }
    else
    {
        TRACE("%s running in background\n", debugstr_w( info->action ));
    }

    return rc;
}

static DWORD WINAPI custom_client_thread(void *arg)
{
    custom_action_info *info = arg;
    DWORD64 thread64;
    HANDLE process;
    HANDLE thread;
    HANDLE pipe;
    DWORD size;
    DWORD rc;

    CoInitializeEx(NULL, COINIT_MULTITHREADED); /* needed to marshal streams */

    if (info->arch == SCS_32BIT_BINARY)
    {
        process = info->package->custom_server_32_process;
        pipe = info->package->custom_server_32_pipe;
    }
    else
    {
        process = info->package->custom_server_64_process;
        pipe = info->package->custom_server_64_pipe;
    }

    EnterCriticalSection(&custom_action_cs);

    if (!WriteFile(pipe, &info->guid, sizeof(info->guid), &size, NULL) ||
        size != sizeof(info->guid))
    {
        ERR("failed to write to custom action client pipe: %lu\n", GetLastError());
        LeaveCriticalSection(&custom_action_cs);
        return GetLastError();
    }
    if (!ReadFile(pipe, &thread64, sizeof(thread64), &size, NULL) || size != sizeof(thread64))
    {
        ERR("failed to read from custom action client pipe: %lu\n", GetLastError());
        LeaveCriticalSection(&custom_action_cs);
        return GetLastError();
    }

    LeaveCriticalSection(&custom_action_cs);

    if (DuplicateHandle(process, (HANDLE)(DWORD_PTR)thread64, GetCurrentProcess(),
        &thread, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
    {
        WaitForSingleObject(thread, INFINITE);
        GetExitCodeThread(thread, &rc);
        CloseHandle(thread);
    }
    else
        rc = GetLastError();

    CoUninitialize();
    return rc;
}
