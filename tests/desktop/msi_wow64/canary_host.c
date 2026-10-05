/* SPDX-License-Identifier: GPL-3.0-or-later
 * Compile-only deliverable until separately authorized to run in a disposable
 * prefix on the target runtime. Does not install or register a product.
 * Creates its own temporary MSI/DLL, invokes type-1 actions and checks effects. */
#include "canary_common.h"
#include <objbase.h>

_Static_assert(sizeof(void *) == 8, "the host must be 64-bit");
_Static_assert(sizeof(MSIHANDLE) == 4, "MSI handles are opaque 32-bit values");
static HANDLE completion;
static const WCHAR *proof_keys[] = {L"MADEIRA_PROOF_A", L"MADEIRA_PROOF_W",
    L"MADEIRA_CHILD_PID", L"MADEIRA_POINTER_BYTES", L"MADEIRA_PROOF_ROUND"};

static DWORD WINAPI watchdog(void *unused)
{
    (void)unused;
    if (WaitForSingleObject(completion, 60000) != WAIT_OBJECT_0) {
        probe_log("FAIL watchdog-timeout", 124);
        ExitProcess(124);
    }
    return 0;
}
static UINT query(MSIHANDLE db, const WCHAR *sql, MSIHANDLE params)
{
    MSIHANDLE view = 0; UINT result = MsiDatabaseOpenViewW(db, sql, &view);
    if (!result) result = MsiViewExecute(view, params);
    if (view) { MsiViewClose(view); MsiCloseHandle(view); }
    return result;
}
static UINT summary(MSIHANDLE db)
{
    MSIHANDLE info = 0; UINT result;
    result = MsiGetSummaryInformationW(db, NULL, 5, &info);
    if (!result) result = MsiSummaryInfoSetPropertyW(info, 7 /*PID_TEMPLATE*/, VT_LPSTR, 0, NULL, L"x64;1033");
    if (!result) result = MsiSummaryInfoSetPropertyW(info, 9 /*PID_REVNUMBER*/, VT_LPSTR, 0, NULL,
                          L"{435C0D6D-E587-48D0-B48D-F30CB14A99F5}");
    if (!result) result = MsiSummaryInfoSetPropertyW(info, 14 /*PID_PAGECOUNT*/, VT_I4, 200, NULL, NULL);
    if (!result) result = MsiSummaryInfoSetPropertyW(info, 15 /*PID_WORDCOUNT*/, VT_I4, 0, NULL, NULL);
    if (!result) result = MsiSummaryInfoSetPropertyW(info, 2 /*PID_TITLE*/, VT_LPSTR, 0, NULL,
                          L"Madeira source-owned WoW64 custom-action probe");
    if (!result) result = MsiSummaryInfoPersist(info);
    if (info) MsiCloseHandle(info);
    return result;
}
static UINT make_database(const WCHAR *path, const WCHAR *dll)
{
    static const WCHAR *sql[] = {
        L"CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)",
        L"INSERT INTO `Property` (`Property`,`Value`) VALUES ('ProductCode','{183C9DA5-FFEF-4204-A00C-6D3602A90DE0}')",
        L"INSERT INTO `Property` (`Property`,`Value`) VALUES ('ProductName','Madeira MSI WoW64 Canary')",
        L"INSERT INTO `Property` (`Property`,`Value`) VALUES ('ProductVersion','1.0.0')",
        L"INSERT INTO `Property` (`Property`,`Value`) VALUES ('ProductLanguage','1033')",
        L"INSERT INTO `Property` (`Property`,`Value`) VALUES ('Manufacturer','Source-owned fixture')",
        L"CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)",
        L"CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(64), `Target` CHAR(0) PRIMARY KEY `Action`)",
        L"INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('MadeiraProbe',1,'probe','MadeiraProbe')",
        L"INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('MadeiraMissingExport',1,'probe','ThisExportMustNotExist')"
    };
    MSIHANDLE db = 0, record = 0; UINT result; unsigned i;
    result = MsiOpenDatabaseW(path, MSIDBOPEN_CREATE, &db);
    for (i = 0; !result && i < sizeof(sql) / sizeof(sql[0]); ++i) result = query(db, sql[i], 0);
    if (!result) result = summary(db);
    if (!result && !(record = MsiCreateRecord(1))) result = ERROR_OUTOFMEMORY;
    if (!result) result = MsiRecordSetStreamW(record, 1, dll);
    if (!result) result = query(db, L"INSERT INTO `Binary` (`Name`,`Data`) VALUES ('probe', ?)", record);
    if (!result) result = MsiDatabaseCommit(db);
    if (record) MsiCloseHandle(record);
    if (db) MsiCloseHandle(db);
    return result;
}
static BOOL property_is(MSIHANDLE session, const WCHAR *key, const WCHAR *expected)
{
    WCHAR value[128]; DWORD length = 128;
    return MsiGetPropertyW(session, key, value, &length) == ERROR_SUCCESS && probe_equal(value, expected);
}
static UINT clear_proofs(MSIHANDLE session)
{
    unsigned i; UINT result;
    for (i = 0; i < sizeof(proof_keys)/sizeof(proof_keys[0]); ++i)
        if ((result = MsiSetPropertyW(session, proof_keys[i], NULL))) return result;
    return ERROR_SUCCESS;
}
static UINT run_session(const WCHAR *path)
{
    MSIHANDLE session = 0; UINT result, negative = ERROR_INSTALL_FAILURE; DWORD length, child, round;
    WCHAR parent[11], round_text[11], child_text[11]; unsigned i;
    MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);
    /* IGNOREMACHINESTATE creates a restricted handle that forbids DLL custom
     * actions on Windows and returns ERROR_FUNCTION_NOT_CALLED (1626).
     * Flags zero permit the explicit source-owned actions below; no standard
     * installation, registration or system-changing action is invoked. */
    result = MsiOpenPackageExW(path, 0, &session);
    if (result) { probe_log("FAIL open-package", result); return result; }
    probe_decimal(GetCurrentProcessId(), parent);
    result = MsiSetPropertyW(session, L"MADEIRA_PARENT_PID", parent);
    if (!result) result = MsiSetPropertyW(session, L"MADEIRA_INPUT_W", probe_unicode);
    for (round = 1; !result && round <= 2; ++round) {
        probe_decimal(round, round_text);
        result = clear_proofs(session);
        if (!result) result = MsiSetPropertyW(session, L"MADEIRA_ROUND", round_text);
        if (!result) {
            result = MsiDoActionW(session, L"MadeiraProbe");
            probe_log("ACTION positive-return", result);
        }
        if (!result && (!property_is(session, L"MADEIRA_PROOF_A", L"i386-ordinal-144") ||
                        !property_is(session, L"MADEIRA_PROOF_W", probe_unicode) ||
                        !property_is(session, L"MADEIRA_POINTER_BYTES", L"4") ||
                        !property_is(session, L"MADEIRA_PROOF_ROUND", round_text))) result = ERROR_INSTALL_FAILURE;
        length = 11; child_text[0] = 0;
        if (!result) result = MsiGetPropertyW(session, L"MADEIRA_CHILD_PID", child_text, &length);
        child = probe_parse_decimal(child_text);
        if (!result && (!child || child == GetCurrentProcessId())) result = ERROR_INSTALL_FAILURE;
        if (!result) probe_log("PASS child-pid", child);
        probe_log(result ? "FAIL positive-round" : "PASS positive-round", round);
    }
    if (!result) result = clear_proofs(session);
    if (!result) result = MsiSetPropertyW(session, L"MADEIRA_ROUND", L"1");
    if (!result) {
        /* Run failure last so it cannot affect the positive probes. All valid
         * callback inputs remain set: an incorrectly resolved positive export
         * must not pass this control by failing on a missing ROUND property. */
        negative = MsiDoActionW(session, L"MadeiraMissingExport");
        probe_log(negative ? "PASS missing-export-rejected" : "FAIL missing-export-reported-success", negative);
        for (i = 0; i < sizeof(proof_keys)/sizeof(proof_keys[0]); ++i)
            if (!property_is(session, proof_keys[i], L"")) result = ERROR_INSTALL_FAILURE;
    }
    /* Attribute close status to the close call, independent of any earlier
     * action failure. Windows may cache its MSI host afterward, so this checks
     * session close, not child-process teardown. */
    {
        UINT closed = MsiCloseHandle(session);
        probe_log(closed ? "FAIL session-close" : "PASS session-close", closed);
        if (!result) result = closed;
    }
    if (!result && !negative) result = ERROR_INSTALL_FAILURE;
    return result;
}

void start(void)
{
    WCHAR directory[MAX_PATH];
    static WCHAR msi_path[MAX_PATH], dll_path[MAX_PATH];
    HMODULE self; HRSRC resource; HGLOBAL loaded; HANDLE file, thread;
    DWORD bytes, written, length; const void *data; UINT result = ERROR_SUCCESS;
    HRESULT com; BOOL com_initialized = FALSE;
    completion = CreateEventW(NULL, TRUE, FALSE, NULL);
    thread = completion ? CreateThread(NULL, 0, watchdog, NULL, 0, NULL) : NULL;
    if (!thread) { probe_log("FAIL watchdog-create", GetLastError()); ExitProcess(125); }
    CloseHandle(thread);
    probe_log("START parent-pid", GetCurrentProcessId());
    /* The package APIs require COM on this thread. Initialize before all MSI
     * calls, and balance S_OK/S_FALSE after the session and temporary files. */
    com = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) { probe_log("FAIL com-initialize", (DWORD)com); result = ERROR_INSTALL_FAILURE; }
    else com_initialized = TRUE;
    length = GetTempPathW(MAX_PATH, directory);
    if (!result && (!length || length >= MAX_PATH)) result = ERROR_BAD_PATHNAME;
    if (!result && !GetTempFileNameW(directory, L"mdm", 0, msi_path)) result = GetLastError();
    if (!result && !GetTempFileNameW(directory, L"mdd", 0, dll_path)) result = GetLastError();
    self = GetModuleHandleW(NULL);
    resource = FindResourceW(self, MAKEINTRESOURCEW(1), (LPCWSTR)RT_RCDATA);
    loaded = resource ? LoadResource(self, resource) : NULL;
    data = loaded ? LockResource(loaded) : NULL;
    bytes = resource ? SizeofResource(self, resource) : 0;
    if (!result && (!data || !bytes)) result = ERROR_RESOURCE_DATA_NOT_FOUND;
    if (!result) {
        file = CreateFileW(dll_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (file == INVALID_HANDLE_VALUE) result = GetLastError();
        else {
            if (!WriteFile(file, data, bytes, &written, NULL) || written != bytes) result = ERROR_WRITE_FAULT;
            if (!CloseHandle(file) && !result) result = GetLastError();
        }
    }
    if (!result) result = make_database(msi_path, dll_path);
    if (!result) result = run_session(msi_path);
    if (*dll_path && !DeleteFileW(dll_path) && !result) result = GetLastError();
    if (*msi_path && !DeleteFileW(msi_path) && !result) result = GetLastError();
    if (com_initialized) CoUninitialize();
    probe_log(result ? "FAIL final" : "PASS final", result);
    SetEvent(completion);
    /* Exit zero alone is insufficient: require both rounds, the checked
     * properties/distinct child PID, session-close and final PASS. Windows may
     * cache the MSI host: this is not Wine child-teardown proof. CA-PROOF stderr
     * may not be inherited on native Windows. */
    ExitProcess(result ? 1 : 0);
}
