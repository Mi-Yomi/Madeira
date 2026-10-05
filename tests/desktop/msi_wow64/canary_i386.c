/* SPDX-License-Identifier: GPL-3.0-or-later
 * A real 32-bit MSI type-1 custom action. SetPropertyA/W are linked by
 * ordinals 144/145, exercising ordinal imports used by mixed-bitness installers. */
#include "canary_common.h"

_Static_assert(sizeof(void *) == 4, "the custom action must be i386");
_Static_assert(sizeof(MSIHANDLE) == 4, "MSI handles are opaque 32-bit values");

UINT WINAPI MadeiraProbe(MSIHANDLE install)
{
    static const struct { BYTE revision, count; SID_IDENTIFIER_AUTHORITY authority; DWORD sub[2]; }
        users = { SID_REVISION, 2, SECURITY_NT_AUTHORITY, {32, 545} };
    WCHAR input[64], parent[11], round[4], name_w[256], domain_w[256], child[11];
    char name_a[256], domain_a[256];
    DWORD length, name_length, domain_length; SID_NAME_USE use; UINT result;

    length = 64;
    if (MsiGetPropertyW(install, L"MADEIRA_INPUT_W", input, &length) ||
        !probe_equal(input, probe_unicode)) return ERROR_INSTALL_FAILURE;
    length = 11;
    if (MsiGetPropertyW(install, L"MADEIRA_PARENT_PID", parent, &length) ||
        !probe_parse_decimal(parent) || probe_parse_decimal(parent) == GetCurrentProcessId())
        return ERROR_INSTALL_FAILURE;
    length = 4;
    if (MsiGetPropertyW(install, L"MADEIRA_ROUND", round, &length) ||
        !(probe_equal(round, L"1") || probe_equal(round, L"2"))) return ERROR_INSTALL_FAILURE;

    /* Exercise the same A/W SID APIs as the measured installer helper.
     * Account names are localized: check valid nonempty results, not spelling. */
    name_length = 256; domain_length = 256;
    if (!LookupAccountSidW(NULL, (PSID)&users, name_w, &name_length,
                          domain_w, &domain_length, &use) || !name_length ||
        use != SidTypeAlias) return ERROR_INSTALL_FAILURE;
    name_length = 256; domain_length = 256;
    if (!LookupAccountSidA(NULL, (PSID)&users, name_a, &name_length,
                          domain_a, &domain_length, &use) || !name_length ||
        use != SidTypeAlias) return ERROR_INSTALL_FAILURE;

    if ((result = MsiSetPropertyA(install, "MADEIRA_PROOF_A", "i386-ordinal-144"))) return result;
    if ((result = MsiSetPropertyW(install, L"MADEIRA_PROOF_W", input))) return result;
    probe_decimal(GetCurrentProcessId(), child);
    if ((result = MsiSetPropertyW(install, L"MADEIRA_CHILD_PID", child))) return result;
    if ((result = MsiSetPropertyW(install, L"MADEIRA_POINTER_BYTES", L"4"))) return result;
    if ((result = MsiSetPropertyW(install, L"MADEIRA_PROOF_ROUND", round))) return result;
    probe_log("CA-PROOF", GetCurrentProcessId());
    return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
