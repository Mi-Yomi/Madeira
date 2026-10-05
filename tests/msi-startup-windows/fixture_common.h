/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MSI_STARTUP_FIXTURE_COMMON_H
#define MSI_STARTUP_FIXTURE_COMMON_H
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

static DWORD64 fixture_reply(const GUID *guid)
{
    return ((DWORD64)guid->Data1 << 32) | 0x13579bdfULL;
}
#endif
