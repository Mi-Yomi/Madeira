/* SPDX-License-Identifier: GPL-3.0-or-later
 * Source-owned Madeira installer ABI probe. No proprietary code or data. */
#ifndef MADEIRA_CANARY_COMMON_H
#define MADEIRA_CANARY_COMMON_H
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wtypes.h>
#include <msi.h>
#include <msiquery.h>

static void probe_decimal(DWORD value, WCHAR out[11])
{
    WCHAR reverse[10]; unsigned i = 0, j;
    do { reverse[i++] = (WCHAR)(L'0' + value % 10); value /= 10; } while (value);
    for (j = 0; j < i; ++j) out[j] = reverse[i - j - 1];
    out[i] = 0;
}
static DWORD probe_parse_decimal(const WCHAR *text)
{
    DWORD value = 0;
    for (; *text; ++text) {
        if (*text < L'0' || *text > L'9' || value > 429496729U ||
            (value == 429496729U && *text > L'5')) return 0;
        value = value * 10 + (*text - L'0');
    }
    return value;
}
static BOOL probe_equal(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static void probe_log(const char *stage, DWORD code)
{
    char line[160]; unsigned n = 0, i; WCHAR number[11]; DWORD written;
    const char *prefix = "MADEIRA-MSI-WOW64: ";
    while (*prefix) line[n++] = *prefix++;
    while (*stage && n < 128) line[n++] = *stage++;
    line[n++] = ' '; probe_decimal(code, number);
    for (i = 0; number[i]; ++i) line[n++] = (char)number[i];
    line[n++] = '\n';
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, n, &written, NULL);
}
static const WCHAR probe_unicode[] = L"Madeira-\x03a9-\x0416-\x4e2d";
#endif
