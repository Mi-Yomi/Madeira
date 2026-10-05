/* Integer-safe session dimensions shared by win32u and the app display shim.
 * This only validates representation, not allocation or GPU size limits. */
#ifndef MADEIRA_DISPLAY_SIZE_H
#define MADEIRA_DISPLAY_SIZE_H

#include <ctype.h>
#include <limits.h>

/* Positive decimal int, with optional surrounding whitespace and leading +.
 * Reject the entire value on malformed or out-of-range input. In particular,
 * atoi's truncation/wraparound must not turn a bad config into a tiny monitor. */
static inline int madeira_screen_dimension( const char *value, int fallback )
{
    const unsigned char *p = (const unsigned char *)value;
    int size = 0;

    if (!p) return fallback;
    while (isspace( *p )) ++p;
    if (*p == '+') ++p;
    if (*p < '0' || *p > '9') return fallback;
    while (*p >= '0' && *p <= '9')
    {
        int digit = *p++ - '0';
        if (size > (INT_MAX - digit) / 10) return fallback;
        size = size * 10 + digit;
    }
    while (isspace( *p )) ++p;
    return !*p && size > 0 ? size : fallback;
}

#endif
