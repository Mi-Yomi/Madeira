/* SPDX-License-Identifier: MIT */
#ifndef MADEIRA_WGL_CANARY_PIXELS_H
#define MADEIRA_WGL_CANARY_PIXELS_H
#include <stdint.h>
enum { CANARY_WIDTH = 17, CANARY_HEIGHT = 13, CANARY_STRIDE_PIXELS = 32 };

static inline uint32_t canary_color(unsigned x, unsigned y)
{
    if (y < CANARY_HEIGHT / 2) return x < CANARY_WIDTH / 2 ? 0x00ff0000u : 0x0000ff00u;
    return x < CANARY_WIDTH / 2 ? 0x000000ffu : 0x00ffffffu;
}

static inline void canary_fill(uint32_t *pixels)
{
    for (unsigned y = 0; y < CANARY_HEIGHT; ++y)
        for (unsigned x = 0; x < CANARY_STRIDE_PIXELS; ++x)
            pixels[y * CANARY_STRIDE_PIXELS + x] = x < CANARY_WIDTH ? canary_color(x, y) : 0x00ff00ffu;
}

/* GDI may change the reserved alpha byte; RGB must match exactly. */
static inline int canary_check(const uint32_t *pixels, unsigned stride)
{
    if (stride < CANARY_WIDTH) return 0;
    for (unsigned y = 0; y < CANARY_HEIGHT; ++y)
        for (unsigned x = 0; x < CANARY_WIDTH; ++x)
            if ((pixels[y * stride + x] & 0xffffffu) != canary_color(x, y)) return 0;
    return 1;
}

static inline int canary_close(unsigned actual, unsigned expected)
{
    return actual >= expected ? actual - expected <= 1 : expected - actual <= 1;
}
#endif
