/* SPDX-License-Identifier: MIT
 * Tests the pixel oracle, not Wine, GDI, WGL, Mesa, FEX or Madeira execution.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wgl_canary_pixels.h"

int main(void)
{
    uint32_t padded[CANARY_STRIDE_PIXELS * CANARY_HEIGHT];
    uint32_t tight[CANARY_WIDTH * CANARY_HEIGHT];
    canary_fill(padded);
    assert(canary_check(padded, CANARY_STRIDE_PIXELS));
    assert(!canary_check(padded, CANARY_WIDTH));
    assert(!canary_check(padded, CANARY_WIDTH - 1));
    for (unsigned y = 0; y < CANARY_HEIGHT; ++y)
        memcpy(tight + y * CANARY_WIDTH, padded + y * CANARY_STRIDE_PIXELS,
               CANARY_WIDTH * sizeof(uint32_t));
    assert(canary_check(tight, CANARY_WIDTH));
    for (unsigned i = 0; i < CANARY_WIDTH * CANARY_HEIGHT; ++i) {
        uint32_t save = tight[i];
        tight[i] ^= 0x00010000u;
        assert(!canary_check(tight, CANARY_WIDTH));
        tight[i] = save | 0xab000000u;
        assert(canary_check(tight, CANARY_WIDTH));
    }
    for (unsigned y = 0; y < CANARY_HEIGHT; ++y)
        memcpy(tight + y * CANARY_WIDTH,
               padded + (CANARY_HEIGHT - 1 - y) * CANARY_STRIDE_PIXELS,
               CANARY_WIDTH * sizeof(uint32_t));
    assert(!canary_check(tight, CANARY_WIDTH));
    for (unsigned a = 0; a < 256; ++a)
        for (unsigned e = 0; e < 256; ++e) {
            int distance = (int)a - (int)e;
            assert(canary_close(a, e) == (distance >= -1 && distance <= 1));
        }
    puts("PASS: padded/tight layout, every RGB corruption, alpha tolerance, vertical reversal and rounding oracle");
}
