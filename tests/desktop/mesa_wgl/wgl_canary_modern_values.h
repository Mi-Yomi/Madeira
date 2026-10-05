/* SPDX-License-Identifier: MIT
 * Pure host oracle. Unsigned wraparound matches GLSL uint arithmetic.
 */
#ifndef WGL_CANARY_MODERN_VALUES_H
#define WGL_CANARY_MODERN_VALUES_H
#include <stdint.h>
#define MODERN_BLOCKS 12u
#define MODERN_WORDS 4u
#define MODERN_SEED_A UINT32_C(0x13579bdf)
#define MODERN_SEED_B UINT32_C(0x2468ace0)
static uint32_t modern_word(uint32_t seed, unsigned block, unsigned word)
{
    uint32_t x = (seed ^ (UINT32_C(0x9e3779b9) * (block + 1u))) +
                 UINT32_C(0x85ebca6b) * (word + 1u);
    x ^= x >> 16; x *= UINT32_C(0x7feb352d); x ^= x >> 15;
    return x;
}
static void modern_checksums(const uint32_t words[MODERN_BLOCKS][MODERN_WORDS], uint32_t out[4])
{
    for (unsigned j = 0; j < 4; ++j) {
        out[j] = UINT32_C(0x31415927) * (j + 1u);
        for (unsigned i = 0; i < MODERN_BLOCKS; ++i)
            out[j] += words[i][j] * (2u * i + 3u + 2u * j);
    }
}
static void modern_color(const uint32_t values[4], unsigned char out[4])
{
    out[0] = (unsigned char)((values[0] ^ (values[1] >> 8)) & 255u);
    out[1] = (unsigned char)((values[1] ^ (values[2] >> 16)) & 255u);
    out[2] = (unsigned char)((values[2] ^ (values[3] >> 24)) & 255u);
    out[3] = 255;
}
static uint32_t modern_instance_value(unsigned index)
{
    return UINT32_C(0x10203040) + UINT32_C(0x01010101) * index;
}
#endif
