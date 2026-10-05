/* SPDX-License-Identifier: MIT. Pure host arithmetic, never a graphics result. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "wgl_canary_modern_values.h"
int main(void)
{
    const uint32_t seeds[2] = {MODERN_SEED_A, MODERN_SEED_B};
    const uint32_t anchored_sums[2][4] = {
        {0x0738b58fu,0x64529b73u,0x954f8ad2u,0x8bb33bfbu},
        {0xf7567380u,0x434ab37cu,0xc6a0d407u,0xcf145f0eu}
    };
    const unsigned char anchored_colors[2][4] = {{20,60,89,255},{51,220,200,255}};
    uint32_t words[12][4], actual[4], changed[4], first[12][4];
    unsigned char rgba[4];
    for (unsigned s = 0; s < 2; ++s) {
        for (unsigned i = 0; i < 12; ++i)
            for (unsigned j = 0; j < 4; ++j) {
                words[i][j] = modern_word(seeds[s], i, j);
                assert(words[i][j] != UINT32_C(0xdeadbeef));
                if (s) assert(words[i][j] != first[i][j]);
            }
        if (!s) memcpy(first, words, sizeof(first));
        modern_checksums(words, actual);
        modern_color(actual, rgba);
        assert(!memcmp(actual, anchored_sums[s], sizeof(actual)));
        assert(!memcmp(rgba, anchored_colors[s], sizeof(rgba)));
        printf("ORACLE seed=%08x sums=%08x,%08x,%08x,%08x rgba=%u,%u,%u,%u\n",
               seeds[s], actual[0], actual[1], actual[2], actual[3], rgba[0], rgba[1], rgba[2], rgba[3]);
        for (unsigned i = 0; i < 12; ++i)
            for (unsigned j = 0; j < 4; ++j) {
                uint32_t saved = words[i][j];
                words[i][j] ^= 1u;
                modern_checksums(words, changed);
                assert(actual[j] != changed[j]);
                for (unsigned k = 0; k < 4; ++k) if (k != j) assert(actual[k] == changed[k]);
                words[i][j] = saved;
            }
    }
    assert(modern_instance_value(7) == UINT32_C(0x17273747));
    assert(modern_instance_value(12) == UINT32_C(0x1c2c3c4c));
    puts("PASS: both seeds, every block/word changes, no sentinel collision, independent checksum sensitivity, instance addressing");
    return 0;
}
