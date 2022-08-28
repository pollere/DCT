#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_
/*
 * header-only version of 32bit MurmurHash3 and 64 bit Moremur finalizer
 *
 * Copyright (C) 2022 Pollere LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 *
 * This code is an adaptation of Austin Appleby's 32-bit MurmurHash3 implementation
 * at https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
 * That code contains this rights statement:
 *    MurmurHash3 was written by Austin Appleby, and is placed in the public
 *    domain. The author hereby disclaims copyright to this source code.
 *
 * This code also contains Pelle Evensen's improved 64-bit mixer, Moremur from
 * https://mostlymangling.blogspot.com/2019/12/stronger-better-morer-moremur-better.html
 */

#include <stdint.h>

struct murmurHash3 {

    static constexpr uint32_t rotl32(uint32_t x, int8_t r) { return (x << r) | (x >> (32 - r)); }

    // Finalization mix - force all bits of a hash block to avalanche

    static constexpr uint32_t fmix32(uint32_t h) {
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;

        return h;
    }

    constexpr auto operator()(uint32_t seed, const uint8_t *data, int len) const noexcept {
        const int nblocks = len / 4;

        uint32_t h1 = seed;

        constexpr uint32_t c1 = 0xcc9e2d51;
        constexpr uint32_t c2 = 0x1b873593;

        //----------
        // body

        const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);

        for (int i = -nblocks; i; i++) {
            uint32_t k1 = blocks[i];

            k1 *= c1;
            k1 = rotl32(k1, 15);
            k1 *= c2;

            h1 ^= k1;
            h1 = rotl32(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        //----------
        // tail

        const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);

        uint32_t k1 = 0;

        switch (len & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        case 2:
            k1 ^= tail[1] << 8;
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = rotl32(k1, 15);
            k1 *= c2;
            h1 ^= k1;
        };

        //----------
        // finalization

        return fmix32(h1 ^ len);
    }

    // moremur() from https://mostlymangling.blogspot.com/2019/12/stronger-better-morer-moremur-better.html
    constexpr auto operator()(uint64_t x) const noexcept {
        x ^= x >> 27;
        x *= uint64_t(0x3C79AC492BA7B653ull);
        x ^= x >> 33;
        x *= uint64_t(0x1C69B3F74AC4AE35ull);
        x ^= x >> 27;
        return uint32_t(x);
    }
};
#endif  // _MURMURHASH3_H_
