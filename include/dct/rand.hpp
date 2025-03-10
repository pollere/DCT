#ifndef DCT_RAND_HPP
#define DCT_RAND_HPP
#pragma once
/*
 * Return uniformly distributed random integers within a specified range
 *
 * Declaring a dct::rand object creates a random number generator
 * supporting three calls:
 *  dct::rand rand_;
 *   ...
 *  auto r = rand_();        // a random integer uniformly distributed on [0,2^32)
 *  auto r = rand_(range);   // a random integer uniformly distributed on [0,range)
 *  auto r = rand_(min,range);  // a random integer uniformly distributed on [min,min+range)
 *
 * This uses Melissa O'Neill's excellent PCG random number generator together
 * with her tweaked version of Lemire's Debiased Integer Multiply approach.
 * (See https://www.pcg-random.org/posts/bounded-rands.html and
 * https://jacquesheunis.com/post/bounded-random/ for background.)
 *
 * Copyright (C) 2025 Pollere LLC
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
 */

#include "pcg_random/pcg_random.hpp"

namespace dct {

struct rand {
    pcg32_fast rng{pcg_extras::seed_seq_from<std::random_device>{}};

    // return a uniformly distributed 32 bit random integer
    uint32_t operator()() { return rng(); }

    // return a uniformly distributed 32 bit random integer in [0, range)
    uint32_t operator()(uint32_t range) {
        uint64_t m = uint64_t(rng()) * uint64_t(range);
        uint32_t l = uint32_t(m);
        if (l < range) {
            uint32_t t = -range;
            if (t >= range) {
                t -= range;
                if (t >= range) t %= range;
            }
            while (l < t) {
                m = uint64_t(rng()) * uint64_t(range);
                l = uint32_t(m);
            }
        }
        return m >> 32;
    }

    // return a uniformly distributed 32 bit random integer in [min, range+min)
    int operator()(int min, uint32_t range) { return min + operator()(range); }
};

} // namespace dct

#endif // DCT_RAND_HPP
