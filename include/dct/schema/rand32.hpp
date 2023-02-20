#ifndef RAND32_HPP
#define RAND32_HPP
#pragma once
/*
 * DCT random number generator (for non-crypto use like Interest nonces)
 *
 * Copyright (C) 2020-2 Pollere LLC
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

#include <array>
#include <random>

namespace dct {

static inline auto& randGen() noexcept {
    static std::minstd_rand randomGen{};
    static bool needInit{true};
    if (needInit) { randomGen.seed((std::random_device{})()); needInit = false; }
    return randomGen;
}

static inline auto rand32() noexcept { return randGen()(); }

} // namespace dct

#endif  // RAND32_HPP
