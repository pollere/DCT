#ifndef FORMAT_HPP
#define FORMAT_HPP
#pragma once
/*
 * Copyright (C) 2020 Pollere LLC
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

// defining DCT_USE_STD_FORMAT will attempt to use the c++ standard libraries
// 'format' routines instead of the github.com/fmtlib/fmt equivalents.
// Note that as of April 2024 the clang standard library <format> was too incomplete
// to compile DCT.
#if DCT_USE_STD_FORMAT
#include <format>

namespace dct {
    using std::format;
    using std::format_to;
    using std::formatter;

template <typename... T>
inline void print(std::format_string<T...> fmt, T&&... args) {
    std::cout << format(fmt, args...);
}

} // namespace dct
#else

// use local version of c++20 formatted output until std library catches up.
// Download fmt from https://fmt.dev/latest/index.html or https://github.com/fmtlib/fmt

#define FMT_HEADER_ONLY
#include "fmt/format.h"
#include "fmt/ostream.h"
#include "fmt/ranges.h"
#include "fmt/chrono.h"
#include "fmt/color.h"

namespace dct {
    using fmt::format;
    using fmt::format_to;
    using fmt::formatter;
    using fmt::print;
} // namespace dct

#endif

#endif //FORMAT_HPP
