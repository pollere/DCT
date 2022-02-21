/*
 * Copyright (C) 2020 Pollere LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */
#ifndef FORMAT_HPP
#define FORMAT_HPP

// use local version of c++20 formatted output until std library catches up.
// Download fmt from https://fmt.dev/latest/index.html or https://github.com/fmtlib/fmt

// As of June 2021, get spurious warnings when compiling fmt because
// std::codecvt is deprecated but there is no standardized replacement.
// Theses pragmas are to prevent the warning from this.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define FMT_HEADER_ONLY
#include "fmt/format.h"
#include "fmt/compile.h"
#include "fmt/ostream.h"
#include "fmt/ranges.h"
#include "fmt/chrono.h"
#include "fmt/color.h"

#pragma GCC diagnostic pop

using fmt::print;
using fmt::format;

#endif //FORMAT_HPP
