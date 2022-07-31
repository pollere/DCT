#ifndef FILE_TO_VEC_HPP
#define FILE_TO_VEC_HPP
/*
 * fileToVec - read the contents of a file into a vector
 *
 * Copyright (C) 2021 Pollere LLC
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
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>
#include "format.hpp"

static auto fileToVec(std::string_view fname) {
    // XXX workaround for macOS clang-11 bug that gives a compiler error is istream 1st arg is a string_view:
    // XXX "error: 'basic_ifstream' is unavailable: introduced in macOS 10.15"
    std::string f{fname};
    std::ifstream is(f, std::ios::binary|std::ios::ate);
    if (! is) throw std::runtime_error(format("can't open file {}", fname));
    auto sz = is.tellg();
    if (sz < 32 || sz > 65536) {
        throw std::runtime_error(format("{} file size unreasonable ({} bytes)\n", fname, sz));
    }
    is.seekg(0);
    std::vector<uint8_t> buf(sz);
    if (! is.read((char*)buf.data(), buf.size())) {
        throw std::runtime_error(format("couldn't read file {}\n", fname));
    }
    is.close();
    return buf;
}
#endif // FILE_TO_VEC_HPP
