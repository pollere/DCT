/*
 * DCT TLV dumper
 *
 * Copyright (C) 2021-2 Pollere LLC
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

#include <iostream>

#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"
#include "dissect.hpp"

int main(int argc, char* argv[])
{
    if (argc > 2) {
        std::cout << "usage: " << argv[0] << " [file]\n";
        return 1;
    }
    try {
        auto v = dct::fileToVec(argc > 1 ? argv[1] : "/dev/stdin");
        dct::Dissect().dissect(std::cout, v);
        exit(0);
    } catch (const std::runtime_error& e) { fmt::print(std::cerr, "- error: {}\n", e.what()); }
    exit(1);
}
