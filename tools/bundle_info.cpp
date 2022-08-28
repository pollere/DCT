/*
 * bundle_info <bundle> <cap> - print the value of capability <cap> in <bundle>
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
#include <fstream>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include "dct/format.hpp"
#include "dct/schema/validate_bootstrap.hpp"
#include "dct/schema/capability.hpp"


int main(int argc, const char* argv[]) {
    if (argc < 3) {
        print("-usage: {} bundle capName\n", argv[0]);
        exit(1);
    }
    try {
        certStore cs{};
        auto bs = validateBootstrap(argv[1], cs);
        auto val = Cap::getval(argv[2], crName{bs.pubVal("#pubPrefix")}, cs)(cs.chains_[0]).toSv();
        print("{} = {}\n", argv[2], val);
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
