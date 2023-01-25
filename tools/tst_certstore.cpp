/*
 * tst_certstore <bundle> - tst certstore methods using bundle
 *
 * Copyright (C) 202d Pollere LLC
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
#include "dct/schema/dct_model.hpp"


int main(int argc, const char* argv[]) {
    using namespace std::literals;
    if (argc < 2) {
        print("- usage: {} bundle\n", argv[0]);
        exit(1);
    }
    dct::DCTmodel dm(argv[1]);
    try {
        print("Signing chain of {}:\n", argv[1]);
        dm.cs_.chain_for_each(dm.cs_.chains_[0], [](const auto& c){ print("{}\n", c.name()); });
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
