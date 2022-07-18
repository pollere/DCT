/*
 *  bld_dump <bundle> - list the pubs produced by an id bundle
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
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include "dct/format.hpp"
#include "dct/schema/buildpub.hpp"
#include "dct/schema/validate_bootstrap.hpp"

int main(int argc, const char* argv[]) {
    if (argc < 2) {
        print("- usage: {} bundle [pubname]\n", argv[0]);
        exit(1);
    }
    try {
        certStore cs{};
        auto bs = validateBootstrap(argv[1], cs);
        
        if (argc < 3) {
            pubBldr<true> bld(bs, cs, bs.pubName(0));
        } else {
            pubBldr<true> bld(bs, cs, argv[2]);
        }
    } catch (const schema_error& se) { print("schema error: {}\n", se.what()); }

    exit(0);
}
