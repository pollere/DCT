/*
 * tst_crname <name> - test crname build and access methods
 *
 * Copyright (C) 2023 Pollere LLC
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

#include <cstring>
#include <fstream>

#include "dct/format.hpp"
#include "dct/schema/crpacket.hpp"


int main(int argc, const char* argv[]) {
    if (argc < 2) {
        print("- usage: {} name\n", argv[0]);
        exit(1);
    }
    //try {
        const auto n = crName(argv[1]);
        const int ncomp = n.nBlks();
        print("{} : {:x}\n", (rName)n, fmt::join(n.v_," "));
        //print("{} {} {:x}\n", n.m_off, n.size(), fmt::join(n.m_blk," "));

        crName t{};
        print("{} : {:x}\n", (rName)(t = appendToName(n, "foo/bar/baz")), fmt::join(t.v_," "));
        print("{} : {:x}\n", (rName)(t = appendToName(n, "/foo//bar/baz/")), fmt::join(t.v_," "));
        print("{} : {:x}\n", (rName)(t = appendToName(n, "one")), fmt::join(t.v_," "));

        print("crName components forwards\n");
        for (int i = 0; i < ncomp; ++i) print(" {} <{},{}> {}\n", i, n[i].typ(), n[i].size(), n[i].toSv());

        print("rName components backwards\n");
        const auto rn = rName(n);
        for (int i = 0; ++i <= ncomp; ) print(" {} <{},{}> {}\n", -i, rn[-i].typ(), rn[-i].size(), rn[-i].toSv());

        print("rName prefixes forwards\n");
        for (int i = 1; i <= ncomp; ++i) {
            auto prefix = rn.first(i);
            print(" {} {} {}\n", i, prefix.size(), prefix);
        }
        print("crName prefixes backwards\n");
        for (int i = 1; i < ncomp; ++i) print(" {} {}\n", -i, n.first(-i));

    //} catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
