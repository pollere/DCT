/*
 * schema_info - print selected info from a binary schema
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
#include "dct/schema/rdschema.hpp"


void usage(const char** argv) {
    print("- usage: {} [-c] [-t] bschema [pubname]\n", argv[0]);
    exit(1);
}

int main(int argc, const char* argv[]) {
    bool trim = false;
    bool chkcap = false;
    const char* pub = "pub0";

    if (argc < 2) usage(argv);

    const char** ap = argv + 1;
    const char** ape = argv + argc;
    if (ap < ape && std::string_view(*ap) == "-c") {
        chkcap = true;
        ap++;
    }
    if (ap < ape && std::string_view(*ap) == "-t") {
        trim = true;
        ap++;
    }
    if (ape - ap < 1 || std::string_view(*ap)[0] == '-') usage(argv);

    const char* sfile = *ap++;
    if (ap < ape) pub = *ap++;
 
    try {
        std::ifstream is(sfile, std::ios::binary);
        rdSchema rs(is);
        bSchema bs{rs.read()};

        if (chkcap) {
            auto i = bs.matchesAny(bs.pubVal("#pubPrefix") + "/CAP/" + pub + "/_/KEY/_/dct/_");
            if (i >= 0) print("{}\n", i);
            exit(0);
        }
        std::string val{};
        if (std::string_view(pub) == "pub0") {
            val = bs.pubName(0);
        } else {
            val = bs.pubVal(pub);
        }
        if (trim) val = val.substr(1);
        print("{}\n", val);
    } catch (const schema_error& se) {
        print("schema error: {}\n", se.what());
        exit(1);
    }

    exit(0);
}
