/*
 * test raw packet manipulation routines
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
#include <set>
#include <string_view>

#include <ndn-ind/data.hpp>

#include "dct/format.hpp"
#include "dct/schema/tlv_encoder.hpp"
#include "dct/schema/rpacket.hpp"

static void usage(const char** argv) {
    print("- usage: {} -o outfile file ...\n", argv[0]);
    exit(1);
}

static auto pname(const rName& rnm) {
    ndn::Name nm{};
    nm.wireDecode(rnm.data(), rnm.size());
    return nm.toUri();
}

int main(int argc, const char* argv[]) {
    //if (argc < 3) usage(argv);
    //const char** ap = argv + 1;
    //const char** ape = argv + argc;
    //if (std::string_view(*ap++) != "-o") usage(argv);
    //outfile = *ap++;
    
    try {
        ndn::Data d1(ndn::Name("a/b"));
        auto& w1 = *d1.wireEncode();
        rData r1(w1.data(), w1.size());

        ndn::Data d2(ndn::Name("a/c/d"));
        auto& w2 = *d2.wireEncode();
        rData r2(w2.data(), w2.size());

        ndn::Data d3(ndn::Name("a/d"));
        auto& w3 = *d3.wireEncode();
        rData r3(w3.data(), w3.size());

        ndn::Data d4(ndn::Name("a/b/c"));
        auto& w4 = *d4.wireEncode();
        rData r4(w4.data(), w4.size());

        std::set<rData> rset;
        rset.emplace(r1);
        rset.emplace(r2);
        rset.emplace(r3);
        rset.emplace(r4);

        for (const auto& rp : rset) {
            ndn::Data d;
            d.wireDecode(rp.data(), rp.size());
            print("{} ({} comps):", pname(rp.name()), rp.name().nBlks());
            for (const auto& p : rset) {
                if (p.name().isPrefix(rp.name())) print(" {}", pname(p.name()));
            }
            print("\n");
        }
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
