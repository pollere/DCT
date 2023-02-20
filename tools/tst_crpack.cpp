/*
 * ls_bundle <name> - list the contents of a cert bundle
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

#include <cstring>
#include <fstream>

#include "dct/format.hpp"
#include "dct/schema/crpacket.hpp"

using namespace dct;

int main(int argc, const char* argv[]) {
    if (argc < 2) {
        print("- usage: {} name size\n", argv[0]);
        exit(1);
    }
    const auto n = crName(argv[1]);
    try {
        for (size_t i = 1; i < 260; ++i) {
            auto v = std::vector<uint8_t>(i);
            crData d(n); d.content(v);
            //crData c((rData)d);
            crData c(d);
            if (d.off() != c.off() || d.size() != c.size()) {
                print("d({},{},{}) != c({},{},{})\n", d.off(), d.size(), d.v_.size(), c.off(), c.size(), c.v_.size());
            }
        }
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    //try {
        std::ofstream os("tst.out", std::ios::binary);

        auto sz = atoi(argv[2]);
        std::vector<uint8_t> v{};
        for (auto i = 0; i < sz; ++i) v.emplace_back((uint8_t)i);
        //print("{} : {:x}\n", (rName)n, fmt::join(n.v_," "));
        //print("{} {} {:x}\n", n.m_off, n.size(), fmt::join(n.m_blk," "));
        auto i = crInterest(crName{n}.append(tlv::Generic, v).done(), 1234ms); //1cp 1mv
        os.write((char*)i.data(), i.size());

        auto c1 = std::to_array<uint8_t>({11, 12, 13, 14, 15, 16, 17, 18});
        auto c2 = std::to_array<uint8_t>({10, 9, 8, 7, 6, 5, 4, 3, 2, 1});
        std::vector<std::span<const uint8_t>> chunks{c1, c2, v};
        //auto d = crData(i).content(chunks);
        //auto d = crData(i.name()).content(chunks);
        auto d = crData(n).content(chunks);
        //auto d = crData(i);
        //crData d{i};
        //d.content(chunks);
        os.write((char*)d.data(), d.size());

        os.close();

        //print("{} = {:x}\n", argv[2], fmt::join(i.v_, " "));
    //} catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
