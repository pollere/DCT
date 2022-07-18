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
#include <iostream>
#include <fstream>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"
#include "dct/schema/cert_bundle.hpp"
#include "dct/schema/rpacket.hpp"


int main(int argc, const char* argv[]) {
    if (argc != 2) {
        print("- usage: {} name\n", argv[0]);
        exit(1);
    }
    auto buf = fileToVec(argv[1]);
    try {
        // make a map relating each cert's thumbprint to its position in bundle
        std::unordered_map<thumbPrint,int> tpmap{};
        int c{0};
        for (const auto& [cert, key] : rdCertBundle(buf)) {
            const auto& ttp = cert.computeThumbPrint();
            if (tpmap.contains(ttp)) print("** duplicate thumbprints: cert {} and {}.\n", tpmap[ttp], c);
            tpmap[ttp] = c++;
        }
        c = 0;
        for (const auto& [cert, key] : rdCertBundle(buf)) {
            const auto& stp = cert.getKeyLoc();
            if (dctCert::selfSigned(stp)) {
                print("{} root", c);
            } else if (! tpmap.contains(stp)) {
                print("{} <= ?", c);
            } else {
                print("{} <= {}", c, tpmap[stp]);
            }
            print(": {}", rData(cert).name());
            if (key.size()) print(" key '{:x}...", fmt::join(std::span{key}.first(4), ""));
            print("\n");
            ++c;
        }
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
