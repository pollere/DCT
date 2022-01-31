/*
 *  tst_validate <bundle> <name> - test structural validation
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
 *  You may contact Pollere, Inc at info@pollere.net.
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
#include "dct/schema/dct_model.hpp"

auto makePub(DCTmodel& dm, const char* nm) {
    auto n = ndn::Name(nm);

    DCTmodel::sPub pub{n.appendTimestamp(std::chrono::system_clock::now())};
    std::cout << "signing " << pub.getName() << '\n';
    dm.pubSigMgr().sign(pub);
    std::cout << "signed " << pub.getName() << '\n';
    return pub;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        print("- usage: {} bundle name\n", argv[0]);
        exit(1);
    }
    try {
        DCTmodel dm(argv[1]);
        dm.start([&dm,argv](bool success) { if (success) dm.publish(makePub(dm, argv[2])); });
        dm.run();
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    exit(0);
}
