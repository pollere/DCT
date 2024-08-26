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
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */
//#include <iostream>
//#include <fstream>
//#include <string>
//#include <string_view>
//#include <tuple>
//#include <type_traits>
//#include <utility>
//#include <variant>
#include "dct/format.hpp"
#include "dct/schema/dct_model.hpp"
#include "../examples/util/dct_example.hpp"

using namespace dct;

auto makePub(DCTmodel& dm, const char* nm) {
    auto pub = crData{crName(nm) / 0xdeadbeef / 0 / (std::chrono::system_clock::now())};
    std::span<const uint8_t> s{};
    pub.content(s);
    dm.msgSigMgr().sign(pub);
    print("signed {}\n", pub.name());
    //pub.signer()[0] ^= 1;
    return pub;
}

static auto& getDCTmodel(const char* bsfile) {
    static dct::DCTmodel* dm{};
    if (! dm) {
        dct::readBootstrap(bsfile);
        dm = new dct::DCTmodel(dct::rootCert, []{return dct::schemaCert();},
                            []{return dct::identityChain();}, []{return dct::getSigningPair();});
    }
    return *dm;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        print("- usage: {} bundle pubname\n", argv[0]);
        exit(1);
    }
    try {
        auto& dm = getDCTmodel(argv[1]);
        dm.start([&dm,argv](bool success) { if (success) dm.publish(makePub(dm, argv[2])); });
        dm.run();
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    exit(0);
}
