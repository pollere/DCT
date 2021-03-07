/*
 * schema_install <file> - install a compiled scheme in the NDN PIB
 *
 * Copyright (C) 2020 Pollere, Inc.
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
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <ndn-ind/security/pib/pib-sqlite3.hpp>
#include "dct/format.hpp"
#include "dct/schema/rdschema.hpp"
#include "dct/schema/schema_install.hpp"

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        print("- usage: {} schemaFile\n", argv[0]);
        exit(1);
    }
    try {
        std::ifstream is{argv[1], std::ios::binary|std::ios::ate};
        auto sz = is.tellg();
        if (sz < 32 || sz > 1200) {
            print("- error: {} file size unreasonable ({} bytes)\n", argv[1], sz);
            exit(1);
        }
        is.seekg(0);
        std::vector<uint8_t> buf(sz);
        if (! is.read((char*)buf.data(), buf.size())) {
            print("- error: couldn't read file {}\n", argv[1]);
            exit(1);
        }
        is.close();
        std::istringstream ss(std::string((char*)buf.data(), buf.size()), std::ios::binary);
        rdSchema rs(ss);
        auto bs = rs.read();
        schemaInstall(bs, buf);
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
