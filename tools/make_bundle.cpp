/*
 * make_bundle -o outfile file ... - make a cert bundle file
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
#include <fstream>
#include <iostream>
#include <string_view>
#include <tuple>
#include <vector>

#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"
#include "dct/schema/cert_bundle.hpp"

using namespace dct;

static void usage(const char** argv) {
    print("- usage: {} [-v] -o outfile file ...\n", argv[0]);
    exit(1);
}

int main(int argc, const char* argv[]) {
    int verbose{};
    const char* outfile{};
    if (argc < 4) usage(argv);
    const char** ap = argv + 1;
    const char** ape = argv + argc;
    if (std::string_view(*ap) == "-v") { verbose++; ap++; };
    if (std::string_view(*ap++) != "-o") usage(argv);
    outfile = *ap++;
    
    try {
        if (verbose) print("{}:\n", outfile);
        std::ofstream os(outfile, std::ios::binary);
        while (ap < ape) {
            auto fname = *ap++;
            bool saveKey = false;
            if (fname[0] == '+') {
                saveKey = true;
                fname++;
            }
            auto buf = fileToVec(fname);
            for (auto&& [cert, key] : rdCertBundle(buf)) {
                os.write((char*)cert.data(), cert.size());
                if (saveKey && key.size()) {
                    os.put(23);
                    os.put(key.size()); //XXX assumes key is < 253 bytes
                    os.write((char*)key.data(), key.size());
                }
                if (verbose) print(" {}cert {}\n", saveKey && key.size()? '+':' ', cert.name());
            }
        }
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
