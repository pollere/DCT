/*
 * schema_cert <file> - embed a binary schema in a signed cert
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
#include <string>
#include <string_view>
#include <tuple>
#include "dct/format.hpp"
#include "dct/file_to_vec.hpp"
#include "dct/schema/cert_bundle.hpp"
#include "dct/schema/rdschema.hpp"
#include "dct/schema/schema_cert.hpp"

static void usage(const char** argv) {
    print("- usage: {} [-o outfile] schemaFile [signer]\n", argv[0]);
    exit(1);
}

int main(int argc, const char* argv[]) {
    std::string outfile{};
    if (argc < 2) usage(argv);
    const char** ap = argv + 1;
    if (std::string_view(*ap) == "-o") {
        if (argc < 4) usage(argv);
        outfile = ap[1];
        ap += 2;
    }
    try {
        auto buf = fileToVec(*ap++);
        std::istringstream ss(std::string((char*)buf.data(), buf.size()), std::ios::binary);
        rdSchema rs(ss);
        auto bs = rs.read();

        // schema must be signed the same way as its pubs
        auto valtype = bs.pubVal("#pubValidator").substr(1);
        auto sm{sigMgrByType(valtype)};
        if (sm.ref().needsKey()) {
            if (ap - argv >= argc ) {
                print("- error: schema needs a type {} signing key\n", valtype);
                exit(1);
            }
            auto [signer, key] = rdCertBundle(fileToVec(*ap))[0];
            sm.ref().updateSigningKey(key, signer);
        }
        auto cert = schemaCert(bs, buf, sm.ref());
        auto wfmt = cert.wireEncode();
        if (! outfile.size()) {
            auto v = cert.getName()[0].getValue();
            outfile = std::string((const char*)v.buf(), v.size()).append(bs.pubName(0));
        }
        std::ofstream os{outfile, std::ios::binary};
        os.write((char*)wfmt.buf(), wfmt.size());
        os.close();
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
