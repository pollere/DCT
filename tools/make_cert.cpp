/*
 * mkcert <name> - create a self-signed DCT cert with NDN name <name>
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
#include <tuple>

#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"
#include "dct/schema/cert_bundle.hpp"
#include "dct/schema/signed_cert.hpp"

using namespace dct;

void usage(const char** argv) {
    print("- usage: {} [-s sigType] [-o outfile] name [signer]\n", argv[0]);
    exit(1);
}

int main(int argc, const char* argv[]) {
    const char* sigType = "EdDSA";
    const char* outfile = "tmp.cert";
    const char* name{};
    const char* signer{};

    if (argc < 2 || argc > 7) usage(argv);

    const char** ap = argv + 1;
    const char** ape = argv + argc;
    if (std::string_view(*ap) == "-s") {
        if (ape - ap <= 2) usage(argv);
        ap++;
        sigType = *ap++;
    }
    if (std::string_view(*ap) == "-o") {
        if (ape - ap <= 2) usage(argv);
        ap++;
        outfile = *ap++;
    }
    if (ape - ap < 1) usage(argv);
    name = *ap++;
    if (ape - ap > 0) signer = *ap++;

    try {
        auto sm{sigMgrByType(sigType)};
        if (signer) {
            auto [scert, key] = rdCertBundle(fileToVec(signer))[0];
            sm.ref().updateSigningKey(key, scert);
        }
        auto [cert, sk] = signer? signedCert(crName(name), sm.ref()) : selfSignedCert(crName(name), sm.ref());
        
        std::ofstream os{outfile, std::ios::binary};
        os.write((char*)cert.data(), cert.size());
        // for now, make the sk a tlv 'signature' object following the cert.
        os.put(23);
        os.put(sk.size());
        os.write((char*)sk.data(), sk.size());
    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
