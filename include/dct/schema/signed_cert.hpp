#ifndef SIGNED_CERT_HPP
#define SIGNED_CERT_HPP
/*
 * Construct a Certificate containing a schema
 *
 * Copyright (C) 2020-2 Pollere LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <string_view>
#include <tuple>

#include "dct_cert.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"


/**
 * Create a public/private keypair
 */
static inline std::pair<keyVal,keyVal> createKeypair() {
    //libsodium set up
    if (sodium_init() == -1) throw std::runtime_error("Connect unable to set up libsodium");

    // generate a secret key and corresponding public key
    keyVal pk(crypto_sign_PUBLICKEYBYTES);
    keyVal sk(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    return {pk, sk};
}

/**
 * Create a signed DCT cert
 *
 *  @nm     is the base cert name. The 4 additional components required for a
 *          valid cert name will be appended.
 *
 *  @sm     a sigmgr appropriate for signing this cert. The sigmgr must have
 *          been setup with the appropriate signing key and locator.
 *
 *  @returns a pair consisting of the signed cert and its signing key
 */
static inline std::pair<dctCert,keyVal> signedCert(crName&& nm, SigMgr& sm,
        std::chrono::seconds lifetime = std::chrono::days(365),
        std::chrono::system_clock::time_point strt = std::chrono::system_clock::now()) {
    auto [pk, sk] = createKeypair();
    return {dctCert(std::move(nm), pk, sm, strt, lifetime), sk};
}

/**
 * Create a self-signed DCT cert
 *
 *  @nm     is the base cert name. The 4 additional components required for a
 *          valid cert name will be appended.
 *
 *  @sm     a sigmgr appropriate for signing this cert
 *
 *  @returns a pair consisting of the signed cert and its signing key
 */
static inline std::pair<dctCert,keyVal> selfSignedCert(crName&& nm, SigMgr& sm) {
    auto [pk, sk] = createKeypair();
    sm.addKey(sk);
    return {dctCert(std::move(nm), pk, sm), sk};
}

#endif // SIGNED_CERT_HPP
