#ifndef IDENTITY_ACCESS_HPP
#define IDENTITY_ACCESS_HPP
#pragma once
/*
 * Provides functions to parse a bootstrap file that contains the certs needed by a DeftT instance:
 *      0: the trust anchor
 *      1: the schema
 *      2..n-2: signing cert's signing chain
 *      n-1: signing cert and its key
 *
 * This alters identity_access.hpp for use with Relays that have multiple DeftT shims. There is
 * a single trust root for all the DeftTs but schemas and identity chains may be different. Identity
 * chains may be the same and should have overlap but this is just going to make multiple
 * copies. This approach will make it easier to test schemas for compatiblity (i.e. some overlap
 * in publication definition) for future use.
 *
 * Provides functions for access to the root of trust, the schema, the identiy chain, and the
 * current signing pair (cert plus secret key) that can be used in lambdas passed to DeftT shims
 * at creation.
 * The locally created cert plus secret key is returned by currentSigningPair. This would be done
 * in TPM or TEE in a deployment.
 * All validation is done in DeftT modules.
 *
 * As trust anchors and secret identities MUST be securely configured in a real deployment,
 * this provides stand-in methods for ones that would access securely configured information.
 * Note that the rest of the identity chain and the schema are validated based on the trust
 * anchor so may be distributed differently.
 *
 * Copyright (C) 2020-23 Pollere LLC
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

#include <string_view>
#include "dct/schema/cert_bundle.hpp"
#include "dct/schema/signed_cert.hpp"
#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"

namespace dct {

std::vector<std::vector<dctCert>> idChain{};
static inline dctCert root{};
static inline std::vector<dctCert> schema{};
static inline std::vector<keyVal> idSecretKey{};     // use to sign new locally created signing pairs
static inline std::vector<certItem> signingPair{};   // current signing key and cert

static inline dctCert rootCert() { return root; }
static inline dctCert schemaCert(int i=0) { return schema[i]; }
static inline std::vector<dctCert> identityChain(int i=0) { return idChain[i]; }

/*
 * XXXX new signing pairs are set up to be made certOverlap (set in dct_model.hpp) before the end of the current pair's validity
 * period (see the oneTime method in the dct_model constructor and in getNewSp() in dct_model.hpp). These, certOverlap in
 * particular, need to be set somewhere convenient to app maker
 */
static constexpr std::chrono::seconds certLifetime = std::chrono::hours(24);     // XXX signing key lifetime should come from schema

// 'bootstrap' is a cert bundle file containing the information needed to start a DeftT instance:
// This routine only parses the file. DeftT functions handle validation.

static inline void readBootstrap(std::string_view bootstrap) {
    // cb is made up of certItems - pair <dctCert,keyVal> where all keyVals are empty except last
    auto cb = rdCertBundle(fileToVec(bootstrap));
    if(cb.size() < 3) {
        print("readBootstrap for shim {} only has {} certs when at least 3 are needed\n", root.size(), cb.size());
        exit(0);
    }
    // first item must be a trust anchor - to be validated by the DeftT
    if (! root.size())
        root = cb[0].first;
    else if ((cb[0].first).computeThumbPrint() != root.computeThumbPrint()) {
        print("readBootstrap for shim {} has different root of trust\n", schema.size());
        exit(0);
    }
    // schema is next
    schema.push_back(cb[1].first);
    // extract the identity chain of certs
    std::vector<dctCert> ic{};
    for (size_t c = 2; c < cb.size(); c++) {
        ic.push_back(cb[c].first);     //add to
    }
    idChain.push_back(ic);  // add this identity chain to the vector
    idSecretKey.push_back(cb.back().second);    // final item in chain has the secret key
}

// if not yet created (or if expired) create a new key pair, make a dctCert with the public key,
// and use the idSecretKey to sign it.
// This should be called by the bootstrap validation modules after everything else passes
// Also on expiration of signing pair

// Assumes the initial pairs are made in-order as each DeftT shim is made which is fine since that's
// the way it's done in the relays but this can be altered if needed
static inline certItem currentSigningPair(int i=0) {
    if(std::cmp_equal(signingPair.size(), i)) {
         try {
             // make a signature manager of the correct type and set it up to use the identity key for signing
            auto sm{sigMgrByType(root.getSigType())};
            sm.ref().updateSigningKey(idSecretKey[i], idChain[i].back());
            // makes a public/secret key pair, then  a cert with public key and signs it
            // the signing cert has a distinguishing component appended to the identity cert's unique name
            // (the last four components of a DCT cert name are pre-defined)
            // Lifetime of the cert can be set as desired (here 1 day) but the code to automatically make a
            // new signing pair hasn't been done yet.
            // Extract the component used in the signing cert (here "sgn") from the schema in future
            signingPair.push_back( signedCert(crName(idChain[i].back().name().first(-4)/"sgn"), sm.ref(), certLifetime) );
         } catch (const std::runtime_error& se)     { print("runtime error: {}\n", se.what()); }
    } else if (std::cmp_greater(i, signingPair.size())) {
        print ("currentSigningPair called with out-of-range id {}\n", i);
        exit (0);
    }
    return signingPair[i];
}
// Makes a new signing pair for ith (defaults to zero) identiy chain on-demand. Does not store the pair
// Optionally pass in which idchain this is for (relays).
// The lifetime should come from configuration (schema eventually)
// An alternative to currentSigningPair above
// Note that currently can only create a new signing pair with the same name and an updated validity period
// since changing signing chain requires a new DeftT
// In setting the validity start period for a future time, make sure you know what you are doing

static inline certItem getSigningPair( int i=0) {
    if(std::cmp_greater(idChain.size(), i)) {   //must be an identity chain for i
         try {
             // make a signature manager of the correct type and set it up to use the identity key for signing
            auto sm{sigMgrByType(root.getSigType())};
            sm.ref().updateSigningKey(idSecretKey[i], idChain[i].back());
            // makes a public/secret key pair, then  a cert with public key and signs it
            // the signing cert has a distinguishing component appended to the identity cert's unique name
            // (the last four components of a DCT cert name are pre-defined)
            // Lifetime of the cert can be set as desired (here 1 day)
            // Not currently a way to separately set the validity period start time (that is, starts now) in the library
            // Extract the component used in the signing cert (here "sgn") from the schema in future
            // If the last element (the start time) is not set, it uses now
           return signedCert(crName(idChain[i].back().name().first(-4)/"sgn"), sm.ref(), certLifetime+2*certOverlap); // , std::chrono::system_clock::now());
         } catch (const std::runtime_error& se)     { print("getSigningPair runtime error: {}\n", se.what()); }
    } else  {
        print ("getSigningPair called with out-of-range identity chain id {}\n", i);
        exit (0);
    }
    return certItem{};
}

} // namespace dct

#endif // IDENTITY_ACCESS_HPP
