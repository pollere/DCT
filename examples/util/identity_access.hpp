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
// the second member of the certItem pair will be the identity secret key which is used
// to sign locally created signing pairs. It could be a pointer to storage in secure memory, etc.
static inline std::unordered_map<thumbPrint,certItem>  idPair{};

static inline dctCert rootCert() { return root; }
static inline dctCert schemaCert(int i=0) { return schema[i]; }
static inline std::vector<dctCert> identityChain(int i=0) { return idChain[i]; }
static inline thumbPrint idTag(int i=0) { return rCert(idChain[i].back()).computeTP(); }

/*
 * new signing pairs are set up to be made certOverlap (set in cert_bundle.hpp) before the end of the current pair's validity
 * period (see the oneTime method in the dct_model constructor and in getNewSp() in dct_model.hpp).
 * XXXX These, certOverlap in particular, need to be set somewhere convenient to installer in future
 */
static constexpr std::chrono::seconds certLifetime = std::chrono::hours(24);     // XXX signing key lifetime should come from schema

// 'bootstrap' is a cert bundle file containing the information needed to start a DeftT instance:
// This routine only parses the file. DeftT functions handle validation.

static inline void readBootstrap(std::string_view bootstrap) {
    // cb is made up of certItems - pair <dctCert,keyVal> where all keyVals are empty except last
    auto cb = rdCertBundle(fileToVec(bootstrap));
    if(cb.size() < 3) {
        dct::print("readBootstrap for shim {} only has {} certs when at least 3 are needed\n", root.size(), cb.size());
        exit(0);
    }
    // first item must be a trust anchor - to be validated by the DeftT
    if (! root.size())
        root = cb[0].first;
    else if ((cb[0].first).computeTP() != root.computeTP()) {
        dct::print("readBootstrap for shim {} has different root of trust\n", schema.size());
        exit(0);
    }
    auto etm = rCert(root).validUntil();
    // schema is next
    schema.push_back(cb[1].first);
    // extract the identity chain of certs
    std::vector<dctCert> ic{};
    for (size_t c = 2; c < cb.size(); c++) {
      /*  if (rCert(cb[c].first).validUntil() > etm) {
             dct::print("readBootstrap: cert {}, position {} on chain, valid longer than its signer\n", cb[c].first.name(), c);
            exit(0);
        }
        */
        etm = rCert(cb[c].first).validUntil();
        ic.push_back(cb[c].first);     //add to
    }
    idChain.push_back(ic);  // add this identity chain to the vector
    idPair[(ic.back()).computeTP()] = cb.back();  // final item in cb has the identity cert, secret key pair
}


// if not yet created (or if expired) create a new key pair, make a dctCert with the public key,
// and use the idPair's secret key to sign it.
// This should be called by the bootstrap validation modules after everything else passes
// Also on expiration of signing pair

// Assumes the initial pairs are made in-order as each DeftT shim is made which is fine since that's
// the way it's done in the relays but this can be altered if needed

// Makes a new signing pair for ith (defaults to zero) identity chain on-demand. Does not store the pair
// Called by the bootstrap validation modules after everything else passes and on expiration of signing pair
// Optionally pass in which idchain this is for (relays) and tdvc adjustment
// The lifetime should come from configuration (schema eventually)
// An alternative to currentSigningPair above
// Note that currently can only create a new signing pair with the same name and an updated validity period
// since changing signing chain requires a new DeftT
// With tdvc use, can incorporate tdvcAdjust value so needs to be passed in and added to now() (default to 0)
// The validity start period MUST be no farther in past than certOverlap/2 + (now + tdvcAdjust) and the
// cert must be valid (against now + tdvcAdjust)
// To handle clock skew, certOverlap is set to at least twice the worst clock skew

static inline certItem getSigningPair(const thumbPrint& itp, std::chrono::microseconds a=0us) {
    if(idPair.contains(itp)) {   //must be an identity key pair for itp
         try {
             // make a signature manager of the correct type and set it up to use the identity key for signing
            auto sm{sigMgrByType(root.getSigType())};
            auto k = idPair[itp].second;
            auto c = idPair[itp].first;
            sm.ref().updateSigningKey(k, c);
            auto now = std::chrono::system_clock::now() + a;
            if ( rCert(c).validUntil() <= now || rCert(c).validAfter() >= now) {
                dct::print("getSigningPair called with invalid (by validity time) identity cert:\n\tvalidUntil {}, validAfter {}, vclk {}\n",
                            rCert(c).validUntil(), rCert(c).validAfter(), now);
                exit(0);
            }
            // signing cert must not outlive the identity that signs it
            auto lt = certLifetime + certOverlap;
            if (lt > rCert(c).validUntil() - now - certOverlap/2)
                lt = std::chrono::duration_cast<decltype(lt)> (rCert(c).validUntil() - now - certOverlap/2);
            // makes a public/secret key pair, then  a cert with public key and signs it
            // the signing cert has a distinguishing component appended to the identity cert's unique name
            // (the last four components of a DCT cert name are pre-defined)
            // Lifetime of the cert can be set as desired (here 1 day)
            // Extract the component used in the signing cert (here "sgn") from the schema in future
            // If the last element (the start time) is not set, it uses now
            return signedCert(crName(c.name().first(-4)/"sgn"), sm.ref(), lt, now-certOverlap/2);
         } catch (const std::runtime_error& se)     { dct::print("getSigningPair runtime error: {}\n", se.what()); }
    } else  {
        dct::print ("getSigningPair called with invalid id cert thumbprint {}\n", itp);
        exit (0);
    }
    return certItem{};
}

} // namespace dct

#endif // IDENTITY_ACCESS_HPP
