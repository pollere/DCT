#ifndef VALIDATE_CERTS_HPP
#define VALIDATE_CERTS_HPP
#pragma once
/*
 * validate certs against a schema
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

#include "bschema.hpp"
#include "certstore.hpp"
#include "dct/format.hpp"

namespace dct {

/*
 * Following routines make use of the low-level binary schema to cross-validate cert and
 * schema information.
 */

// common code of 'matches' and 'startsWith'. caller must check that prefix.size() <= cert.size().
static inline bool matchesPrefix(const bSchema& bs, tlvVec& cert, const bName& prefix) {
    const auto ntok = bs.tok_.size();
    for (auto n = prefix.size(), i=0ul; i < n; i++) {
        if (prefix[i] < ntok && cert[i].toSv() != bs.tok_[prefix[i]]) return false;
    }
    return true;
}

// check if 'cert' matchs schema name 'bcert'
static inline bool matches(const bSchema& bs, tlvVec& cert, const bName& bcert) {
    if (cert.size() != bcert.size()) return false;
    return matchesPrefix(bs, cert, bcert);
}

// check if 'cert' starts with 'prefix'
static inline bool startsWith(const bSchema& bs, tlvVec& cert, const bName& prefix) {
    if (cert.size() < prefix.size()) return false;
    return matchesPrefix(bs, cert, prefix);
}

// check if 'cert' matchs schema cert at index 'sc'
static inline bool matches(const bSchema& bs, tlvVec& cert, const size_t idx) {
    if (idx >= bs.cert_.size()) return false;
    return matches(bs, cert,  bs.cert_[idx]);
}
static inline bool matches(const bSchema& bs, const rName& cert, const size_t idx) {
    auto c = tlvVec{cert};
    return  matches(bs, c, idx);
}

// check if 'cert' matchs any schema cert except the root cert
static inline int matchesAny(const bSchema& bs, tlvVec& cert) {
    if (bs.cert_.size() <= 1) return -1;
    for (int n = bs.cert_.size() - 1, i=0; i < n; i++) if (matches(bs, cert,  i)) return i;
    return -1;
}
static inline int matchesAny(const bSchema& bs, const rName& cert) {
    auto c = tlvVec{cert};
    return matchesAny(bs, c);
}

// check if 'cv' matchs all the certs in schema chain sc
static inline bool matchesAll(const bSchema& bs, certVec& cv, const bChain& sc) {
    if (cv.size() != sc.size()) return false;
    for (size_t n = cv.size(), i=0; i < n; i++) if (! matches(bs, cv[i],  sc[i])) return false;
    return true;
}

// check if 'cert' matchs one of the schema's pub signing certs
static inline int matchesChain(const bSchema& bs, const certStore& cs, const dctCert& cert) {
    auto chn = cs.chainNames(cert);
    for (int n = bs.chain_.size(), i=0; i < n; i++) if (matchesAll(bs, chn, bs.chain_[i])) return i;
    return -1;
}

// check that schema 'bs' cert name component correspondences indexed by 'ci'
// hold for vector of cert names 'cv'.
static inline bool validateChainCors(const bSchema& bs, certVec&& cv, coridx ci) {
    for (const auto [n1, c1, n2, c2] : bs.cor_[ci]) {
        if (n1 > 0 && cv[n1-1][c1].toSv() != cv[n2-1][c2].toSv()) return false;
    }
    return true;
}

// validate the entire signing chain of 'cert' against schema 'bs'. 'cert' must be a signing cert.
// 'cert' doesn't need to be in certStore 'cs' but all the other certs of the chain must be.
static inline int validateChain(const bSchema& bs, const certStore& cs, const dctCert& cert) {
    auto c = matchesChain(bs, cs, cert);
    if (c < 0) return c; // chain doesn't match any schema chain

    // if schema has any cors, check cors for all the discrims that include this chain
    if (bs.cor_.size() == 0) return c; // no cors - done
    auto chn = 1u << c;
    for (const auto& d : bs.discrim_) {
        if ((d.cbm & chn) == 0) continue;           // not this chain
        if (bs.cor_[d.cor].size() == 0) continue;   // no cors
        if (! validateChainCors(bs, cs.chainNames(cert), d.cor)) return -1;
    }
    return c;
}

static inline auto getSigMgr(const bSchema& bs) { return sigMgrByType(bs.pubVal("#pubValidator").substr(1)); }
static inline auto getCertSigMgr(const bSchema&) { return sigMgrByType("EdDSA"s); }
static inline auto getWireSigMgr(const bSchema& bs) { return sigMgrByType(bs.pubVal("#wireValidator").substr(1)); }

} // namespace dct

#endif // VALIDATE_CERTS_HPP
