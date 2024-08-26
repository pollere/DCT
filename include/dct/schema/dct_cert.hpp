#ifndef DCTCERT_HPP
#define DCTCERT_HPP
#pragma once
/*
 * Data Centric Transport schema certificate  abstraction
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

/*
 * DCT certs are compatible with the NDN Certificate standard V2
 * but adhere to a stricter set of conventions to make them resistant
 * to substitution, work factor and DoS attacks. (These conventions
 * are, regrettably, not supported by the security machinery of
 * the ndn-ind or ndn-cxx standard libraries but are handled by
 * DCT's more flexible 'sigmgr' framework.)
 *
 *  - The only KeyLocator type allowed in a DCT cert is a KeyDigest
 *    (tlv 29) that must contain the 32 byte SHA256 digest of the
 *    *entire* signing cert (including signature). A self-signed
 *    cert (such as a trust anchor) must set this digest to all zero.
 *
 *  - This digest, called a cert 'thumbprint' in the DCT code, is
 *    the only locator allowed in *any* signed DCT object (publications,
 *    packets, schemas, certs, etc.) and *must* be present in every
 *    signed object (there is *no* 'default key' notion in DCT).
 *
 *  - Any signed object using a 'Name' locator will be considered
 *    unverifiable and silently ignored.
 *
 *  - The original publisher of any signed object *must* ensure that
 *    that *all* certs, schemas, etc., needed to validate the object
 *    have been published *before* the object is published.
 *
 *  - If some entity receives a signed object but is missing any of
 *    its signing dependencies, the object should be considered
 *    unverifiable and silently ignored. Such objects should *never*
 *    be propagated to other entities.
 */

#include <algorithm>
#include <array>
#include <string_view>

#include "../sigmgrs/sigmgr.hpp"
#include "crpacket.hpp"

// XXX would be nice if std:array had its own hash specialization
template<> struct std::hash<dct::thumbPrint> {
    size_t operator()(const dct::thumbPrint& tp) const noexcept {
        return std::hash<std::u8string_view>{}({(char8_t*)tp.data(), tp.size()});
    }
};

namespace dct {

struct dctCert : crCert {
    // dctCert is a certificate with contraints on its name and key locator
    // (checked at sign/validate time).
    using systime = std::chrono::system_clock::time_point;;
    using seconds = std::chrono::seconds;
    using days = std::chrono::days;

    constexpr dctCert() = default;
    dctCert(rCert d) : crCert(d) { }

    static constexpr auto keyId(keyRef pk) {
        // key ID is a 4-byte hash of the public key.
        std::array<uint8_t, 4> kId;
        crypto_generichash(kId.data(), kId.size(), pk.data(), pk.size(), NULL, 0);
        return kId;
    }
    // construct a dctCert with the given name. The name will be suffixed with the
    // 4 required NDN components (KEY/<kid>/<creator>/<creationTime>), have content type
    // 'key', a validity period starting at 'strt' of duration 'dur' and signed with 'sm'.
    dctCert(crName&& name, keyRef pk, SigMgr& sm, systime strt, seconds dur)
        : crCert(name/"KEY"/keyId(pk)/"dct"/std::chrono::system_clock::now()) {
        content(pk);

        // set up the cert's signature info including a 1 year validity period
        auto vp = TLV<tlv::ValidityPeriod>(tlvFlatten(
                      TLV<tlv::NotBefore>(iso8601(strt)),
                      TLV<tlv::NotAfter>(iso8601(strt + dur))));
        auto sigInfo = sm.getSigInfo();
        sigInfo.insert(sigInfo.end(), vp.begin(), vp.end());
        sigInfo[1] += vp.size();
        if (! sm.sign(*this, sigInfo)) exit(1);
    }

    dctCert(crName&& name, keyRef pk, SigMgr& sm)
     : dctCert(std::move(name), pk, sm, std::chrono::system_clock::now(), days(365)) {}

    dctCert(std::string_view nm, keyRef pk, SigMgr& sm) : dctCert(crName{nm}, pk, sm) {}
 
    // a hash that's 32 bytes of zero is the thumbprint of a "self-signed" cert. The DCT model
    // requires that a thumbprint be cryptographically assured 1-1 mapping to certs. I.e., it
    // must include all three pieces of information that a cert binds together: name, public
    // key and provenance (signing key locator+signature) or the unconstrained binding(s) are
    // easily attacked. This implies that the thumbprint has to (a) include the signature and
    // (b) be covered by the signature. The requirements can be met for everything but
    // self-signed certs where they conflict. But self-signed certs are "self locating" so a
    // reserved locator value meaning "this cert" meets all the requirments.
    static constexpr bool selfSigned(const thumbPrint& t) {
        return std::all_of(t.begin(), t.end(), [](uint8_t b){ return b == 0; });
    }
    auto selfSigned() const { return selfSigned(this->signer()); }

    // return the 'signature type' (tlv 27) byte of 'data'
    static inline auto getSigType(rData data) { return data.sigType(); }
    auto getSigType() const { return getSigType(*this); }
};

} // namespace dct

#endif // DCTCERT_HPP
