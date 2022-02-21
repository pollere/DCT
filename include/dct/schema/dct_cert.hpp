#ifndef DCTCERT_HPP
#define DCTCERT_HPP
/*
 * Data Centric Transport schema certificate  abstraction
 *
 * Copyright (C) 2020-2 Pollere LLC
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

extern "C" {
#include <sodium.h>
}
#include <algorithm>
#include <array>
#include <string_view>

#include "dct/sigmgrs/sigmgr.hpp"
#include "rpacket.hpp"

constexpr size_t thumbPrint_s{crypto_hash_sha256_BYTES};
using thumbPrint = std::array<uint8_t,thumbPrint_s>;
// XXX would be nice if std:array had its own hash specialization
template<> struct std::hash<thumbPrint> {
    size_t operator()(const thumbPrint& tp) const noexcept {
        return std::hash<std::u8string_view>{}({(char8_t*)tp.data(), tp.size()});
    }
};

using certName = ndn::Name;

struct dctCert : ndn::Data {
    // dctCert is a certificate that has contraints on its key locator (which are checked at
    // sign/validate time). dctCert is derived from ndn::Data

    dctCert(const ndn::Data& p) { *this = reinterpret_cast<const dctCert&>(p); }
    dctCert(ndn::Data&& p) { *this = std::move(reinterpret_cast<dctCert&&>(p)); }

    // construct a dctCert with the given name. The name will be suffixed with the
    // 4 required NDN components (KEY/<kid>/<creator>/<creationTime>), have content type
    // 'key', a 1 hour freshness period, a 1 year validity period and signed with 'sm'.
    dctCert(const certName& name, const keyVal& pk, SigMgr& sm) {
        std::array<uint8_t, 4> kId;  //hash pk to get key Id
        crypto_generichash(kId.data(), kId.size(), pk.data(), pk.size(), NULL, 0);
        auto now = std::chrono::system_clock::now();
        auto nm = name;
        nm.append("KEY").append(kId.data(), kId.size()).append("dct") .appendTimestamp(now);
        setName(nm);

        getMetaInfo().setType(ndn_ContentType_KEY);
        getMetaInfo().setFreshnessPeriod(std::chrono::hours(1));
        setContent(pk.data(), pk.size());

        /* Set Validity Period to 1-year
         * 0xFD Validity Period 0xFE NotBefore 0xFF Not After
         * (ValidityPeriod(now, now + std::chrono::hours(1 * 365 * 24)));
         * notBefore  number of milliseconds since 1970 ndn::MillisecondsSince1970
         * For some reason, wireEncode() doesn't like the ValidityPeriod in the
         * GenericSignature but if don't add its length in, it passes through okay.
         * (Have to insert 0xFD 0x00 before anything larger than 0xFC)
         */
        //Type for Validity Period, length of subfields, notBefore type and length
        std::vector<uint8_t> valPer;
        uint8_t vp[8] = {0xFD, 0x00, 0xFD, 0x26, 0xFD, 0x00, 0xFE, 0x0F};
        valPer.insert(valPer.end(),vp, vp+8);
        auto itt = std::chrono::system_clock::to_time_t(now);
        char iso8601[16];      //space for string terminator
        std::strftime(iso8601, 16, "%G%m%eT%H%M%S", gmtime(&itt));
        valPer.insert(valPer.end(), iso8601, iso8601 + 15);
        uint8_t na[4] = {0xFD, 0x00, 0xFF, 0x0F}; //type and length for notAfter time
        valPer.insert(valPer.end(),na, na+4);
        itt = std::chrono::system_clock::to_time_t(now + std::chrono::hours(1 * 365 * 24));
        std::strftime(iso8601, 16, "%G%m%eT%H%M%S", gmtime(&itt));
        valPer.insert(valPer.end(), iso8601, iso8601 + 15);

        std::vector<uint8_t> sigInfo = sm.getSigInfo();
        sigInfo.insert(sigInfo.end(), valPer.begin(), valPer.end());
        sigInfo[1] += 0x2A;    //Increase Signature Info length field by Validity Period
        if (! sm.sign(*this, sigInfo)) {
          //_LOG_ERROR("dctCert(" << nm << ") signing failed");
          exit(1);
        }
    }
 
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

    static inline thumbPrint computeThumbPrint(const ndn::Data& cert) {
        thumbPrint tp;
        auto certWF = cert.wireEncode();
        crypto_hash_sha256(tp.data(), certWF.buf(), certWF.size());
        return tp;
    }
    static inline const thumbPrint& getKeyLoc(rData data) { return (const thumbPrint&)*data.thumbprint(); }

    static inline const thumbPrint& getKeyLoc(const ndn::Data& data) { return getKeyLoc(rData(data)); }

    const thumbPrint& getKeyLoc() const { return getKeyLoc(*this); }

    auto selfSigned() const { return selfSigned(getKeyLoc()); }

    thumbPrint computeThumbPrint() const { return computeThumbPrint(*this); }

    // return the 'signature type' (tlv 27) byte of 'data'
    static inline auto getSigType(rData data) { return data.sigType(); }
    static inline auto getSigType(const ndn::Data& data) { return getSigType(rData(data)); }
    auto getSigType() const { return getSigType(*this); }
};

template<> struct std::hash<dctCert> {
    size_t operator()(const dctCert& c) const noexcept {
        const auto& e = *c.wireEncode();
        return std::hash<std::string_view>{}({(const char*)e.data(), e.size()});
    }
};
template<> struct std::less<dctCert> {
    bool operator()(const dctCert& a, const dctCert& b) const noexcept {
        return std::less<decltype(*a.wireEncode())>{}(*a.wireEncode(),*b.wireEncode());
    }
};
template<> struct std::equal_to<dctCert> {
    bool operator()(const dctCert& a, const dctCert& b) const noexcept {
        return std::equal_to<decltype(*a.wireEncode())>{}(*a.wireEncode(),*b.wireEncode());
    }
};

//XXX these don't belong here but need to be somewhere and aren't in NDN libs
template<> struct std::hash<ndn::Data> {
    size_t operator()(const ndn::Data& c) const noexcept {
        const auto& e = *c.wireEncode();
        return std::hash<std::string_view>{}({(const char*)e.data(), e.size()});
    }
};
template<> struct std::less<ndn::Data> {
    bool operator()(const ndn::Data& a, const ndn::Data& b) const noexcept {
        return std::less<decltype(*a.wireEncode())>{}(*a.wireEncode(),*b.wireEncode());
    }
};
template<> struct std::equal_to<ndn::Data> {
    bool operator()(const ndn::Data& a, const ndn::Data& b) const noexcept {
        return std::equal_to<decltype(*a.wireEncode())>{}(*a.wireEncode(),*b.wireEncode());
    }
};

#endif // DCTCERT_HPP
