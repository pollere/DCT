#ifndef MKCERT_HPP
#define MKCERT_HPP
/*
 * Construct a Certificate containing a schema
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

#include <algorithm>
#include <chrono>
#include <concepts>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#include <ndn-ind/security/v2/certificate-v2.hpp>
#include "dct/format.hpp"
#include "dct/sigmgrs/sigmgr.hpp"

using namespace std::literals::chrono_literals;

#define _LOG_INFO(x) {}
     
// augment vector type with an 'append sequence' method
template<typename T, typename V=std::vector<T>>
struct Vec : V {
    using V::V;
    Vec(const V& v) { *(V*)(this) = v; }
    Vec(V&& v) { V::swap(v); }

    template<typename Src> requires requires (T t, Src s) { t = *s.cbegin(); }
    Vec& append(Src s) { V::insert(V::end(), s.begin(), s.end()); return *this; }

    Vec& append(std::initializer_list<T> s) { V::insert(V::end(), s.begin(), s.end()); return *this; }
    Vec& prepend(std::initializer_list<T> s) { V::insert(V::begin(), s.begin(), s.end()); return *this; }
};
 
// construct an ISO 8601 "yyyymmddThhmm" time string from a timepoint
template<typename Time>
auto iso8601(Time timep) { return format("{:%G%m%dT%H%M%S}", fmt::gmtime(timep)); }

/**
 * construct an NDN-compatible cert
 *
 *  @prefix is the base cert name. It will be concatenated with the 4 additional
 *          components required for a valid cert name.
 *
 *  @pk     is a blob of bytes (normally a public key but can be anything)
 *
 *  @signer is a sigmgr appropriate for signing this cert (signing key, if
 *          any, is held in the sigmgr. For a self-signed cert, it could be
 *          the secret key associated with 'pk'.
 *
 *  @returns the signed cert
 */
auto mkCert(const ndn::Name& prefix, const auto& pk, SigMgr& signer,
            std::chrono::seconds validDur = std::chrono::years(1)) {

    // add the four required components to name prefix ("KEY", key fingerprint, Issuer Id and Version)
    //std::array<uint8_t, crypto_hash_sha256_BYTES> kId{};  //hash pk to get key Id
    //crypto_hash_sha256(kId.data(), pk.data(), pk.size());
    std::array<uint8_t, 8> kId{};  // 64-bit random number
    randombytes_buf(kId.data(), kId.size());
    auto now = std::chrono::system_clock::now();
    auto name(prefix);
    name.append("KEY").append(kId.data(), kId.size()).append("schema")
        .appendVersion(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
    // make a CertificateV2 for the public key
    auto pubCert = ndn::CertificateV2();
    pubCert.getMetaInfo().setType(ndn_ContentType_KEY);
    pubCert.getMetaInfo().setFreshnessPeriod(std::chrono::hours(1));
    pubCert.setContent((uint8_t*)pk.data(), pk.size());
    pubCert.setName(name);

    // Set cert's validity period.

    // DER for Validity Period type, length of subfields, notBefore type and length
    Vec<uint8_t> sigInfo = signer.getSignatureInfo();
    Vec<uint8_t> valPer = {0xFD, 0x00, 0xFD, 0x26, 0xFD, 0x00, 0xFE, 0x0F};
    valPer.append(iso8601(now));
    valPer.append({0xFD, 0x00, 0xFF, 0x0F}); //type and length for notAfter time
    valPer.append(iso8601(now + validDur));
    sigInfo.append(valPer);
    sigInfo[1] += valPer.size();    //Increase Signature Info length field by Validity Period
    signer.sign(pubCert, sigInfo);
    return pubCert;
}
#endif // MKCERT_HPP
