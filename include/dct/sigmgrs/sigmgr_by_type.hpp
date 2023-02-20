#ifndef SIGMGR_BY_TYPE_HPP
#define SIGMGR_BY_TYPE_HPP
#pragma once
/*
 * Return a sigmgr given its signer type or name
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
 * This routine returns the sigmgr appropriate for some signer type.
 * A std::variant is used for the return value so sigmgr can be stack
 * allocated and subject to compiler RVO. 
 *
 * List of Signature-managers by SIGNER_TYPE:
 * (Note: in case DCT is being used with the NDN forwarder of named-data.net, its values of
 * 0x01 RSASHA256, 0x04 HMACSHA256, 0x03 ECDSA are not used in DCT.)
 *  0x00 SHA256
 *  0x07 AEAD
 *  0x08 EdDSA
 *  0x09 RFC7693
 *  0x0a NULL
 *  0x0b PPAEAD
 *  0x0c PPSIGN
 *  0x0d AEADSGN
 */
#include <string>
#include <string_view>
#include <variant>
#include <unordered_map>
#include "../format.hpp"
#include "sigmgr_aead.hpp"
#include "sigmgr_eddsa.hpp"
#include "sigmgr_rfc7693.hpp"
#include "sigmgr_sha256.hpp"
#include "sigmgr_ppaead.hpp"
#include "sigmgr_ppaeadsgn.hpp"
#include "sigmgr_aeadsgn.hpp"
#include "sigmgr_null.hpp"

namespace dct {

using namespace std::string_literals;

template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
template<class... Ts> overload(Ts...) -> overload<Ts...>;

using Variants = std::variant<SigMgrSHA256,SigMgrAEAD,SigMgrRFC7693,SigMgrNULL,SigMgrEdDSA,SigMgrPPAEAD,SigMgrPPSIGN,SigMgrAEADSGN>;

struct SigMgrAny : Variants {
    using Variants::Variants;

    // return a reference to whichever sigmgr is in the variant
    SigMgr& ref() const noexcept { return (SigMgr&)*this; }

    // invoke methods of whichever sigmgr is set in the variant
    bool sign(crData& d) { return ref().sign(d); }
    bool sign(crData& d, const SigInfo& s) { return ref().sign(d, s); }
    bool sign(crData& d, const SigInfo& s, const keyVal& k) { return ref().sign(d, s, k); }
    bool validate(rData d) { return ref().validate(d); }
    bool validate(rData d, const rData& c) { return ref().validate(d, c); }
    bool validateDecrypt(rData d) { return ref().validateDecrypt(d); }
    bool validateDecrypt(rData d, const rData& c) { return ref().validateDecrypt(d, c); };

    void addKey(keyRef k, uint64_t ktm = 0) { ref().addKey(k, ktm); }
    void addKey(keyRef k, keyRef s) { ref().addKey(k, s); };
    void updateSigningKey(keyRef k, const rData& c) { ref().updateSigningKey(k, c); }
    void setKeyCb(KeyCb&& kcb) { ref().setKeyCb(std::move(kcb)); }

    bool needsKey() const noexcept { return ref().needsKey(); }
};

static inline const std::unordered_map<std::string,uint8_t> sigmgr_name_to_type {
    {"SHA256"s,  stSHA256},
    {"AEAD"s,    stAEAD},
    {"EdDSA"s,   stEdDSA},
    {"RFC7693"s, stRFC7693},
    {"NULL"s,    stNULL},
    {"PPAEAD"s,  stPPAEAD},
    {"PPSIGN"s,  stPPSIGN},
    {"AEADSGN"s, stAEADSGN}
};

static inline SigMgrAny sigMgrByType(uint8_t type) {
    switch (type) {
        case stSHA256:  return SigMgrSHA256();
        case stAEAD:    return SigMgrAEAD();
        case stEdDSA:   return SigMgrEdDSA();
        case stRFC7693: return SigMgrRFC7693();
        case stNULL:    return SigMgrNULL();
        case stPPAEAD:  return SigMgrPPAEAD();
        case stPPSIGN:    return SigMgrPPSIGN();
        case stAEADSGN: return SigMgrAEADSGN();
    }
    throw std::runtime_error(format("sigMgrByType: unknown signer type {}", type));
}

[[maybe_unused]]
static inline SigMgrAny sigMgrByType(std::string_view sv) {
    std::string s(sv);
    if (! sigmgr_name_to_type.contains(s)) throw std::runtime_error(format("sigMgrByType: unknown signer type {}", s));
    return sigMgrByType(sigmgr_name_to_type.at(s));
}

} // namespace dct

#endif //SIGMGR_BY_TYPE_HPP
