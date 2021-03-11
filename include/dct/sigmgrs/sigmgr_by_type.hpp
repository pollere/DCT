#ifndef SIGMGR_BY_TYPE_HPP
#define SIGMGR_BY_TYPE_HPP
/*
 * Return a sigmgr given its signer type or name
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

/*
 * This routine returns the sigmgr appropriate for some signer type.
 * A std::variant is used for the return value so sigmgr can be stack
 * allocated and subject to compiler RVO. 
 *
 * List of Signature-managers by SIGNER_TYPE:
 * (some can't be used generally until ndn-ind issues are fixed)
 *  0x00 SHA256
 *  0x01 RSASHA256 (not yet)
 *  0x03 ECDSA
 *  0x04 HMACSHA256 (not yet)
 *  0x07 AEAD (ndn-ind issues)
 *  0x08 EdDSA (ndn-ind issues)
 *  0x09 RFC7693 (ndn-ind issues)
 */
#include <string>
#include <string_view>
#include <variant>
#include <unordered_map>
//#include "sigmgr_aead.hpp"
#include "sigmgr_ecdsa.hpp"
//#include "sigmgr_eddsa.hpp"
//#include "sigmgr_rfc7693.hpp"
#include "sigmgr_sha256.hpp"

using namespace std::string_literals;

template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
template<class... Ts> overload(Ts...) -> overload<Ts...>;

using Variants = std::variant<SigMgrSHA256,SigMgrECDSA,SigMgrRFC7693>;

struct SigMgrAny : Variants {
    using Variants::Variants;

    // return a reference to whichever sigmgr is in the variant
    SigMgr& ref() { return (SigMgr&)*this; }

    // validate 'd' using whichever sigmgr is set in the variant
    bool validate(ndn::Data& d) { return ref().validate(d); }
};

static inline const std::unordered_map<std::string,uint8_t> sigmgr_name_to_type {
    {"SHA256"s, 0}, {"ECDSA"s, 3}, {"RFC7693"s, 9}
};

static SigMgrAny sigMgrByType(uint8_t type) {
    switch (type) {
        case 0: return SigMgrSHA256();
        case 3: return SigMgrECDSA();
        //case 7: return SigMgrAEAD();
        //case 8: return SigMgrEdDSA();
        case 9: return SigMgrRFC7693();
    }
    throw std::runtime_error(format("sigMgrByType: unknown signer type {}", type));
}

[[maybe_unused]]
static SigMgrAny sigMgrByType(std::string_view sv) {
    std::string s(sv);
    if (! sigmgr_name_to_type.contains(s)) throw std::runtime_error(format("sigMgrByType: unknown signer type {}", s));
    return sigMgrByType(sigmgr_name_to_type.at(s)); }

#endif //SIGMGR_BY_TYPE_HPP
