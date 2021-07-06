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
 * (NFD reserved values 0x01 RSASHA256, 0x04 HMACSHA256, 0x03 ECDSA
 *  are not implemented in DCT but an interested user could add them)
 *  0x00 SHA256
 *  0x07 AEAD
 *  0x08 EdDSA
 *  0x09 RFC7693
 *  0x0a NULL
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
#include "sigmgr_null.hpp"

using namespace std::string_literals;

template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
template<class... Ts> overload(Ts...) -> overload<Ts...>;

using Variants = std::variant<SigMgrSHA256,SigMgrAEAD,SigMgrRFC7693,SigMgrNULL,SigMgrEdDSA>;

struct SigMgrAny : Variants {
    using Variants::Variants;

    // return a reference to whichever sigmgr is in the variant
    SigMgr& ref() const noexcept { return (SigMgr&)*this; }

    // validate 'd' using whichever sigmgr is set in the variant
    bool validate(const ndn::Data& d) { return ref().validate(d); }
    bool validateDecrypt(ndn::Data& d) { return ref().validateDecrypt(d); }
    bool validate(const ndn::Data& d, const dct_Cert& c) { return ref().validate(d, c); };

    bool needsKey() const noexcept { return ref().needsKey(); };
};

static inline const std::unordered_map<std::string,uint8_t> sigmgr_name_to_type {
    {"SHA256"s,  SigMgr::stSHA256},
    {"AEAD",     SigMgr::stAEAD},
    {"EdDSA"s,   SigMgr::stEdDSA},
    {"RFC7693"s, SigMgr::stRFC7693},
    {"NULL"s,    SigMgr::stNULL}
};

static inline SigMgrAny sigMgrByType(uint8_t type) {
    switch (type) {
        case SigMgr::stSHA256:  return SigMgrSHA256();
        case SigMgr::stAEAD:    return SigMgrAEAD();
        case SigMgr::stEdDSA:   return SigMgrEdDSA();
        case SigMgr::stRFC7693: return SigMgrRFC7693();
        case SigMgr::stNULL:    return SigMgrNULL();
    }
    throw std::runtime_error(format("sigMgrByType: unknown signer type {}", type));
}

[[maybe_unused]]
static inline SigMgrAny sigMgrByType(std::string_view sv) {
    std::string s(sv);
    if (! sigmgr_name_to_type.contains(s)) throw std::runtime_error(format("sigMgrByType: unknown signer type {}", s));
    return sigMgrByType(sigmgr_name_to_type.at(s));
}

#endif //SIGMGR_BY_TYPE_HPP
