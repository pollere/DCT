#ifndef TLV_HPP
#define TLV_HPP
#pragma once
/*
 * Data Centric Transport c++ TLV defines
 * (from NDN Packet Format Specification 0.3
 *  https://named-data.net/doc/NDN-packet-spec/current/types.html)
 *
 * Copyright (C) 2022 Pollere LLC.
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
#include <array>

namespace dct {

enum class tlv : uint16_t {
    Name = 7,
        // name component types
        Generic = 8,
        Segment = 33,
        csID = 35,
        Timestamp = 36,
        SequenceNum = 37,

    // a DCT cState packet contains exactly 3 TLV blocks in the following order:
    //   7 (Name), 10 (Nonce), 12 (cStateLifetime)
    cState = 5,
        Nonce = 10,
        Lifetime = 12,

    // DCT publications, certs and cAdd PDUs contain exactly 5 TLV blocks in the following order:
    //   7 (Name), 20 (Metainfo), 21 (Content), 22 (SignatureInfo), 23 (SignatureValue)
    //
    // Metainfo can only contain a content type:
    //   cAdd PDUs have Metainfo>ContentType>ContentType_CAdd
    //   msgs have Metainfo>ContentType>ContentType_Blob
    //   certs have Metainfo>ContentType>ContentType_Key
    //
    // A cert's siginfo must contain a validity period, pub and cAdd siginfo must not.
    Data = 6,
        MetaInfo = 20,
            ContentType = 24,
                // Content types
                ContentType_Blob = 0,
                ContentType_Key = 2,
                ContentType_CAdd = 42,
        Content = 21,
        SignatureInfo = 22,
            SignatureType = 27,
                stSHA256 = 0,
                stAEAD = 7,
                stEdDSA = 8,
                stRFC7693 = 9,
                stPPAEAD = 11,
                stPPSIGN = 12,
                stAEADSGN = 13,

            KeyLocator = 28,
            KeyDigest = 29,
            ValidityPeriod = 253,
                NotBefore = 254,
                NotAfter = 255,
        SignatureValue = 23
};

// Routines to construct TLVs at compile time. They result in a std::array
// containing the TLV(s). 

// flatten 'args' into a single array. Used to make one TLV from two
// arrays, one containing the T,L and the other containing L bytes
// of content. Also used to construct a sequence of TLVs.
template<size_t... S>
static constexpr auto tlvFlatten(std::array<uint8_t,S>... args) noexcept {
    constexpr auto s = (0 + ... + sizeof(args));
    std::array<uint8_t,s> r;
    size_t o{};
    ((std::copy(args.begin(), args.end(), r.begin()+o), o += sizeof(args)), ...);
    return r;
}

template<tlv typ, size_t siz, size_t n=((uint16_t(typ) < 253? 1 : 3) + (siz < 253? 1 : 3))>
static consteval auto TLVhdr() {
    //consteval auto n = (uint16_t(typ) < 253? 1 : 3) + (siz < 253? 1 : 3);
    //std::array<uint8_t, 6> h;
    std::array<uint8_t, n> h;
    unsigned int o = 0;
    if (uint16_t(typ) >= 253) {
        h[o++] = 253u;
        h[o++] = uint8_t(uint16_t(typ) >> 8);
    }
    h[o++] = uint8_t(typ);

    if (siz >= 253) {
        h[o++] = 253u;
        h[o++] = uint8_t(siz >> 8);
    }
    h[o++] = uint8_t(siz);
    return h;
}

// wrap 'args' in a tlv of type 'typ'
template<tlv typ, typename... T>
static constexpr auto xTLV(T... args) noexcept {
    constexpr auto s = (0 + ... + sizeof(args));
    return std::to_array<uint8_t>({ uint8_t(typ), s, args...});
}

// construct one tlv of type 'typ' with contents 'arg'
template<tlv typ, size_t S>
static constexpr auto TLV(std::array<uint8_t,S> arg) noexcept { return tlvFlatten(TLVhdr<typ,S>(), arg); }

template<tlv typ>
static constexpr auto TLV(uint8_t arg) noexcept { return std::to_array<uint8_t>({ uint8_t(typ), 1, arg}); }

} // namespace dct

#endif // TLV_HPP
