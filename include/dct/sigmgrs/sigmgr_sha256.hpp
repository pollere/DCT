#ifndef SIGMGRSHA256_HPP
#define SIGMGRSHA256_HPP
/*
 * SHA256 Signature Manager
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
 * SigMgr SHA256 provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() computes the SHA256 hash and sets SignatureValue to that value.
 * validate() computes the SHA256 hash over the passed in Data packet's signed
 * portion and compares it to the value in SignatureValue.
 * Signed portion includes up to, not including the Signature Value TLV
 *
 * see https://doc.libsodium.org/ for excellent explanations of the library
 *
 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x00 (this SIGNER Type from signing-info.hpp)
 *  Followed by:
 *  0x17 (SignatureValueType) <number of bytes in signature> <signature bytes>
 */

#include <array>
#include <cstring>

#include "sigmgr.hpp"

struct SigMgrSHA256 final : SigMgr {

    SigMgrSHA256() : SigMgr(stSHA256) { }

    bool sign(crData& d, const SigInfo& si, const keyVal&) override final {
        d.siginfo(si);
        auto sig = d.signature(crypto_hash_sha256_BYTES);
        auto s = d.rest();
        s = s.first(s.size() - sig.size() - 2);
        crypto_hash_sha256(sig.data(), s.data(), s.size());
        return true;
    }

    bool validate(rData d) override final {
        std::array<uint8_t, crypto_hash_sha256_BYTES> dataHash;

        // the hash of the signed portion of the Data must match the packet's signature.
        auto sig = d.signature();
        if (sig.size() - sig.off() != dataHash.size()) { return false; }
        auto strt = d.name().data();
        auto sz = sig.data() - strt;
        crypto_hash_sha256(dataHash.data(), strt, sz);

        if (std::memcmp(sig.data() + sig.off(), dataHash.data(), dataHash.size()) != 0) return false;
        return true;
    }
};

#endif // SIGMGRSHA256_HPP
