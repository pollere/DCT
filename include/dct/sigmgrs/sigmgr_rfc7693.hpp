#ifndef SIGMGRRFC7693_HPP
#define SIGMGRRFC7693_HPP
/*
 * RFC7693 Signature Manager
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
 * SigMgr RFC7693 provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() computes the RFC7693 hash and sets SignatureValue to that value.
 * validate() computes the RFC7693 hash over the passed in Data packet's signed
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
 *  0x06 (this SIGNER Type)
 *  Followed by:
 *  0x17 (SignatureValueType) <number of bytes in signature> <signature bytes>
 */

#include <array>

#include "sigmgr.hpp"

struct SigMgrRFC7693 final : SigMgr {

    SigMgrRFC7693() : SigMgr(stRFC7693) { }

    bool sign(crData& d, const SigInfo& si, const keyVal&) override final {
        d.siginfo(si);
        auto sig = d.signature(crypto_generichash_BYTES);
        auto s = d.rest();
        s = s.first(s.size() - sig.size() - 2);
        crypto_generichash(sig.data(), sig.size(), s.data(), s.size(), NULL, 0);
        return true;
    }
    bool validate(rData d) override final {
        //get the Signed Portion of the Data
        auto sig = d.signature();
        if (sig.size() - sig.off() != crypto_generichash_BYTES) {
            //print("rfc7693 size wrong: {}\n", sig.size() - sig.off());
            return false;
        }
        auto strt = d.name().data();
        auto sz = sig.data() - strt;
        //get its RFC7693 hash
        std::array<uint8_t, crypto_generichash_BYTES> dataHash;
        crypto_generichash(dataHash.data(), dataHash.size(), strt, sz, NULL, 0);
        if (std::memcmp(sig.data() + sig.off(), dataHash.data(), dataHash.size()) != 0) return false;
        return true;
    }
};

#endif // SIGMGRRFC7693_HPP
