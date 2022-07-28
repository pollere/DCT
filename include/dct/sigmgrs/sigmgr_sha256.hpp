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

    SigMgrSHA256() : SigMgr(stSHA256, {0x16, 0x03, 0x1b, 0x01, stSHA256}) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
    }
    bool sign(ndn::Data& data, const SigInfo& si, const keyVal&) override final {
        // get Data in wire format then compute the SHA256 hash of the signed part
        auto dataWF = setupSignature(data, si);
        std::vector<uint8_t> sigValue (crypto_hash_sha256_BYTES,0);
        crypto_hash_sha256(sigValue.data(), dataWF.signedBuf(), dataWF.signedSize());
        data.getSignature()->setSignature(sigValue);


        // Encode again to include the signature.
        dataWF = data.wireEncode();
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
    bool validate(const ndn::Data& d) override final { return validate(rData(d)); }
    bool validate(const ndn::Data& d, const dct_Cert&) override final { return validate(rData(d)); }

    bool needsKey() const noexcept override final { return 0; };
};

#endif // SIGMGRSHA256_HPP
