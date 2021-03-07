#ifndef SIGMGRSHA256_HPP
#define SIGMGRSHA256_HPP
/*
 * SHA256 Signature Manager
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
 * SigMgr SHA256 provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() sets the SignatureInfoEncoding (a Blob of the SignatureInfo),
 * computes the SHA256 hash and sets SignatureValue to that value.
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

    SigMgrSHA256() : SigMgr(0, {0x16, 0x03, 0x1b, 0x01, 0x00}) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
    }
    bool sign(ndn::Data& data, const SigInfo& si) override final {
        // get Data in wire format then compute the SHA256 hash of the signed part
        auto dataWF = setupSignature(data, si);
        std::array<uint8_t, crypto_hash_sha256_BYTES> sigVal;
        crypto_hash_sha256(sigVal.data(), dataWF.signedBuf(), dataWF.signedSize());
        data.getSignature()->setSignature(ndn::Blob(sigVal.data(), sigVal.size()));
        // Encode again to include the signature.
        dataWF = data.wireEncode();
        return true;
    }
    /*
     * ndn::validator has a complex pattern of handing off to ValidatorState, etc
     * Here just return true if success, false if failure
     * (Should log the reason)
     */
     bool validate(ndn::Data& data) override final {
        //get the Signed Portion of Data from wire format
        auto dataWF = data.wireEncode();
        //get its SHA256 hash
        std::array<uint8_t, crypto_hash_sha256_BYTES> dataHash;
        crypto_hash_sha256(dataHash.data(), dataWF.signedBuf(), dataWF.signedSize());
        //location of Signature size in bytes (followed by Signature Value)
        const uint8_t* sigVal = dataWF.buf()+dataWF.getSignedPortionEndOffset()+1;
        if(*sigVal++ != dataHash.size()) return false;

        return std::memcmp(sigVal, dataHash.data(), dataHash.size()) == 0;
    }
    bool needsKey() const noexcept override final { return 0; };
};

#endif // SIGMGRSHA256_HPP
