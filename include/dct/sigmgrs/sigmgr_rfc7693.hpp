#ifndef SIGMGRRFC7693_HPP
#define SIGMGRRFC7693_HPP
/*
 * RFC7693 Signature Manager
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

    SigMgrRFC7693() : SigMgr(stRFC7693, {0x16, 0x03, 0x1b, 0x01, stRFC7693}) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
    }
    bool sign(ndn::Data& data, const SigInfo&, const keyVal&) override final {
        //set up the Signature field then get the Signed Portion of Data from wire format
        auto dataWF = setupSignature(data, m_sigInfo);;
        // get the RFC7693 hash
        std::vector<uint8_t> sigValue (crypto_generichash_BYTES,0);
        crypto_generichash(sigValue.data(), sigValue.size(), dataWF.signedBuf(), dataWF.signedSize(), NULL, 0);
        data.getSignature()->setSignature(sigValue);
        // Encode again to include the signature.
        dataWF = data.wireEncode();
        return true;
    }
    /*
     * ndn::validator has a complex pattern of handing off to ValidatorState, etc
     * Here just return true if success, false if failure (maybe should log the reason)
     */
     bool validate(const ndn::Data& data) override final {
        //get the Signed Portion of Data from wire format
        auto dataWF = data.wireEncode();
        //get its RFC7693 hash
        uint8_t dataHash[crypto_generichash_BYTES];
        crypto_generichash(dataHash, crypto_generichash_BYTES,
                           dataWF.signedBuf(), dataWF.signedSize(), NULL, 0);
        //location of Signature size in bytes (followed by Signature Value)
        const uint8_t* sigVal = dataWF.buf()+dataWF.getSignedPortionEndOffset()+1;
        if((*sigVal) != crypto_generichash_BYTES) {
            //failureCB(data, "SigMgrRFC7693: wrong size Signature Value");
            return false;
        }
        for(auto i=0u; i<crypto_generichash_BYTES; ++i) {
            if(dataHash[i] != *(++sigVal)) {
                //failureCB(data, "Signature Value does not match hash");
                return false;
            }
        }
        return true;
    }
    bool validate(const ndn::Data& data, const dct_Cert&) override final { return validate(data); }

    bool needsKey() const noexcept override final { return 0; };
};

#endif // SIGMGRRFC7693_HPP
