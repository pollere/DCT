#ifndef SIGMGRECDSA_HPP
#define SIGMGRECDSA_HPP
/*
 * ECDSA Signature Manager
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
 * SigMgr ECDSA provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() sets the SignatureInfoEncoding (a Blob of the SignatureInfo),
 * computes the SHA256 hash and sets SignatureValue to the public key signature
 * of that value.
 * validate() computes the SHA256 hash over the passed in Data packet's signed
 * portion, the signature of that, and compares it to the value in SignatureValue.
 * Signed portion includes the key locator - up to, not including the Signature Value TLV
 *
 * see https://doc.libsodium.org/ for excellent explanations of the library
 *
 */

/*
* From: https://named-data.net/doc/NDN-packet-spec/current/signature.html#keylocator:
* SignatureSha256WithEcdsa defines an ECDSA public key signature that is calculated over
* the SHA-256 hash of the “signed portion” of an Interest or Data packet. This signature
* algorithm is defined in RFC 5753, Section 2.1. All NDN implementations MUST support
* this signature type with the NIST P-256 curve.
* The KeyDigest option in KeyLocator is defined as the SHA-256 digest of the DER encoding
* of the SubjectPublicKeyInfo for an EC key as defined by RFC 5480.
* The value of SignatureValue of SignatureSha256WithEcdsa is a DER-encoded Ecdsa-Sig-Value
*  structure as defined in RFC 3279, Section 2.2.3.
*
* The TLV-VALUE of SignatureType is 3
* KeyLocator is required
*/

extern "C" {
    #include <openssl/ssl.h>
};

/*
 * The SignatureInfo content for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo through the key Name>
 *  0x1b followed by 0x01, 0x03 (this SIGNER Type from signing-info.hpp)
 * (Signature Type 0x01 for signed by RSA key, 0x03 for signed by ECDSA key)
 *  0x1c (indicates KeyLocator type)<number of octets in Name>
 *  <Name of Key><KEY><key Id>
 * Must compute the number of octets in the key Name and fill in the relevant
 * two fields. This can be done once at initialization for the signing key.
 * (Just using the ndn::keyChain::sign() presently)
 *  Followed by:
 *  0x17 (SignatureValueType) <number of bytes in signature> <signature bytes>
 * These fields are computed for each Data
 */

#include <array>

#include "sigmgr.hpp"

#include <ndn-ind/security/key-chain.hpp>

struct SigMgrECDSA final : SigMgr {

    SigMgrECDSA() : SigMgr(3) {}

    // signs with this name: getDefaultCertificateName()
    bool sign(ndn::Data& data) override final { 
        m_kc.sign(data);
        // Encode again to include the signature.     
        auto dataWF = data.wireEncode();
        return true;
    }
    bool sign(ndn::Data& data, const SigInfo& si) override final { 
        ndn::SigningInfo  signinfo(std::string{}); //XXX
        if (si.size() > 0) { //XXX
            auto now = std::chrono::system_clock::now();
            signinfo.setValidityPeriod({now, now + std::chrono::years(1)});
        }
        m_kc.sign(data, signinfo);
        // Encode again to include the signature.     
        auto dataWF = data.wireEncode();
        return true;
    }
    /*
     * Return true if success, false if failure
     * (Should log the reason)
     */
     bool validate(ndn::Data& data) override final {
        auto dataWF = data.wireEncode();
        //get SHA256 hash of the Signed Portion of Data
        uint8_t dataHash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(dataHash, dataWF.signedBuf(), dataWF.signedSize());

        //compute ECDSA public key signature of SHA256 hash
        if (! ndn::KeyLocator::canGetFromSignature(data.getSignature())) return false;
        const ndn::KeyLocator& kl(ndn::KeyLocator::getFromSignature(data.getSignature()));
        if (kl.getType() != ndn_KeyLocatorType_KEYNAME) return false;
        const auto& keyname = kl.getKeyName();

        // Uses key locator key prefix to get the identity
        // getPublicKey() returns the Der format in a Blob
        auto pkDer = m_kc.getPib().getIdentity(keyname.getPrefix(-2))->getKey(keyname)->getPublicKey();
        const uint8_t* pk = pkDer.buf();

        // Set digest to the digest of the signed portion of the signedBlob.
        // first parameter (type) is ignored
        //location of Signature size in bytes (followed by Signature Value)
        int sigLen = *(dataWF.buf()+dataWF.getSignedPortionEndOffset()+1);
        const uint8_t* sigVal = dataWF.buf()+dataWF.getSignedPortionEndOffset()+2;
        if(ECDSA_verify(0, dataHash, crypto_hash_sha256_BYTES, sigVal, sigLen,
                        d2i_EC_PUBKEY(NULL, &(pk), pkDer.size())) != 1) {
            return false;
        }
        return true;
    }

    ndn::KeyChain m_kc{};
};

#endif // SigMgrECDSA_HPP
