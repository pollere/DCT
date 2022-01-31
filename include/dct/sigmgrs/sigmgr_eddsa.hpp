#ifndef SIGMGREdDSA_HPP
#define SIGMGREdDSA_HPP
/*
 * EdDSA Signature Manager
 *
 * Copyright (C) 2020-2 Pollere LLC
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
 * SigMgr EdDSA provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() sets SignatureValue.
 * validate() computes the SHA256 hash over the passed in Data packet's signed
 * portion, the signature of that, and compares it to the value in SignatureValue.
 * Signed portion includes the key locator - up to, not including the Signature Value TLV
 *
 * see https://doc.libsodium.org/ for excellent explanations of the library
 *
 */

/*
 * SignatureBlake2bWithEdDSA defines an EdDSA public key signature that is calculated over
 * the Blake2b hash of the “signed portion” of a Data packet.
 * Requires a signing key and access to the public key's of signers of
 * received Data.
 *
 * The TLV-VALUE of SignatureType is 8
 * KeyLocator is required
 */

/*
 * The SignatureInfo content for this signing method starts with fixed 5 bytes:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo through the key Identity>
 *  0x1b followed by 0x01, 0x08 (this SIGNER Type)
 * (Signature Type 0x08 for signed by EdDSA key)
 *  0x1c (indicates KeyLocator type)<number of octets in Key Locator> followed by
 *   0x1d (indicates KeyDigest locator)<number of octets in Key Digest> followed by
 *    <SHA256 'thumbprint' of signing certificate (including its signature) with
 *     32 bytes of zero indicating "self-signed">
 *
 * Since thumbprints are fixed length (32 bytes), the entire locator preamble can
 * be built at initialization time and the thumbprint added when the signing key.
 * is updated.
 *
 *  Followed by: 0x17 (SignatureValueType) then
 *   <number of bytes in signature> <signature bytes>
 *      fields that are computed for each Data
 */

#include <array>
#include "sigmgr.hpp"
#include "dct/schema/dct_cert.hpp"

/*
 * The sigInfo this signature manager uses stays the same for a
 * particular signing key. Can extract the needed information from
 * the dct certificate or create it from the signing key name.
 * Here passing in the function to get signing key and the name,
 * but could change this to a function to get the cert and then
 * extract other information from the cert
 *
 * To validate, this sigmgr needs the public signing key of the sender.
 * This may be provided by the function that is calling validate() in the future,
 * but for now, there is a callback, m_keyCb that passes in the key locator (from
 * the packet) and a holder for a returned signing key. This cb is set using setKeyCb()
 * and if it is not set, then, can't validate. Would expect to set it with a lambda from
 * the parent function that looks like:
 * [this](std::string& loc, std::vector<uint8_t>& keyCopy){ auto c = m_certstore.at(loc);
 *      keyCopy.assign(c.getContent().buf(), crypto_sign_PUBLICKEYBYTES);}
 */

struct SigMgrEdDSA final : SigMgr {    

    SigMgrEdDSA() :
        SigMgr(stEdDSA,
                  { 0x16, 39, // siginfo, 39 bytes
                      0x1b,  1, stEdDSA, // sig type eddsa
                      0x1c,  34, 0x1d, 32, // keylocator is 32 byte keydigest (thumbprint)
                        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // thumbprint (defaults to "self-signed")
                        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0
                  }) { if (sodium_init() == -1) exit(EXIT_FAILURE); }

    /*
     * Called by parent when there is a new signing key.
     * Need to set m_sigInfo (should only need to do key Id part for reset...)
     * Use the pubcert name to set up m_sigInfo
     * Here Key Locator is the subName of cert Name that includes Key Id
     * (one component past 'KEY')
     */
    void updateSigningKey(const keyVal& sk, const dct_Cert& nk) override final {
        // update private signing key then compute thumbprint of cert and put it at end of sigInfo
        addKey(sk);
        auto tp = dctCert::computeThumbPrint(nk);
        const auto off = m_sigInfo.size() - sizeof(tp);
        std::copy(tp.begin(), tp.end(), m_sigInfo.begin() + off);
    }

    /* private signing key */
    void addKey(const keyVal& sk, uint64_t = 0) override final { m_signingKey.assign(sk.begin(), sk.end()); }

    /*
     * This method is added for use by Certificates
     * (or anything that needs additions to sigInfo)
     * certificates will have Signature Info filled in
     * except for Signature so skips the "set up the Signature
     * field" section in sign() above
     */
    bool sign(ndn::Data& data, const SigInfo& si, const keyVal& sk) override final {
        if(sk.empty() || si.empty()) {
            throw std::runtime_error("SigMgrEdDSA: can't sign without a key and siginfo");
        }
        std::vector<uint8_t> sigValue (crypto_sign_BYTES,0);
        unsigned long long sigLen;
        auto dataWF = setupSignature(data, si);
        crypto_sign_detached(sigValue.data(), &sigLen, dataWF.signedBuf(), dataWF.signedSize(), sk.data());
        data.getSignature()->setSignature(sigValue);
        dataWF = data.wireEncode();
        return true;
    }

    // common validate logic
    bool validate(rData d, keyRef pk) const {
        auto sig = d.signature();
        if (sig.size() - sig.off() != crypto_sign_BYTES) {
            print("eddsa size wrong: {}\n", sig.size() - sig.off());
            return false;
        }
        auto strt = d.name().data();
        auto sz = sig.data() - strt; 
        if (crypto_sign_verify_detached(sig.data() + sig.off(), strt, sz, pk.data()) != 0) {
            print("eddsa verify failed\n");
            return false;
        }
        return true;
    }
    bool validate(rData d, const dct_Cert& scert) override final {
        return validate(d, *(scert.getContent()));
    }
    bool validate(rData d) override final {
        if (m_keyCb == 0) throw std::runtime_error("SigMgrEdDSA validate needs signing key callback");
        try {
            return validate(d, m_keyCb(d));
        } catch (...) {}
        return false;
    }

    bool validate(const ndn::Data& data, keyRef pk) const {
        auto sig = data.getSignature()->getSignature();
        if((sig.size()) != crypto_sign_BYTES) return false;
        const auto& wf = data.wireEncode();
        if (crypto_sign_verify_detached(sig.buf(), wf.signedBuf(), wf.signedSize(), pk.data()) != 0) return false;
        return true;
    }
    bool validate(const ndn::Data& data, const dct_Cert& scert) override final {
        return validate(data, *(scert.getContent()));
    }
    bool validate(const ndn::Data& data) override final {
        if (m_keyCb == 0) {
            throw std::runtime_error("SigMgrEdDSA validate needs callback to get signing keys");
        }
        try {
            return validate(data, m_keyCb(data));
        } catch (...) {}
        return false;
    }
};

#endif // SigMgrEdDSA_HPP
