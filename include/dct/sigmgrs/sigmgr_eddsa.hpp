#ifndef SIGMGREdDSA_HPP
#define SIGMGREdDSA_HPP
#pragma once
/*
 * EdDSA Signature Manager
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
 * SigMgr EdDSA provides a signing and validation methods that uses libsodium to
 * hash the signed portion of a passed in Data packet and check the received
 * value, respectively.
 * sign() sets SignatureValue.
 * validate() computes the SHA256 hash over the passed in Data packet's signed
 * portion, the signature of that, and compares it to the value in SignatureValue.
 * Signed portion omits the leading Data TLV but includes everything else up to
 * but not including the payload of the SignatureValue TLV.
 *
 * see https://doc.libsodium.org/ for excellent explanations of the library
 *
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

#include "sigmgr.hpp"

namespace dct {

/*
 * The sigInfo this signature manager uses stays the same for a
 * particular signing key. Can extract the needed information from
 * the dct certificate or create it from the signing key name.
 * Here passing in the function to get signing key and the name,
 * but could change this to a function to get the cert and then
 * extract other information from the cert
 *
 * To validate, this sigmgr needs the public signing key of the sender.
 * This may be provided by the function that is calling validate()
 * or the callback, m_keyCb that passes in the key locator (from
 * the packet) and a holder for a returned signing key. This cb is set using setKeyCb()
 * and if it is not set, then, can't validate. Would expect to set it with a lambda from
 * the parent function that looks like:
 * [this](std::string& loc, std::vector<uint8_t>& keyCopy){ auto c = m_certstore.at(loc);
 *      keyCopy.assign(c.getContent().buf(), crypto_sign_PUBLICKEYBYTES);}
 */

struct SigMgrEdDSA final : SigMgr {

    SigMgrEdDSA() : SigMgr(stEdDSA, crypto_sign_BYTES) { }

    /*
     * Called by parent when there is a new signing key.
     * Need to set m_sigInfo (should only need to do key Id part for reset...)
     * Use the pubcert name to set up m_sigInfo
     * Here Key Locator is the subName of cert Name that includes Key Id
     * (one component past 'KEY')
     */
    void updateSigningKey(keyRef sk, const rData& nk) override final {
        // update private signing key then compute thumbprint of cert and put it at end of sigInfo
        addKey(sk);
        auto tp = nk.computeTP();;
        const auto off = m_sigInfo.size() - sizeof(tp);
        std::copy(tp.begin(), tp.end(), m_sigInfo.begin() + off);
    }

    /* private signing key */
    void addKey(keyRef sk, uint64_t = 0) override final { m_signingKey.assign(sk.begin(), sk.end()); }

    bool sign(crData& d, const SigInfo& si, const keyVal& sk) override final {
        if(sk.empty() || si.empty()) return false;

        // add the two final TLVs to 'd' to avoid realloc memcpy during signing
        d.siginfo(si);
        auto sig = d.signature(crypto_sign_BYTES);
        unsigned long long sigLen;
        auto s = d.rest();
        s = s.first(s.size() - sig.size() - 2);
        crypto_sign_detached(sig.data(), &sigLen, s.data(), s.size(), sk.data());
        return true;
    }

    // common validate logic
    bool validate(rData d, keyRef pk) const {
        auto sig = d.signature();
        if (sig.size() - sig.off() != crypto_sign_BYTES)    return false;

        // signed region goes from start of 'name' to end of 'signature' tlv
        auto strt = d.name().data();
        return crypto_sign_verify_detached(sig.data() + sig.off(), strt, sig.data() - strt, pk.data()) == 0;
    }

    bool validate(rData d, const rData& scert) override final { return validate(d, scert.content().rest()); }

    bool validate(rData d) override final {
        assert(m_keyCb != 0);
        try { return validate(d, m_keyCb(d)); } catch (...) {}
        return false;
    }

    /*
     * returns true if the publication's signer is in the certstore
     */
    bool haveSigner(rData d) override final {
        keyRef ppk;
        try {
            ppk = m_keyCb(d);
        } catch(...) {
            return false;   // no public cert for key locator in the rData
        }
        return true;
    }

};

} // namespace dct

#endif // SigMgrEdDSA_HPP
