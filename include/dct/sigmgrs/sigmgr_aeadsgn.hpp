#ifndef SIGMGRAEADSGN_HPP
#define SIGMGRAEADSGN_HPP
/*
 * AEAD Signature Manager
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
 * sigmgr_aead.hpp provides signing method that uses libsodium to
 * properly Encrypt-then-MAC (EtM) the Data Content and a validatation method to authenticate and decrypt.
 * sign() sets the SignatureInfoEncoding, encrypts the Data Content and uses the rest of the Data packet as
 * Associated Data (includes TLV of Content up to but not including
 * the TLV of the actual Signature) using the detached approach.
 * Replaces Content with this and sets SignatureValue to concatenate of the nonce and the returned MAC.
 * The nonce is a unique value for each key (the Initial Vector) xor'd
 * with a unique value for each packet. Here assuming the first is
 * either sent explicitly with each distributed group key or (implicitly)
 * is the creation time of each group key. DTLS v1.3 and Quic xor this 12 Byte
 * IV with the 64-bit packet sequence number. Since syncData have
 * neither sequence numbers or timestamps, have to keep some local value to use.
 * Here, using a 12 byte random value set at initiation and
 * incremented after each encryption.
 *
 * Using:
 * https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_xchacha20-poly1305_construction
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose lenth is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_xchacha20poly1305_IETF_ABYTES bytes
 * Following this, the message is signed by the publisher (as in sigmgr_eddsa.hpp)
 * and that signature is appended to the signature field
 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x0d (encrypted with AEAD key, signed using EdDSA)
 *  Followed by:
 *  0x17 (SignatureValueType) <number of bytes in signature> <signature bytes>
 */

#include <array>
#include <cstring>  // for memcpy
#include <ranges>
#include "sigmgr.hpp"

struct SigMgrAEADSGN final : SigMgr {
    struct keyRecord {
        keyVal key;
        keyVal iv;

        keyRecord(keyRef k, uint64_t kts) {
            key.assign(k.begin(),k.end());
            //convert key timestamp to array of uint8_t
            for(int i=0; i<8; ++i) iv.push_back((unsigned char) (kts >> (i*8)));
        }
    };
    static constexpr uint32_t aeadkeySize = crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
    static constexpr uint32_t nonceSize = crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
    static constexpr uint32_t macSize = crypto_aead_xchacha20poly1305_IETF_ABYTES;
    static constexpr uint32_t sigSize = nonceSize + macSize + crypto_sign_BYTES;

    std::array<uint8_t,nonceSize>  m_nonce;
    std::vector<keyRecord> m_keyList;
    size_t m_decryptIndex;

    SigMgrAEADSGN() : SigMgr(stAEAD) {
        randombytes_buf(m_nonce.data(), m_nonce.size()); //always done - set unique part of nonce (12 bytes)
    }

        /*
     * Called by parent when there is a new signing key.
     * Need to set m_sigInfo (should only need to do key Id part for reset...)
     * Use the pubcert tp to set up m_sigInfo
     */
    void updateSigningKey(keyRef sk, const rData& c) override final {
        // update private signing key then compute thumbprint of cert and put it at end of sigInfo
        m_signingKey.assign(sk.begin(), sk.end());
        auto tp = c.computeTP();   // to reset thumbPrint in sigInfo
        auto k = c.content().rest();
        m_signingKey.assign(k.data(), k.data()+crypto_sign_PUBLICKEYBYTES);
        const auto off = m_sigInfo.size() - sizeof(tp);
        std::copy(tp.begin(), tp.end(), m_sigInfo.begin() + off);
        }

    // update to signing keyList with these values. New key goes
    // at the front of keyList and no more than two keys are kept.
    void addKey(keyRef k, uint64_t ktm) override final {
        m_keyList.insert(m_keyList.begin(), keyRecord(k, ktm));
        if(m_keyList.size() > 2) m_keyList.pop_back();
        m_decryptIndex = (keyListSize() > 1) ? 1 : 0;
    }

    bool sign(crData& d, const SigInfo& si, const keyVal&) override final {
        if (!keyListSize()) return false;

        // add the two final TLVs to 'd' to avoid realloc memcpy during signing
        d.siginfo(si);
        auto sig = d.signature(sigSize);

        // The content to be encrypted is the Content tlv's payload.
        // Associated data is everything in the Data tlv's payload
        // up to but not including the start of the content (but including
        // the Content TLV).  The siginfo information following the content
        // is not included since it's constant for this sigmgr and adding
        // it would require making a copy of the rest of the a.d.
        auto content = d.content().rest();
        auto ad = d.rest();
        ad = ad.first(content.data() - ad.data());

        // The signature contains a unique-per-packet nonce followed by the mac. The nonce generation
        // below follows the guidelines in RFC5116 sec.3.1 for multiple devices performing encryption
        // using a single key: The per-packet nonce is a mixture of a locally generated random part
        // and the timestamp of the current shared key. The 12 byte random number is generated at
        // startup and incremented immediately after each use to ensure it's not re-used.
        auto mac = std::span(sig.data() + nonceSize, macSize);
        std::copy(m_nonce.begin(), m_nonce.end(), sig.begin());
        sodium_increment(m_nonce.data(), nonceSize);
        const auto& [curKey, curIV] = m_keyList.front();
        for (auto i = 0u; i < curIV.size(); ++i) sig[i] ^= curIV[i];

        std::vector<uint8_t> ctext(content.size(),0);
        unsigned long long maclen;
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(ctext.data(), mac.data(), &maclen,
                             content.data(), content.size(), ad.data(), ad.size(),
                             NULL, sig.data(), curKey.data());
        if (content.size()) std::memcpy((uint8_t*)content.data(), ctext.data(), content.size());

        //sign the data up through nonce|mac and put signature after nonce and mac
        unsigned long long sigLen;
        auto s = d.rest();
        s = s.first(s.size() - crypto_sign_BYTES);
        crypto_sign_detached(sig.data() + nonceSize + macSize, &sigLen, s.data(), s.size(), m_signingKey.data());
        return true;
    }
    /*
     * Decrypts rData d's content and replaces d's content with the decrypted data
     * This is used on rData that have already been validated
     */

    bool decrypt(rData d) override final {
       if(!keyListSize()) return false;    //can't decrypt without a key
        auto content = d.content().rest();
        auto ad = d.rest();
        ad = ad.first(content.data() - ad.data());
        auto sig = d.signature().rest();
        std::vector<uint8_t> decrypted(content.size(),0);
        auto i = m_decryptIndex;    //start with last successful key
        do {
            if(crypto_aead_xchacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, content.data(), content.size(), sig.data() + nonceSize,
                             ad.data(), ad.size(), sig.data(), m_keyList[i].key.data()) == 0) {
                m_decryptIndex = i; //successful key index
                // copy decrypted content back into packet
                if (content.size()) std::memcpy((uint8_t*)content.data(), decrypted.data(), content.size());
                return true;
             }
             i = (i + 1) % keyListSize();
        } while (i != m_decryptIndex);
        // print("aeadsgn decrypt failed on {}\n", d.name());
        return false;
    }

    /*
     * Validate the signature that follows the nonce and computed MAC in the Signature value
     * The signed region goes from the start of the name through the Signature tlv and includes
     * the nonce and MAC.
     * The key locator is the thumbprint of the signer and EdDSA is used
     */
    bool validate(rData d) override final {
        auto sig = d.signature().rest();
        if (sig.size() != sigSize) { return false; }

        keyRef ppk;                         // for publisher public key
        try {
            ppk = m_keyCb(d);
        } catch(...) {
            return false;   // no public cert for key locator in the rData
        }

        auto o = nonceSize + macSize;
        auto strt = d.name().data();
        if(crypto_sign_verify_detached(sig.data() + o, strt, sig.data() + o - strt, ppk.data()) != 0)
            return false;   //eddsa provenance and integrity verify failed
        return true;
    }

    /*
     * returns true if success, false if failure. On success, the content of 'd' will have been decrypted.
     */
    bool validateDecrypt(rData d) override final {       
        if(! validate(d))    return false;
        return decrypt(d);
    }

    inline size_t keyListSize() const { return m_keyList.size(); }
};

#endif // SIGMGRAEADSGN_HPP








