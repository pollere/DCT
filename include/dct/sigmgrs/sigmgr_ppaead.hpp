#ifndef SIGMGRPPAEAD_HPP
#define SIGMGRPPAEAD_HPP
/*
 * PPAEAD Signature Manager
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
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

/*
 * sigmgr_ppaead.hpp provides signing method that uses libsodium to
 * properly Encrypt-then-MAC (EtM) the Data Content and a validatation method to authenticate and decrypt.
 * sign() sets the SignatureInfoEncoding, encrypts the Data Content and uses everything in the Data tlv's
 * payload up to but not including the start of the content (but including the Content TLV)
 * as Associated Data using the detached approach.
 * Replaces Content with this and sets SignatureValue to concatenate of the nonce and the returned MAC.
 * The nonce is a unique value for each key (the Initial Vector) xor'd
 * with a unique value for each packet. Here assuming the first is
 * either sent explicitly with each distributed group key or (implicitly)
 * is the creation time of each group key. DTLS v1.3 and Quic xor this 12 Byte
 * IV with the 64-bit packet sequence number. Since syncData have
 * neither sequence numbers or timestamps, have to keep some local value to use.
 * Here, using a 12 byte random value set at initiation and
 * incremented after each encryption.
 * The public key of the publisher is required in addition to the secret key of the
 * Subscriber Group in order to decrypt so the publisher's thumbprint is included in the SigInfo
 * (as in EdDSA) although this is not signed by that key.
 * NOTE: This means that an entity with subscriber capability could forge a publication
 * from an entity with the ability to publish in the Collection. This is not of concern 1) if there
 * is only a single subscriber in the group or 2) depending on other elements/requirements of a particular
 * application's set up (e.g., if provenance is ensured via signing Publication or Wire Packet,
 * or if such potential forging is not of concern).
 *
 * References:
 * https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_xchacha20-poly1305_construction
 * https://doc.libsodium.org/key_exchange
 * https://doc.libsodium.org/advanced/ed25519-curve25519
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose lenth is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_xchacha20poly1305_IETF_ABYTES bytes

 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x0b (signed via PPAEAD)
 *  0x1c (indicates KeyLocator type)<number of octets in Key Locator> followed by
 *  0x1d (indicates KeyDigest locator)<number of octets in key thumbprint>
 *  followed by (32 byte) thumbprint which remains the same until the signing key
 *  changes
 */

#include <array>
#include <cstring>  // for memcpy
#include "dct/utility.hpp"
#include "sigmgr.hpp"

struct SigMgrPPAEAD final : SigMgr {
    static constexpr uint32_t aeadkeySize = crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
    static constexpr uint32_t nonceSize = crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
    static constexpr uint32_t macSize = crypto_aead_xchacha20poly1305_IETF_ABYTES;
    static constexpr uint32_t sigSize = nonceSize + macSize;

    struct kpInfo { //holds information about a key pair for a subscription group
        keyVal sk;  //signing key (only if have subscriber capability)
        keyVal pk;  //public key (publishers and subscribers receive)
        keyVal ek;  //encryption key used by this publisher
        keyVal iv;  //initial vector associated with this ek

        kpInfo(keyRef s, keyRef p, uint64_t kts) {
            sk.assign(s.begin(),s.end());
            pk.assign(p.begin(),p.end());
            //convert key timestamp to array of uint8_t
            for(int i=0; i<8; ++i) iv.push_back((unsigned char) (kts >> (i*8)));
        }
    };

    std::array<uint8_t,nonceSize>  m_nonce;
    size_t m_decryptIndex;      //index of SG key pairs to try first (usually last successful one)
    keyVal m_publicKey{};           //the public key for this publisher
    std::unordered_map<thumbPrint, keyVal> m_decKeys;   //keep list of computed decryption keys
    //this vector keeps group keys and derived information - up to two deep
    std::vector<kpInfo>  m_keyList{};


    SigMgrPPAEAD() : SigMgr(stPPAEAD) {
        randombytes_buf(m_nonce.data(), m_nonce.size()); //always done - set unique part of nonce (12 bytes)
    }

    /*
     * Called by parent when there is a new signing key.
     * Need to set m_sigInfo (should only need to do key Id part for reset...)
     * Use the pubcert name to set up m_sigInfo
     * Key Locator is the subName of cert Name that includes Key Id (one component past 'KEY')
     */
    void updateSigningKey(keyRef sk, const rData& nk) override final {
        // update private signing key then compute thumbprint of cert and put it at end of sigInfo
        // private signing key is in the front followed by private key (not needed here)
       // m_signingKey.assign(sk.begin(), sk.begin()+(crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES));
        m_signingKey.assign(sk.begin(), sk.end());
        auto tp = nk.computeTP();   // to reset thumbPrint in sigInfo
        auto k = nk.content().rest();
        m_publicKey.assign(k.data(), k.data()+crypto_sign_PUBLICKEYBYTES);
        const auto off = m_sigInfo.size() - sizeof(tp);
        std::copy(tp.begin(), tp.end(), m_sigInfo.begin() + off);
        //check that subscriber group public key has been received
        //  and replace any older encryption key for newest entry
        //  (always encrypts using newest group key
        if(pKeyListSize() && eKeySize(0)) {
            computeNewEncKey();
        }
    }
    //compute the secret encryption key specific to this publisher and the latest SG key pair
    // gets called when there is a new signing group key pair or a new local signing identity pair
    void computeNewEncKey() {
        m_keyList[0].ek.resize(crypto_kx_SESSIONKEYBYTES); //for encrypting publications to Subscriber Group
        //convert new local signing key pair's keys to x form
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xsk;
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xpk;
        if(crypto_sign_ed25519_sk_to_curve25519(xsk.data(), m_signingKey.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeNewEncKey unable to convert signing sk to sealed box sk");
        }
        if(crypto_sign_ed25519_pk_to_curve25519(xpk.data(), m_publicKey.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeNewEncKey unable to convert signing pk to sealed box pk");
        }
        //compute the encryption key (always from the newest key pair received)
        if(crypto_kx_client_session_keys(NULL, m_keyList[0].ek.data(), xpk.data(), xsk.data(), m_keyList[0].pk.data()) !=0) {
            throw std::runtime_error("SigMgrPPAEAD::computeNewEncKey unable to create publisher encryption key");
        }
    }

    inline size_t sKeyListSize() const { return (m_keyList.size() > 0 && m_keyList[0].sk.size() > 0); }
    inline size_t pKeyListSize() const { return (m_keyList.size() > 0 && m_keyList[0].pk.size() > 0); }
    inline size_t eKeySize(auto i) const { return (m_keyList.size() > 0 && m_keyList[i].ek.size() > 0); }

    /* update the subscriber group key pair
     * a publisher needs the latest private key
     * a member of SG will also get the secret key to add to its keyList
     * (keyList keeps no more than two keys)
     */
    virtual void addKey(keyRef pk, keyRef sk, uint64_t ts) override final {
        if(m_keyList.size() > 1) {  //keep no more than two
            m_keyList.pop_back();
        }
        auto kpi = kpInfo(sk,pk,ts);
        kpi.pk.assign(pk.begin(), pk.end());
        m_decryptIndex = m_keyList.size(); //set to 0 if new key pair, otherwise set to 1 (the previous kp)
        //add to front of key pair vector; encryption key isn't computed until first use
        m_keyList.insert(m_keyList.begin(), kpi);
    }

    /*
     * uses AEAD with a symmetric key computable by SG members and specific publishers
     * the publisher's unique encryption key and initial vector (m_encKey and m_encIV)
       get used in signing which is otherwise like AEAD
     */
    bool sign(crData& d, const SigInfo& si, const keyVal&) override final {
        if(!pKeyListSize()) return false; //can't sign without a signing group public key
        if(eKeySize(0) == 0) computeNewEncKey(); //haven't yet computed an encryption key

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
        const auto& curKey = m_keyList.front().ek;
        const auto& curIV = m_keyList.front().iv;
        for (auto i = 0u; i < curIV.size(); ++i) sig[i] ^= curIV[i];

        std::vector<uint8_t> ctext(content.size(),0);
        unsigned long long maclen;
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(ctext.data(), mac.data(), &maclen,
                             content.data(), content.size(), ad.data(), ad.size(),
                             NULL, sig.data(), curKey.data());
            if (content.size())  std::memcpy((uint8_t*)content.data(), ctext.data(), content.size());
        return true;
    }

    /*
     * returns true if success, false if failure. On success, the content
     * of rData 'd' will have been decrypted.
     */
    bool validateDecrypt(rData d) override final {
        //can't decrypt without a subscriber group secret key - silent discard
        if(!sKeyListSize())   return false;
        if (m_keyCb == 0) throw std::runtime_error("SigMgrPPAEAD::validateDecrypt needs signing key callback");

        auto sig = d.signature().rest();
        if (sig.size() != sigSize) return false;

        const auto& tp = d.thumbprint();    //get the thumbprint of publisher
        if(m_decKeys.count(tp) == 0) {  //get or compute the associated decryption key
            try {
                computeDecKey(0, m_keyCb(d), tp);   //compute decryption key using latest SG key pair
            } catch(...) {
                return false;   //no public cert for thumbprint in key locator field
            }
        }
        keyVal curKey = m_decKeys.at(tp);

        auto content = d.content().rest();
        auto ad = d.rest();
        ad = ad.first(content.data() - ad.data());
        //decrypt
        std::vector<uint8_t> decrypted(content.size(),0);
        auto i = m_decryptIndex;            //start with last successful key
        do {
            if(crypto_aead_xchacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, content.data(), content.size(), sig.data() + nonceSize,
                             ad.data(), ad.size(), sig.data(), curKey.data()) == 0) {
                // copy decrypted content back into packet
                if (content.size())  std::memcpy((uint8_t*)content.data(), decrypted.data(), content.size());
                m_decryptIndex = i; //successful key index
                return true;
             }
             if(m_keyList.size() > 1) { //try next key pair if there is one
                 i = i==0? 1 : 0;
                 if(i == m_decryptIndex) {   //been here before
                    return false;   //unable to decrypt
                 }
                 computeDecKey(i, m_keyCb(d), tp);   //recompute decryption key using other SG key pair
                 curKey = m_decKeys.at(tp);
            }
        } while (i != m_decryptIndex);
        return false;   //unable to decrypt
    }

    //compute the SG decryption key for this publisher and i-th sg key pair
    // should perhaps remove the older SG key pair after some set expiration time?
    // would then need to keep the update time
    void computeDecKey(size_t i, keyRef pk, thumbPrint tp) {
        //(re)compute decryption key for this publisher using the newest SG key pair
        unsigned char xpk[crypto_scalarmult_curve25519_BYTES];
        if (crypto_sign_ed25519_pk_to_curve25519(xpk, pk.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeDecKey unable to convert signing pk to sealed box pk");
        }
        unsigned char dk[crypto_kx_SESSIONKEYBYTES];
        if (crypto_kx_server_session_keys(dk, NULL, m_keyList[i].pk.data(), m_keyList[i].sk.data(), xpk) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeDecKey unable to convert signing pk to sealed box pk");
        }
        m_decKeys[tp].assign(dk, dk + crypto_kx_SESSIONKEYBYTES);
    }
};

#endif // SigMgrPPAEAD_HPP








