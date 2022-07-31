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
 * https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
 * https://doc.libsodium.org/key_exchange
 * https://doc.libsodium.org/advanced/ed25519-curve25519
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose lenth is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_chacha20poly1305_IETF_ABYTES bytes
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
#include "sigmgr.hpp"

struct SigMgrPPAEAD final : SigMgr {
    static constexpr uint32_t aeadkeySize = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    static constexpr uint32_t nonceSize = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;

    unsigned char m_nonceUnique[nonceSize];
    std::vector<keyVal> m_sgSK{};     //keeps the most recent two secret group keys for a subscriber
    std::vector<keyVal> m_sgPK{};     //signing group public key: publisher uses to compute encryption key
    keyVal m_encKey{};              //encryption key for a publisher
    std::vector<uint8_t> m_encIV{}; //initial vector for publisher encryption
    keyVal m_publicKey{};           //the public key for this publisher
    std::unordered_map<thumbPrint, keyVal> m_decKeys;   //keep list of computed decryption keys

    SigMgrPPAEAD() : SigMgr(stPPAEAD,
        { 0x16, 39, // siginfo, 39 bytes
            0x1b, 0x01, stPPAEAD,   //sig type ppaead
            0x1c,  34, 0x1d, 32, // keylocator is 32 byte keydigest (thumbprint)
              0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // thumbprint placeholder
              0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
        randombytes_buf(m_nonceUnique, sizeof m_nonceUnique); //always done - set unique part of nonce (12 bytes)
    }

    /*
     * Called by parent when there is a new signing key.
     * Need to set m_sigInfo (should only need to do key Id part for reset...)
     * Use the pubcert name to set up m_sigInfo
     * Key Locator is the subName of cert Name that includes Key Id (one component past 'KEY')
     */
    void updateSigningKey(const keyVal& sk, const dct_Cert& nk) override final {
        // update private signing key then compute thumbprint of cert and put it at end of sigInfo
        // private signing key is in the front followed by private key (not needed here)
        m_signingKey.assign(sk.begin(), sk.begin()+(crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES));
        m_publicKey.assign(nk.getContent()->data(), nk.getContent()->data()+crypto_sign_PUBLICKEYBYTES);
        auto tp = dctCert::computeThumbPrint(nk);   // reset thumbPrint in sigInfo
        const auto off = m_sigInfo.size() - tp.size();
        m_sigInfo.resize(off);
        m_sigInfo.insert(m_sigInfo.end(), tp.begin(), tp.end());
        //check that subscriber group public key has been received
        //    and there's an older encryption key that needs to be replaced
        if(m_sgPK.size() && m_encKey.size()) {
            computeNewEncKey();
        }
    }
    //compute the secret encryption key specific to me as a publisher
    // gets called when there is a new signing group key pair or a new local signing identity pair
    void computeNewEncKey() {
        m_encKey.resize(crypto_kx_SESSIONKEYBYTES); //for encrypting publications to Subscriber Group
        //convert new local signing key pair's keys to x form
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xsk;
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xpk;
        if(crypto_sign_ed25519_sk_to_curve25519(xsk.data(), m_signingKey.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeNewEncKey unable to convert signing sk to sealed box sk");
        }
        if(crypto_sign_ed25519_pk_to_curve25519(xpk.data(), m_publicKey.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::computeNewEncKey unable to convert signing pk to sealed box pk");
        }
        //compute the encryption key
        if(crypto_kx_client_session_keys(NULL, m_encKey.data(), xpk.data(), xsk.data(), m_sgPK[0].data()) !=0) {
            throw std::runtime_error("sigmgrPPAEAD::computeNewEncKey unable to create publisher encryption key");
        }
        //use current time converted to array of uint8_t as IV
        uint64_t kt = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
        for(int i=0; i<8; ++i) {
            m_encIV.push_back((unsigned char) (kt >> (i*8)));
        }
    }

    inline size_t pKeyListSize() const { return m_sgPK.size(); }
    inline size_t sKeyListSize() const { return m_sgSK.size(); }

    /* update the subscriber group key pair
     * a publisher needs the latest private key
     * a member of SG will also get the secret key to add to its keyList
     * (keyList keeps no more than two keys)
     */
    virtual void addKey(const keyVal& pk, const keyVal& sk, uint64_t) override final {
        //_LOG_INFO("sigmgrPPAEAD::addKey called with group secret key size " << sk.size());
        //add to front of public key vector
        m_sgPK.insert(m_sgPK.begin(), pk);
        if(m_sgPK.size() > 2)   //keep no more than two
            m_sgPK.pop_back();
        //if this is a publisher it will compute the key the first time sign() is called
        if(m_encKey.size())
            computeNewEncKey();
        if(sk.size() == 0) {
            return; //isn't a SG member
        }
        //add to front of secret key vector
        m_sgSK.insert(m_sgSK.begin(), sk);
        if(m_sgSK.size() > 2)   //keep no more than two
            m_sgSK.pop_back();
    }

    /*
     * uses AEAD with a symmetric key computable by SG members and specific publishers
     * the publisher's unique encryption key and initial vector
       get used in signing which is otherwise like AEAD
     */
    bool sign(ndn::Data& data, const SigInfo&, const keyVal&) override final {
        if(!pKeyListSize()) { //can't sign without a signing group public key
            return false;    //can't sign without a signing group public key
        }
        if(m_encKey.size() == 0)
            computeNewEncKey(); //haven't yet computed an encryption key

        //set the Signature field (empty Signature Value - TLV 0x17 and 0x00)
        auto dataWF = setupSignature(data, m_sigInfo);
        size_t mlen = data.getContent().size();
        std::vector<uint8_t> msg (data.getContent()->data(), data.getContent()->data() + mlen);
        //get the Associated Data: front bytes plus Signature Info
        auto fblen = dataWF.signedSize() - (mlen + m_sigInfo.size());
        std::vector<uint8_t> ad (dataWF.signedBuf(), dataWF.signedBuf() + fblen);   //front bytes
        ad.insert(ad.end(), std::begin(m_sigInfo), std::end(m_sigInfo));

        std::vector<uint8_t> cipherCont (mlen,0);       //cipher content length same as original
        std::array<uint8_t,crypto_aead_chacha20poly1305_IETF_ABYTES> mac;
        unsigned long long maclen;      //expect crypto_aead_chacha20poly1305_IETF_ABYTES

        size_t ivX = m_encIV.size(); //vector of bytes so equals no. elements
        //set up nonce and place in sigValue (m_nonceUnique len >= curIV)
        std::vector<uint8_t> sigValue;
        for(size_t i=0; i<nonceSize; ++i)   //after this, sigValue holds nonce used
        {
            if(i < ivX)
                sigValue.push_back(m_nonceUnique[i] ^ m_encIV[i]);
            else
                sigValue.push_back(m_nonceUnique[i]);
        }
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(cipherCont.data(), mac.data(), &maclen,
                             msg.data(), mlen,         //to be encrypted
                             ad.data(), ad.size(),    //the associated data
                             NULL, sigValue.data(), m_encKey.data());
        sodium_increment(&m_nonceUnique[0], nonceSize);
        data.setContent(cipherCont.data(), mlen);

        //Signature value is nonce append mac
        sigValue.insert (sigValue.end(), mac.begin(), mac.begin()+maclen);
        data.getSignature()->setSignature(sigValue);
        data.wireEncode(); //Encode again including the signature
        return true;
    }

    /*
     * returns true if success, false if failure. On success, the content
     * of rData 'd' will have been decrypted.
     * need publisher cert
     */
    bool validateDecrypt(rData d) override final {
        //can't decrypt without a subscriber group key - silent discard
        if(!sKeyListSize()) {
            //print("sigmgrPPAEAD can't validate without a signing group key\n");
            return false;
        }
        if (m_keyCb == 0) throw std::runtime_error("SigMgrPPAEAD::validateDecrypt needs signing key callback");
        auto tp = dctCert::getKeyLoc(d);    //get the thumbprint of publisher from key locator field
        //get or compute the associated decryption key
        if(m_decKeys.count(tp) == 0) {
            try {
                computeDecKey(0, m_keyCb(d), tp);   //compute decryption key using latest SG key pair
            } catch(...) {
                //_LOG_INFO("SigmgrPPAEAD::validateDecrypt: no public cert for thumbprint in key locator field");
                return false;
            }
        }
        keyVal curKey = m_decKeys.at(tp);

        // signature holds nonce followed by computed MAC for this Data
        auto sig = d.signature();
        if (sig.size() - sig.off() != nonceSize + crypto_aead_chacha20poly1305_IETF_ABYTES) {
            //print("ppaead bad sig size\n");
            return false;
        }

        auto strt = d.name().data();
        auto msg = d.content().rest();
        auto mlen = msg.size();

        // get the Associated Data: start of d to start of content plus
        // end of content to start of signature.
        std::vector<uint8_t> ad(strt, msg.data());
        ad.insert(ad.end(), msg.data() + mlen, sig.data());

        // get the Associated Data: start of d to start of content plus
        // end of content to start of signature.
        auto s = sig.data() + sig.off();    //nonce at front of signature, followed by MAC

        //decrypt
        std::vector<uint8_t> decrypted(mlen,0);
        if(crypto_aead_chacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, msg.data(), mlen, s + nonceSize,
                             ad.data(), ad.size(), s, curKey.data()) == 0) {
            // copy decrypted content back into packet
            std::memcpy((char*)msg.data(), decrypted.data(), mlen);
            return true;
        }
        if(m_sgPK.size() > 1) {                            //check for older key pair
            computeDecKey(0, m_keyCb(d), tp);   //recompute decryption key using latest SG key pair
            if(curKey == m_decKeys.at(tp))
                computeDecKey(1, m_keyCb(d), tp);                   //try previous SG pair
        } else
            return false;       //nothing else to try
        curKey = m_decKeys.at(tp);
        if(crypto_aead_chacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, msg.data(), mlen, s + nonceSize,
                             ad.data(), ad.size(), s, curKey.data()) == 0) {
            // copy decrypted content back into packet
            std::memcpy((char*)msg.data(), decrypted.data(), mlen);
            return true;
        }
        return false;
    }

    //compute the SG decryption key for this publisher and i-th sg key pair
    // should perhaps remove the older SG key pair after some set expiration time?
    // would then need to keep the update time
    void computeDecKey(size_t i, keyRef pk, thumbPrint tp) {
        //(re)compute decryption key for this publisher using the newest SG key pair
        unsigned char xpk[crypto_scalarmult_curve25519_BYTES];
        if (crypto_sign_ed25519_pk_to_curve25519(xpk, pk.data()) != 0) {
            throw std::runtime_error("sigmgr_ppaead::getDecKey unable to convert signing pk to sealed box pk");
        }
        unsigned char dk[crypto_kx_SESSIONKEYBYTES];
        if (crypto_kx_server_session_keys(dk, NULL, m_sgPK[i].data(), m_sgSK[i].data(), xpk) != 0) {
            throw std::runtime_error("sigmgr_ppaead::getDecKey unable to convert signing pk to sealed box pk");
        }
        m_decKeys[tp].assign(dk, dk + crypto_kx_SESSIONKEYBYTES);
    }
};

#endif // SIGMGRPPAEAD_HPP








