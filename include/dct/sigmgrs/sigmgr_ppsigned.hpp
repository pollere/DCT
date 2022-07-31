#ifndef SIGMGRPPSIGN_HPP
#define SIGMGRPPSIGN_HPP
/*
 * PPSIGN Signature Manager
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
 * sigmgr_ppsigned.hpp provides a signing method built on sigmgr_ppaead.hpp, but
 * adding publisher signing to add provenance that can be ensured within the authorized
 * subscriber group. (see comments in sigmgr_ppaead.hpp)
 * We hoped to utilize the signCryption functions at https://github.com/jedisct1/libsodium-signcryption
 * but its use of different key types makes that more fiddly than seems currently warranted (and
 * the possibility that it would not be more efficient than just adding separate signing).
 *
 * Once the ndn::Data are changed to rData in sign(), the plan is to sign the encrypted packet
 * through the nonce and mac.
 *
 * References:
 * https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
 * https://doc.libsodium.org/key_exchange
 * https://doc.libsodium.org/advanced/ed25519-curve25519
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose lenth is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_chacha20poly1305_IETF_ABYTES bytes
 * Following this, the message is signed by the publisher (as in sigmgr_eddsa.hpp)
 * and that signature is appended to the signature field
 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x0c (signed via PPSIGN)
 *  0x1c (indicates KeyLocator type)<number of octets in Key Locator> followed by
 *  0x1d (indicates KeyDigest locator)<number of octets in key thumbprint>
 *  followed by (32 byte) thumbprint which remains the same until the signing key
 *  changes
 */

#include <array>
#include <cstring>  // for memcpy
#include "sigmgr.hpp"

//hold information about a key pair for a subscription group
struct kpInfo {
    keyVal sk{};  //signing key (only if have subscriber capability)
    keyVal pk{};  //public key (publishers and subscribers receive)
    keyVal ek{};  //encryption key used by this publisher
    std::vector<uint8_t> iv{};  //initial vector associated with this ek
};

struct SigMgrPPSIGN final : SigMgr {
    static constexpr uint32_t aeadkeySize = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    static constexpr uint32_t nonceSize = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;

    unsigned char m_nonceUnique[nonceSize];
    keyVal m_publicKey{};           //the public key for this publisher
    std::unordered_map<thumbPrint, keyVal> m_decKeys;   //keep list of computed decryption keys
    //this vector keeps subscriber group key pairs and derived information - up to two deep
    std::vector<kpInfo>  m_sgKP{};
    size_t m_decryptIndex;      //index of SG key pairs to try first (usually last successful one)

    SigMgrPPSIGN() : SigMgr(stPPSIGN,
        { 0x16, 39, // siginfo, 39 bytes
            0x1b, 0x01, stPPSIGN,   //sig type ppsign
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
        m_signingKey.assign(sk.begin(), sk.end());
        m_publicKey.assign(nk.getContent()->data(), nk.getContent()->data()+crypto_sign_PUBLICKEYBYTES);
        auto tp = dctCert::computeThumbPrint(nk);   // reset thumbPrint in sigInfo
        const auto off = m_sigInfo.size() - tp.size();
        m_sigInfo.resize(off);
        m_sigInfo.insert(m_sigInfo.end(), tp.begin(), tp.end());
        //check that subscriber group public key has been received
        //  and replace any older encryption key for newest entry
        //  (always encrypts using newest group key
        if(pKeyListSize() && eKeySize()) {
            computeNewEncKey();
        }
    }
    //compute the secret encryption key specific to this publisher and the latest SG key pair
    // gets called when there is a new signing group key pair or a new local signing identity pair
    void computeNewEncKey() {
        m_sgKP[0].ek.resize(crypto_kx_SESSIONKEYBYTES); //for encrypting publications to Subscriber Group
        //convert new local signing key pair's keys to x form
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xsk;
        std::array<uint8_t,crypto_scalarmult_curve25519_BYTES> xpk;
        std::vector<uint8_t> msk (m_signingKey.begin(), m_signingKey.begin() + crypto_sign_SECRETKEYBYTES-crypto_sign_PUBLICKEYBYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(xsk.data(), msk.data()) != 0) {
            throw std::runtime_error("sigmgr_ppsign::computeNewEncKey unable to convert signing sk to sealed box sk");
        }
        if(crypto_sign_ed25519_pk_to_curve25519(xpk.data(), m_publicKey.data()) != 0) {
            throw std::runtime_error("sigmgr_ppsign::computeNewEncKey unable to convert signing pk to sealed box pk");
        }
        //compute the encryption key
        if(crypto_kx_client_session_keys(NULL, m_sgKP[0].ek.data(), xpk.data(), xsk.data(), m_sgKP[0].pk.data()) !=0) {
            throw std::runtime_error("SigMgrPPSIGN::computeNewEncKey unable to create publisher encryption key");
        }
        //use current time converted to array of uint8_t as IV
        uint64_t kt = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
        for(int i=0; i<8; ++i) {
            m_sgKP[0].iv.push_back((unsigned char) (kt >> (i*8)));
        }
    }

    inline size_t sKeyListSize() const { return m_sgKP.size()? m_sgKP[0].sk.size() : 0; }
    inline size_t pKeyListSize() const { return m_sgKP.size()? m_sgKP[0].pk.size() : 0; }
    inline size_t eKeySize() const { return m_sgKP.size()? m_sgKP[0].ek.size() : 0; }

    /* update the subscriber group key pair
     * a publisher needs the latest private key
     * a member of SG will also get the secret key to add to its keyList
     * (keyList keeps no more than two keys)
     */
    virtual void addKey(const keyVal& pk, const keyVal& sk, uint64_t) override final {
        if(m_sgKP.size() > 1) {  //keep no more than two
            m_sgKP.pop_back();
        }
        auto kpi = kpInfo();
        kpi.pk = pk;
        if(sk.size() == 0) {
            kpi.sk.clear(); //not a subscriber
        } else {
            kpi.sk = sk;
            m_decryptIndex = (m_sgKP.size() > 1) ? 1 : 0;
        }
        //add to front of key pair vector; encryption key isn't computed until first use
        m_sgKP.insert(m_sgKP.begin(), kpi);
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
        if(eKeySize() == 0)
            computeNewEncKey(); //haven't yet computed encryption key

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

        auto kpi = m_sgKP[0];   //encryption always uses newest key pair info
        size_t ivX = kpi.iv.size(); //vector of bytes so equals no. elements
        //set up nonce and place in sigValue (m_nonceUnique len >= curIV)
        std::vector<uint8_t> sigValue;
        for(size_t i=0; i<nonceSize; ++i)   //after this, sigValue holds nonce used
        {
            if(i < ivX)
                sigValue.push_back(m_nonceUnique[i] ^ kpi.iv[i]);
            else
                sigValue.push_back(m_nonceUnique[i]);
        }
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(cipherCont.data(), mac.data(), &maclen,
                             msg.data(), mlen,         //to be encrypted
                             ad.data(), ad.size(),    //the associated data
                             NULL, sigValue.data(), kpi.ek.data());
        sodium_increment(&m_nonceUnique[0], nonceSize);
        data.setContent(cipherCont.data(), mlen);
        //append mac to nonce
        sigValue.insert (sigValue.end(), mac.begin(), mac.begin()+maclen);
        //sign the data and append the signature to sigValue
        auto off = sigValue.size();
        unsigned long long slen;
        sigValue.resize(sigValue.size()+crypto_sign_BYTES);
        dataWF = data.wireEncode(); //Encode again including the signature
        crypto_sign_detached(sigValue.data()+off, &slen, dataWF.signedBuf(), dataWF.signedSize(), m_signingKey.data());
        if(slen > crypto_sign_BYTES) {
            //_LOG_INFO("sigmgrPPSIGN: provenance signature is too long");
        }
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
        //can't decrypt without a subscriber group secret key
        if(!sKeyListSize()) {
            return false;
        }
        auto kpi = m_sgKP[m_decryptIndex];
        if(!kpi.sk.size()) {
            return false;   //no signing group secret key available
        }
        if (m_keyCb == 0) throw std::runtime_error("SigMgrPPSIGN::validateDecrypt needs signing key callback");
        auto tp = dctCert::getKeyLoc(d);    //get the thumbprint of publisher from key locator field
        keyRef ppk;
        try {
            ppk = m_keyCb(d);
        } catch(...) {
            return false;   //no public cert for thumbprint in key locator field
        }

        auto strt = d.name().data();
        auto sig = d.signature();   // signature holds nonce followed by computed MAC followed by the publisher signature for this Data
        auto sz = sig.data() - strt;
        if (sig.size() - sig.off() != nonceSize + crypto_aead_chacha20poly1305_IETF_ABYTES + crypto_sign_BYTES) {
            return false;   //bad signature size
        }
        //check provenance and integrity
        auto off = sig.off() + nonceSize + crypto_aead_chacha20poly1305_IETF_ABYTES;
        if (crypto_sign_verify_detached(sig.data() + off, strt, sz, ppk.data()) != 0) {
            return false;   //eddsa provenance verify failed
        }
        //get or compute the decryption key associated with the publisher indicated in the key locator
        if(m_decKeys.count(tp) == 0)
            computeDecKey(0, ppk, tp);   //compute decryption key using latest SG key pair
        keyVal curKey = m_decKeys.at(tp);
        auto msg = d.content().rest();
        auto mlen = msg.size();

        // get the Associated Data: start of d to start of content plus
        // end of content to start of signature.
        std::vector<uint8_t> ad(strt, msg.data());
        ad.insert(ad.end(), msg.data() + mlen, sig.data());
        auto s = sig.data() + sig.off();    //nonce at front of signature, followed by MAC

        //decrypt
        std::vector<uint8_t> decrypted(mlen,0);
        auto i = m_decryptIndex;            //start with last successful key
        do {
            if(crypto_aead_chacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, msg.data(), mlen, s + nonceSize,
                             ad.data(), ad.size(), s, curKey.data()) == 0) {
                // copy decrypted content back into packet
                std::memcpy((char*)msg.data(), decrypted.data(), mlen);
                m_decryptIndex = i; //successful key index
                return true;
            }
            if(m_sgKP.size() > 1) { //try next key pair if there is one
                i = i==0? 1 : 0;
                if(i == m_decryptIndex) {   //been here before
                    return false;   //unable to decrypt
                }
                kpi = m_sgKP[i];
                computeDecKey(i, ppk, tp);   //recompute decryption key using other SG key pair
                curKey = m_decKeys.at(tp);
            }

        } while(i != m_decryptIndex);
        return false;   //unable to decrypt
    }

    //compute the SG decryption key for this publisher and i-th sg key pair
    // should perhaps remove the older SG key pair after some set expiration time?
    // would then need to keep the update time
    void computeDecKey(size_t i, keyRef pk, thumbPrint tp) {
        //(re)compute decryption key for this publisher using the newest SG key pair
        unsigned char xpk[crypto_scalarmult_curve25519_BYTES];
        if (crypto_sign_ed25519_pk_to_curve25519(xpk, pk.data()) != 0) {
            throw std::runtime_error("sigmgr_ppsign::getDecKey unable to convert signing pk to sealed box pk");
        }
        unsigned char dk[crypto_kx_SESSIONKEYBYTES];
        if (crypto_kx_server_session_keys(dk, NULL, m_sgKP[i].pk.data(), m_sgKP[i].sk.data(), xpk) != 0) {
            throw std::runtime_error("sigmgr_ppsign::getDecKey unable to convert signing pk to sealed box pk");
        }
        m_decKeys[tp].assign(dk, dk + crypto_kx_SESSIONKEYBYTES);
    }
};

#endif // SigMgrPPSIGN_HPP








