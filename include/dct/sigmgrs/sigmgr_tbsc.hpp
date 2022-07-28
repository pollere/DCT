#ifndef SIGMGRTBSC_HPP
#define SIGMGRTBSC_HPP
/*
 * TBSC Signature Manager
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
 * sigmgr_tbsc.hpp provides signing and validation using the implementation of
 * Toorani-Beheshti SignCryption functions at https://github.com/jedisct1/libsodium-signcryption.
 * Specifically, the tbsbe alternative which uses the standard edwards25519 encoding.
 * (A future version may employ the BLAKE2b hash function and the Ristretto255 group in tbsbr.)
 * This sigmgr is for implementing publisher privacy and a trust schema specified subscriber group.
 * Publishers use their current secret signing key (from or derived from identity bundle)
 * converted (map to the "sender" keys mentioned in the above repo's README)
 * and the current public key for the subscription group ("recipient"), as published in the "keys"
 * collection, with the signcrypt algorithm to encrypt the passed in Data Content. Bespoke transports
 * that are designated subscribers for the collection also receive copies of the subscription
 * group's secret key, encrypted for each participating BT identity.
 *
 * Currently converting the signing key pair to use in encryption
 * (see https://doc.libsodium.org/advanced/ed25519-curve25519) but as
 * this is "not recommended" a future publisher privacy collection's cert distributor MAY
 * add creation and distribution of an X25519 pair, signed by the ed25519 identity
 * signing key.
 *
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
 * https://doc.libsodium.org/secret-key_cryptography/tbsc/chacha20-poly1305/ietf_chacha20-poly1305_construction
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose length is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_chacha20poly1305_IETF_ABYTES bytes
 * 03.29.2022: link no longer reachable. Try https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x0c (signed via TBSC)
 *  0x1c (indicates KeyLocator type)<number of octets in Key Locator> followed by
 *  0x1d (indicates KeyDigest locator)<number of octets in key thumbprint>
 */

 /*
  * publisher/signer needs its own (converted) pub/priv key pair and the thumbPrint of its (normal) public signing cert
  *     also needs certRecord to contain public key of subscriber group, its thumbPrint and timestamp
  * subscriber needs the pub/priv subscriber group key pair and the thumbPrint of the pub cert
  *     if validate passes in the public signing key and/or its thumbprint, should be good
  *     [doesn't need to have signinginfo or identity signing key stuff but may be easier to just set it and not use it]
  *
  */

#include <array>
#include <cstring>  // for memcpy
#include "sigmgr.hpp"

// this file is included so libsodium calls can be available
extern "C" {
    #include "../../../examples/tbsbe/signcrypt_tbsbe.h"
};

//hold information about a key pair for a subscription group
struct kpInfo {
    keyVal sk{};  //signing key (only if have subscriber capability)
    keyVal pk{};  //public key (publishers and subscribers receive)
    std::vector<uint8_t> id{};  //used in signing; incorporates latest SG key pair creation time
    std::vector<uint8_t> iv{};  //hash of the SG private key serves as the recipient ID
};

struct SigMgrTBSC final : SigMgr {
    static const uint32_t nonceSize = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    keyVal m_publicKey{};       //the public key for this BT
    thumbPrint m_tp;            //thumbprint of public identity cert for this BT
    unsigned char m_nonceUnique[nonceSize];    
    //this vector keeps subscriber group key pairs and derived information - up to two deep
    std::vector<kpInfo>  m_sgKP{};
    std::unordered_map<thumbPrint,keyVal> m_decPKs{};   //keep list of computed decryption keys
    size_t m_decryptIndex;      //index of SG key pairs to try first (usually last successful one)

    SigMgrTBSC() : SigMgr(stTBSC, { 0x16, 39, // siginfo, 39 bytes
                      0x1b,  1, stTBSC, // sig type TBSC
                      0x1c,  34, 0x1d, 32, // keylocator is 32 byte thumbprint of signer/publisher
                        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0, // initializes thumbprint
                        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0
                  }) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
        randombytes_buf(m_nonceUnique, sizeof m_nonceUnique); //always done - set unique part of nonce (12 bytes)
    }

    /*
     * Called by parent to set m_sigInfo when there is a new signing key for
     * this publisher identity
     * Key Locator is the thumbprint of the public key identity cert for this BT
     */
    void updateSigningKey(const keyVal& sk, const dct_Cert& nk) override final {
        m_tp = dctCert::computeThumbPrint(nk);
        //only the bytes of the actual key are needed
        m_signingKey.assign(sk.begin(), sk.begin() + (crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES));
        m_publicKey.assign(nk.getContent()->data(), nk.getContent()->data() + crypto_sign_PUBLICKEYBYTES);
        // put thumbprint of cert in sigInfo
        const auto off = m_sigInfo.size() - m_tp.size();
        m_sigInfo.resize(off);
        m_sigInfo.insert(m_sigInfo.end(), m_tp.begin(), m_tp.end());
    }

    //add a subscription group cert - called by distributor
    // keep no more than two keys with newest at the front
    // currently, dist_sgkey distributes x keys and converting to ed25519
    void addKey(const keyVal& pk, const keyVal& sk, uint64_t ktm) override final {
        //_LOG_INFO("sigmgrTBSC::addKey called with new subscriber group key pair");
        if(m_sgKP.size() > 2) {  //keep no more than two
            m_sgKP.pop_back();
        }
        auto kpi = kpInfo();
        kpi.pk = pk;
        //convert key creation time to array of uint8_t, IV associated with this SG key pair
        for(int i=0; i<8; ++i) {
            kpi.iv.push_back((unsigned char) (ktm >> (i*8)));
        }
        //hash used as identity of subscription group;
        uint32_t pkh = ndn::CryptoLite::murmurHash3(syncps::N_HASHCHECK, pk.data(), pk.size());
        for(int i=0; i<4; ++i) {
            kpi.id.push_back((unsigned char) (pkh >> (i*8)));
        }
        if(sk.size() == 0) {
            kpi.sk.clear(); //not a subscriber
        } else {
          //  kpi.sk.assign(sk.begin(), sk.begin()+crypto_scalarmult_curve25519_BYTES);
            kpi.sk = sk;
            m_decryptIndex = (m_sgKP.size() > 1) ? 1 : 0;
        }
        //add to front of key pair vector
        m_sgKP.insert(m_sgKP.begin(), kpi);
    }

    /*
     * use public signing key thumbprints as sender and recipient ids
     * ("recipient" is the subscription group)
     * the "context" or info just uses the nonce and appends it to signature
     * signing always uses the latest signing key pair or index 0 of m_sKP
     */
    bool sign(ndn::Data& data, const SigInfo&, const keyVal&) override final {
        if(m_signingKey.empty() || m_sgKP.empty())
            throw std::runtime_error("SigMgrTBSC: can't sign without local signing key and subscriber group public key");
        //set the Signature field (empty Signature Value - TLV 0x17 and 0x00)
      //  auto dataWF =
        setupSignature(data, m_sigInfo);
        //process portion to encrypt
        uint64_t mlen = data.getContent().size();
        std::vector<uint8_t> msg (data.getContent()->data(), data.getContent()->data() + mlen);
        std::array<uint8_t, crypto_secretbox_MACBYTES> mac; //encrypted content mac
        std::vector<uint8_t> encMsg(mlen, 0);
        //set up nonce and place in sigValue (m_nonceUnique len >= curIV)
        size_t ivX = m_sgKP.front().iv.size(); //array of bytes so equals no. elements
        std::vector<uint8_t> sigValue;
        for(size_t i=0; i<nonceSize; ++i)
        {
            if(i < ivX)
                sigValue.push_back(m_nonceUnique[i] ^ m_sgKP.front().iv[i]);
            else
                sigValue.push_back(m_nonceUnique[i]);
        }
        // uses nonce as "info"
        std::array<uint8_t, crypto_signcrypt_tbsbe_STATEBYTES> st;          //set by signcrypt
        std::array<uint8_t, crypto_signcrypt_tbsbe_SHAREDBYTES> cryptKey;   //set by signcrypt
        std::array<uint8_t,crypto_signcrypt_tbsbe_SIGNBYTES> sig;           //set by signcrypt
        if(crypto_signcrypt_tbsbe_sign_before(st.data(), cryptKey.data(),
                                           m_tp.data(), m_tp.size(),
                                           m_sgKP.front().id.data(), m_sgKP.front().id.size(),
                                           sigValue.data(), sigValue.size(), m_signingKey.data(),
                                           m_sgKP.front().pk.data(), msg.data(), msg.size()) != 0 ||
                crypto_secretbox_detached(encMsg.data(), mac.data(), msg.data(), mlen, sigValue.data(), cryptKey.data()) != 0 ||
              //  crypto_box_seal(encMsg.data(), msg.data(), mlen, cryptKey.data()) != 0 ||
                //sign using state and local converted private signing key, returns signature
                crypto_signcrypt_tbsbe_sign_after(st.data(), sig.data(), m_signingKey.data(), encMsg.data(), mlen) != 0) {
            //_LOG_INFO("sigmgrTBSC::sign()) unable to signcrypt data");
            return false;
        }

        data.setContent(encMsg.data(), mlen);
        sodium_increment(&m_nonceUnique[0], nonceSize);         //ready for next use
        //set up Signature value as nonce append mac append sig
        sigValue.insert (sigValue.end(), mac.data(), mac.data()+crypto_secretbox_MACBYTES);
        sigValue.insert (sigValue.end(), sig.begin(), sig.end());
        data.getSignature()->setSignature(sigValue);
        auto wf = *data.wireEncode(); //Encode again including the signature
        std::vector<uint8_t> mt;
        mt.resize(mlen);
 if(crypto_secretbox_open_detached(mt.data(), encMsg.data(), mac.data(), mlen, sigValue.data(), cryptKey.data()) == 0 )
      validateDecrypt(rData{wf});
        validateDecrypt(rData{wf});
        return true;
    }
    /*
     * returns true if success, false if failure. On success, the content
     * of rData 'd' will have been decrypted.
     */
    bool validateDecrypt(rData d) override final {
        //can't decrypt without a key
        if(!m_sgKP.size()) {
            //_LOG_INFO("sigmgrTBSC can't validate without a signing group key");
            return false;
        }
        //get converted signing key of publisher
        if (m_keyCb == 0) throw std::runtime_error("SigMgrTBSC::validateDecrypt needs signing key callback");
        auto tp = dctCert::getKeyLoc(d);    //get the thumbprint of publisher from key locator field
      //  auto curPK = m_keyCb(d);
 auto curPK = m_publicKey;
        auto sig = d.signature();
        // signature holds nonce followed by computed MAC followed by computed sig for message
        if (sig.size() - sig.off() != nonceSize + crypto_secretbox_MACBYTES + crypto_signcrypt_tbsbe_SIGNBYTES) {
            //_LOG_INFO("sigmgr_tbsc::validatedDecrypt: bad signature size (should be nonce+mac+sig)");
            return false;
        }
        auto msg = d.content().rest();
        uint64_t mlen = msg.size();
        auto s = sig.data() + sig.off();    //start of signature value
        std::vector<uint8_t> decMsg (mlen,0);
        auto i = m_decryptIndex;            //start with last successful key
        do {
            auto kpi = m_sgKP[i];
            std::array<uint8_t, crypto_signcrypt_tbsbe_STATEBYTES> st;      //set by signcrypt
            std::array<uint8_t, crypto_signcrypt_tbsbe_SHAREDBYTES> cryptKey;    //set by signcrypt
            if(crypto_signcrypt_tbsbe_verify_before(st.data(), cryptKey.data(), s + nonceSize + crypto_secretbox_MACBYTES,
                                                 tp.data(), tp.size(),
                                                 kpi.id.data(), kpi.id.size(), s, nonceSize,
                                                 curPK.data(), kpi.sk.data()) == 0 ) // &&
        if(
                  //  crypto_secretbox_open_easy(decMsg.data(), msg.data(), mlen, s, cryptKey.data()) == 0 ) // &&
                    crypto_secretbox_open_detached(decMsg.data(), msg.data(), s+nonceSize, mlen, s, cryptKey.data()) == 0 ) // &&
        if(
                    crypto_signcrypt_tbsbe_verify_after(st.data(), s+nonceSize, curPK.data(), msg.data(), mlen) == 0)
            {
                m_decryptIndex = i; //successful key index
                // copy decrypted content back into packet
                // decrypted message is smaller than encrypted message - how to handle this?
                std::memcpy((char*)msg.data(), decMsg.data(), mlen);
                return true;
            }
             i = (i + 1) % m_sgKP.size();   //try next key pair if there is one
        } while (i != m_decryptIndex);
        //_LOG_INFO("sigmgrTBSC unable to verify/decrypt/validate packet");
        return false;
    }

};

#endif // SIGMGRTBSC_HPP
