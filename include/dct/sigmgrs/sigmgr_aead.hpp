#ifndef SIGMGRAEAD_HPP
#define SIGMGRAEAD_HPP
/*
 * AEAD Signature Manager
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
 * https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
 * Encrypts message with key and nonce. Returns resulting ciphertext
 * whose lenth is equal to the message length. Also computes a tag that
 * authenticates the ciphertext plus the ad of adlen and puts the tag
 * into mac of length of crypto_aead_chacha20poly1305_IETF_ABYTES bytes
 */

/*
 * The SignatureInfo content is fixed 5 bytes for this signing method:
 *  0x16 (SigInfo) <number of bytes to follow in SigInfo>
 *  0x1b (SignatureType) <number of bytes to follow that give signatureType>
 *  0x07 (signed by AEAD key)
 *  Followed by:
 *  0x17 (SignatureValueType) <number of bytes in signature> <signature bytes>
 */

#include <array>
#include <cstring>  // for memcpy
#include "sigmgr.hpp"

struct keyRecord {
    keyRecord (keyVal k, uint64_t kts)
    {
        key = k;
        //convert key timestamp to array of uint8_t
        for(int i=0; i<8; ++i) {
            iv.push_back((unsigned char) (kts >> (i*8)));
        }
    }
    keyVal key;
    std::vector<uint8_t> iv;
    //maybe add a fingerprint of the key to include in packet
};

struct SigMgrAEAD final : SigMgr {
    static constexpr uint32_t aeadkeySize = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    static constexpr uint32_t nonceSize = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
    unsigned char m_nonceUnique[nonceSize];
    std::vector<keyRecord> m_keyList;
    size_t m_decryptIndex;

    SigMgrAEAD() : SigMgr(stAEAD, {0x16, 0x03, 0x1b, 0x01, stAEAD}) {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
        randombytes_buf(m_nonceUnique, sizeof m_nonceUnique); //always done - set unique part of nonce (12 bytes)
    }

    //update to signing keyList with these values (keyList keeps no more than two keys)
    virtual void addKey(const keyVal& k, uint64_t ktm) override final {
        //add to front of key vector
        m_keyList.insert(m_keyList.begin(), keyRecord(k, ktm));
        if(m_keyList.size() > 2)   //keep no more than 2 keys
            m_keyList.pop_back();
        m_decryptIndex = (keyListSize() > 1) ? 1 : 0;
    }

    bool sign(ndn::Data& data, const SigInfo&, const keyVal&) override final {
        if(!keyListSize()) return false;    //can't sign without a key
        ///set the Signature field (empty Signature Value - TLV 0x17 and 0x00)
        auto dataWF = setupSignature(data, m_sigInfo);
        size_t mlen = data.getContent().size();
        std::vector<uint8_t> msg (data.getContent()->data(), data.getContent()->data() + mlen);
        //get the Associated Data: front bytes plus Signature Info
        auto adlen = dataWF.signedSize() - (mlen + m_sigInfo.size());
        std::vector<uint8_t> ad (dataWF.signedBuf(), dataWF.signedBuf() + adlen);
        ad.insert(ad.end(), std::begin(m_sigInfo), std::end(m_sigInfo));

        std::vector<uint8_t> cipherCont(mlen,0);       //cipher content length same as original
        std::array<uint8_t,crypto_aead_chacha20poly1305_IETF_ABYTES> mac;
        unsigned long long maclen;      //expect crypto_aead_chacha20poly1305_IETF_ABYTES
        keyVal curKey = m_keyList.front().key;
        keyVal curIV = m_keyList.front().iv;
        auto ivX = curIV.size(); //array of bytes so equals no. elements
        //set up nonce and place in sigValue (m_nonceUnique len >= curIV)
        std::vector<uint8_t> sigValue;
        for(size_t i=0; i<nonceSize; ++i)
        {
            if(i < ivX)
                sigValue.push_back(m_nonceUnique[i] ^ curIV[i]);
            else
                sigValue.push_back(m_nonceUnique[i]);
        }
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(cipherCont.data(), mac.data(), &maclen,
                             msg.data(), mlen,         //to be encrypted
                             ad.data(), ad.size(),    //the associated data
                             NULL, sigValue.data(), curKey.data());
        sodium_increment(&m_nonceUnique[0], nonceSize);
        data.setContent(cipherCont.data(), mlen);

        //set up Signature value as nonce append mac
        sigValue.insert (sigValue.end(), mac.begin(), mac.begin()+maclen);
        data.getSignature()->setSignature(sigValue);
        data.wireEncode(); //Encode again including the signature
        return true;
    }
    /*
     * returns true if success, false if failure. On success, the content
     * of rData 'd' will have been decrypted.
     */
    bool validateDecrypt(rData d) override final {
        //can't decrypt without a key
        if(!keyListSize()) return false;
 
        // signature holds nonce followed by computed MAC for this Data
        auto sig = d.signature();
        if (sig.size() - sig.off() != nonceSize + crypto_aead_chacha20poly1305_IETF_ABYTES) {
            //print("aead bad sig size\n");
            return false;
        }
        auto strt = d.name().data();
        auto con = d.content().rest();
        auto mlen = con.size();

        // get the Associated Data: start of d to start of content plus
        // end of content to start of signature.
        std::vector<uint8_t> ad(strt, con.data());
        ad.insert(ad.end(), con.data() + mlen, sig.data());

        auto s = sig.data() + sig.off();    //start of signature
        std::vector<uint8_t> decrypted(mlen,0);
        auto i = m_decryptIndex;    //start with last successful key
        do {
            if(crypto_aead_chacha20poly1305_ietf_decrypt_detached(decrypted.data(),
                             NULL, con.data(), mlen, s + nonceSize,
                             ad.data(), ad.size(), s, m_keyList[i].key.data()) == 0) {
                m_decryptIndex = i; //successful key index
                // copy decrypted content back into packet
                std::memcpy((uint8_t*)con.data(), decrypted.data(), mlen);
                return true;
             }
             i = (i + 1) % keyListSize();
        } while (i != m_decryptIndex);
        return false;
    }

    inline size_t keyListSize() const { return m_keyList.size(); }
};

#endif // SIGMGRAEAD_HPP








