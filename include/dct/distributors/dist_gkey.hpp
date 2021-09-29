#ifndef DIST_GKEY_HPP
#define DIST_GKEY_HPP
/*
 * dist_gkey.hpp
 * Distributes a symmetric key (used for encryption) for a group of peers.
 * This version runs with the ndn-ind library and is a self-contained, 'header-only' library.
 *
 * DistGKey manages all the group key operations including the decision on which (eligible) entity will create the
 * group key. Only one entity should be making group keys and will rekey at periodic intervals to
 * distribute a new key, encrypting each key with the public key of each peer.
 * (see  https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
 * If a new membercomes up between rekeying, it is added to the list of encrypted keys which is republished.
 * The group key can be used by sigmgr_aead.hpp
 *
 * Copyright (C) 2020-1 Pollere, Inc.
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
 *  dist_gkey is not intended as production code.
 */

#include <functional>

#include "../schema/dct_cert.hpp"
#include "../schema/certstore.hpp"
#include "../schema/tlv_encoder.hpp"
#include "../schema/tlv_parser.hpp"
#include "dct/sigmgrs/sigmgr.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"
#include "dct/syncps/syncps.hpp"
#include "dct/utility.hpp"

const uint32_t aeadKeySz = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
static constexpr size_t encGKeySz = crypto_box_SEALBYTES + aeadKeySz;
using encGK = std::array<uint8_t, crypto_box_SEALBYTES + aeadKeySz>;
using keyVal = std::vector<uint8_t>;
using thumbPrint = std::array<uint8_t,32>;
using connectedCb = std::function<void(bool)>;
using pubCnt = uint16_t;
using addKeyCb = std::function<void(const keyVal&, uint64_t)>;
using Timer = ndn::scheduler::ScopedEventId;

/*
 * DistGKey Publications contain the creation time of the symmetric key and a list of
 * pairs containing that symmetric key individually encrypted for each peer. Each
 * pair has the thumbprint of a signing key and the symmetric key encrypted using that
 * (public) signing key. (12 bytes also accounts for tlv indicators)
 */
using gkr = std::pair <thumbPrint, encGK>;
static constexpr int max_gkRs = (syncps::maxPubSize - 12) /(32+encGKeySz);

struct DistGKey
{    
    ndn::Name m_pubPrefix;     //prefix for group symmetric key
    SigMgrAny m_syncSigMgr{sigMgrByType("EdDSA")};      // to sign/validate SyncData packets
    SigMgrAny m_keySigMgr{sigMgrByType("EdDSA")};    // to sign/validate key list Publications
    syncps::SyncPubsub m_sync;
    const certStore& m_certs;
    addKeyCb m_newKeyCb;   // called when group key rcvd
    connectedCb m_connCb{[](auto) {}};
    log4cxx::LoggerPtr staticModuleLogger{log4cxx::Logger::getLogger("DistGKey")};
    Timer m_timer{};
    thumbPrint m_tp{};
    keyVal m_pDecKey{};         //transformed pk used to encrypt group key
    keyVal m_sDecKey{};         //transformed sk used to decrypt group key
    keyVal m_curKey{};          //current group key
    uint64_t m_curKeyCT{};      //current key creation time in microsecs
    std::map<thumbPrint,encGK> m_gkrList{};
    std::chrono::milliseconds m_reKeyInt{};
    std::chrono::milliseconds m_keyRand{};
    std::chrono::milliseconds m_keyLifetime{};
    bool m_keyMaker{false}; //indicates if this entity is a key maker
    bool m_init{true};      //key maker status unknown while in initialization
    bool m_conn{false};     //haven't called connection cb yet

    DistGKey(const std::string& pPre, const ndn::Name& wPre, addKeyCb&& gkeyCb, const certStore& cs,
        std::chrono::milliseconds reKeyInterval = std::chrono::seconds(3600),
        std::chrono::milliseconds reKeyRandomize = std::chrono::seconds(10),
        std::chrono::milliseconds expirationGB = std::chrono::seconds(60)) :
        m_pubPrefix{pPre},
        m_sync(wPre, m_syncSigMgr.ref(), m_keySigMgr.ref()),
        m_certs{cs},
        m_newKeyCb{std::move(gkeyCb)}, //called when a (new) group key arrives or is created
        m_reKeyInt(reKeyInterval), m_keyRand(reKeyRandomize),
        m_keyLifetime(reKeyInterval + reKeyRandomize)
        {
            m_sync.pubLifetime(std::chrono::milliseconds(reKeyInterval + reKeyRandomize + expirationGB));
            m_sync.isExpiredCb([this](auto p) {
                if(p.getName()[-1].toTimestampMicroseconds() < m_curKeyCT) {
                    _LOG_DEBUG("DistGKey received expired Publication");
                    return 1;
                }
                return 0;
            });
            m_sync.filterPubsCb([this](auto& pOurs, auto& pOthers) mutable {
                    // Order publications by most recent first and discard older keys
                    // Respond with as many pubs will fit in one Data.
                    _LOG_DEBUG("DistGKey filterPubs with pOurs " << pOurs.size());
                    if (pOurs.empty()) { return pOurs; } //XXX means only key maker will respond: remove once supression works
                    //filter any older key - a bit kludgy
                    const auto cmp = [](const auto p1, const auto p2) {
                        return p1->getName()[-1].toTimestamp() > p2->getName()[-1].toTimestamp();  
                    };
                    if (pOurs.size() > 1) {
                        std::sort(pOurs.begin(), pOurs.end(), cmp);
                    }
                    if(pOthers.empty()) {
                        return pOurs;
                    }
                    std::sort(pOthers.begin(), pOthers.end(), cmp);
                    for (auto& p : pOthers) {
                        pOurs.push_back(p);
                    }
                    return pOurs;
                });
            if (sodium_init() == -1) exit(EXIT_FAILURE);
            m_tp = m_certs.Chains()[0];
            // creates versions of signing keys for encrypt/decrypt and updates SigMgrs
            updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
        }

    /*
     * setUp() is called from a connect() function in dct_model and is passed in an indicator of whether
     * the entity can make group keys. If so, schedule callback after a short randomized delay
     * If no group key was received during the delay, set self to keyMaker and create a key list.
     *
     * (This is probably not adequate since it completely relies on the randomization but
     * could continue to monitor the topic by subscribing and doing some sort of resolution
     * function if another keymaker is found. Can have a simple resolution based on
     * highest id number. More sophistication could be added to have another key generation-capable
     * entity take over if the original becomes unavailable.)
     */
    void setup(connectedCb ccb, bool keyMaker = false) {
        m_connCb = std::move(ccb);
        _LOG_INFO("DistGKey setUp() subscribes to keys");
        if(!keyMaker) {
            _LOG_INFO("This entity doesn't make keys");
            m_gkrList.clear();   //housekeeping: clear if added any before setup
            m_init = false;
        } else {
            // random delay
            auto dly = 10 + 10*randombytes_uniform((uint32_t)49); //libsodium
            _LOG_INFO("DistGKey::setUp set random delay " << dly <<
                    "ms before trying to become key creator");
            m_timer = m_sync.schedule(std::chrono::milliseconds(dly), [this](){
                //if a groupKeyList arrived before timeout, act as member
                _LOG_DEBUG("DistGKey::setUp delay timer expired");
                if(m_init)  {  //if receiveGKeyList was called, will be false
                    _LOG_INFO("DistGKey: " << sysID() << " will become a key generator");
                    m_keyMaker = true;    //act as key generator
                    m_init = false;  //exit initialization
                    m_sync.unsubscribe(m_pubPrefix);   //unless checking for conflicts
                    makeGKey();  //create a group key, publish it, callback parent with key
                    m_conn = true;
                    m_connCb(m_conn);
                } else {
                    _LOG_INFO("DistGKey: " << sysID() << " received a key, is a member");
                    m_gkrList.clear();   //housekeeping: clear if added any
                }
            });
        }
        //subscribe to key collection and wait for a group key list
        m_sync.subscribeTo(m_pubPrefix, [this](auto p) {receiveGKeyList(p);});
    }

    /*
     * Used by the keyMaker
     * Create publications containing the group key's creation time and the gkrList
     * Publish even if the list is empty to continue to assert keymaker role
     */
    void publishKeyList()
    {
        auto dCnt = pubCnt(0);  //defaults for single packet
        int p = 1;
        auto s = m_gkrList.size();
        if(s > max_gkRs) // determine number of Publications needed if > 1
        {
            p = (s/max_gkRs) + (s % max_gkRs != 0);
            dCnt = pubCnt( p + 256 ); //upper 8 bits to k, lower 8 bits to n, 256 is (1 << 8)
        }
        _LOG_INFO("publishKeyList to publish " << p << " Publications of key records");

        auto pubTS = std::chrono::system_clock::now();
        auto it = m_gkrList.begin();
        for(auto i=0; i<p; ++i) {
            auto r = s < max_gkRs ? s : max_gkRs;
            std::vector<gkr> gkrSet;    // holds one Publication's content
            for(size_t j=0; j < r; ++j, ++it) gkrSet.push_back({it->first, it->second});
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            gkrEnc.addArray(130, gkrSet);    //says Array but it's okay with vector
            addToCollection(dCnt, pubTS, gkrEnc.vec());
            dCnt += 256;   // increment the publication# part of dCnt
            s -= r;
        }
    }

    /*
     * Use passed in component values and content to create Publication and add
     * to the group key list collection
     */
    void addToCollection(pubCnt d, std::chrono::system_clock::time_point ts, const std::vector<uint8_t>& c)
    {
        ndn::Name n(m_pubPrefix);
        n.append(sysID());   //for development/debug
        n.appendNumber(d);
        n.appendTimestamp(ts);
        syncps::Publication p(n);
        p.setContent(c);
        m_keySigMgr.ref().sign(p);
        _LOG_INFO("addToCollection passes group key list pub " << d << " to m_sync");
        m_sync.publish(std::move(p));
        return;
    }

    /*
     * Only key maker (re)schedules this method.
     * First, generates a new key. Go through the list of current group
     * members and encrypt and store new key.
     * Reschedule for reKeyInterval plus a randomization
     * This simple approach could mean a lot of work at setUp if all new entities
     * setUp at once, but keeps the logic simpler and the delay in setUp()
     * could be lengthened.
     */

    // convert the pk to a version usable by secret box
    auto encryptGKey(const uint8_t* pk)
    { 
        uint8_t cpk[crypto_scalarmult_curve25519_BYTES];
        if(crypto_sign_ed25519_pk_to_curve25519(cpk, pk) != 0)
            _LOG_INFO("encryptGKey: unable to convert signing pk to sealed box pk");
        // set encryptedKey to gk encrypted by epk version of pk
        encGK egKey;
        crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), cpk);
        return egKey;
    }

    void makeGKey()
    {
        //make a new key
        m_curKey.resize(aeadKeySz); // crypto_aead_chacha20poly1305_IETF_KEYBYTES
        crypto_aead_chacha20poly1305_ietf_keygen(m_curKey.data());
        //set the key's creation time
        m_curKeyCT = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        _LOG_INFO("makeGKey makes " << m_curKey.size() << " byte key with time " << m_curKeyCT);

        //iterate the map of thumbprints and encrypted keys to update the encrypted group key
        _LOG_INFO("makeGKey has " << m_gkrList.size() << " members on list");
        for(auto it = m_gkrList.begin(); it != m_gkrList.end(); ++it) {
            auto c = m_certs[it->first];
            it->second = encryptGKey(c.getContent()->data());
        }
        publishKeyList();
        _LOG_INFO("makeGKey reschedules makeGKey");
        m_timer = m_sync.schedule(m_reKeyInt, [this](){ makeGKey();});  //next re-keying event
        m_newKeyCb(m_curKey, m_curKeyCT);   // call back to parent with new key
    }

    /*
     * dct_model calls when there is a new valid peer signing cert.
     * This indicates to the keyMaker there is a new peer that needs the group key
     * Ignore if not a keyMaker. If initialization, go ahead and add to list in case
     * this becomes the keyMaker, but don't try to publish.
     *
     */
    void addGroupMem(const dctCert& c)
    {
        if(!m_init && !m_keyMaker) {
            _LOG_INFO("addGroupMem called for non-keyMaker");
            return;
        } else if (m_init) {
            _LOG_INFO("addGroupMem in init state gets cert " << c.getName().toUri());
            m_gkrList[c.computeThumbPrint()] = encGK{}; //add this peer to m_gkrList with empty key
            return;
        } else if (m_gkrList.size() == 80*max_gkRs) {
            // number of Publications must be fewer than smaller of
            // expectedNumberEntries for iblt (80) or 256 (dCnt limit)
            _LOG_INFO("addGroupMem can't add this peer as exceeds maximum");
            return;
        }
        //create new gkr for this peer and add to m_gkrList
        _LOG_INFO("addGroupMem gets cert " << c.getName().toUri());
        m_gkrList[c.computeThumbPrint()] = encryptGKey(c.getContent()->data());
        publishKeyList();    //publish the updated m_gkrList
    }

    // won't encrypt a group key for this thumbPrint in future
    void removeGroupMem(thumbPrint& tp) {
           m_gkrList.erase(tp);
           return;
       }

    /*
     * Called when a new Publication is received in the key collection
     * Look for the group key record with *my* key thumbprint
     * No need to keep track of all the Publications (if more than one)
     * unless to indicate an error condition if no matching key was found, so skipping for now.
     * (syncps should take care of getting any missing Publication as it would show up in the IBLT)
     */
    void receiveGKeyList(syncps::Publication& p)
    {
        _LOG_INFO("receiveGKeyList receives publication " << p.getName().toUri());
        /* receiving a group key publication means there is already a keyMaker.
         * Exit initialization so expiring timer callback in setUp() won't try to make key.
         */
        if(m_init) {
            m_init = false;
        } else if(m_keyMaker) {
            return; //shouldn't happen currently, keyMaker unsubscribes to collection
        }
        if(p.getName()[-1].toTimestampMicroseconds() < m_curKeyCT) {
            _LOG_INFO("group key publication is older than current stored key");
            return;
        }
        // decode the Content
        _LOG_INFO("receiveGKeyList will try to locate and decrypt group key from publication");
        uint64_t newCT{};
        std::vector<gkr> gkrSet{};
        try {
            tlvParser decode(*p.getContent());
            // the first tlv should be type 36 and it should decode to a uint64_t
            newCT = decode.nextBlk(36).toNumber();
            // the second tlv should be type 130 and should be a vector of gkr pairs
            gkrSet = decode.nextBlk(130).toVector<gkr>();
            // a new key will have a creation time larger than m_curKeyCT
            // (future: ensure it's from the same creator as last time?)
        } catch (std::runtime_error& ex) {
            _LOG_WARN("Ignoring groupKey message: content type error: " << ex.what());
            return;
        }
        if(newCT <= m_curKeyCT) {
            _LOG_INFO("key is not newer: new key time " << newCT << " have key time " << m_curKeyCT);
            return;
        }
        for (auto it : gkrSet) {  // go through the pairs look for match to m_tp
            if(m_tp == it.first) {
                auto nk = it.second;    // decrypt the key
                uint8_t m[aeadKeySz];
                if(crypto_box_seal_open(m, nk.data(), nk.size(), m_pDecKey.data(), m_sDecKey.data()) != 0) {
                    _LOG_INFO("receiver can't open encrypted key");
                    return;
                }
                m_curKeyCT = newCT; //save the key
                m_curKey = std::vector<uint8_t>(m, m+ aeadKeySz);
                _LOG_INFO("received new key with creation time " << m_curKeyCT);
                m_newKeyCb(m_curKey, m_curKeyCT);   // call back parent with new key
                if(!m_conn) {   //have the group key so invoke completion callback
                    m_conn = true;
                    m_connCb(m_conn);
                }
                return;
            }
        }
        _LOG_INFO("receiveGKeyList: didn't find a key in publication");
    }
    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.
     */
    void updateSigningKey(const keyVal sk, const dctCert& pubCert) {
        _LOG_INFO("updateSigningKey a signing cert Name of " << pubCert.getName().toUri());
        m_tp = m_certs.Chains()[0]; // thumbprint of signing cert
        m_syncSigMgr.ref().updateSigningKey(sk, pubCert);
        //syncSigMgr needs to get public keys of signers of Publications
        m_syncSigMgr.ref().setKeyCb([&cs=m_certs](const syncps::Publication& d) -> const keyVal& { return *(cs[d].getContent()); });
        m_keySigMgr.ref().updateSigningKey(sk, pubCert);
        //keySigMgr needs to get public keys of signers of Publications
        m_keySigMgr.ref().setKeyCb([&cs=m_certs](const syncps::Publication& d) -> const keyVal& { return *(cs[d].getContent()); });
        m_sDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(m_sDecKey.data(), sk.data()) != 0) {
            _LOG_ERROR("DistGKey::updateSigningKey could not convert secret key");
        }
        m_pDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        const auto& pk = *pubCert.getContent();
        if(crypto_sign_ed25519_pk_to_curve25519(m_pDecKey.data(), pk.data()) != 0)
            _LOG_ERROR("DistGKey::updateSigningKey unable to convert signing pk to sealed box pk");
    }
};

#endif //DIST_GKEY_HPP
