#ifndef DIST_GKEY_HPP
#define DIST_GKEY_HPP
/*
 * dist_gkey - distribute a symmetric encryption key to a group of peers.
 * This version is a self-contained 'header-only' library.
 *
 * DistGKey manages all the group key operations including the decision on
 * which (eligible) entity will create the group key. Only one entity should
 * be making group keys and will rekey at periodic intervals to distribute
 * a new key, encrypting each key with the public key of each peer (see
 * https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519). If a new
 * member joins between rekeying, it is added to the list of encrypted keys
 * which is republished.  The group key is currently used by sigmgr_aead.hpp
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
 *  dist_gkey is not intended as production code.
 */

#include <algorithm>
#include <functional>
#include <utility>

#include <dct/schema/dct_cert.hpp>
#include <dct/schema/certstore.hpp>
#include <dct/schema/tlv_encoder.hpp>
#include <dct/schema/tlv_parser.hpp>
#include <dct/sigmgrs/sigmgr_by_type.hpp>
#include <dct/syncps/syncps.hpp>
#include <dct/utility.hpp>

using namespace std::literals::chrono_literals;

struct DistGKey {    
    using Publication = const syncps::Publication;
    using Name = syncps::Name;
    using connectedCb = std::function<void(bool)>;

    static constexpr uint32_t aeadKeySz = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    static constexpr size_t encGKeySz = crypto_box_SEALBYTES + aeadKeySz;
    using encGK = std::array<uint8_t, crypto_box_SEALBYTES + aeadKeySz>;
    using pubCnt = uint16_t;
    using addKeyCb = std::function<void(const keyVal&, uint64_t)>;

    /*
     * DistGKey Publications contain the creation time of the symmetric key and a list of
     * pairs containing that symmetric key individually encrypted for each peer. Each
     * pair has the thumbprint of a signing key and the symmetric key encrypted using that
     * (public) signing key. (12 bytes also accounts for tlv indicators)
     */
    using gkr = std::pair<const thumbPrint, encGK>;
    static constexpr int max_gkRs = (syncps::maxPubSize - 12) / (sizeof(thumbPrint) + encGKeySz);

    Name m_pubPrefix;     // prefix for group symmetric key list publications
    Name m_kmPrefix;      // prefix for keyMaker election publications
    SigMgrAny m_syncSM{sigMgrByType("EdDSA")};  // to sign/validate SyncData packets
    SigMgrAny m_keySM{sigMgrByType("EdDSA")};   // to sign/validate key list Publications
    syncps::SyncPubsub m_sync;
    const certStore& m_certs;
    addKeyCb m_newKeyCb;   // called when group key rcvd
    connectedCb m_connCb{[](auto) {}};
    log4cxx::LoggerPtr staticModuleLogger{log4cxx::Logger::getLogger("DistGKey")};
    thumbPrint m_tp{};
    keyVal m_pDecKey{};         // transformed pk used to encrypt group key
    keyVal m_sDecKey{};         // transformed sk used to decrypt group key
    keyVal m_curKey{};          // current group key
    uint64_t m_curKeyCT{};      // current key creation time in microsecs
    std::map<thumbPrint,encGK> m_gkrList{};
    std::chrono::milliseconds m_reKeyInt{};
    std::chrono::milliseconds m_keyRand{};
    std::chrono::milliseconds m_keyLifetime{};
    std::chrono::milliseconds m_electionDuration{100};
    uint32_t m_KMepoch{0};      // current election epoch
    int m_mayMakeKeys{0};       // >0 if this entity is a candidate key maker
    bool m_keyMaker{false};     // true if this entity is current key maker
    bool m_init{true};          // key maker status unknown while in initialization

    DistGKey(const std::string& pPre, const Name& wPre, addKeyCb&& gkeyCb, const certStore& cs,
             std::chrono::milliseconds reKeyInterval = std::chrono::seconds(3600),
             std::chrono::milliseconds reKeyRandomize = std::chrono::seconds(10),
             std::chrono::milliseconds expirationGB = std::chrono::seconds(60)) :
             m_pubPrefix{pPre + "/list"}, m_kmPrefix{pPre + "/km"},
             m_sync(wPre, m_syncSM.ref(), m_keySM.ref()),
             m_certs{cs},
             m_newKeyCb{std::move(gkeyCb)}, //called when a (new) group key arrives or is created
             m_reKeyInt(reKeyInterval), m_keyRand(reKeyRandomize),
             m_keyLifetime(reKeyInterval + reKeyRandomize) {
        m_sync.syncInterestLifetime(70ms);
        m_sync.pubLifetime(std::chrono::milliseconds(reKeyInterval + reKeyRandomize + expirationGB));
        m_sync.getLifetimeCb([this](Publication& p) {
            if (p.getName()[m_pubPrefix.size()].getValue()->front() == 'c') return m_electionDuration; // candidate
            return m_keyLifetime; // list pub and election result
        });
        // Order publications by ours first then most recent first
        m_sync.filterPubsCb([](auto& pOurs, auto& pOthers) {
                if (pOurs.empty()) return pOurs; // non-keymakers don't reply
                const auto cmp = [](const auto& p1, const auto& p2) {
                    return p1->getName()[-1].toTimestamp() > p2->getName()[-1].toTimestamp();  
                };
                if (pOurs.size() > 1) std::sort(pOurs.begin(), pOurs.end(), cmp);
                if(! pOthers.empty()) {
                    std::sort(pOthers.begin(), pOthers.end(), cmp);
                    for (auto& p : pOthers) pOurs.push_back(p);
                }
                return pOurs;
            });
        if (sodium_init() == -1) exit(EXIT_FAILURE);
        // creates versions of signing keys for encrypt/decrypt and updates SigMgrs
        m_tp = m_certs.Chains()[0];
        updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.
     */
    void updateSigningKey(const keyVal sk, const dctCert& pubCert) {
        _LOG_INFO("updateSigningKey a signing cert Name of " << pubCert.getName().toUri());
        // sigmgrs need to get the new signing keys and public key lookup callbacks
        m_syncSM.updateSigningKey(sk, pubCert);
        m_keySM.updateSigningKey(sk, pubCert);
        m_syncSM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
        m_keySM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });

        // convert the new key to form needed for group key encrypt/decrypt
        m_sDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(m_sDecKey.data(), sk.data()) != 0) {
            _LOG_ERROR("DistGKey::updateSigningKey could not convert secret key");
        }
        m_pDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        const auto& pk = *pubCert.getContent();
        if(crypto_sign_ed25519_pk_to_curve25519(m_pDecKey.data(), pk.data()) != 0) {
            _LOG_ERROR("DistGKey::updateSigningKey unable to convert signing pk to sealed box pk");
        }
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
        const auto& n = p.getName();
        _LOG_INFO("receiveGKeyList receives publication " << n.toUri());
        if(n[-1].toTimestampMicroseconds() < m_curKeyCT) {
            _LOG_INFO("group key publication is older than current stored key");
            return;
        }
        // if this msg was from an earlier Key Maker epoch, ignore it. If from a later
        // epoch, wrongEpoch will cancel any in-progress election and update our epoch.
        auto epoch = n[-3].toNumber();
        if (wrongEpoch(epoch) && epoch != m_KMepoch) return;

        // shouldn't happen: keyMaker unsubscribes to collection
        if (m_keyMaker) return;

        // decode the Content
        uint64_t newCT{};
        std::span<const gkr> gkrVec{};
        try {
            tlvParser decode(*p.getContent(), 0);
            // the first tlv should be type 36 and it should decode to a uint64_t
            newCT = decode.nextBlk(36).toNumber();
            // the second tlv should be type 130 and should be a vector of gkr pairs
            gkrVec = decode.nextBlk(130).toSpan<gkr>();
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
        auto it = std::find_if(gkrVec.begin(), gkrVec.end(), [this](auto p){ return p.first == m_tp; });
        if (it == gkrVec.end()) {
            _LOG_INFO("receiveGKeyList: didn't find a key in publication");
            return;
        }

        // decrypt and save the key
        const auto& nk = it->second;
        uint8_t m[aeadKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), m_pDecKey.data(), m_sDecKey.data()) != 0) {
            _LOG_INFO("receiver can't open encrypted key");
            return;
        }
        m_curKeyCT = newCT;
        m_curKey = std::vector<uint8_t>(m, m + aeadKeySz);
        _LOG_INFO("received new key with creation time " << m_curKeyCT);
        m_newKeyCb(m_curKey, m_curKeyCT);   // call back parent with new key
        if(m_init) {
            // parent has key so callback to start next stage
            m_sync.syncInterestLifetime(std::chrono::milliseconds(6763));
            m_init = false;
            m_connCb(true);
        }
    }

    /*
     * setUp() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when a group key has been received (i.e., when this entity is
     * able to encrypt/decrypt wirepacket content) and an indicator, 'keyMaker',
     * controlling whether this entity is a candidate group key maker
     * ('keyMaker <= 0' indicates it is not a candidate). Positive values influence
     * the probability of this entity being elected with larger values giving
     * higher priority.
     *
     * The keyMaker election happens via publications to topic m_kmPrefix. The
     * election is currently one-round & priority-based but will eventually follow
     * a 'simple paxos' re-election model to handle loss of the current keymaker.
     *
     * Candidate KeyMakers send a 'proposal' consisting of an election
     * epoch number plus their keyMaker priority and thumbprint. Proposals are
     * normal, signed, publications with a fixed lifetime and replay protection.
     * The thumbprint used to rank the proposal is taken from the publication's
     * key locator so proposals cannot be forged.
     *
     * The election runs for a fixed time interval starting with the first
     * publication of the current epoch.  Publications prior to the current
     * epoch are ignored.  Current epoch publications are ordered by km value
     * then thumbprint and the highest value announced wins the election.
     * The election winner increments the epoch and sends a 'finalize' publication
     * to end the election. The winner republishes this announcement at a
     * fixed keepalive interval so late joiners can learn the election outcome.
     * The epoch semantics and keepalive also allow for keyMaker failure detection
     * and Paxos-like re-election proposals but this has not been implemented yet.
     *
     * All candidates send their initial proposal with an epoch of 0.  If they receive
     * a proposal with a later epoch, the election has been finalized and they
     * are not the keyMaker.  To support (future) re-election on keyMaker failure,
     * the current epoch is remembered in m_kmEpoch.
     */
    void setup(connectedCb&& ccb, int keyMaker = 0) {
        _LOG_INFO("DistGKey setUp() mayMakeKeys = " << keyMaker);
        m_connCb = std::move(ccb);
        m_mayMakeKeys = keyMaker;
        // subscribe to key collection and wait for a group key list
        m_sync.subscribeTo(m_pubPrefix, [this](auto p){ receiveGKeyList(p); });
        m_sync.subscribeTo(Name(m_kmPrefix).append("elec"), [this](auto p){ handleKMelec(p); });
        if(keyMaker > 0 && m_mayMakeKeys > 0) joinKMelection();
    }

    /*** Following methods are used by candidate keymakers for the key maker election ***/

    // build and publish a key maker ('km') pubication
    //  XXX arg should be a string_view but current NDN library doesn't support that
    void publishKM(const char* topic) {
        syncps::Publication p(Name(m_kmPrefix).append(topic).appendNumber(m_KMepoch)
                                .appendNumber(m_mayMakeKeys).appendTimestamp(std::chrono::system_clock::now()));
        m_keySM.sign(p);
        m_sync.publish(std::move(p));
    }

    void joinKMelection() {
        publishKM("cand");
        m_sync.subscribeTo(Name(m_kmPrefix).append("cand"), [this](auto p){ handleKMcand(p); });
        m_sync.oneTime(std::chrono::milliseconds(m_electionDuration), [this]{ electionDone(); });
    }

    // This is called when the local election timer times out. If this instance didn't win
    // (signaled by m_mayMakeKeys <= 0), nothing more is done. Otherwise, the winning instance
    // increments m_KMepoch then sends an 'elected' pub to tell other candidate KMs that it
    // has won. It then sends a group key list to everyone which will take them out of init state.
    void electionDone() {
        _LOG_DEBUG("DistGKey election done, m_mayMakeKeys = " << m_mayMakeKeys);
        if (m_mayMakeKeys <= 0) return;

        ++m_KMepoch;
        m_keyMaker = true;    //act as key generator
        m_sync.unsubscribe(m_pubPrefix);   //unless checking for conflicts
        makeGKey();  //create a group key, publish it, callback parent with key
        publishKM("elec");
        m_sync.syncInterestLifetime(std::chrono::milliseconds(6763));
        m_init = false;
        m_connCb(true); // parent has key so let it proceed
    }

    // Update our contending/lost state based on a new peer "candidate" publication.
    // "m_mayMakeKeys" is our election 'priority' (a positive integer; higher wins).
    // If peer has a larger priority or thumbprint we can't win the election which
    // we note by negating the value of m_mayMakeKeys.
    void handleKMcand(const syncps::Publication& p) {
        if (m_mayMakeKeys < 0) return; // already know election is lost
        const auto& n = p.getName();
        if (n.size() != m_kmPrefix.size() + 4) return; // bad name format
        if (wrongEpoch(n[-3].toNumber())) return;

        auto pri = n[-2].toNumber();
        if (std::cmp_greater(m_mayMakeKeys, pri)) return; // candidate loses
        if (std::cmp_greater(pri, m_mayMakeKeys) ||
                dctCert::getKeyLoc(p) > m_tp) m_mayMakeKeys = -m_mayMakeKeys; // we lose
    }

    // check that msg from peer in same epoch as us. Return value of 'true'
    // means msg should be ignored because of epoch mis-match.  If peers are
    // in later epoch, cancel current election & update our epoch.
    bool wrongEpoch(const auto epoch) {
        if (epoch == m_KMepoch) return false;
        if (epoch > m_KMepoch) {
            if (m_mayMakeKeys > 0) m_mayMakeKeys = -m_mayMakeKeys;
            m_KMepoch = epoch;
        }
        return true;
    }

    // handle an "I won the election" publication from some peer
    void handleKMelec(const syncps::Publication& p) {
        const auto& n = p.getName();
        if (n.size() != m_kmPrefix.size() + 4) return; // bad name format
        auto epoch = n[-3].toNumber();
        if (m_KMepoch >= epoch) return; // ignore msg from earlier election
        if (m_mayMakeKeys > 0) {
            _LOG_INFO("elected msg from peer while m_mayMakeKeys = " << m_mayMakeKeys);
            m_mayMakeKeys = -m_mayMakeKeys;
        }
        m_KMepoch = epoch;
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key list ***/

    /*
     * Create publications containing the group key's creation time and the gkrList
     * Publish even if the list is empty to continue to assert keyMaker role
     */
    void publishKeyList() {
        // assume one publication will hold all the keys
        int p = 1;
        auto dCnt = pubCnt(0);
        auto s = m_gkrList.size();
        if(s > max_gkRs) {
            // determine number of Publications needed since > 1 required
            p = (s + max_gkRs - 1) / max_gkRs;
            dCnt = pubCnt( p + 256 ); //upper 8 bits to k, lower 8 bits to n, 256 is (1 << 8)
        }
        _LOG_INFO("publishKeyList to publish " << p << " Publications of key records");

        auto pubTS = std::chrono::system_clock::now();
        auto it = m_gkrList.begin();
        for(auto i=0; i<p; ++i) {
            auto r = s < max_gkRs ? s : max_gkRs;
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            it = gkrEnc.addArray(130, it, r);
            publishKeyChunk(dCnt, pubTS, gkrEnc.vec());
            dCnt += 256;   // increment the publication# part of dCnt
            s -= r;
        }
    }

    // Publish one chunk of the group key list collection
    void publishKeyChunk(pubCnt d, auto ts, auto& c) {
        syncps::Publication p(Name(m_pubPrefix).append(sysID()).appendNumber(m_KMepoch)
                                               .appendNumber(d).appendTimestamp(ts));
        p.setContent(c);
        m_keySM.sign(p);
        m_sync.publish(std::move(p));
    }

    // return the group key in a sealed box that can only opened by the 
    // secret key associated with public key 'pk'
    auto encryptGKey(const uint8_t* pk) const noexcept { 
        // convert pk to form that can be used to encrypt
        uint8_t cpk[crypto_scalarmult_curve25519_BYTES];
        if(crypto_sign_ed25519_pk_to_curve25519(cpk, pk) != 0)
            _LOG_INFO("encryptGKey: unable to convert signing pk to sealed box pk");
        // set encryptedKey to gk encrypted by epk version of pk
        encGK egKey;
        crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), cpk);
        return egKey;
    }

    // Make a new group key and update the group key list with per-member encrypted
    // versions of it. Then publish the new group key list, schedule the next re-key,
    // and locally switch to using the new key.
    void makeGKey() {
        //make a new key
        m_curKey.resize(aeadKeySz); // crypto_aead_chacha20poly1305_IETF_KEYBYTES
        crypto_aead_chacha20poly1305_ietf_keygen(m_curKey.data());
        //set the key's creation time
        m_curKeyCT = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
        _LOG_INFO("makeGKey makes " << m_curKey.size() << " byte key with time " << m_curKeyCT
                    << " for " << m_gkrList.size() << " list members");

        //iterate the map of thumbprints and encrypted keys to update the encrypted group key
        std::for_each(m_gkrList.begin(), m_gkrList.end(), [this](auto& gke) {
                gke.second = encryptGKey(m_certs[gke.first].getContent()->data()); });
        publishKeyList();
        m_sync.oneTime(m_reKeyInt, [this](){ makeGKey();});  //next re-keying event
        m_newKeyCb(m_curKey, m_curKeyCT);   // call back to parent with new key
    }

    /*
     * This called when there is a new valid peer signing cert.
     * This indicates to the keyMaker there is a new peer that needs the group key
     * Ignore if not a keyMaker. If initialization, go ahead and add to list in case
     * this becomes the keyMaker, but don't try to publish.
     */
    void addGroupMem(const dctCert& c) {
        if(!m_init && !m_keyMaker) return;

        // number of Publications should be fewer than 'complete peeling' iblt threshold (currently 80).
        // Each gkR is ~100 bytes so the default maxPubSize of 1024 allows for ~800 members. 
        if (m_gkrList.size() == 80*max_gkRs) {
            _LOG_INFO("addGroupMem can't add this peer as exceeds maximum of " << 80*max_gkRs);
            return;
        }
        if (m_init) {
            _LOG_INFO("addGroupMem in init state gets cert " << c.getName().toUri());
            m_gkrList[c.computeThumbPrint()] = encGK{}; //add this peer to m_gkrList with empty key
            return;
        }
        //create new gkr for this peer and add to m_gkrList
        _LOG_INFO("addGroupMem gets cert " << c.getName().toUri());
        m_gkrList[c.computeThumbPrint()] = encryptGKey(c.getContent()->data());
        publishKeyList();    //publish the updated m_gkrList
    }

    // won't encrypt a group key for this thumbPrint in future
    void removeGroupMem(thumbPrint& tp) { m_gkrList.erase(tp); }
};

#endif //DIST_GKEY_HPP
