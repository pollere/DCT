#ifndef DIST_SGKEY_HPP
#define DIST_SGKEY_HPP
/*
 * dist_sgkey - distribute a pub/priv X keypair to the peers in a bespoke
 * transport using publisher privacy with authorized subscription.
 * This version is a self-contained 'header-only' library.
 *
 * DistSGKey manages all the group key operations including the decision on
 * which (eligible) entity will create the subscriber group key pair. Only one entity should
 * be making group key pairs and will rekey at periodic intervals to distribute
 * a new key, encrypting each private key with the public key of each peer with
 * subscriber capability (see https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519),
 * denoted by "SG" capability. The corresponding public key is not encrypted.
 * If a new subscribing member joins between rekeying, it is added to the list
 * of encrypted keys and republished
 * The group key pair is used by sigmgr_sgaead.hpp
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
 *  dist_sgkey is not intended as production code.
 */

#include <algorithm>
#include <functional>
#include <utility>

#include <dct/schema/capability.hpp>
#include <dct/schema/certstore.hpp>
#include <dct/schema/tlv_encoder.hpp>
#include <dct/schema/tlv_parser.hpp>
#include <dct/sigmgrs/sigmgr_by_type.hpp>
#include <dct/syncps/syncps.hpp>
#include <dct/utility.hpp>

using namespace std::literals::chrono_literals;

struct DistSGKey {
    using Publication = syncps::Publication;
    using Name = syncps::Name;
    using connectedCb = std::function<void(bool)>;

    static constexpr uint32_t kxpkKeySz = crypto_kx_PUBLICKEYBYTES;
    static constexpr uint32_t kxskKeySz = crypto_kx_SECRETKEYBYTES;
    static constexpr size_t encSGKeySz = crypto_box_SEALBYTES + kxskKeySz;
    using encSGK = std::array<uint8_t, crypto_box_SEALBYTES + kxskKeySz>;
    using xmpk = std::array<uint8_t, crypto_scalarmult_curve25519_BYTES>;
    using pubCnt = uint16_t;
    using addKeyCb = std::function<void(const keyVal&, const keyVal&, uint64_t)>;

    /*
     * DistSGKey Publications contain the creation time of the group key pair, the pair public
     * key and a list containing the pair secret key individually encrypted for each authorized
     * subscriber peer. The list holds the thumbprint of a signing key and the group secret
     * key encrypted using that (public) signing key. (12 bytes also accounts for tlv indicators)
     */
    using gkr = std::pair<const thumbPrint, encSGK>;
    static constexpr int max_gkRs = (syncps::maxPubSize - kxpkKeySz - 12) / (sizeof(thumbPrint) + encSGKeySz);

    Name m_pubPrefix;     // prefix for subscriber group key pair publications (topic list)
    Name m_kmPrefix;      // prefix for keyMaker election publications (topic km)
    SigMgrAny m_syncSM{sigMgrByType("EdDSA")};  // to sign/validate SyncData packets
    SigMgrAny m_keySM{sigMgrByType("EdDSA")};   // to sign/validate Publications in key Collection
    syncps::SyncPubsub m_sync;
    const certStore& m_certs;
    addKeyCb m_newKeyCb;   // called when subscriber group key pair rcvd
    connectedCb m_connCb{[](auto) {}};
    Cap::capChk m_kmCap;   // routine to check a signing chain for key maker capability
    Cap::capChk m_sgCap;   // routine to check a signing chain for subscriber capability
    thumbPrint m_tp{};
    keyVal m_pDecKey{}; //local public signing key converted to X and
    keyVal m_sDecKey{}; // local signing sk converted to X (used by subr to open sealed box with subscriber group secret key)
    keyVal m_sgSK{};    // current subscribergroup secret key
    keyVal m_sgPK{};    // current subscribergroup public key
    uint64_t m_curKeyCT{};      // current sg key pair creation time in microsecs
    std::map<thumbPrint,encSGK> m_gkrList{};
    std::unordered_map<thumbPrint,xmpk> m_mbrList{};
    std::chrono::milliseconds m_reKeyInt{};
    std::chrono::milliseconds m_keyRand{};
    std::chrono::milliseconds m_keyLifetime{};
    std::chrono::milliseconds m_electionDuration{100};
    uint32_t m_KMepoch{0};      // current election epoch
    int m_mayMakeKeys{0};       // >0 if this entity is a candidate key maker
    bool m_init{true};          // key maker status unknown while in initialization
    bool m_subr{false};         // set if this identity has the subscriber capability

    DistSGKey(syncps::FaceType& face, const std::string& pPre, const Name& wPre, addKeyCb&& sgkeyCb,
             const certStore& cs,
             std::chrono::milliseconds reKeyInterval = std::chrono::seconds(3600),
             std::chrono::milliseconds reKeyRandomize = std::chrono::seconds(10),
             std::chrono::milliseconds expirationGB = std::chrono::seconds(60)) :
             m_pubPrefix{pPre + "/list"}, m_kmPrefix{pPre + "/km"},
             m_sync(face, wPre, m_syncSM.ref(), m_keySM.ref()),
             m_certs{cs},
             m_newKeyCb{std::move(sgkeyCb)}, //called when a (new) group key arrives or is created
             m_kmCap{Cap::checker("KM", pPre, cs)},
             m_sgCap{Cap::checker("SG", pPre, cs)},
             m_reKeyInt(reKeyInterval), m_keyRand(reKeyRandomize),
             m_keyLifetime(reKeyInterval + reKeyRandomize) {
        m_sync.cStateLifetime(70ms);
        m_sync.pubLifetime(std::chrono::milliseconds(reKeyInterval + reKeyRandomize + expirationGB));
        m_sync.getLifetimeCb([this](const Publication& p) {
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
        // get our identity thumbprint, check if we're allowed to make keys, check if we
        // are in subscriber group, then set up our public and private signing keys.
        m_tp = m_certs.Chains()[0];
        updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.
     * Creates X version of group member's signing key for encrypt/decrypt
     * Currently only called at start up but this would need to be called (likely through dct_model)
     * if a local signing key pair is updated after start up.
     */
    void updateSigningKey(const keyVal sk, const dctCert& pubCert) {

        m_tp = dctCert::computeThumbPrint(pubCert);
        m_subr = m_sgCap(m_tp).first;
        if(m_subr)   //can't make keys unless a member of the subscriber group
            m_mayMakeKeys = m_kmCap(m_tp).first? 1 : 0;

        // sigmgrs need to get the new signing keys and public key lookup callbacks
        m_syncSM.updateSigningKey(sk, pubCert);
        m_keySM.updateSigningKey(sk, pubCert);
        m_syncSM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
        m_keySM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
        if(!m_subr)  return;

        // convert the new key to form needed for group key encrypt/decrypt
        //only need first 32 bytes of sk (rest is appended pk)
        keyVal ssk(sk.begin(), sk.begin()+32);
        m_sDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(m_sDecKey.data(), ssk.data()) != 0) {
            std::runtime_error("DistSGKey::updateSigningKey could not convert secret key");
        }
        m_pDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        const auto& pk = *pubCert.getContent();
        if(crypto_sign_ed25519_pk_to_curve25519(m_pDecKey.data(), pk.data()) != 0) {
            std::runtime_error("DistSGKey::updateSigningKey unable to convert signing pk to sealed box pk");
        }
    }

    /*
     * Called when a new Publication is received in the key collection
     * If have subr capability, look for the group key record with *my* key thumbprint
     * No need to keep track of all the Publications (if more than one)
     * unless to indicate an error condition if no matching key was found, so skipping for now.
     * (syncps should take care of getting any missing Publication as it would show up in the IBLT)
     */
    void receiveSGKeyList(syncps::Publication& p)
    {
        if (m_mayMakeKeys > 0) return;  //shouldn't happen: keyMaker unsubscribes to collection
        if (! m_kmCap(dctCert::getKeyLoc(p)).first || ! m_sgCap(dctCert::getKeyLoc(p)).first) {      
            return; //ignore keylist signed by unauthorized identity
        }
        const auto& n = p.getName();
        if(n[-1].toTimestampMicroseconds() < m_curKeyCT) {
            return; //group key publication is older than current stored key
        }
        // if this msg was from an earlier Key Maker epoch, ignore it. If from a later
        // epoch, wrongEpoch will cancel any in-progress election and update our epoch.
        auto epoch = n[-3].toNumber();
        if (wrongEpoch(epoch) && epoch != m_KMepoch) return;

        // decode the Content
        uint64_t newCT{};
        std::span<const gkr> gkrVec{};
        try {
            tlvParser decode(*p.getContent(), 0);
            // the first tlv should be type 36 and it should decode to a uint64_t
            newCT = decode.nextBlk(36).toNumber();
            // a new key will have a creation time larger than m_curKeyCT
            if(newCT <= m_curKeyCT) {
                return; //received key is not newer that current key
            }

            // the second tlv should be type 150 and should decode to a vector of uint8_t (for public SG key)
            m_sgPK = decode.nextBlk(150).toVector<uint8_t>();
            if(!m_subr) {
                if(m_init) {
                    m_curKeyCT = newCT;
                    m_newKeyCb(m_sgPK, m_sgSK, m_curKeyCT); //use addKeyCb to set new sg public key in pub privacy sigmgr
                    // parent has public key so callback to start next stage
                    m_sync.cStateLifetime(std::chrono::milliseconds(6763));
                    m_init = false;
                    m_connCb(true);
                }
                return;
            }
            // the second tlv should be type 130 and should be a vector of gkr pairs
            gkrVec = decode.nextBlk(130).toSpan<gkr>();    
            // (future: ensure it's from the same creator as last time?)
        } catch (std::runtime_error& ex) {
            return; //ignore this groupKey message - content type error e.what()
        }

        auto it = std::find_if(gkrVec.begin(), gkrVec.end(), [this](auto p){ return p.first == m_tp; });
        if (it == gkrVec.end()) {
            return; //didn't find a key in publication
        }

        // decrypt and save the secret key of pair [might not need to save since gets passed to sigmgr to use]
        const auto& nk = it->second;
        uint8_t m[kxskKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), m_pDecKey.data(), m_sDecKey.data()) != 0) {
            return; //can't open encrypted key
        }

        m_sgSK = std::vector<uint8_t>(m, m + kxskKeySz);
        m_curKeyCT = newCT; //now that we know it's a good key, we can set it
        m_newKeyCb(m_sgPK, m_sgSK, m_curKeyCT);   //call back parent to pass the new sg key pair to pub privacy sigmgr
        if(m_init) {
            // parent has key so callback to start next stage
            m_sync.cStateLifetime(std::chrono::milliseconds(6763));
            m_init = false;
            m_connCb(true);
        }
    }

    /*
     * setUp() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when a group key has been received (i.e., when this entity is
     * able to encrypt/decrypt wirepacket content). This module checks for two
     * possible capabilities that may appear in its signing identity chain.
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
    void setup(connectedCb&& ccb) {
        m_connCb = std::move(ccb);
        // subscribe to key collection and wait for a group key list
        m_sync.subscribeTo(m_pubPrefix, [this](auto p){ receiveSGKeyList(p); });
        m_sync.subscribeTo(Name(m_kmPrefix).append("elec"), [this](auto p){ handleKMelec(p); });
        if(m_mayMakeKeys > 0) joinKMelection();
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
        if (m_mayMakeKeys <= 0) return;

        ++m_KMepoch;
        m_sync.unsubscribe(m_pubPrefix);   //unless checking for conflicts
        sgkeyTimeout();  //create a group key, publish it, callback parent with key, set next rekey
        publishKM("elec");
        m_sync.cStateLifetime(std::chrono::milliseconds(6763));
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
        auto pubTS = std::chrono::system_clock::now();
        auto it = m_gkrList.begin();
        for(auto i=0; i<p; ++i) {
            auto r = s < max_gkRs ? s : max_gkRs;
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            gkrEnc.addArray(150, m_sgPK);
            it = gkrEnc.addArray(130, it, r);
            publishKeySeg(dCnt, pubTS, gkrEnc.vec());
            dCnt += 256;   // increment the publication# part of dCnt
            s -= r;
        }
    }

    // Publish one segment of the subscriber group key list
    void publishKeySeg(pubCnt d, auto ts, auto& c) {
        syncps::Publication p(Name(m_pubPrefix).append(sysID()).appendNumber(m_KMepoch)
                                               .appendNumber(d).appendTimestamp(ts));
        p.setContent(c);
        m_keySM.sign(p);
        m_sync.publish(std::move(p));
    }

    // return the subscriber group secret key in a sealed box that can only opened by the
    // (X converted) secret key associated with public key 'pk'
    auto encryptSGKey(const thumbPrint tp) const noexcept {
        auto xpk = m_mbrList.at(tp);   //get this member's converted pub key
        // encrypt the sub group's key pair's secret key with xpk
        encSGK egKey;
        crypto_box_seal(egKey.data(), m_sgSK.data(), m_sgSK.size(), xpk.data());
        return egKey;
    }

    // Make a new subscriber key pair and update the key list with per-member encrypted
    // versions of it. Then publish the new group key list, and locally switch to using the new key.

    void makeSGKey() {
        //make a new key pair
        m_sgPK.resize(kxpkKeySz);
        m_sgSK.resize(kxskKeySz);
        crypto_kx_keypair(m_sgPK.data(), m_sgSK.data());    //X25519

        //set the creation time
        m_curKeyCT = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
        /* std::cout <<("makeSGKey makes " << m_sgPK.size() << " byte public key and " <<
                  m_sgSK.size() << " byte secret key with time " << m_curKeyCT
                  << " for " << m_gkrList.size() << " list members\n";*/

        //iterate the map of thumbprints and encrypted keys to update the encrypted group key
        std::for_each(m_gkrList.begin(), m_gkrList.end(), [this](auto& gke) {
                gke.second = encryptSGKey(gke.first); });
        publishKeyList();
        m_newKeyCb(m_sgPK, m_sgSK, m_curKeyCT);   // call back to parent with new key pair
                                      //    parent calls the application publication sigmgr's addKey()
    }

    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void sgkeyTimeout() {
        makeSGKey();
        m_sync.oneTime(m_reKeyInt, [this](){ sgkeyTimeout();});  //next re-keying event
    }

    /*
     * This called when there is a new valid peer signing cert.
     * This indicates to the keyMaker there is a new peer that needs the group key
     * Ignore if not a keyMaker. If initialization, go ahead and add to list in case
     * this becomes the keyMaker, but don't try to publish.
     */
    void addGroupMem(const dctCert& c) {
        if(m_mayMakeKeys <= 0) return;  //this entity is not a keymaker
        auto tp = dctCert::computeThumbPrint(c);
        //shouldn't have to republish the keylist so a publisher can get public key since key list lifefime is long
        if(!m_sgCap(tp).first) return;  //this signing cert doesn't have SG capability.

        // number of Publications should be fewer than 'complete peeling' iblt threshold (currently 80).
        // Each gkR is ~100 bytes so the default maxPubSize of 1024 allows for ~800 members. 
        if (m_gkrList.size() == 80*max_gkRs) {
            return; // exceeds maximum of " << 80*max_gkRs);
        }
        // convert pk to form that can be used to encrypt and add to member list
        if(crypto_sign_ed25519_pk_to_curve25519(m_mbrList[tp].data(), c.getContent()->data()) != 0)
            return;     //unable to convert member's pk to sealed box pk

        if (m_init) {
            m_gkrList[tp] = encSGK{}; //add this peer to m_gkrList with empty key
        } else {
            m_gkrList[tp] = encryptSGKey(tp);   //add this peer to key list with encrypted sg sk
            publishKeyList();                   //publish the updated m_gkrList
        }
    }

    // won't encrypt a group key for this thumbPrint in future
    // if reKey is set, change the group key now to exclude the removed member
    void removeGroupMem(thumbPrint& tp, bool reKey = false) {
        m_gkrList.erase(tp);
        m_mbrList.erase(tp);
        if(reKey) { makeSGKey(); } //new key without disturbing rekey schedule
    }
};

#endif //DIST_SGKEY_HPP
