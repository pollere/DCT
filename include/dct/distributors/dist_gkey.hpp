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
 *  dist_gkey is not intended as production code.
 */

#include <algorithm>
#include <cstring> // for memcmp
#include <functional>
#include <utility>

#include <dct/schema/capability.hpp>
#include <dct/schema/certstore.hpp>
#include <dct/schema/tlv_encoder.hpp>
#include <dct/schema/tlv_parser.hpp>
#include <dct/sigmgrs/sigmgr_by_type.hpp>
#include <dct/syncps/syncps.hpp>
#include <dct/utility.hpp>
#include "km_election.hpp"

using namespace std::literals::chrono_literals;

namespace dct {

struct DistGKey {
    using connectedCb = std::function<void(bool)>;

    static constexpr uint32_t aeadKeySz = crypto_aead_chacha20poly1305_IETF_KEYBYTES;
    static constexpr size_t encGKeySz = crypto_box_SEALBYTES + aeadKeySz;
    using encGK = std::array<uint8_t, crypto_box_SEALBYTES + aeadKeySz>;
    using xmpk = std::array<uint8_t, crypto_scalarmult_curve25519_BYTES>;
    using addKeyCb = std::function<void(keyRef, uint64_t)>;
    using kmpriCB = ofats::any_invocable<int32_t(thumbPrint)>;

    /*
     * DistGKey Publications contain the creation time of the symmetric key and a list of
     * pairs containing that symmetric key individually encrypted for each peer. Each
     * pair has the thumbprint of a signing key and the symmetric key encrypted using that
     * (public) signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators)
     */
    using gkr = std::pair<const thumbPrint, encGK>;
    static constexpr int maxKR = (maxPubSize - 96) / (sizeof(thumbPrint) + encGKeySz);

    const crName m_prefix;        // prefix for pubs in this distributor's collection
    const crName m_pubPrefix;     // prefix for group symmetric key list publications
    SigMgrAny m_syncSM{sigMgrByType("EdDSA")};  // to sign/validate SyncData packets
    SigMgrAny m_keySM{sigMgrByType("EdDSA")};   // to sign/validate key list Publications
    SyncPS m_sync;
    const certStore& m_certs;
    addKeyCb m_newKeyCb;   // called when group key rcvd
    connectedCb m_connCb{[](auto) {}};
    kmpriCB m_kmpri;
    thumbPrint m_tp{};
    keyVal m_pDecKey{};         // transformed pk used to encrypt group key; use with
    keyVal m_sDecKey{};         // transformed sk used to decrypt group key
    keyVal m_curKey{};          // current group key
    uint64_t m_curKeyCT{};      // current key creation time in microsecs
    std::map<thumbPrint,xmpk> m_mbrList{};

    std::chrono::milliseconds m_reKeyInt{3600};
    std::chrono::milliseconds m_keyRand{10};
    std::chrono::milliseconds m_keyLifetime{3600+10};
    kmElection* m_kme{};
    uint32_t m_KMepoch{};       // current election epoch
    bool m_keyMaker{false};     // true if this entity is a key maker
    bool m_init{true};          // key maker status unknown while in initialization

    DistGKey(DirectFace& face, const Name& pPre, const Name& wPre, addKeyCb&& gkeyCb, const certStore& cs,
             std::chrono::milliseconds reKeyInterval = std::chrono::seconds(3600), //XXX make methods
             std::chrono::milliseconds reKeyRandomize = std::chrono::seconds(10),
             std::chrono::milliseconds expirationGB = std::chrono::seconds(60)) :
             m_prefix{pPre}, m_pubPrefix{pPre/"gk"}, m_sync(face, wPre, m_syncSM.ref(), m_keySM.ref()),
             m_certs{cs}, m_newKeyCb{std::move(gkeyCb)}, //called when a (new) group key arrives or is created
             m_reKeyInt(reKeyInterval), m_keyRand(reKeyRandomize),
             m_keyLifetime(m_reKeyInt + m_keyRand) {
        m_sync.cStateLifetime(253ms);
        m_sync.pubLifetime(std::chrono::milliseconds(reKeyInterval + reKeyRandomize + expirationGB));
        m_sync.getLifetimeCb([this,cand=crPrefix(m_prefix/"KM"/"cand")](const auto& p) {
            return cand.isPrefix(p.name())? 100ms : m_keyLifetime;
        });
#if 0
        // Order publications by ours first then most recent first
        m_sync.filterPubsCb([](auto& pOurs, auto& pOthers) {
                if (pOurs.empty()) return; // non-keymakers don't reply
                const auto cmp = [](const auto& p1, const auto& p2) {
                    return p1.name().last().toTimestamp() > p2.name().last().toTimestamp();  
                };
                if (pOurs.size() > 1) std::sort(pOurs.begin(), pOurs.end(), cmp);
                if(! pOthers.empty()) {
                    std::sort(pOthers.begin(), pOthers.end(), cmp);
                    for (auto& p : pOthers) pOurs.push_back(p);
                }
            });
#endif
        // get our identity thumbprint, check if we're allowed to make keys,
        // then set up our public and private signing keys.
        m_tp = m_certs.Chains()[0];
        updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        // sigmgrs need to get the new signing keys and public key lookup callbacks
        m_syncSM.updateSigningKey(sk, pubCert);
        m_keySM.updateSigningKey(sk, pubCert);
        m_syncSM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
        m_keySM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });

        // convert the new key to form needed for group key encrypt/decrypt
        m_sDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(m_sDecKey.data(), sk.data()) != 0) {
            std::runtime_error("DistGKey::updateSigningKey could not convert secret key");
        }
        m_pDecKey.resize(crypto_scalarmult_curve25519_BYTES);
        const auto& pk = pubCert.content().toSpan();
        if(crypto_sign_ed25519_pk_to_curve25519(m_pDecKey.data(), pk.data()) != 0) {
            std::runtime_error("DistGKey::updateSigningKey unable to convert signing pk to sealed box pk");
        }
    }

    void initDone() {
        if (m_init) {
            m_init = false;
            m_sync.cStateLifetime(6763ms);
            m_connCb(true);
        }
    }

    /*
     * Called when a new Publication is received in the key collection
     * Look for the group key record with *my* key thumbprint
     *      * Using first 4 bytes of thumbPrints as identifiers. In the unlikely event that the first and last
     * thumbPrint identifiers are the same, doesn't really matter since we look through for our full
     * thumbPrint and just return if don't find it
     * gk names <m_pubPrefix><epoch><low tpId><high tpId><timestamp>
     */
    void receiveGKeyList(const rPub& p)
    {
        if (m_keyMaker) {
            print("keymaker got keylist from {}\n", m_certs[p].name());
            return;
        }
        if (m_kmpri(p.thumbprint()) <= 0) {
            print("ignoring keylist signed by unauthorized identity {}\n", m_certs[p].name());
            return;
        }
        /*
         * Parse the name and make checks to determine if this key record publication should be used.
         * if this msg was from an earlier Key Maker epoch, ignore it. If from a later
         * epoch, wrongEpoch will cancel any in-progress election and update our epoch.
         */

        auto n = p.name();
        auto epoch = n.nextAt(m_pubPrefix.size()).toNumber();
        if (epoch != m_KMepoch) {
            if (epoch > 1) { // XXX change this when re-elections supported
                print("keylist ignored: bad epoch {} in {} from {}\n", epoch, p.name(), m_certs[p].name());
                return;
            }
            //assert(m_KMepoch == 0);
            m_KMepoch = epoch;
        }
        // check if I'm in this publication's range
        static constexpr auto less = [](const auto& a, const auto& b) -> bool {
            auto asz = a.size();
            auto bsz = b.size();
            auto r = std::memcmp(a.data(), b.data(), asz <= bsz? asz : bsz);
            if (r == 0) return asz < bsz;
            return r < 0;
        };

        auto tpl = n.nextBlk().toSpan();
        auto tph = n.nextBlk().toSpan();
        auto tpId = std::span(m_tp).first(tpl.size());
        if(less(tpId, tpl) || less(tph, tpId))
            return; //no key for me in this pub
        if(std::cmp_less(n.last().toTimestamp().time_since_epoch().count(), m_curKeyCT)) {
            //group key publication is older than current stored key
            return;
        }

        // decode the Content
        decltype(m_curKeyCT) newCT{};
        std::span<const gkr> gkrVec{};
        try {
            auto content = p.content();
            // the first tlv should be type 36 and it should decode to a uint64_t
            // a new key will have a creation time larger than m_curKeyCT
            // (future: ensure it's from the same creator as last time?)
            newCT = content.nextBlk(36).toNumber();
            if(newCT <= m_curKeyCT) return; // group key not newer than ours
 
            // the second tlv should be type 130 and should be a vector of gkr pairs
            gkrVec = content.nextBlk(130).toSpan<gkr>();
        } catch (std::runtime_error& ex) {
            return; //ignore this publication
        }
        auto it = std::find_if(gkrVec.begin(), gkrVec.end(), [this](auto p){ return p.first == m_tp; });
        if (it == gkrVec.end()) return; // didn't find our key in pub

        // decrypt and save the key
        const auto& nk = it->second;
        uint8_t m[aeadKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), m_pDecKey.data(), m_sDecKey.data()) != 0) {
            return;
        }
        m_curKeyCT = newCT;
        m_curKey = std::vector<uint8_t>(m, m + aeadKeySz);
        m_newKeyCb(m_curKey, m_curKeyCT);   // call back parent with new key
        if (m_init) initDone();
    }

    /*
     * setup() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when a group key has been received (i.e., when this entity is
     * able to encrypt/decrypt wirepacket content). There may also be a
     * kmCap capability cert in this entity's signing chain which allows
     * it to participate in keyMaker elections.  The value of the
     * capability influences the probability of this entity being elected
     * with larger values giving higher priority.
     */

    void setup(connectedCb&& ccb) {
        m_connCb = std::move(ccb);

        // build function to get the key maker priority from a signing chain then
        // use it to see if we should join the key maker election
        auto kmval = Cap::getval("KM", m_prefix, m_certs);
        auto kmpri = [kmval](const thumbPrint& tp) {
                          // return 0 if cap wasn't found or has wrong content
                          // XXX value currently has to be a single digit
                          auto kmv = kmval(tp);
                          if (kmv.size() != 3) return 0;
                          auto c = kmv.cur();
                          if (c < '0' || c > '9') return 0;
                          return c - '0';
                      };
        m_kmpri = kmpri;
        // subscribe to key collection and wait for a group key list
        m_sync.subscribe(m_pubPrefix, [this](const auto& p){ receiveGKeyList(p); });

        if(m_kmpri(m_tp) > 0) {
            auto eDone = [this](auto elected, auto epoch) {
                            m_keyMaker = elected;
                            m_KMepoch = epoch;
                            if (! elected) return;
                            m_sync.unsubscribe(m_pubPrefix);
                            gkeyTimeout();  //create a group key, publish it, callback parent with key
                            initDone();
                          };
            m_kme = new kmElection(m_prefix/"km", m_keySM.ref(), m_sync, std::move(eDone), std::move(kmpri), m_tp);
        }
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key list ***/

   // Publish the group key list from thumbpring tpl to thumbprint tph
   // gk names <m_pubPrefix><epoch><low tpId><high tpId><timestamp>
    void publishKeyRange(auto& tpl, auto& tph, auto ts, auto& c) {
        auto TP = [](auto tp){ return std::span(tp).first(4); };    //constant 4 can be determined dynamically later
        crData p(m_pubPrefix/m_KMepoch/TP(tpl)/TP(tph)/ts);
        p.content(c);
        m_keySM.sign(p);
        m_sync.publish(std::move(p));
    }

    // Make a new group key, publish it, and locally switch to using the new key.
    void makeGKey() {
        //make a new key
        m_curKey.resize(aeadKeySz); // crypto_aead_chacha20poly1305_IETF_KEYBYTES
        crypto_aead_chacha20poly1305_ietf_keygen(m_curKey.data());
        //set the key's creation time
        m_curKeyCT = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();

        //encrypt the new group key for all the group members in a sealed box
        // that can only opened by the secret key associated with converted public key in mbrList
        std::vector<gkr> pubPairs;
        for (auto& [k,v]: m_mbrList) {
            encGK egKey;
            crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), v.data());
            pubPairs.push_back(gkr(k,egKey));
        }

        auto s = m_mbrList.size();
        auto p = s <= maxKR ? 1 : (s + maxKR - 1) / maxKR; // determine number of Publications needed
        auto pubTS = std::chrono::system_clock::now();
        auto it = pubPairs.begin();
        for(auto i=0u; i<p; ++i) {
            auto r = s < maxKR ? s : maxKR;
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            if(m_mbrList.size()==0) {
                // publish empty list to continue to assert keyMaker role
                gkrEnc.addArray(130, pubPairs);
                // use own tp in range
                publishKeyRange(m_tp, m_tp, pubTS, gkrEnc.vec());
                break;
            }
            it = gkrEnc.addArray(130, it, r);
            auto l = i*maxKR;
            publishKeyRange(pubPairs[l].first, pubPairs[l+r-1].first, pubTS, gkrEnc.vec());
            s -= r;
        }

        m_newKeyCb(m_curKey, m_curKeyCT);   // call back to parent with new key
        // parent calls the application publication sigmgr's addKey()
    }


    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void gkeyTimeout() {
        makeGKey();
        m_sync.oneTime(m_reKeyInt, [this](){ gkeyTimeout();});  //next re-keying event
    }

    /*
     * This called when there is a new valid peer signing cert.
     * This indicates to the keyMaker there is a new peer that needs the group key
     * Ignore if not a keyMaker. If initialization, go ahead and add to list in case
     * this becomes the keyMaker, but don't try to publish.
     * Shouldn't have to republish the entire keylist, so this version publishes the
     * new encrypted group key separately.
     * Might also want to check if this peer is de-listed (blacklisted)
     */

    void addGroupMem(const rData& c) {
        if (!m_init && !m_keyMaker) return;
        auto tp = dctCert::computeThumbPrint(c);

        // number of Publications should be fewer than 'complete peeling' iblt threshold (currently 80).
        // Each gkR is ~100 bytes so the default maxPubSize of 1024 allows for ~800 members. 
        if (m_mbrList.size() == 80*maxKR) return;

        auto pk = c.content().toVector();   //extract the public key
        // convert pk to form that can be used to encrypt and add to member list
        if(crypto_sign_ed25519_pk_to_curve25519(m_mbrList[tp].data(), pk.data()) != 0)
            return;     //unable to convert member's pk to sealed box pk

        if (!m_init) {   //publish the group key for this new peer
            encGK egKey;
            crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), m_mbrList[tp].data());
            std::vector<gkr> ek {{tp,egKey}};
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            gkrEnc.addArray(130, ek);
            publishKeyRange(tp, tp, std::chrono::system_clock::now(), gkrEnc.vec());
            return;
        }
    }

    // won't encrypt a group key for this thumbPrint in future
    // if reKey is set, change the group key now to exclude the removed member
    void removeGroupMem(thumbPrint& tp, bool reKey = false) {
        m_mbrList.erase(tp);
        if (reKey) makeGKey();
    }
};

} // namespace dct

#endif //DIST_GKEY_HPP
