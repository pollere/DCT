#ifndef DIST_GKEY_HPP
#define DIST_GKEY_HPP
#pragma once
/*
 * dist_gkey - distribute a symmetric encryption key to a group of peers.
 * This version is a self-contained 'header-only' library.
 *
 * DistGKey manages all the group key operations including the decision on
 * which (eligible) entity will create the group key. Only one entity should
 * be making group keys and will rekey at periodic intervals to distribute
 * a new key, encrypting each key with the public key of each peer (see
 * https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519). If a new
 * member joins between rekeying, it is added to the list of encrypted keys and
 * a key list publication is issued with just the new encrypted key.
 *
 * This distributor puts three separate subtopics into use: <pubprefix>/{km,mr,gk}
 * where <pubprefix> is passed in as the topic for all publications and
 * subtopic km is used by the key maker election,
 * subtopic mr is used by members of the group to request a copy of the encryption key, and
 * subtopic gk is used by the key maker to publish key records where the symmetric key is encrypted
 *      for each valid member of the group.
 * The PDU prefix the distributor's sync uses is <tp_id>/keys/<msgs || pdus>, in the "keys" collection
 *
 * As soon as its syncps is registered, it will receive pubs into its collection(s) but the pubs don't invoke
 * a subscription callback until one is registered (in setup)
 * 
 * Copyright (C) 2020-3 Pollere LLC
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

    static constexpr uint32_t aeadKeySz = crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
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

    const crName m_prefix;        // prefix for pubs in this distributor's collection
    const crName m_gkPrefix;     // prefix for group symmetric key list publications
    const crName m_mrPrefix;    // prefix for member request publications
    SigMgrAny m_keySM{sigMgrByType("EdDSA")};   // to sign/validate Publications and PDUs
    SyncPS m_sync;
    size_t m_maxContent = m_sync.maxInfoSize();
    size_t m_maxKR;
    const certStore& m_certs;
    addKeyCb m_newKeyCb;   // called when group key rcvd
    connectedCb m_connCb{[](auto) {}};
    kmpriCB m_kmpri;
    thumbPrint m_tp{};
    thumbPrint m_kmtp{};        // thumbprint of the keymaker  
    keyVal m_pDecKey{};         // transformed pk used to encrypt group key; use with
    keyVal m_sDecKey{};         // transformed sk used to decrypt group key
    keyVal m_curKey{};          // current group key
    uint64_t m_curKeyCT{};      // current key creation time in microsecs
    std::map<thumbPrint,xmpk> m_mbrList{};

    std::chrono::milliseconds m_reKeyInt{3600s};
    std::chrono::milliseconds m_keyRand{10s};
    std::chrono::milliseconds m_keyLifetime{3600s+10s};
    std::chrono::milliseconds m_mrLifetime{5s}; // set to ~ few dispersion delays
    kmElection* m_kme{};
    uint32_t m_KMepoch{};        // current election epoch
    bool m_keyMaker{false};      // true if this entity is a key maker
    bool m_init{true};                  // key maker status unknown while in initialization
    bool m_msgsdist = false;     // true indicates this is a group key distributor for msgs  (not pdus)
    bool m_mrPending{false};    //member request pending
    Cap::capChk m_relayChk;   // method to return true if the identity chain has the relay (RLY) capability
    pTimer m_mrRefresh{std::make_shared<Timer>(getDefaultIoContext())};

    DistGKey(DirectFace& face, const Name& pPre, const Name& dPre, addKeyCb&& gkeyCb, const certStore& cs,
             std::chrono::milliseconds reKeyInterval = std::chrono::seconds(3600), //XXX make methods
             std::chrono::milliseconds reKeyRandomize = std::chrono::seconds(10),
             std::chrono::milliseconds expirationGB = std::chrono::seconds(60)) :
             m_prefix{pPre}, m_gkPrefix{pPre/"gk"}, m_mrPrefix{pPre/"mr"},
             m_sync(face, dPre, m_keySM.ref(), m_keySM.ref()),
             m_certs{cs}, m_newKeyCb{std::move(gkeyCb)}, //called when a (new) group key arrives or is created
             m_reKeyInt(reKeyInterval),
             m_keyRand(reKeyRandomize),
             m_keyLifetime(m_reKeyInt + m_keyRand),
             m_relayChk{Cap::checker("RLY", pPre, cs)}
        {
       // if the syncps set its cStateLifetime longer, means we are on a low rate network
       if (m_sync.cStateLifetime_ < 6763ms) m_sync.cStateLifetime(6763ms);
       m_sync.pubLifetime(std::chrono::milliseconds(reKeyInterval + reKeyRandomize + expirationGB));
       m_sync.getLifetimeCb([this,cand=crPrefix(m_prefix/"km"/"cand"),elec=crPrefix(m_prefix/"km"/"elec"),mreq=crPrefix(m_mrPrefix)](const auto& p) ->std::chrono::milliseconds {
            if (mreq.isPrefix(p.name())) return m_mrLifetime;
            if (cand.isPrefix(p.name())) return 1000ms;
            // if the Publication's signer is the keymaker, its assertion gk and km/elec should persist until there's a new epoch       
            const auto& tp = p.thumbprint();    // get thumbprint of this Pub's signer
            auto n = p.name();
            if (elec.isPrefix(n)) {
                auto epoch = n.nthBlk(elec.nBlks()).toNumber();
                // (potential) keymaker's elec should persist for keylifetime
                if (tp >= m_kmtp && epoch >= m_KMepoch) return m_keyLifetime;
                return 0ms;     // not the keymaker
            }

            if (! crPrefix(m_gkPrefix).isPrefix(p.name())) return 0ms; // shouldn't happen - expect a gk list
            auto epoch = n.nextAt(m_gkPrefix.size()).toNumber();
            if (epoch < m_KMepoch) return 0ms;  // from earlier epoch
            // Check if this is an assertion gk list Pub which should persist
            static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
                        return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };
            auto tpl = n.nextBlk().toSpan();
            auto tpId = std::span(tp).first(tpl.size());    // get corresponding portion of signer's tp
            auto tph = n.nextBlk().toSpan();                // shouldn't actually have to check that tpl=tph
            // keymaker assertion gk should persist for keylifetime
            if(equal(tpId, tpl) && equal(tpl, tph)) return m_keyLifetime;
            return m_mrLifetime;                                // other gk lists only need to last as long as member requests
                                                                             // if members might sleep after request could be m_keyLifetime
        }); // end of getLifetimeCb

        // get our identity thumbprint, check if we're allowed to make keys,
        // then set up our public and private signing keys.
        m_tp = m_certs.Chains()[0];
        updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
         // compute space for content for the gkr Publication. Other Pubs are smaller, so gkr is worst-case
        m_maxContent -= m_prefix.size() + 2 +3 + 9 + 2 + 2 + 2*(4+2);    // all the components of Name
        if (m_maxContent < (sizeof(thumbPrint) + encGKeySz))
            throw ("DistGKey: not enough space in Pub Content to carry group key list");
        m_maxKR = (m_maxContent) / (sizeof(thumbPrint) + encGKeySz);
        // print ("DistGKey: maxContent is {} max num key records is {}\n", m_maxContent, m_maxKR);
    }

    auto isRelay(const thumbPrint& tp) { return m_relayChk(tp).first; }    // identity 'tp' has RLY capability?

    // publish my membership request with updated key: name <m_mrPrefix><timestamp>
    // requests don't have epoch since the keymaker sets the epoch, member learns from key list
    // Member requests have a lifetime on order of a few distribution delays and are reissued until
    // a gk is received
    void publishMembershipReq() {
        if (m_msgsdist && isRelay(m_tp))  return;   // relays don't publish mrs (shouldn't get here)
        /*using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
        auto now = std::chrono::system_clock::now();
        print("{:%M:%S} {} publishes a {} membership request\n",  ticks(now.time_since_epoch()), m_certs[m_tp].name(), m_sync.collName_.last().toSv());*/
        m_mrRefresh->cancel();  // if a membership request refresh is scheduled, cancel it
        crData p(m_mrPrefix/std::chrono::system_clock::now());
        p.content(std::vector<uint8_t>{});
        m_mrPending = true;
        try {
            m_sync.signThenPublish(std::move(p));
        } catch (const std::exception& e) {
            std::cerr << "dist_gkey::publishMembershipReq: " << e.what() << std::endl;
        }
        m_mrRefresh = m_sync.schedule(m_mrLifetime, [this](){ publishMembershipReq(); });
    }

    // Called when a group key has been received and decrypted.
    // Cancel any pending MR refresh
    // Means there won't be an active MR until
    // and reissue MR if learns there's a new keymaker and I'm not in the list
    void receivedGK() {
        m_mrRefresh->cancel();  // if a membership request refresh is scheduled, cancel it
        m_mrPending = false;
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.  
     *      use new key immediately to sign - update the my signature managers
     *      if member, send a new membership request
     *     keymaker needs to assert its role under new cert
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        m_tp = m_certs.Chains()[0];     // set to the thumbPrint of the new first signing chain
        if (m_tp != dctCert::computeThumbPrint(pubCert))
            throw runtime_error("dist_gkey:updateSigningKey gets new key not at chains[0]");

        // sigmgr needs to get the new signing keys and public key lookup callbacks
        m_keySM.updateSigningKey(sk, pubCert);
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
        if (m_init) return;

        if (! m_keyMaker) {
            // print("DistGKey::updateSigningKey new SP for member {}\n", pubCert.name() );
            m_kmtp.fill(0);     // reset my record of keymaker so that GK received for my previous SP will be overwritten
             publishMembershipReq();
             return;
        }
        // if keymaker is rekeyed it needs to change epoch
        if (m_kmpri(m_tp) <= 0) std::runtime_error("DistGKey::updateSigningKey keymaker capability change indicates bad signing chain");
        m_kmtp = m_tp;
        ++m_KMepoch;
        // print("DistGKey::updateSigningKey new SP for keymaker {} epoch = {}\n", pubCert.name(), m_KMepoch);
        makeGKey(); // redo this so gklists are under the new signing cert
    }

    void initDone() {
        if (m_init) {
            m_init = false;
            m_connCb(true);
        }
    }

    /*
     * Called when a new Publication is received in the key collection
     * Look for the group key record with *my* key thumbprint
     * Using first 4 bytes of thumbPrints as identifiers. In the event that the first and last
     * thumbPrint identifiers are the same, doesn't really matter since we look through for our full
     * thumbPrint and just return if don't find it
     * Since keymaker publishes an empty gk when it wins election, the receipt causes
     * non-keymakers to publish first membership request
     * gk names <m_gkPrefix><epoch><low tpId><high tpId><timestamp>
     */
    void receiveGKeyList(const rPub& p) {
        if (m_msgsdist && isRelay(m_tp))  return;   // relays don't get pub keys for msgs collection

        const auto& tp = p.thumbprint();    // thumbprint of this GKeyList's signer
        if (m_kmpri(tp) <= 0) {
            print("DistGKey:receiveGKeyList ignoring keylist signed by unauthorized identity {}\n", m_certs[p].name());
            return;
        }

        auto n = p.name();
        auto epoch = n.nextAt(m_gkPrefix.size()).toNumber();
        // check if keylist is from earlier signing key of same signing identity
        if (m_certs[tp].thumbprint() == m_certs[m_tp].thumbprint()) {
            if (m_keyMaker) return; // ignore if I'm still keymaker
            // keylist from my identity when I haven't set keymaker implies I've restarted
            // (some other keymaker may have already taken over but that should get resolved eventually - do something better later)
            m_keyMaker = true;
            m_KMepoch = ++epoch;
            m_sync.subscribe(m_mrPrefix, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
            gkeyTimeout();  //create a group key and reschedule group key creation
            return;
        }

        if (m_keyMaker) {
            // another member claims to be a keyMaker - largest thumbPrint and most recent epoch wins
            if ((m_tp < tp && epoch == m_KMepoch) || (epoch > m_KMepoch)) {
                // relinquish keymaker status
                m_keyMaker = false;
                m_kmtp = tp;
                m_curKeyCT = 0;
                m_KMepoch = epoch;
                m_sync.unsubscribe(m_mrPrefix);
                publishMembershipReq();
            }
            return;
        }

        // still in m_init and not the keymaker; set this gklist sender as my keymaker, publish a membership request
        if (m_init && !m_mrPending) {
            m_kmtp = tp;
            m_KMepoch = epoch;
            publishMembershipReq();
            return;
        }

        /*
         * I am a member and have an outstanding membership request that this gklist may service.
         * Parse the name and make checks to determine if this key record publication should be used.
         * if this msg was from an earlier Key Maker epoch, ignore it. If from a later
         * epoch, wrongEpoch will cancel any in-progress election and update our epoch.
         */
        if (epoch != m_KMepoch) {
            if (epoch < m_KMepoch) { // XXX change this when re-elections supported
                print("DistGKey:receiveGKeyList  keylist ignored: bad epoch {} in {} from {}\n", epoch, p.name(), m_certs[p].name());
                return;
            }
            m_KMepoch = epoch;
            m_kmtp.fill(0);     //new epoch, reset my record of keymaker tp so I'll change km below
        }
        // check if this keymaker has a larger tp than my previous km (stored)
        // (can resolve conflict after elections though can happen in relayed domains in particular)
        // if so, (re)set my km and curkey ct records so I get a new key and publish MRs until get a good gk
        // if keyMaker rekeys itself with a smaller tp it sets a new epoch so members reset their m_kmtp values
        if (m_kmtp < tp)    {
            m_kmtp = tp;    // changing keymaker
            m_curKeyCT = 0;
        } else if (m_kmtp > tp) return;   // from a keymaker that has been displaced by one I've already heard from

        static constexpr auto less = [](const auto& a, const auto& b) -> bool {
            auto asz = a.size();
            auto bsz = b.size();
            auto r = std::memcmp(a.data(), b.data(), asz <= bsz? asz : bsz);
            if (r == 0) return asz < bsz;
            return r < 0;
        };

        decltype(m_curKeyCT) newCT{};   //decode the new key's creation time

        // check if I'm in this gk publication's range
        auto tpl = n.nextBlk().toSpan();
        auto tph = n.nextBlk().toSpan();
        auto tpId = std::span(m_tp).first(tpl.size());
        if(less(tpId, tpl) || less(tph, tpId)) {
             // no key for me in this pub
            if (m_curKeyCT == 0 && !m_mrPending) publishMembershipReq(); // make sure new KM has my MR
            return;
         }

        // decode the content of the GK list
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
        if (it == gkrVec.end()) {
            // didn't find our encrypted key in pub - make sure new KM it has our request
            if (m_curKeyCT == 0 && !m_mrPending) publishMembershipReq();
            return;
        }

        // decrypt and save the key
        const auto& nk = it->second;
        uint8_t m[aeadKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), m_pDecKey.data(), m_sDecKey.data()) != 0) return;

        m_curKeyCT = newCT;
        m_curKey = std::vector<uint8_t>(m, m + aeadKeySz);
        m_newKeyCb(m_curKey, m_curKeyCT);   // call back parent with new key
        receivedGK();   //got a new group key, cancel pending member request
        if (m_init)  initDone();    // member has a key, can exit init state
    }

    /*
     * setup() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when a group key has been received (i.e., when this entity is
     * able to encrypt/decrypt pdu content). There may also be a
     * km capability cert in this entity's signing chain which allows
     * it to participate in keyMaker elections.  The value of the
     * capability influences the probability of this entity being elected
     * with larger values giving higher priority.
     * subscribes will process any publications waiting in collection
     */
    void setup(connectedCb&& ccb) {
        m_connCb = std::move(ccb);
        if ( m_sync.collName_.last().toSv() == "msgs") m_msgsdist = true;

        // relay doesn't participate in pub group as it doesn't do encryption or decryption
        // but needs to pass through the gklists so has a gk distributor active with its own subscription cb
        // which is set by the ptps shim when the interface is "connected"
        if (m_msgsdist && isRelay(m_tp)) { initDone(); return; }

        // build function to get the key maker priority from a signing chain then
        // use it to see if we should join the key maker election
        auto kmval = Cap::getval(m_msgsdist ? "KMP" : "KM", m_prefix, m_certs);

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

        // subscribe could result in finding a GKList in local collection that could be from the elected keymaker
        m_sync.subscribe(m_gkPrefix, [this](const auto& p){ receiveGKeyList(p); });
        if (m_kmpri(m_tp) <= 0 || m_KMepoch > 0) {  // check for not keymaker capability or got a gkey that tells us the election is done
            //if (m_KMepoch > 0) print("{} found {} elected epoch {}\n",  m_certs[m_tp].name(), m_certs[m_kmtp].name(), m_KMepoch);
            return;
        }
        // check if keymaker candidate and whether election is over
        auto eDone = [this](auto elected, auto epoch) {
                m_keyMaker = elected;
                m_KMepoch = epoch;
                if (! elected) return;
                //print("{} wins election to make {} GKs\n", m_certs[m_tp].name(), m_sync.collName_.last().toSv());
                m_sync.subscribe(m_mrPrefix, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                gkeyTimeout();  //create a group key and reschedule group key creation                
        };
        // start election. election durations should be ~10 distDelays
        m_kme = new kmElection(m_prefix/"km", m_certs, m_sync, std::move(eDone), std::move(kmpri), m_tp, 500ms);
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key list ***/

   // Publish the group key list from thumbprint tpl to thumbprint tph
   // gk names <m_gkPrefix><epoch><low tpId><high tpId><timestamp>
    void publishKeyRange(const auto& tpl, const auto& tph, auto ts, auto& c) {
        //constant 4 may be determined dynamically later
        const auto TP = [](const auto& tp){ return std::span(tp).first(4); };
        crData p(m_gkPrefix/m_KMepoch/TP(tpl)/TP(tph)/ts);
        p.content(c);
        try {
            m_sync.signThenPublish(std::move(p));
       } catch (const std::exception& e) {
            std::cerr << "dist_gkey::publishKeyRange: " << e.what() << std::endl;
        }
    }

    /*
     * Make a new group key, publish it, and locally switch to using the new key.
     * A keymaker that has just won an election will publish an empty gk list to assert its win
     * to later joiners. Since subscribers get this gklist, using reception of any gklist (when in init
     * state with no pending member requests) to publish a membership request.
     *
     * If in init state and there are group members, call initDone to exit init
    */
    void makeGKey() {
        m_curKey.resize(aeadKeySz); // crypto_aead_xchacha20poly1305_IETF_KEYBYTES
        crypto_aead_xchacha20poly1305_ietf_keygen(m_curKey.data());
        //print("{} makes a new {} GK\n", m_certs[m_tp].name(), m_sync.collName_.last().toSv());
        //set the key's creation time
        m_curKeyCT = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();

        // remove expired certs (thumbprints) from memberList
        auto now = std::chrono::system_clock::now();
        std::erase_if(m_mbrList, [this,now](auto& kv) { return m_certs.contains(kv.first)? rCert(m_certs[kv.first]).validUntil() < now : true; });

        //encrypt the new group key for all the group members in a sealed box
        // that can only opened by the secret key associated with converted public key in mbrList
        std::vector<gkr> pubPairs{};
        for (const auto& [k,v]: m_mbrList) {
            encGK egKey;
            crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), v.data());
            pubPairs.emplace_back(k, egKey);
        }

        auto s = m_mbrList.size();
        auto p = s <= m_maxKR ? 1 : (s + m_maxKR - 1) / m_maxKR; // determine number of Publications needed
        auto pubTS = std::chrono::system_clock::now();
        auto it = pubPairs.begin();
        for(auto i=0u; i<p; ++i) {
            auto r = s < m_maxKR ? s : m_maxKR;
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, m_curKeyCT);
            if(i==0) {  // once every time the keymaker makes a new key
                // publish empty list to continue to assert keymaker role ("assertion gk")
                gkrEnc.addArray(130, pubPairs);              
                publishKeyRange(m_tp, m_tp, pubTS, gkrEnc.vec());   // use own tp in range
                if (s==0) break;
            }
            it = gkrEnc.addArray(130, it, r);
            auto l = i*m_maxKR;
            publishKeyRange(pubPairs[l].first, pubPairs[l+r-1].first, pubTS, gkrEnc.vec());
            s -= r;
        }
         // call back to parent with new key, parent calls the application publication sigmgr's addKey()
        m_newKeyCb(m_curKey, m_curKeyCT);

        if(m_init && m_mbrList.size())  initDone();
    }

    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void gkeyTimeout() {
        if (!m_keyMaker) return;    // since not a cancelable timer, need to stop if I lose a future election or another keymaker took priority
        makeGKey();
        m_sync.oneTime(m_reKeyInt, [this](){ gkeyTimeout();});  //next re-keying event
    }

    /*
     * This called when there is a new valid peer member request to join the distribution group.
     * This indicates to the keyMaker there is a new peer that needs the group key.
     * Only subscribe to this after win election to be keyMaker, ignore if not a keyMaker as a safeguard
     * If received while in initialization state, haven't made a key yet so don't try to publish.
     *
     * If conversion of public key works, that adds this member to list (by thumbprint).
     * Shouldn't have to republish the entire keylist, so  publishes the
     * new encrypted group key separately for members joining after initialization
     * .
     * Might also want to check if this peer is de-listed (e.g., blacklisted) but for now assuming this
     * would be handled in validation of cAdd PDU and of Publication.
     */

    void addGroupMem(const rData& p) {
        if (!m_keyMaker) return;
        // number of Publications should be fewer than 'complete peeling' iblt threshold (currently 80).
        if (m_mbrList.size() == 80*m_maxKR) return;

        auto tp = p.thumbprint();   // thumbprint of the signer of the member request
        if (m_msgsdist && isRelay(tp)) return;  // identities with RLY don't get pub keys

        if (!m_mbrList.contains(tp)) {     // not already a member, add to list
            auto pk = m_certs[tp].content().toVector();   //access the public key for this signer's thumbPrint
            // convert pk to form that can be used to encrypt and add to member list
            if(crypto_sign_ed25519_pk_to_curve25519(m_mbrList[tp].data(), pk.data()) != 0) {
                m_mbrList.erase(tp);    //unable to convert member's pk to sealed box pk
                return;
            }
            // if there is an earlier signing key from the same identity, remove it
            auto itp = m_certs[tp].thumbprint();
            auto sameId = std::erase_if(m_mbrList, [this,tp,itp](auto& kv) { return kv.first != tp? rCert(m_certs[kv.first]).thumbprint() == itp : false; });
            if (sameId) print ("DistGKey::addGroupMem: found and erased {} earlier signing cert(s) from this identity\n", sameId);
        }

        if(!m_curKeyCT)    return;  // haven't made first group key

        //publish the group key for this member: if new, first time, if already a member, republish in response to this mr
        encGK egKey;
        crypto_box_seal(egKey.data(), m_curKey.data(), m_curKey.size(), m_mbrList[tp].data());
        std::vector<gkr> ek{ {tp, egKey} };
        tlvEncoder gkrEnc{};    //tlv encoded content
        gkrEnc.addNumber(36, m_curKeyCT);
        gkrEnc.addArray(130, ek);
        publishKeyRange(tp, tp, std::chrono::system_clock::now(), gkrEnc.vec());

        if (m_init) initDone();    // keyMaker was in init state but now has a group key, and at least one member
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
