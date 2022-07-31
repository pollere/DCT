/*
 * Copyright (C) 2019-2 Pollere LLC
 * Pollere authors at info@pollere.net
 *
 * This file is part of syncps (DCT pubsub via Collection Sync)
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
 */

#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP

#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <unordered_map>

#include <ndn-ind/lite/util/crypto-lite.hpp>

#include <dct/face/direct.hpp>
#include <dct/format.hpp>
#include <dct/sigmgrs/sigmgr.hpp>
#include "iblt.hpp"

namespace syncps
{

using Name = ndn::Name;         // type of a name
using Publication = ndn::Data;  // type of a publication
using PubVec = std::vector<Publication>;

using namespace std::literals::chrono_literals;

//default values
static constexpr int maxPubSize = 1024; // max payload in Data (with 1448B MTU
                                        // and 424B iblt, 1K left for payload)
static constexpr std::chrono::milliseconds maxPubLifetime = 2s;
static constexpr std::chrono::milliseconds maxClockSkew = 1s;
static constexpr uint32_t maxDifferences = 38u;  // = 57/1.5 (see iblt.hpp)

/**
 * @brief app callback when new publications arrive
 */
using UpdateCb = std::function<void(const Publication&)>;
/**
 * @brief app callback when publication arrives from net
 */
using PublishCb = std::function<void(const Publication&, bool)>;
/**
 * @brief app callback to test if publication is expired
 */
using IsExpiredCb = std::function<bool(const Publication&)>;
/**
 * @brief app callback to return lifetime of this Publication
 */
using GetLifetimeCb = std::function<std::chrono::milliseconds(const Publication&)>;
/**
 * @brief app callback to filter peer publication requests
 */
using PubPtr = std::shared_ptr<const Publication>;
using VPubPtr = std::vector<PubPtr>;
using FilterPubsCb = std::function<VPubPtr(VPubPtr&,VPubPtr&)>;

/**
 * @brief sync a collection of publications between an arbitrary set of nodes.
 *
 * Application should call 'publish' to add a new publication to the
 * set and register an UpdateCallback that is called whenever new
 * publications from others are received. Publications are automatically
 * deleted (without notice) at the end their lifetime.
 *
 * Publications are named, signed objects (ndn::Data). The last component of
 * their name is a version number (local ms clock) that is used to bound the
 * pub lifetime. This component is added by 'publish' before the publication
 * is signed so it is protected against replay attacks. App publications
 * are signed by pubCertificate and external publications are verified by
 * pubValidator on arrival.
 */
using FaceType=ndn::DirectFace;

//template<typename FaceType=ndn::AsyncFace>
//template<typename FaceType=ndn::DirectFace>
struct SyncPubsub {
    using Nonce = uint32_t; // cState Nonce format
    struct Error : public std::runtime_error { using std::runtime_error::runtime_error; };

    FaceType& m_face;
    ndn::Name m_syncPrefix;
    std::vector<uint8_t>  m_rPrefix; // wire-format syncPrefix
    IBLT m_iblt;
    IBLT m_pcbiblt;
    // currently active published items
    std::unordered_map<std::shared_ptr<const Publication>, uint8_t> m_active{};
    std::unordered_map<uint32_t, std::shared_ptr<const Publication>> m_hash2pub{};
    std::map<const Name, UpdateCb> m_subscription{};
    std::unordered_map <uint32_t, PublishCb> m_pubCbs;
    SigMgr& m_sigmgr;               // cAdd packet signing and validation
    SigMgr& m_pubSigmgr;            // Publication validation
    std::chrono::milliseconds m_cStateLifetime{1357ms};
    std::chrono::milliseconds m_cAddLifetime{3s};
    std::chrono::milliseconds m_pubLifetime{maxPubLifetime};
    std::chrono::milliseconds m_pubExpirationGB{maxPubLifetime};
    pTimer m_scheduledCStateId{std::make_shared<Timer>(getDefaultIoContext())};
    std::minstd_rand m_randGen{};   // random number generator (seeded in constructor)
    std::uniform_int_distribution<unsigned short> m_rand10{1u, 10u};
    Nonce  m_nonce{};               // nonce of current cState
    uint32_t m_publications{};      // # local publications
    bool m_delivering{false};       // currently processing a cAdd
    bool m_registering{true};
    bool m_autoStart{true};
    GetLifetimeCb m_getLifetime{ [this](auto){ return m_pubLifetime; } }; // default just returns m_pubLifetime
    IsExpiredCb m_isExpired{
        // default CB assume last component of name is a timestamp and says pub is expired
        // if the time from publication to now is >= the pub lifetime
        [this](auto p) { auto dt = std::chrono::system_clock::now() - p.getName()[-1].toTimestamp();
                         return dt >= m_getLifetime(p) + maxClockSkew || dt <= -maxClockSkew; } };
    FilterPubsCb m_filterPubs{
        [](auto& pOurs, auto& ) mutable {
            // By default only reply with our pubs, ordered by most recent first.
            if (pOurs.size() > 1) {
                std::sort(pOurs.begin(), pOurs.end(), [](const auto p1, const auto p2) {
                            return p1->getName()[-1].toTimestamp() > p2->getName()[-1].toTimestamp(); });
            }
            return pOurs;
        } };

    static FaceType& defaultFace() {
        static FaceType* face{};
        if (face == nullptr) face = new FaceType();
        return *face;
    }

    auto rand10() { return m_rand10(m_randGen); }

    /**
     * @brief constructor
     *
     * Registers syncPrefix in NFD and sends a cState
     *
     * @param face - application's face
     * @param syncPrefix - collection name for cState/cAdd
     * @param wsig - sigmgr for cAdd packet signing and validation
     * @param psig - sigmgr for Publication validation
     */
    SyncPubsub(FaceType& face, Name syncPrefix, SigMgr& wsig, SigMgr& psig)
        : m_face(face),
          m_syncPrefix(std::move(syncPrefix)),
          m_rPrefix(*m_syncPrefix.wireEncode()),
          m_iblt{},
          m_pcbiblt{},
          m_sigmgr(wsig),
          m_pubSigmgr(psig) {

        // initialize random number generator
        std::random_device rd;
        m_randGen.seed(rd());

        // if auto-starting, when 'run()' is called, fire off a register for syncPrefix
        getDefaultIoContext().dispatch([this]() {
            if (m_autoStart) start();
        });
    }

    SyncPubsub(Name syncPrefix, SigMgr& wsig, SigMgr& psig) : SyncPubsub(defaultFace(), syncPrefix, wsig, psig) {}


    /**
     * @brief startup related methods start and autoStart
     *
     * 'start' starts up the bottom half (ndn network) communication by registering RIT
     * callbacks for cStates matching this collection's prefix then sending an initial
     * 'cState' to solicit/distribute publications.
     *
     * 'autoStart' gives the upper level control over whether 'start' is called automatically
     * after 'run()' is called (the default) or if it will be called explicitly
     */
    void start() {
        m_face.addToRIT(rName(m_rPrefix), [this](auto p, auto i){ onCState(p, i); },
                        [this](rName) -> void { m_registering = false; sendCState(); });
    }

    auto& autoStart(bool yesNo) { m_autoStart = yesNo; return *this; }

    /**
     * @brief methods to change the 'getLifetime', 'isExpired' and/or 'filterPubs' callbacks
     */
    SyncPubsub& getLifetimeCb(GetLifetimeCb&& getLifetime) {
        m_getLifetime = std::move(getLifetime);
        return *this;
    }
    SyncPubsub& isExpiredCb(IsExpiredCb&& isExpired) {
        m_isExpired = std::move(isExpired);
        return *this;
    }
    SyncPubsub& filterPubsCb(FilterPubsCb&& filterPubs) {
        m_filterPubs = std::move(filterPubs);
        return *this;
    }
    /**
     * @brief methods to change various timer values
     */
    SyncPubsub& cStateLifetime(std::chrono::milliseconds time) {
        m_cStateLifetime = time;
        return *this;
    }
    SyncPubsub& cAddLifetime(std::chrono::milliseconds time) {
        m_cAddLifetime = time;
        return *this;
    }
    SyncPubsub& pubLifetime(std::chrono::milliseconds time) {
        m_pubLifetime = time;
        return *this;
    }
    SyncPubsub& pubExpirationGB(std::chrono::milliseconds time) {
        m_pubExpirationGB = time > maxClockSkew? time : maxClockSkew;
        return *this;
    }


    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and lives for at most pubLifetime.
     * Assume Publications arrive signed.
     *
     * @param pub the object to publish
     */
    uint32_t publish(Publication&& pub)
    {
        if (isKnown(pub)) {
            return 0;
        }
        ++m_publications;
        auto h = hashPub(pub);
        addToActive(std::move(pub), true);
        // new pub may let us respond to pending cState(s).
        if (! m_delivering) {
            sendCState();
            handleCStates();
        }
        return h;
    }
    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and lives for at most pubLifetime. This version
     * takes a callback so publication can be confirmed or failure reported so "at least once" or other
     * semantics can be built into shim. Sets callback.
     *
     * @param pub the object to publish
     */
    uint32_t publish(Publication&& pub, PublishCb&& cb)
    {
        auto h = publish(std::move(pub));
        if (h != 0) {
            //using returned hash of signed pub
            m_pubCbs[h] = std::move(cb);
            m_pcbiblt.insert(h);
        }
        return h;
    }

    /**
     * @brief subscribe to a subtopic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     *
     * @param  topic the topic
     */
    SyncPubsub& subscribeTo(const Name& topic, UpdateCb&& cb)
    {
        // add to subscription dispatch table. If subscription is new,
        // 'cb' will be called with each matching item in the active
        // publication list. Otherwise subscription will be
        // only be changed to the new callback.
        if (auto t = m_subscription.find(topic); t != m_subscription.end()) {
            t->second = std::move(cb);
            return *this;
        }
        for (const auto& [pub, flags] : m_active) {
            if ((flags & 3) == 1 && topic.isPrefixOf(pub->getName())) {
                cb(*pub);
            }
        }
        m_subscription.emplace(topic, std::move(cb));
        return *this;
    }

    /**
     * @brief unsubscribe to a subtopic
     *
     * A subscription to 'topic', if any, is removed.
     *
     * @param  topic the topic
     */
    SyncPubsub& unsubscribe(const Name& topic)
    {
        m_subscription.erase(topic);
        return *this;
    }

    /**
     * @brief start running the event manager main loop
     *
     * (usually doesn't return)
     */
    void run() { getDefaultIoContext().run(); }

    /**
     * @brief schedule a callback after some time
     *
     * Can be used by application to schedule a cancelable timer. Note that
     * this is expensive compared to a oneTime timer and should be used
     * only for timers that need to be canceled before they fire. Otherwise
     * 'oneTime' should be used.
     *
     * This lives here to avoid exposing applications to the complicated mess
     * of NDN's relationship to Boost
     *
     * @param after how long to wait (in microseconds)
     * @param cb routine to call
     */
    auto schedule(std::chrono::microseconds after, TimerCb&& cb) { return m_face.schedule(after, std::move(cb)); }

    /**
     * @brief schedule a one time, self-deleting callback after some time
     *
     * @param after how long to wait (in microseconds)
     * @param cb routine to call
     */
    auto oneTime(std::chrono::microseconds after, TimerCb&& cb) { return m_face.oneTime(after, std::move(cb)); }

    /**
     * Get the publication from the active set by exact name match.
     * @param name The name of the publication to search for.
     * @return A shared_ptr to the publication, or a null shared_ptr if not found.
     */
    std::shared_ptr<const Publication> getPubByName(const Name& name)
    {
      for (auto p = m_active.begin(); p != m_active.end(); ++p) {
        if (p->first->getName() == name)
          return p->first;
      }
      return std::shared_ptr<const Publication>();
    }

   private:

    /**
     * @brief Send a cState describing our publication set to our peers.
     *
     * Creates & sends cState of the form: /<sync-prefix>/<own-IBF>
     */
    void sendCState() {
        // if an cState is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (m_registering) return;

        m_scheduledCStateId->cancel();

        // Build and ship the cState. Format is /<sync-prefix>/<ourLatestIBF>
        ndn::Name name = m_syncPrefix;
        name.append(m_iblt.rlEncode());

        ndn::Interest cState(name);
        m_nonce = m_randGen();
       cState.setNonce({(uint8_t*)&m_nonce, sizeof(m_nonce)})
             .setCanBePrefix(true)
             .setMustBeFresh(true)
             .setInterestLifetime(m_cStateLifetime);
        m_face.express(rInterest(cState),
                [this](auto ri, auto rd) {
                    if (! m_sigmgr.validateDecrypt(rd)) {
                        // if cAdd consumed our current cState refresh it soon
                        // but not immediately since if we get the same cAdd back
                        // from some content store we'll just loop here.
                        if (ri.nonce() == m_nonce) sendCStateSoon();
                    } else
                        onCAdd(ri, rd);
                },
                [this](auto& ) { sendCState(); });
    }

    /**
     * @brief Send a cState sometime soon
     */
    void sendCStateSoon() {
        m_scheduledCStateId->cancel();
        m_scheduledCStateId = m_face.schedule(std::chrono::milliseconds(rand10()), [this]{ sendCState(); });
    }

    /**
     * @brief callback to Process a new cState
     *
     * Get differences between our IBF and IBF in the cState.
     * If we have some things that the other side does not have,
     * reply with a cAdd packet containing (some of) those things.
     *
     * @param prefixName prefix registration that matched cState
     * @param cState   cState packet
     */
    void onCState(const rName& prefixName, const rInterest& cState) {
        auto name = cState.name();

        if (name.nBlks() - prefixName.nBlks() != 1) {
            return;
        }
        handleCState(name);
    }

    auto name2iblt(const rName& name) const noexcept {
        IBLT iblt{};
        try {
            iblt.rlDecode(name.lastBlk().rest());
        } catch (const std::exception& e) {
        }
        return iblt;
    }

    bool handleCState(const rName& name) {
        // The last component of 'name' is the peer's iblt. 'Peeling'
        // the difference between the peer's iblt & ours gives two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        auto iblt{name2iblt(name)};
        if(m_pubCbs.size()) {
            // some publications have delivery callbacks so see if any
            // are in this iblt (they'll be in the 'need' set).
            auto [have, need] = ((m_iblt - m_pcbiblt) - iblt).peel();
            for (const auto hash : need) {
                if (!m_pubCbs.contains(hash)) continue;
                // there's a callback for this hash. make sure the pub is still active
                if (auto h = m_hash2pub.find(hash); h != m_hash2pub.end()) {
                    // 2^0 bit of p->second is =1 if pub not expired; 2^1 bit is 1 if we did publication.
                    if (auto p = m_active.find(h->second); p != m_active.end() && (p->second & 3) == 3) {
                        //published here and has cb - do the cb then erase it
                        m_pubCbs[hash](*h->second, true);
                    }
                }
                m_pubCbs.erase(hash);
                m_pcbiblt.erase(hash);
            }
        }

        // If we have things the other side doesn't, send as many as
        // will fit in one cAdd. Make two lists of needed, active publications:
        // ones we published and ones published by others.
        auto [have, need] = (m_iblt - iblt).peel();
        if (have.size() == 0) return false;

        VPubPtr pOurs, pOthers;
        for (const auto hash : have) {
            if (auto h = m_hash2pub.find(hash); h != m_hash2pub.end()) {
                // 2^0 bit of p->second is =0 if pub expired; 2^1 bit is 1 if we
                // did publication.
                if (const auto p = m_active.find(h->second); p != m_active.end()
                    && (p->second & 1U) != 0) {
                    ((p->second & 2U) != 0? &pOurs : &pOthers)->push_back(h->second);
                }
            }
        }
        pOurs = m_filterPubs(pOurs, pOthers);
        if (pOurs.empty()) {
            return false;
        }

        // if both have & need are non-zero, peer may need our current cState to reply
        if (need.size() != 0 && !m_delivering) sendCStateSoon();

        // send all the pubs that will fit in a cAdd packet, always sending at least one.
        for (size_t pubsSize = 0, i = 0; i < pOurs.size(); ++i) {
            auto encoding = pOurs[i]->wireEncode();
            pubsSize += encoding.size();
            if (pubsSize >= maxPubSize) {
                // if we're over and there's more than one piece leave the last
                if (pubsSize > maxPubSize && i > 0) --i;
                pOurs.resize(i + 1);
                break;
            }
        }
        sendcAdd(name.r2n(), pOurs);
        return true;
    }

    bool handleCStates() {
        bool res{false};
        for (const auto& n : m_face.pendingInterests(rName(m_rPrefix))) res |= handleCState(n);
        return res;
    }

    /**
     * @brief Send a cAdd packet responding to a cState.
     *
     * Send a packet containing one or more publications that are known
     * to be in our active set but not in the cState sender's set.
     *
     * @param name  is the name from the cState we're responding to
     *              (cAdd packet's base name)
     * @param pubs  vector of publications (cAdd packet's payload)
     */
    void sendcAdd(const ndn::Name& name, const VPubPtr& pubs)
    {
        ndn::Data cAdd(name);
        // cAdd only useful until iblt changes so limit freshness
        cAdd.getMetaInfo().setFreshnessPeriod(m_cAddLifetime);
        //cAdd.getMetaInfo().setType(tlv::syncpsContent);
        if (pubs.size() > 1) {
            // have to concatenate the pubs
            std::vector<uint8_t> c{};
            for (const auto& p : pubs) {
                auto v = *(p->wireEncode());
                c.insert(c.end(), v.begin(), v.end());
            }
            cAdd.setContent(c);
        } else {
            cAdd.setContent(pubs[0]->wireEncode());
        }
        if(! m_sigmgr.sign(cAdd)) {
            return;
        }
        m_face.send(rData(cAdd));
    }

    /**
     * @brief Process cAdd after successful validation
     *
     * Add each item in cAdd content that we don't have to
     * our list of active publications then notify the
     * application about the updates.
     *
     * @param cState   cState for which we got the cAdd
     * @param cAdd     cAdd content
     */
    void onCAdd(const rInterest& , const rData& cAdd) {

        // if publications result from handling this cAdd we don't want to
        // respond to a peer's cState until we've handled all of them.
        m_delivering = true;
        auto initpubs = m_publications;

        for (auto c : cAdd.content()) {
            if (! c.isType(tlv::Data)) continue;
            auto d = rData(c);
            if (! d.valid()) continue;
            auto pub = d.r2d();

            if (isKnown(pub)) {
                continue;
            }
            if (m_isExpired(pub) || ! m_pubSigmgr.validate(pub)) {
                // unwanted pubs have to go in our iblt or we'll keep getting them
                ignorePub(pub);
                continue;
            }

            // we don't already have this publication so deliver it
            // to the longest match subscription.
            // XXX lower_bound goes one too far when doing longest
            // prefix match. It would be faster to stick a marker on
            // the end of subscription entries so this wouldn't happen.
            // Also, it would be faster to do the comparison on the
            // wire-format names (excluding the leading length value)
            // rather than default of component-by-component.
            const auto& p = addToActive(std::move(pub));
            const auto& nm = p->getName();
            auto sub = m_subscription.lower_bound(nm);
            if ((sub != m_subscription.end() && sub->first.isPrefixOf(nm)) ||
                (sub != m_subscription.begin() && (--sub)->first.isPrefixOf(nm))) {
                sub->second(*p);
            }
        }

        // We've delivered all the publications in the cAdd.  There may be
        // additional in-bound cAdds for the same cState so sending an updated
        // cState now will result in unnecessary duplicates being sent.
        // The face is doing Deferred Delete of the PIT entry to collect those
        // cAdds and its timeout callback will send an updated cState.
        //
        // If the cAdd resulted in new outbound pubs, cAdd them to pending peer CStates.
        m_delivering = false;
        if (initpubs != m_publications) handleCStates();
        sendCStateSoon();
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    // publications are stored using a shared_ptr so we
    // get to them indirectly via their hash.

    uint32_t hashPub(const Publication& pub) const noexcept {
        const auto& b = *pub.wireEncode();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, b.data(), b.size());
    }

    bool isKnown(uint32_t h) const noexcept { return m_hash2pub.contains(h); }

    bool isKnown(const Publication& pub) const noexcept { return isKnown(hashPub(pub)); }

    std::shared_ptr<Publication> addToActive(Publication&& pub, bool localPub = false) {
        auto hash = hashPub(pub);
        auto p = std::make_shared<Publication>(pub);
        m_active[p] = localPub? 3 : 1;
        m_hash2pub[hash] = p;
        m_iblt.insert(hash);

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock
        // skew).  An expired publication is never supplied in response to a sync
        // cState so this extra hold time prevents end-of-lifetime spurious
        // exchanges due to clock skew.
        //
        // Expired publications are kept in the iblt for at least the max clock skew
        // interval to prevent a peer with a late clock giving it back to us as soon
        // as we delete it.

        auto pubLifetime = m_getLifetime(*p);
        if (pubLifetime == decltype(pubLifetime)::zero()) return p; // this pub doesn't expire

        oneTime(pubLifetime, [this, p, hash] {
                                                m_active[p] &=~ 1U;
                                                if(m_pubCbs.contains(hash)) {
                                                    m_pubCbs[hash](*p, false);
                                                    m_pubCbs.erase(hash);
                                                    m_pcbiblt.erase(hash);
                                                } });
        oneTime(pubLifetime + maxClockSkew, [this, hash] { m_iblt.erase(hash); });
        oneTime(pubLifetime + m_pubExpirationGB, [this, p] { removeFromActive(p); });

        return p;
    }

    /*
     * @brief ignore a publication by temporarily adding it to the our iblt
     */
    void ignorePub(const Publication& pub) {
        auto hash = hashPub(pub);
        m_iblt.insert(hash);
        oneTime(m_pubLifetime + maxClockSkew, [this, hash] { m_iblt.erase(hash); });
    }

    void removeFromActive(const PubPtr& p) {
        m_active.erase(p);
        m_hash2pub.erase(hashPub(*p));
    }

    uint32_t hashIBLT(const rName& n) const noexcept {
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, n.data(), n.size());
    }

    uint32_t hashIBLT(const Name& n) const noexcept { return hashIBLT(rName(n)); }
};

}  // namespace syncps

#endif  // SYNCPS_SYNCPS_HPP
