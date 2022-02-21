/*
 * Copyright (C) 2019-2 Pollere LLC
 * Pollere authors at info@pollere.net
 *
 * This file is part of syncps (NDN sync for pubsub).
 *
 * syncps is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * syncps is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * syncps, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP

#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <unordered_map>

#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>

#include <dct/face/direct.hpp>
#include <dct/format.hpp>
#include <dct/sigmgrs/sigmgr.hpp>
#include "iblt.hpp"

namespace syncps
{
INIT_LOGGER("syncps");

using Name = ndn::Name;         // type of a name
using Publication = ndn::Data;  // type of a publication
using PubVec = std::vector<Publication>;

using namespace std::literals::chrono_literals;

//default values
static constexpr int maxPubSize = 1024; // max payload in Data (with 1460B MTU
                                        // and 400B iblt, 1K left for payload)
static constexpr std::chrono::milliseconds maxPubLifetime = 2s;
static constexpr std::chrono::milliseconds maxClockSkew = 1s;
static constexpr uint32_t maxDifferences = 85u;  // = 128/1.5 (see iblt.hpp)

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
 * @brief sync a lifetime-bounded set of publications among
 *        an arbitrary set of nodes.
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
    using Nonce = uint32_t; // Interest Nonce format
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
    SigMgr& m_sigmgr;               // SyncData packet signing and validation
    SigMgr& m_pubSigmgr;            // Publication validation
    std::chrono::time_point<std::chrono::system_clock> m_SIsend{};  // last sync interest send time
    std::chrono::milliseconds m_syncInterestLifetime{557ms};
    std::chrono::milliseconds m_syncDataLifetime{3s};
    std::chrono::milliseconds m_pubLifetime{maxPubLifetime};
    std::chrono::milliseconds m_pubExpirationGB{maxPubLifetime};
    pTimer m_scheduledSyncInterestId{std::make_shared<Timer>(getDefaultIoContext())};
    std::minstd_rand m_randGen{};   // random number generator (seeded in constructor)
    std::uniform_int_distribution<unsigned short> m_rand10{1u, 10u};
    log4cxx::LoggerPtr staticModuleLogger;
    Nonce  m_nonce{};               // nonce of current sync interest
    uint32_t m_publications{};      // # local publications
    bool m_delivering{false};       // currently processing a Data
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
     * Registers syncPrefix in NFD and sends a sync interest
     *
     * @param face application's face
     * @param syncPrefix The ndn name prefix for sync interest/data
     * @param wsig The sigmgr for Data packet signing and validation
     * @param psig The sigmgr for Publication validation
     */
    SyncPubsub(FaceType& face, Name syncPrefix, SigMgr& wsig, SigMgr& psig)
        : m_face(face),
          m_syncPrefix(std::move(syncPrefix)),
          m_rPrefix(*m_syncPrefix.wireEncode()),
          m_iblt(maxDifferences),
          m_pcbiblt(maxDifferences),
          m_sigmgr(wsig),
          m_pubSigmgr(psig),
          staticModuleLogger{log4cxx::Logger::getLogger(m_syncPrefix.toUri())} {

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
     * callbacks for interests matching this collection's prefix then sending an initial
     * 'sync interest' to solicit/distribute publications.
     *
     * 'autoStart' gives the upper level control over whether 'start' is called automatically
     * after 'run()' is called (the default) or if it will be called explicitly
     */
    void start() {
        m_face.addToRIT(rName(m_rPrefix), [this](auto p, auto i){ onSyncInterest(p, i); },
                        [this](rName) -> void { m_registering = false; sendSyncInterest(); });
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
    SyncPubsub& syncInterestLifetime(std::chrono::milliseconds time) {
        m_syncInterestLifetime = time;
        return *this;
    }
    SyncPubsub& syncDataLifetime(std::chrono::milliseconds time) {
        m_syncDataLifetime = time;
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
            _LOG_INFO("republish of '" << pub.getName() << "' ignored");
            return 0;
        }
        _LOG_INFO("Publish: " << pub.getName());
        ++m_publications;
        auto h = hashPub(pub);
        addToActive(std::move(pub), true);
        // new pub may let us respond to pending interest(s).
        if (! m_delivering) {
            sendSyncInterest();
            handleInterests();
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
        _LOG_INFO("subscribeTo: " << topic);
        if (auto t = m_subscription.find(topic); t != m_subscription.end()) {
            t->second = std::move(cb);
            return *this;
        }
        for (const auto& [pub, flags] : m_active) {
            if ((flags & 3) == 1 && topic.isPrefixOf(pub->getName())) {
                _LOG_DEBUG("subscribeTo delivering " << pub->getName());
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
        _LOG_INFO("unsubscribe: " << topic);
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
     * @brief Send a sync interest describing our publication set to our peers.
     *
     * Creates & sends interest of the form: /<sync-prefix>/<own-IBF>
     */
    void sendSyncInterest() {
        // if an interest is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (m_registering) return;

        m_scheduledSyncInterestId->cancel();

        // Build and ship the interest. Format is /<sync-prefix>/<ourLatestIBF>
        ndn::Name name = m_syncPrefix;
        m_iblt.appendToName(name);

        ndn::Interest syncInterest(name);
        m_nonce = m_randGen();
        syncInterest.setNonce({(uint8_t*)&m_nonce, sizeof(m_nonce)})
            .setCanBePrefix(true)
            .setMustBeFresh(true)
            .setInterestLifetime(m_syncInterestLifetime);
        _LOG_DEBUG(format("sendSyncInterest {:x}/{:x}", hashIBLT(name), m_nonce));
        m_SIsend = std::chrono::system_clock::now();
        m_face.express(rInterest(syncInterest),
                [this](auto ri, auto rd) {
                    if (! m_sigmgr.validateDecrypt(rd)) {
                        _LOG_DEBUG(fmt::format("can't validate: {}", rd.name()));
                        // if data consumed our current interest refresh it soon
                        // but not immediately since if we get the same Data back
                        // from some content store we'll just loop here.
                        if (ri.nonce() == m_nonce) sendSyncInterestSoon();
                    } else
                        onValidData(ri, rd);
                },
                [this](auto& ri) { _LOG_INFO(fmt::format("Timeout for {}", ri.name())); sendSyncInterest(); });
    }

    /**
     * @brief Send a sync interest sometime soon
     */
    void sendSyncInterestSoon() {
        _LOG_DEBUG("sendSyncInterestSoon");
        m_scheduledSyncInterestId->cancel();
        m_scheduledSyncInterestId = m_face.schedule(std::chrono::milliseconds(rand10()), [this]{ sendSyncInterest(); });
    }

    /**
     * @brief callback to Process a new sync interest
     *
     * Get differences between our IBF and IBF in the sync interest.
     * If we have some things that the other side does not have,
     * reply with a Data packet containing (some of) those things.
     *
     * @param prefixName prefix registration that matched interest
     * @param interest   interest packet
     */
    void onSyncInterest(const rName& prefixName, const rInterest& interest) {
        auto name = interest.name();
        _LOG_DEBUG(format("onSyncInterest {:x}/{:x}", hashIBLT(name), interest.nonce()));

        if (name.nBlks() - prefixName.nBlks() != 1) {
            _LOG_INFO("invalid sync interest");
            return;
        }
        handleInterest(name);
    }

    void handleInterests() {
        _LOG_DEBUG("handleInterests");
        for (const auto& n : m_face.pendingInterests(rName(m_rPrefix))) handleInterest(n);
    }

    bool handleInterest(const rName& name) {
        // The last component of 'name' is the peer's iblt. 'Peeling'
        // the difference between the peer's iblt & ours gives two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        IBLT iblt(maxDifferences);
        try {
            iblt.initialize(name.lastBlk().rest());
        } catch (const std::exception& e) {
            _LOG_WARN(e.what());
            return true;
        }
        std::set<uint32_t> have;
        std::set<uint32_t> need;
        if(m_pubCbs.size()) {
            // some publications have delivery callbacks so see if any
            // are in this iblt (they'll be in the 'need' set).
            ((m_iblt - m_pcbiblt) - iblt).listEntries(have, need);
            _LOG_INFO(format("deliverycb waiting {} need {}  have {}", m_pubCbs.size(), need.size(), have.size()));
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
            have.clear();
            need.clear();
        }

        // If we have things the other side doesn't, send as many as
        // will fit in one Data. Make two lists of needed, active publications:
        // ones we published and ones published by others.
        (m_iblt - iblt).listEntries(have, need);
        _LOG_INFO(format("handleInterest {:x} need {}  have {}", hashIBLT(name), need.size(), have.size()));
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
        if (pOurs.empty()) return false;

        // if both have & need are non-zero, peer may need our current interest to reply
        if (need.size() != 0 && !m_delivering) sendSyncInterestSoon();

        // send all the pubs that will fit in a data packet, always sending at least one.
        for (size_t pubsSize = 0, i = 0; i < pOurs.size(); ++i) {
            _LOG_DEBUG("Send pub " << pOurs[i]->getName());
            auto encoding = pOurs[i]->wireEncode();
            pubsSize += encoding.size();
            if (pubsSize >= maxPubSize) {
                // if we're over and there's more than one piece leave the last
                if (pubsSize > maxPubSize && i > 0) --i;
                pOurs.resize(i + 1);
                break;
            }
        }
        sendSyncData(name.r2n(), pOurs);
        if (std::chrono::system_clock::now() - m_SIsend > 1s) sendSyncInterestSoon(); //XXX
        return true;
    }

    /**
     * @brief Send a sync data packet responding to a sync interest.
     *
     * Send a packet containing one or more publications that are known
     * to be in our active set but not in the interest sender's set.
     *
     * @param name  is the name from the sync interest we're responding to
     *              (data packet's base name)
     * @param pubs  vector of publications (data packet's payload)
     */
    void sendSyncData(const ndn::Name& name, const VPubPtr& pubs)
    {
        _LOG_DEBUG(format("sendSyncData {:x} {}", hashIBLT(name), name.toUri()));
        ndn::Data data(name);
        // data only useful until iblt changes so limit freshness
        data.getMetaInfo().setFreshnessPeriod(m_syncDataLifetime);
        //data.getMetaInfo().setType(tlv::syncpsContent);
        if (pubs.size() > 1) {
            // have to concatenate the pubs
            std::vector<uint8_t> c{};
            for (const auto& p : pubs) {
                auto v = *(p->wireEncode());
                c.insert(c.end(), v.begin(), v.end());
            }
            data.setContent(c);
        } else {
            data.setContent(pubs[0]->wireEncode());
        }
        if(! m_sigmgr.sign(data)) {
            _LOG_WARN("sendSyncData: failed to sign " << name);
            return;
        }
        m_face.send(rData(data));
    }

    /**
     * @brief Process sync data after successful validation
     *
     * Add each item in Data content that we don't have to
     * our list of active publications then notify the
     * application about the updates.
     *
     * @param interest interest for which we got the data
     * @param data     sync data content
     */
    void onValidData(const rInterest& interest, const rData& data) {
        _LOG_DEBUG(format("onValidData {:x}/{:x} {}", hashIBLT(interest.name()), interest.nonce(), data.name()));

        // if publications result from handling this data we don't want to
        // respond to a peer's interest until we've handled all of them.
        m_delivering = true;
        auto initpubs = m_publications;

        for (auto c : data.content()) {
            if (! c.isType(tlv::Data)) continue;
            auto d = rData(c);
            if (! d.valid()) continue;
            auto pub = d.r2d();

            if (isKnown(pub)) {
                _LOG_DEBUG("ignore known " << pub.getName());
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
                _LOG_DEBUG("deliver " << nm << " to " << sub->first);
                sub->second(*p);
            } else {
                _LOG_DEBUG("no sub for  " << nm);
            }
        }

        // We've delivered all the publications in the Data.  There may be additional in-bound
        // publications satisfying the same Interest and, if so, sending an updated sync interest
        // now will result in unnecessary duplicates being sent. The face is doing Deferred Delete
        // of the arriving Data's PIT entry to collect those duplicates and its timeout callback will
        // send an updated sync interest. If the Data resulted in new outbound pubs try to
        // satisfy pending peer interests.
        m_delivering = false;
        if (initpubs != m_publications) { handleInterests(); sendSyncInterest(); }
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    // publications are stored using a shared_ptr so we
    // get to them indirectly via their hash.

    uint32_t hashPub(const Publication& pub) const
    {
        const auto& b = *pub.wireEncode();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, b.data(), b.size());
    }

    bool isKnown(uint32_t h) const
    {
        //return m_hash2pub.contains(h);
        return m_hash2pub.find(h) != m_hash2pub.end();
    }

    bool isKnown(const Publication& pub) const
    {
        // publications are stored using a shared_ptr so we
        // get to them indirectly via their hash.
        return isKnown(hashPub(pub));
    }

    std::shared_ptr<Publication> addToActive(Publication&& pub, bool localPub = false)
    {
        _LOG_DEBUG("addToActive: " << pub.getName());
        auto hash = hashPub(pub);
        auto p = std::make_shared<Publication>(pub);
        m_active[p] = localPub? 3 : 1;
        m_hash2pub[hash] = p;
        m_iblt.insert(hash);

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock
        // skew).  An expired publication is never supplied in response to a sync
        // interest so this extra hold time prevents end-of-lifetime spurious
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
        _LOG_DEBUG("ignorePub: " << pub.getName());
        auto hash = hashPub(pub);
        m_iblt.insert(hash);
        oneTime(m_pubLifetime + maxClockSkew, [this, hash] { m_iblt.erase(hash); });
    }

    void removeFromActive(const PubPtr& p)
    {
        _LOG_DEBUG("removeFromActive: " << p->getName());
        m_active.erase(p);
        m_hash2pub.erase(hashPub(*p));
    }

    /**
     * @brief Log a message if setting an interest filter fails
     *
     * @param prefix
     */
    void onRegisterFailed(const ndn::Name& prefix) const {
        _LOG_ERROR("onRegisterFailed " << prefix.toUri());
        BOOST_THROW_EXCEPTION(Error("onRegisterFailed " + prefix.toUri()));
    }

    uint32_t hashIBLT(const rName& n) const {
        auto b = n.lastBlk().rest();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, b.data(), b.size());
    }

    uint32_t hashIBLT(const Name& n) const {
        const auto& b = *n[-1].getValue();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, b.data(), b.size());
    }
};

}  // namespace syncps

#endif  // SYNCPS_SYNCPS_HPP
