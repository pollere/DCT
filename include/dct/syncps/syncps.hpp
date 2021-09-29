/*
 * Copyright (c) 2019-2020,  Pollere Inc.
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

#include <ndn-ind/async-face.hpp>
#include <ndn-ind/security/key-chain.hpp>
#include <ndn-ind/security/validator-null.hpp>
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/util/scheduler.hpp>

#include "dct/format.hpp"
#include "dct/sigmgrs/sigmgr.hpp"
#include "iblt.hpp"

namespace syncps
{
INIT_LOGGER("syncps");

using Name = ndn::Name;         // type of a name
using Publication = ndn::Data;  // type of a publication
using PubVec = std::vector<Publication>;
using ScopedEventId = ndn::scheduler::ScopedEventId; // scheduler events
using Timer = ndn::scheduler::ScopedEventId; // for key-distributors

enum class tlv : uint8_t {
    Data = 6,           // Publication (AKA NDN Data object)
    syncpsContent = 129 // block of publications
};

//default values
static constexpr int maxPubSize = 1024; // max payload in Data (with 1460B MTU
                                        // and 400B iblt, 1K left for payload)
static constexpr std::chrono::milliseconds maxPubLifetime = std::chrono::seconds(2);
static constexpr std::chrono::milliseconds maxClockSkew = std::chrono::seconds(1);
static constexpr uint32_t maxDifferences = 85u;  // = 128/1.5 (see detail/iblt.hpp)

/**
 * @brief app callback when new publications arrive
 */
using UpdateCb = std::function<void(const Publication&)>;
/**
 * @brief app callback when publication is seen on another node's list
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

class SyncPubsub
{
  public:
    using Nonce = std::array<uint8_t,4>; // Interest Nonce format
    struct Error : public std::runtime_error { using std::runtime_error::runtime_error; };

    static ndn::AsyncFace& getFace() {
        static ndn::AsyncFace* face{};
        if (face == nullptr) {
            face = new ndn::AsyncFace();
            // Use the default certificate to sign commands.
            ndn::KeyChain* kc = new ndn::KeyChain();
            face->setCommandSigningInfo(*kc, kc->getDefaultCertificateName());
        }
        return *face;
    }

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
    SyncPubsub(Name syncPrefix, SigMgr& wsig, SigMgr& psig) : SyncPubsub(getFace(), syncPrefix, wsig, psig) {}

    SyncPubsub(ndn::AsyncFace& face, Name syncPrefix, SigMgr& wsig, SigMgr& psig)
        : m_face(face),
          m_syncPrefix(std::move(syncPrefix)),
          m_scheduler(m_face.getIoService()),
          m_iblt(maxDifferences),
          m_pcbiblt(maxDifferences),
          m_sigmgr(wsig),
          m_pubSigmgr(psig),
          staticModuleLogger{log4cxx::Logger::getLogger(m_syncPrefix.toUri())},
          m_registeredPrefix(m_face.registerPrefix(
              m_syncPrefix,
              [this](auto& prefix, auto& i, auto&/*face*/, auto/*id*/, auto&/*filter*/) { onSyncInterest(*prefix, *i); },
              [this](auto& n) { onRegisterFailed(*n); },
              [this](auto&/*n*/, auto/*id*/) { m_registering = false; sendSyncInterest(); }))
    { }

    /**
     * @brief methods to change the 'isExpired' and/or 'filterPubs' callbacks
     */
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
     * A publication is published at most once and
     * lives for at most pubLifetime.
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
     * A publication is published at most once and
     * lives for at most pubLifetime. This version
     * takes a callback so publication can be confirmed
     * or failure reported so "at least once" or other
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
    void run() { m_face.getIoService().run(); }

    /**
     * @brief schedule a callback after some time
     *
     * This lives here to avoid exposing applications to the complicated mess
     * of NDN's relationship to Boost
     *
     * @param after how long to wait (in nanoseconds)
     * @param cb routine to call
     */
    ScopedEventId schedule(std::chrono::nanoseconds after,
                           const std::function<void()>& cb)
    {
        return m_scheduler.schedule(after, cb);
    }

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
     * @brief reexpress our current sync interest so it doesn't time out
     */
    void reExpressSyncInterest()
    {
        // The interest is sent 20ms ahead of when it's due to time out
        // to allow for propagation and precessing delays.
        //
        // note: previously scheduled timer is automatically cancelled.
        auto when = m_syncInterestLifetime - std::chrono::milliseconds(20);
        m_scheduledSyncInterestId = m_scheduler.schedule(when, [this] { sendSyncInterest(); });
    }

    /**
     * @brief Send a sync interest describing our publication set
     *        to our peers.
     *
     * Creates & sends interest of the form: /<sync-prefix>/<own-IBF>
     */
    void sendSyncInterest()
    {
        // if an interest is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (m_registering) return;

        // schedule the next send
        reExpressSyncInterest();

        // Build and ship the interest. Format is
        // /<sync-prefix>/<ourLatestIBF>
        ndn::Name name = m_syncPrefix;
        m_iblt.appendToName(name);

        ndn::Interest syncInterest(name);
        ndn::CryptoLite::generateRandomBytes(m_nonce.data(), m_nonce.size());
        syncInterest.setNonce(ndn::Blob{m_nonce.data(), m_nonce.size()})
            .setCanBePrefix(true)
            .setMustBeFresh(true)
            .setInterestLifetime(m_syncInterestLifetime);
        // For logging, interpret the nonce as a hex integer.
        _LOG_DEBUG(format(fmt::runtime("sendSyncInterest {:x}/{:x} {}"), hashIBLT(name), *(uint32_t*)m_nonce.data(),
                    fmt::join(m_syncPrefix,"/")));
        m_face.expressInterest(syncInterest,
                [this](auto& i, auto& d) {
                    if (! m_sigmgr.validateDecrypt(*d)) {
                        _LOG_DEBUG("can't validate: " << d->getName());
                        // if data consumed our current interest refresh it soon
                        // but not immediately since if we get the same Data back
                        // from the content store we'll just loop here.
                        const auto& n = *i->getNonce();
                        if (std::equal(n.begin(), n.end(), m_nonce.begin())) sendSyncInterestSoon();
                    } else
                        onValidData(*i, *d);
                },
                [this](auto& i) { _LOG_INFO("Timeout for " << i->toUri()); },
                [this](auto& i, auto&/*n*/) { _LOG_INFO("Nack for " << i->toUri()); });
        ++m_interestsSent;
    }

    /**
     * @brief Send a sync interest sometime soon
     */
    void sendSyncInterestSoon()
    {
        _LOG_DEBUG("sendSyncInterestSoon");
        m_scheduledSyncInterestId =
            m_scheduler.schedule(std::chrono::milliseconds(11), [this]{ sendSyncInterest(); });
    }

    /**
     * @brief callback to Process a new sync interest from NFD
     *
     * Get differences between our IBF and IBF in the sync interest.
     * If we have some things that the other side does not have,
     * reply with a Data packet containing (some of) those things.
     *
     * @param prefixName prefix registration that matched interest
     * @param interest   interest packet
     */
    void onSyncInterest(const ndn::Name& prefixName, const ndn::Interest& interest)
    {
        if (std::equal(m_nonce.begin(), m_nonce.end(), interest.getNonce()->begin())) return; // interest looped back

        const ndn::Name& name = interest.getName();
        _LOG_DEBUG(format(fmt::runtime("onSyncInterest {:x}/{:x}"), hashIBLT(name),
                    *(uint32_t*)interest.getNonce().buf()));

        if (name.size() - prefixName.size() != 1) {
            _LOG_INFO("invalid sync interest: " << name);
            return;
        }
        if (! handleInterest(name)) {
            // couldn't handle interest immediately - remember it until
            // we satisfy it or it times out;
            m_interest = { name, std::chrono::system_clock::now() + m_syncInterestLifetime};
        }
    }

    void handleInterests()
    {
        _LOG_DEBUG("handleInterests");
        auto now = std::chrono::system_clock::now();
        auto& [name, expires] = m_interest;
        if (name.size() && expires > now) if (handleInterest(name)) expires = now;
    }

    bool handleInterest(const ndn::Name& name)
    {
        // 'Peeling' the difference between the peer's iblt & ours gives
        // two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        IBLT iblt(maxDifferences);
        try {
            iblt.initialize(name.get(-1));
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
            for (const auto hash : need) {
                if (!m_pubCbs.contains(hash)) continue;
                // there's a callback for this hash. make sure the pub is still active
                auto h = m_hash2pub.find(hash);
                if (h == m_hash2pub.end()) continue;
                // 2^0 bit of p->second is =0 if pub expired; 2^1 bit is 1 if we did publication.
                const auto p = m_active.find(h->second);
                if (p == m_active.end() || (p->second & 3) != 3) continue;
                //published here and has cb - do the cb then erase it
                m_pubCbs[hash](*h->second, true);
                m_pubCbs.erase(hash);
                m_pcbiblt.erase(hash);
            }
            have.clear();
            need.clear();
        }
        (m_iblt - iblt).listEntries(have, need);
        _LOG_INFO("handleInterest " << std::hex << hashIBLT(name) << std::dec
                      << " need " << need.size() << ", have " << have.size());

        // If we have things the other side doesn't, send as many as
        // will fit in one Data. Make two lists of needed, active publications:
        // ones we published and ones published by others.

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
        sendSyncData(name, pOurs);
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
        _LOG_DEBUG(format(fmt::runtime("sendSyncData {:x} {}"), hashIBLT(name), name.toUri()));
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
        m_face.putData(data);
    }

    auto parsePubs(const std::vector<uint8_t>& dat, tlv expected) const {
        PubVec pubs{};
        auto pp = dat.data();
        auto ep = dat.data() + dat.size();
        // minimum Data size is at least 8 bytes
        while (pp < ep - 8) {
            auto bp = pp;
            if ((tlv)*bp++ != expected) {
                _LOG_WARN("unexpected tlv in pub content");
                return PubVec();
            }
            size_t len = *bp++;
            if (len > 253) {
                _LOG_WARN("tlv length >64k");
                return PubVec();
            }
            if (len == 253) {
                len = size_t(*bp++) << 8;
                len |= *bp++;
            }
            if (bp + len > ep) {
                _LOG_WARN("pub bigger than content");
                return PubVec();
            }
            // Data length includes tlv bytes
            len += bp - pp;
            Publication pub{};
            pub.wireDecode(pp, len);
            pubs.emplace_back(pub);
            pp += len;
        }
        if (pp != ep) {
            _LOG_WARN("extra data in pub content");
            return PubVec();
        }
        return pubs;
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
    void onValidData(const ndn::Interest& interest, const ndn::Data& data)
    {
        _LOG_DEBUG(format(fmt::runtime("onValidData {:x}/{:x} {}"), hashIBLT(interest.getName()),
                    *(uint32_t*)interest.getNonce().buf(), data.getName().toUri()));

        // if publications result from handling this data we don't want to
        // respond to a peer's interest until we've handled all of them.
        m_delivering = true;
        auto initpubs = m_publications;

        for (auto& pub : parsePubs(*data.getContent(), tlv::Data)) {
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

        // We've delivered all the publications in the Data.
        // Send an interest to replace the one consumed by the Data.
        // If deliveries resulted in new publications, try to satisfy
        // pending peer interests.
        m_delivering = false;
        sendSyncInterest();

        if (initpubs != m_publications) handleInterests();
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

        auto pubLifetime = m_pubLifetime; //in case becomes a function of *p
        if (pubLifetime == decltype(pubLifetime)::zero()) return p; // pubs don't expire in this collection

        m_scheduler.schedule(pubLifetime, [this, p, hash] {
                                                m_active[p] &=~ 1U;
                                                if(m_pubCbs.contains(hash)) {
                                                    m_pubCbs[hash](*p, false);
                                                    m_pubCbs.erase(hash);
                                                    m_pcbiblt.erase(hash);
                                                } });
        m_scheduler.schedule(pubLifetime + maxClockSkew, [this, hash] { m_iblt.erase(hash); });
        m_scheduler.schedule(pubLifetime + m_pubExpirationGB, [this, p] { removeFromActive(p); });

        return p;
    }

    /*
     * @brief ignore a publication by temporarily adding it to the our iblt
     */
    void ignorePub(const Publication& pub) {
        _LOG_DEBUG("ignorePub: " << pub.getName());
        auto hash = hashPub(pub);
        m_iblt.insert(hash);
        m_scheduler.schedule(m_pubLifetime + maxClockSkew, [this, hash] { m_iblt.erase(hash); });
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
    void onRegisterFailed(const ndn::Name& prefix) const
    {
        _LOG_ERROR("onRegisterFailed " << prefix.toUri());
        BOOST_THROW_EXCEPTION(Error("onRegisterFailed " + prefix.toUri()));
    }

    uint32_t hashIBLT(const Name& n) const
    {
        const auto& b = n[-1].getValue();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK, b.buf(), b.size());
    }

  private:
    ndn::AsyncFace& m_face;
    ndn::Name m_syncPrefix;
    ndn::scheduler::Scheduler m_scheduler;
    std::pair<ndn::Name,std::chrono::system_clock::time_point> m_interest{};
    IBLT m_iblt;
    IBLT m_pcbiblt;
    // currently active published items
    std::unordered_map<std::shared_ptr<const Publication>, uint8_t> m_active{};
    std::unordered_map<uint32_t, std::shared_ptr<const Publication>> m_hash2pub{};
    std::map<const Name, UpdateCb> m_subscription{};
    std::unordered_map <uint32_t, PublishCb> m_pubCbs;
    SigMgr& m_sigmgr;               // SyncData packet signing and validation
    SigMgr& m_pubSigmgr;            // Publication validation
    std::chrono::milliseconds m_syncInterestLifetime{std::chrono::milliseconds(557)};
    std::chrono::milliseconds m_syncDataLifetime{std::chrono::seconds(3)};
    std::chrono::milliseconds m_pubLifetime{maxPubLifetime};
    std::chrono::milliseconds m_pubExpirationGB{maxPubLifetime};
    ndn::scheduler::ScopedEventId m_scheduledSyncInterestId;
    log4cxx::LoggerPtr staticModuleLogger;
    uint64_t m_registeredPrefix;
    Nonce  m_nonce{};               // nonce of current sync interest
    uint32_t m_publications{};      // # local publications
    uint32_t m_interestsSent{};
    bool m_delivering{false};       // currently processing a Data
    bool m_registering{true};
    IsExpiredCb m_isExpired{
        // default CB assume last component of name is a timestamp and says pub is expired
        // if the time from publication to now is >= the max pub lifetime
        [](auto p) { auto dt = std::chrono::system_clock::now() - p.getName()[-1].toTimestamp();
                    return dt >= maxPubLifetime+maxClockSkew || dt <= -maxClockSkew; } };
    FilterPubsCb m_filterPubs{
        [](auto& pOurs, auto& ) mutable {
            // By default only reply with our pubs, ordered by most recent first.
            if (pOurs.size() > 1) {
                std::sort(pOurs.begin(), pOurs.end(), [](const auto p1, const auto p2) {
                            return p1->getName()[-1].toTimestamp() > p2->getName()[-1].toTimestamp(); });
            }
            return pOurs;
        } };
};

}  // namespace syncps

#endif  // SYNCPS_SYNCPS_HPP
