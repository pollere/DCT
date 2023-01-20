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

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <ranges>
#include <type_traits>
#include <unordered_map>

#include <dct/face/direct.hpp>
#include <dct/format.hpp>
#include <dct/schema/dct_cert.hpp>
#include "iblt.hpp"

namespace dct
{
// recognize containers that combine a view with its backing store
template<typename C> concept hasView = requires { std::remove_cvref_t<C>().asView(); };

using rPub = rData; // internal pub rep
using Name = rName; // type of a name
using Publication = crData;  // type of a publication

using namespace std::literals::chrono_literals;

//default values
static constexpr int maxPubSize = 1024; // max payload in Data (with 1448B MTU
                                        // and 424B iblt, 1K left for payload)
static constexpr std::chrono::milliseconds maxPubLifetime = 2s;
static constexpr std::chrono::milliseconds maxClockSkew = 1s;

/**
 * @brief app callback when new publications arrive
 */
using SubCb = std::function<void(const rPub&)>;

/**
 * @brief callback when pub delivered or times out
 */
using DelivCb = std::function<void(const rPub&, bool)>;

/**
 * @brief app callback to test if publication is expired
 */
using IsExpiredCb = std::function<bool(const rPub&)>;
/**
 * @brief app callback to return lifetime of this Publication
 */
using GetLifetimeCb = std::function<std::chrono::milliseconds(const rPub&)>;
/**
 * @brief app callback to filter peer publication requests
 */
using PubPtr = rPub;
using PubVec = std::vector<PubPtr>;
using OrderPubCb = std::function<void(PubVec&)>;

/**
 * @brief sync a collection of publications between an arbitrary set of nodes.
 *
 * Application should call 'publish' to add a new publication to the
 * set and register an UpdateCallback that is called whenever new
 * publications from others are received. Publications are automatically
 * deleted (without notice) at the end their lifetime.
 *
 * Publications are named, signed objects (rData). The last component of
 * their name is a version number (local ms clock) that is used to bound the
 * pub lifetime. This component is added by 'publish' before the publication
 * is signed so it is protected against replay attacks. App publications
 * are signed by pubCertificate and external publications are verified by
 * pubValidator on arrival.
 */
struct SyncPS {
    using Error = std::runtime_error;
    using Nonce = uint32_t; // cState Nonce format

    // pubs are identified and accessed only by their hash. A pubs Collection entry holds the
    // actual pub Item, its source (local or from net) and whether it is active (unexpired).
    // The collection keeps both a hash-indexed map of entries and the iblt of the collection
    // so it can guarantee they are consistent with each other.
    using PubHash = uint32_t; // iblt publication hash type
    static inline PubHash hashPub(const rPub& r) { return IBLT<PubHash>::hashobj(r); }

    template<typename Item>
    struct CE { // Collection Entry 
        Item i_;
        uint8_t s_; // item status

        constexpr CE(Item&& i, uint8_t s) : i_{std::forward<Item>(i)}, s_{s} {}
        static constexpr uint8_t act = 1;  // 0 = expired, 1 = active
        static constexpr uint8_t loc = 2;  // 0 = from net, 2 = local
        auto active() const noexcept { return (s_ & act) != 0; }
        auto fromNet() const noexcept { return (s_ & (act|loc)) == act; }
        auto local() const noexcept { return (s_ & (act|loc)) == (act|loc); }
        auto& deactivate() { s_ &=~ act; return *this; }
    };

    template<typename Item, typename Ent = CE<Item>, typename Base = std::unordered_map<PubHash,Ent>>
    struct Collection : Base {
        IBLT<PubHash> iblt_{};

        constexpr auto& iblt() noexcept { return iblt_; }

        template<typename C=Item> requires hasView<C>
        constexpr auto contains(decltype(C().asView())&& c) const noexcept { return Base::contains(hashPub(c)); }

        PubHash add(PubHash h, Item&& i, decltype(Ent::s_) s) {
            if (const auto& [it,added] = Base::try_emplace(h, std::forward<Item>(i), s); !added) return 0;
            iblt_.insert(h);
            return h;
        }
        auto addLocal(PubHash h, Item&& i) { return add(h, std::forward<Item>(i), Ent::loc|Ent::act); }

        auto add(Item&& i, decltype(Ent::s_) s) { return add(hashPub(i), std::forward<Item>(i), s); }
        auto addLocal(Item&& i) { return add(std::forward<Item>(i), Ent::loc|Ent::act); }
        auto addNet(Item&& i) { return add(std::forward<Item>(i), Ent::act); }

        template<typename C=Item> requires hasView<C>
        auto addNet(decltype(C().asView())&& c) { return add(Item{c}, Ent::act); }

        auto deactivate(PubHash h) {
            if (auto p = Base::find(h); p != Base::end() && p->second.active()) {
                p->second.deactivate();
                iblt_.erase(h);
            }
        }
        auto erase(PubHash h) {
            if (auto p = Base::find(h); p != Base::end()) {
                if (p->second.active()) iblt_.erase(h);
                Base::erase(p);
            }
        }
    };

    Collection<crData> pubs_{};             // current publications
    Collection<DelivCb> pubCbs_{};          // pubs requesting delivery callbacks
    lpmLT<crPrefix,SubCb> subscriptions_{}; // subscription callbacks

    DirectFace& face_;
    const crName collName_;         // 'name' of the collection
    SigMgr& pktSigmgr_;             // cAdd packet signing and validation
    SigMgr& pubSigmgr_;             // Publication validation
    std::chrono::milliseconds cStateLifetime_{1357ms};
    std::chrono::milliseconds pubLifetime_{maxPubLifetime};
    std::chrono::milliseconds pubExpirationGB_{maxPubLifetime};
    pTimer scheduledCStateId_{std::make_shared<Timer>(getDefaultIoContext())};
    std::uniform_int_distribution<unsigned short> randInt_{1u, 13u}; // cstate publish delay interval
    Nonce  nonce_{};                // nonce of current cState
    uint32_t publications_{};       // # local publications
    bool delivering_{false};        // currently processing a cAdd
    bool registering_{true};        // RIT not set up yet
    bool autoStart_{true};          // call 'start()' when done registering
    GetLifetimeCb getLifetime_{ [this](auto){ return pubLifetime_; } };
    IsExpiredCb isExpired_{
        // default CB assumes last component of name is a timestamp and says pub is expired
        // if the time from publication to now is >= the pub lifetime
        [this](const auto& p) { auto dt = std::chrono::system_clock::now() - p.name().last().toTimestamp();
                         return dt >= getLifetime_(p) + maxClockSkew || dt <= -maxClockSkew; } };
    OrderPubCb orderPub_{[](PubVec& pv){
            // can't use modern c++ on a mac
            //std::ranges::sort(pOurs, {}, [](const auto& p) { return p.name().last().toTimestamp(); });
            std::sort(pv.begin(), pv.end(), [](const auto& p1, const auto& p2){
                    return p1.name().last().toTimestamp() > p2.name().last().toTimestamp(); });
        }
    };

    constexpr auto randInt() { return randInt_(randGen()); }

    /**
     * @brief constructor
     *
     * @param face - application's face
     * @param collName - collection name for cState/cAdd
     * @param wsig - sigmgr for cAdd packet signing and validation
     * @param psig - sigmgr for Publication validation
     */
    SyncPS(DirectFace& face, rName collName, SigMgr& wsig, SigMgr& psig)
        : face_{face}, collName_{collName}, pktSigmgr_{wsig}, pubSigmgr_{psig} {
        // if auto-starting at the time 'run()' is called, fire off a register for collection name
        getDefaultIoContext().dispatch([this]{ if (autoStart_) start(); });
    }

    SyncPS(rName collName, SigMgr& wsig, SigMgr& psig) : SyncPS(defaultFace(), collName, wsig, psig) {}


    /**
     * @brief add a new local or network publication to the 'active' pubs set
     */
    auto addToActive(crData&& p, bool localPub) {
        //print("addToActive {:x} {} {}: {}\n", hashPub(p), p.size(), p.name(), localPub);
        auto lt = getLifetime_(p);
        auto hash = localPub? pubs_.addLocal(std::move(p)) : pubs_.addNet(std::move(p));
        if (hash == 0 || lt == decltype(lt)::zero()) return hash;

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock skew).
        // An expired publication is never supplied in a cAdd so this hold time prevents
        // spurious end-of-lifetime exchanges due to clock skew.
        //
        // Expired publications are kept in the iblt for at least the max clock skew
        // interval to prevent a peer with a late clock giving it back to us as soon
        // as we delete it.

        if (localPub) oneTime(lt, [this, hash]{ if (pubCbs_.size() > 0) doDeliveryCb(hash, false); });
        oneTime(lt + maxClockSkew, [this, hash]{ pubs_.deactivate(hash); });
        oneTime(lt + pubExpirationGB_, [this, hash]{ pubs_.erase(hash); });
        return hash;
    }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and lives for at most pubLifetime.
     * Publications are signed before calling this routine.
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub) {
        auto h = addToActive(std::move(pub), true);
        if (h == 0) return h;
        ++publications_;
        // new pub may let us respond to pending cState(s).
        if (! delivering_) {
            sendCState();
            handleCStates();
        }
        return h;
    }
    auto publish(const rData pub) { return publish(crData{pub}); }

    /**
     * @brief handle a new publication from app requiring a 'delivery callback'
     *
     * Takes a callback so pub arrival at other entity(s) can be confirmed or
     * failure reported so "at least once" semantics can be built into shim.
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub, DelivCb&& cb) {
        auto h = publish(std::move(pub));
        if (h != 0) pubCbs_.addLocal(h, std::move(cb));
        return h;
    }

    /**
     * @brief subscribe to a topic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     */
    auto& subscribe(crPrefix&& topic, SubCb&& cb) {
        //print("subscribe {}\n", (rPrefix)topic);
        // add to subscription dispatch table. If subscription is new,
        // 'cb' will be called with each matching item in the active
        // publication list. Otherwise subscription will be
        // only be changed to the new callback.
        if (auto t = subscriptions_.find(topic); t != subscriptions_.end()) {
            t->second = std::move(cb);
            return *this;
        }
        // deliver all active pubs matching this subscription
        for (const auto& [h, pe] : pubs_) if (pe.fromNet() && topic.isPrefix(pe.i_.name())) cb(pe.i_);

        subscriptions_.add(std::move(topic), std::move(cb));
        return *this;
    }
    auto& subscribe(crName&& topic, SubCb&& cb) { return subscribe(crPrefix{std::move(topic)}, std::move(cb)); }
    auto& subscribe(const rName& topic, SubCb&& cb) { return subscribe(crPrefix{topic}, std::move(cb)); }

    auto& unsubscribe(crPrefix&& topic) { subscriptions_.erase(topic); return *this; }

    /**
     * @brief timers to schedule a callback after some time
     *
     * 'oneTime' schedules a non-cancelable callback, 'schedule' creates a cancelable/restartable
     * timer. Note that this is expensive compared to a oneTime timer and oneTime should be used
     * when the timer doesn't need to referenced.
     */
    auto schedule(std::chrono::microseconds after, TimerCb&& cb) const { return face_.schedule(after, std::move(cb)); }
    void oneTime(std::chrono::microseconds after, TimerCb&& cb) const { return face_.oneTime(after, std::move(cb)); }

    /**
     * @brief Send a cState describing our publication set to our peers.
     *
     * Creates & sends cState of the form: /<sync-prefix>/<own-IBF>
     */
    void sendCState() {
        // if n cState is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (registering_) return;

        scheduledCStateId_->cancel();
        nonce_ = rand32();
        face_.express(crInterest(collName_/pubs_.iblt().rlEncode(), cStateLifetime_, nonce_),
                        [this](auto ri, auto rd) { // cAdd response to interest
                            if (! pktSigmgr_.validateDecrypt(rd)) {
                                // Got an invalid cAdd so ignore the pubs it contains.  Need to reissue
                                // our pending cState but delay a bit or we'll get the same thing again.
                                // XXX may want to track & filter out bad actors to avoid DoS potential here.
                                if (ri.nonce() == nonce_) sendCStateSoon();
                                return;
                            }
                            onCAdd(ri, rd);
                        },
                        [this](auto& /*ri*/) { sendCState(); } // interest timeout
                    );
    }

    /**
     * @brief Send a cState after a random delay. If called again before timer expires
     * restart the time. (This is used to collect all the cAdds responding to a cState
     * before sending a new cState.)
     */
    void sendCStateSoon() {
        scheduledCStateId_->cancel();
        scheduledCStateId_ = schedule(std::chrono::milliseconds(randInt()), [this]{ sendCState(); });
    }

    auto name2iblt(const rName& name) const noexcept {
        IBLT<PubHash> iblt{};
        try { iblt.rlDecode(name.last().rest()); } catch (const std::exception& e) { }
        return iblt;
    }

    void doDeliveryCb(PubHash hash, bool arrived) {
        auto cb = pubCbs_.find(hash);
        if (cb == pubCbs_.end()) return;

        // there's a callback for this hash. do it if pub was ours and is still active
        if (auto p = pubs_.find(hash); p != pubs_.end() && p->second.local()) (cb->second.i_)(p->second.i_, arrived);
        pubCbs_.erase(hash);
    }

    bool handleCState(const rName& name) {
        // The last component of 'name' is the peer's iblt. 'Peeling'
        // the difference between the peer's iblt & ours gives two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        //
        // pubCbs_ contains pubs that require delivery callbacks so which the peer already has.
        // pubs_ contains all pubs we have so send the ones we have & the peer doesn't.
        auto iblt{name2iblt(name)};
        if(pubCbs_.size()) {
            // remove delivery confirmation pubs from our iblt to see which the peer has (will be in 'need' set)
            for (const auto hash : (pubs_.iblt() - pubCbs_.iblt() - iblt).peel().second) doDeliveryCb(hash, true);
        }
        auto [have, need] = (pubs_.iblt() - iblt).peel();
        if (have.size() == 0) return false;

        PubVec pv{};
        for (const auto hash : have) {
            if (const auto& p = pubs_.find(hash); p != pubs_.end() && p->second.local()) pv.emplace_back(p->second.i_);
        }
        if (pv.empty()) return false;

        // if both have & need are non-zero, peer may need our current cState to reply
        if (need.size() != 0 && !delivering_) sendCStateSoon();

        // send all the pubs that will fit in a cAdd packet, always sending at least one.
        if (pv.size() > 1) {
            orderPub_(pv);
            for (size_t i{}, psize{}; i < pv.size(); ++i) {
                if (pv[i].size() > maxPubSize) {
                    print("pub {} too large: {} {}\n", i, pv[i].size(), pv[i].name());
                    abort();
                }
                if ((psize += pv[i].size()) > maxPubSize) { pv.resize(i); break; }
            }
        }
        auto cAdd = crData{name}.content(pv);
        if (pktSigmgr_.sign(cAdd)) face_.send(cAdd);
        return true;
    }

    bool handleCStates() {
        bool res{false};
        for (const auto& n : face_.pendingInterests(collName_)) res |= handleCState(n);
        return res;
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
    void onCAdd(const rInterest& /*cState*/, const rData& cAdd) {

        // if publications result from handling this cAdd we don't want to
        // respond to a peer's cState until we've handled all of them.
        delivering_ = true;
        auto initpubs = publications_;

        for (auto c : cAdd.content()) {
            if (! c.isType(tlv::Data)) continue;
            rData d(c);
            if (! d.valid() || pubs_.contains(d)) {
                //print("pub invalid or dup: {}\n", d.name());
                continue;
            }
            if (isExpired_(d) || ! pubSigmgr_.validate(d)) {
                //print("pub {}: {}\n", isExpired_(d)? "expired":"failed validation", d.name());
                // unwanted pubs have to go in our iblt or we'll keep getting them
                ignorePub(d);
                continue;
            }

            // we don't already have this publication so deliver it
            // to the longest match subscription.
            if (addToActive(crData(d), false) == 0) {
                //print("addToActive failed: {}\n", d.name());
                continue;
            }
            if (auto s = subscriptions_.findLM(d.name()); subscriptions_.found(s)) {
                //print("delivering: {}\n", d.name());
                s->second(d);
            //} else { print("no subscription for {}\n", d.name());
            }
        }

        // We've delivered all the publications in the cAdd.  There may be
        // additional in-bound cAdds for the same cState so sending an updated
        // cState now will result in unnecessary duplicates being sent.
        // The face is doing Deferred Delete of the PIT entry to collect those
        // cAdds and its timeout callback will send an updated cState.
        //
        // If the cAdd resulted in new outbound pubs, cAdd them to pending peer CStates.
        delivering_ = false;
        if (initpubs != publications_) handleCStates();
        sendCStateSoon();
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    /*
     * @brief ignore a publication by temporarily adding it to the our iblt
     * XXX fix to add hash to pubs_ so dups can be recognized
     */
    void ignorePub(const rPub& pub) {
        auto hash = hashPub(pub);
        pubs_.iblt().insert(hash);
        oneTime(pubLifetime_ + maxClockSkew, [this, hash] { pubs_.iblt().erase(hash); });
    }

    /**
     * @brief startup related methods start and autoStart
     *
     * 'start' starts up the bottom half (network) communication by registering RIT
     * callbacks for cStates matching this collection's prefix then sending an initial
     * 'cState' to solicit/distribute publications. Since the content of cAdd packets
     * can be encrypted, it's pointless to send a cState before optaining the decryption
     * key. dct_model sets up an appropriate chain of callbacks such that 'start()' is
     * called after all the prerequisites for syncing this collection have been obtained.
     *
     * 'autoStart' gives the upper level control over whether 'start' is called automatically
     * after 'run()' is called (the default) or if it will be called explicitly
     */
    void start() {
        face_.addToRIT(collName_,
                       [this, ncomp = collName_.nBlks()+1](auto /*prefix*/, auto i) {
                           // cState must have one more name component (an iblt) than the collection name
                           if (auto n = i.name(); n.nBlks() == ncomp) handleCState(n);
                       },
                       [this](rName) -> void { registering_ = false; sendCState(); });
    }

    auto& autoStart(bool yesNo) { autoStart_ = yesNo; return *this; }

    /**
     * @brief start running the event manager main loop (use stop() to return)
     */
    void run() { getDefaultIoContext().run(); }

    /**
     * @brief stop the running the event manager main loop
     */
    void stop() { getDefaultIoContext().stop(); }

    /**
     * @brief methods to change callbacks
     */
    auto& getLifetimeCb(GetLifetimeCb&& getLifetime) { getLifetime_ = std::move(getLifetime); return *this; }
    auto& isExpiredCb(IsExpiredCb&& isExpired) { isExpired_ = std::move(isExpired); return *this; }
    auto& orderPubCb(OrderPubCb&& orderPub) { orderPub_ = std::move(orderPub); return *this; }

    /**
     * @brief methods to change various timer values
     */
    auto& cStateLifetime(std::chrono::milliseconds time) { cStateLifetime_ = time; return *this; }

    auto& pubLifetime(std::chrono::milliseconds time) { pubLifetime_ = time; return *this; }

    auto& pubExpirationGB(std::chrono::milliseconds time) {
        pubExpirationGB_ = time > maxClockSkew? time : maxClockSkew;
        return *this;
    }
};

}  // namespace dct

#endif  // SYNCPS_SYNCPS_HPP
