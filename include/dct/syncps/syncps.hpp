#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP
#pragma once
/*
 * Copyright (C) 2019-2024 Pollere LLC
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

namespace dct {

// recognize containers that combine a view with its backing store
template<typename C> concept hasView = requires { std::remove_cvref_t<C>().asView(); };

using rPub = rData; // internal pub rep
using Name = rName; // type of a name
using Publication = crData;  // type of a publication

using namespace std::literals::chrono_literals;

/*
 * syncps gets the mtu bytes available for its PDUs (cAdds and cStates) from its face
 * For most networks, cState size will not be a problem; for rate-challenged networks, may need to
 * set stSize in iblt.hpp to a smaller (prime) value.
 * cAdds are made up of  5 required TLVs and syncps can upper bound the non-Content components,
 * plus accounting for top-level TL of 2 bytes and the TL of 2 bytes for the Content component.
 * The remaining bytes are available for Publications (maxPubSize_)
 * Publications require the same 5 TLVs and syncps has the ability to determine the size of 3 of these plus
 * the "type-length" overhead for the Name and Content, leaving an upper bound on the information
 * size (Name value field plus Content value field) available for the shim or distributor using this syncps
 */
 static constexpr size_t cAddTLVs = 37 + 107;    // max of 144 bytes of required TLVs in every cAdd.
                                                        // XXX this should be function of sigmgr type - 107 for EdDSA and 80 for AEAD
//default values
static constexpr std::chrono::milliseconds maxPubLifetime = 2s;
static constexpr std::chrono::milliseconds maxClockSkew = 1s;
static constexpr std::chrono::milliseconds stateLifetime = 1357ms;

// set an estimated processing overhead that will dominate distDelay for higher speed networks
static constexpr std::chrono::milliseconds pduProc = 50ms;

/*
 * In syncps constructor, add the mtu()/rate() to distDelay. distDelay is (an estimate of) the time to
 * get a PDU processed by every member within range.
 * A Publication in a meshed network might take multiple hops to reach all members and may transit
 * multiple relays in a trust domain extended with relays. This means that Publication lifetimes must
 * be chosen with this in mind.
 *
 * Initially, setting the cStateLifetime for Publications in the msgs collection to ~ 30 * distDelay
 * pubLifetime should be ~ (1.5) * cStateLifetime if not set by shim or distributor to something longer
 * (e.g., certs and keys). Otherwise Pubs expire too soon. cStateLifetime must be larger than 2-3
 * distDelay even in slow networks or sendOthers won't work.
 */


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
 *
 * Changed the Cb to return a bool in order to indicate if new local pubs
 * are on the ordered vector. This value will be set to true in the default
 * so it has same behavior as before.
 */
using PubPtr = rPub;
using PubVec = std::vector<PubPtr>;
using OrderPubCb = std::function<bool(PubVec&)>;

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
    using PubHashVec = std::vector<PubHash>;
    static inline PubHash hashPub(const rPub& r) { return IBLT<PubHash>::hashobj(r); }

    template<typename Item>
    struct CE { // Collection Entry
        Item i_;
        uint8_t s_; // item status
        std::chrono::system_clock::time_point hold_{};       // if non-zero, hold time

        constexpr CE(Item&& i, uint8_t s) : i_{std::forward<Item>(i)}, s_{s} {}
        static constexpr uint8_t act = 1;  // 0 = expired, 1 = active
        static constexpr uint8_t loc = 2;  // 0 = from net, 2 = local
        static constexpr uint8_t net = 0;  // 0 = from net, 2 = local
        static constexpr uint8_t nos = 4;  // 4 = no signing cert
        static constexpr uint8_t sts = act|loc;  // mask for all status bits
        auto inIblt() const noexcept { return (s_ & (nos|act)) != 0; }
        auto active() const noexcept { return (s_ & act) != 0; }
        auto fromNet() const noexcept { return (s_ & (act|loc)) == act; }
        auto local() const noexcept { return (s_ & (act|loc)) == (act|loc); }
        auto noSigner() const noexcept { return (s_ & (nos|act)) == nos; }
        auto& deactivate() { s_ &=~ act; return *this; }
        auto& activate() { s_ |= act; return *this; }
        auto& signer() { s_ &=~ nos; return *this; }
    };

    template<typename Item, typename Ent = CE<Item>, typename Base = std::unordered_map<PubHash,Ent>>
    struct Collection : Base {
        IBLT<PubHash> iblt_{};

        constexpr auto& iblt() noexcept { return iblt_; }

        constexpr auto contains(PubHash h) const noexcept { return Base::contains(h); }

        template<typename C=Item> requires hasView<C>
        constexpr auto contains(decltype(C().asView())&& c) const noexcept { return Base::contains(hashPub(c)); }

        template<typename UnOp> requires hasView<Item>
        constexpr void forEach(UnOp&& cb, decltype(Ent::s_) cond) const noexcept {
            for (const auto& [h, e] : *(Base*)this) if ((e.s_ & Ent::sts) == (cond|Ent::act)) cb(e.i_);
        }

        constexpr void forEachNoS(auto&& cb) const noexcept {
            for (auto& [h, e] : *(Base*)this) if ((e.s_ & Ent::nos) != 0) cb(e);
        }

        PubHash add(PubHash h, Item&& i, decltype(Ent::s_) s) {
            if (const auto& [it,added] = Base::try_emplace(h, std::forward<Item>(i), s); !added) return 0;
            iblt_.insert(h);
            return h;
        }
        auto addLocal(PubHash h, Item&& i) { return add(h, std::forward<Item>(i), Ent::loc|Ent::act); }

        auto add(Item&& i, decltype(Ent::s_) s) { return add(hashPub(i), std::forward<Item>(i), s); }
        auto addLocal(Item&& i) { return add(std::forward<Item>(i), Ent::loc|Ent::act); }
        auto addNet(Item&& i) { return add(std::forward<Item>(i), Ent::act); }
        auto addNoSigner(Item&& i) { return add(std::forward<Item>(i), Ent::nos|Ent::net); }

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
                if (p->second.inIblt()) iblt_.erase(h);
                Base::erase(p);
            }
        }
    };

    /*
     * special collections that just contain hashes of pubs with some special property
     * (like they're being ignored). This iblt is added to the outgoing cstate iblt to
     * suppress (re)sending of the pub. These hashes have no additional attributes.
     */
    struct HashCollection : std::unordered_set<PubHash> {
        using Base =  std::unordered_set<PubHash>;
        IBLT<PubHash> iblt_{};

        constexpr auto& iblt() noexcept { return iblt_; }

        constexpr auto contains(PubHash h) const noexcept { return Base::contains(h); }

        PubHash add(PubHash h) {
            if (const auto& [it,added] = Base::emplace(h); !added) return 0;
            iblt_.insert(h);
            return h;
        }
        auto erase(PubHash h) {
            if (Base::contains(h)) {
                iblt_.erase(h);
                Base::erase(h);
            }
        }
    };

    Collection<crData> pubs_{};     // current publications
    Collection<DelivCb> pubCbs_{};  // pubs requesting delivery callbacks
    HashCollection ignore_{};       // currently ignored pubs
    lpmLT<crPrefix,SubCb> subscriptions_{}; // subscription callbacks
    std::map<uint32_t,PubHashVec> pendOthers_{};    // for effective meshing, need to send non-local origin pubs

    DirectFace& face_;
    const crName collName_;     // 'name' of the collection
    SigMgr& pktSigmgr_;         // cAdd packet signing and validation
    SigMgr& pubSigmgr_;         // Publication validation
    size_t maxPubSize_;         // max space in bytes available in Content of a cAdd
    size_t maxInfoSize_;        // max space in bytes for Publication Name plus Content
    std::chrono::milliseconds cStateLifetime_{stateLifetime};
    std::chrono::milliseconds pubLifetime_{};
    std::chrono::milliseconds pubExpirationGB_{};
    std::chrono::milliseconds distDelay_{pduProc};  // time for a PDU to be distributed to all members on this subnet
    std::chrono::milliseconds signerHold_{distDelay_};
    pTimer scheduledCStateId_{std::make_shared<Timer>(getDefaultIoContext())};
    std::uniform_int_distribution<unsigned short> randInt_{7u, 12u}; //  cState delay  randomization
    Nonce  nonce_{};            // nonce of current cState
    uint32_t publications_{};   // # locally originated publications
    uint32_t noSignerPubs_{};   // # publications whose signer isn't in my certstore (yet)
    bool delivering_{false};    // currently processing a cAdd
    bool registering_{true};    // RST not set up yet
    bool netCState_{false};     // no cState from net seen in this collection yet
    bool batching_{false};      // can be used to hold off cState for a batch of new Publications
    bool autoStart_{true};      // call 'start()' when done registering
    GetLifetimeCb getLifetime_{ [this](auto){ return pubLifetime_; } };
    IsExpiredCb isExpired_{
        // default CB assumes last component of name is a timestamp and says pub is expired
        // if the time from publication to now is >= the pub lifetime
        [this](const auto& p) { auto dt = std::chrono::system_clock::now() - p.name().last().toTimestamp();
                         return dt >= getLifetime_(p) + maxClockSkew || dt <= -maxClockSkew; } };
    OrderPubCb orderPub_{[](PubVec& pv){   //default
            // can't use modern c++ on a mac
            //std::ranges::sort(pOurs, {}, [](const auto& p) { return p.name().last().toTimestamp(); });
            std::sort(pv.begin(), pv.end(), [](const auto& p1, const auto& p2){
                    return p1.name().last().toTimestamp() < p2.name().last().toTimestamp(); });
            return true;
        }
    };

    constexpr auto randInt() { return randInt_(randGen()); }

    constexpr auto maxInfoSize() const noexcept { return maxInfoSize_; }
    constexpr auto mtu() const noexcept { return face_.mtu(); }
    constexpr auto tts() const noexcept { return face_.tts(); }
    constexpr auto unicast() const noexcept { return face_.unicast(); }

    auto batchPubs() { batching_ = true; return pubs_.size(); }
    void batchDone(size_t n) {
        batching_ = false;
        if (!delivering_ && !registering_ && n < pubs_.size()) sendCAdd(); // try to send a cAdd if items added during batch
    }

    template<typename UnOp>
    constexpr void forFromNet(UnOp&& cb) const noexcept { pubs_.forEach(std::forward<UnOp>(cb), CE<crData>::net); }
    template<typename UnOp>
    constexpr void forFromLoc(UnOp&& cb) const noexcept { pubs_.forEach(std::forward<UnOp>(cb), CE<crData>::loc); }

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
        // maxPubSize_ is the mtu minus (top-level TL + size of the name including csID + MetaInfo size + Content TL + crypto overhead)
        maxPubSize_ = mtu() - (4 + (collName_.ssize() + 2+4) + 5 + 3 + pktSigmgr_.sigSpace());
        // max information size (Name Value components plus Content Value) available for shim/distributor
        maxInfoSize_ = maxPubSize_ -(2 + 3 + pubSigmgr_.sigSpace());
        if (maxPubSize_ <= 0 || maxInfoSize_ <= 0)
            throw runtime_error("syncps: no space for Pub /Info");
        distDelay_ += std::chrono::milliseconds(tts());
        signerHold_ = distDelay_;   //default
        if (distDelay_ > 300ms) {
            cStateLifetime_ = 30 * distDelay_ > 6000s ? 6000ms : 30*distDelay_;  // distributors can change
            pubLifetime_ = maxPubLifetime > 10*cStateLifetime_ ? maxPubLifetime : 10*cStateLifetime_;
        } else
            pubLifetime_ = maxPubLifetime;
        pubExpirationGB_ = pubLifetime_;
        // print ("syncps for {} computes pubSize: {}, infoSize: {}, distDly: {}\n", collName_, maxPubSize_, maxInfoSize_, distDelay_.count());
    }

    SyncPS(rName collName, SigMgr& wsig, SigMgr& psig) : SyncPS(defaultFace(), collName, wsig, psig) {}


    /**
     * complete lifetime timer setup for pub newly added to collection or just activated.
     */
    auto finishActivate(PubHash hash, std::chrono::milliseconds lt) {
        if (hash == 0 || lt == decltype(lt)::zero()) return hash;

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock skew).
        // An expired publication is never supplied in a cAdd so this hold time prevents
        // spurious end-of-lifetime exchanges due to clock skew.
        //
        // Expired publications are kept in the iblt for at least the max clock skew
        // interval to prevent a peer with a late clock giving it back to us as soon
        // as we delete it.

        oneTime(lt + maxClockSkew, [this, hash]{ pubs_.deactivate(hash); });
        oneTime(lt + pubExpirationGB_, [this, hash]{ pubs_.erase(hash); });
        return hash;
    }

    /**
     * @brief add a new local or network publication to the 'active' pubs set
     */
    auto addToActive(crData&& p, bool localPub) {
        //print("{:%M:%S} addToActive {} {}: {}\n", std::chrono::system_clock::now(), p.name(), p.size(), localPub);
        auto lt = getLifetime_(p);
        auto hash = localPub? pubs_.addLocal(std::move(p)) : pubs_.addNet(std::move(p));
        return finishActivate(hash, lt);
    }

    /*
     * @brief activate a no-signer entry whose signing cert has arrived.
     */
    auto activateEntry(const auto& e) {
        const auto& p = e.i_;
        //print("{:%M:%S} activateEntry {} {}: {}\n", std::chrono::system_clock::now(), p.name(), p.size(), localPub);
        if (e.fromNet())
            if (auto s = subscriptions_.findLM(p.name()); subscriptions_.found(s)) deliver(p, s->second);

        return finishActivate(hashPub(p), getLifetime_(p));
    }

    /**
     * @brief add a new network publication to the collection, but marked as both inactive
     * and noSigner. For otherwise okay Publications whose signer is not (yet) in local
     * certstore. Publication is marked "inactive" so won't be sent in a cAdd or returned in
     * a subscribe cb.
     * This is only kept for a short time (~distDelay)
     */
    bool addToNoSigner(crData&& p) {
        auto hash = pubs_.addNoSigner(std::move(p));
        //print("{:%M:%S} addToNoSigner {} {} ^{:x}\n", std::chrono::system_clock::now(), p.name(), p.size(), hash);
        if (hash == 0 || noSignerPubs_ > 50) return false;
        noSignerPubs_++;
        // Remove a publication that had no signing cert when it arrived if its signer
        // does not show up after brief delay. Check to make sure it hasn't become active.
        oneTime(signerHold_ + maxClockSkew, [this, hash]{
            if (pubs_.contains(hash) && !(pubs_.at(hash).active())) {
                //print("{:%M:%S} addToNoSigner now ignoring ^{:x}\n", std::chrono::system_clock::now(), hash);
                --noSignerPubs_;
                pubs_.erase(hash);
                ignorePub(hash);
            }
        });
        return true;
    }

    /*
     *  called after the associated cert store adds a new signing cert to see if this permits any
     *  of the held publications to be validated and moved to active
     */
    void newSigner(const thumbPrint& tp) {
        if (noSignerPubs_ == 0) return;
        //print("{:%M:%S} newSigner called with {} entries\n", std::chrono::system_clock::now(), noSignerPubs_);
        pubs_.forEachNoS([this,tp](auto& e) {
            const auto& p = e.i_;   // reference to pub
            if (tp == p.signer() && pubSigmgr_.validate(p)) {
                //print("syncps::newSigner is activating {}\n", p.name());
                e.signer().activate();
                --noSignerPubs_;
                activateEntry(e);
            }
        });
    }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and lives for at most pubLifetime.
     * Publications are signed before calling this routine.
     * Publications from the application always are additions to the collection so
     * are pushed to the network in response to any cState in PST
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub) {
        if (pub.size() > maxPubSize_) return 0;
        auto h = addToActive(std::move(pub), true);
        //print("{:%M:%S} publish {} {:x} d {} r {}\n", std::chrono::system_clock::now(), pub.name(), h, delivering_, registering_);
        if (h == 0) return h;   // already in actives
        ++publications_;
        // if a delivery callback is waiting on this pub, call it
        // doDeliveryCb(h, true);
        // new pub is always sent if 1) not delivering 2) not registering and 3) a cState is in collection
        // If no cStates, send a cState including this pub
        if (!delivering_ && !registering_ && !batching_) {
            // don't send publications until completely registered for responses
            if (netCState_ == false || sendCAdd() == false) sendCState();
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
     * Mainly for relays, Publications may altready have been received via the
     * network from another member and in this case the confirmation cb
     * should be invoked since this Publication is not just locally known
     *
     * returns 0 if Publication was neither added nor in the collection
     *
     * @param pub the object to publish
     */
    PubHash publish(crData&& pub, DelivCb&& cb) {
        auto h = hashPub(pub);
        if (pubs_.contains(h)) {
            if ((pubs_.at(h)).fromNet()) {
            print("syncps::publish w cb instant cb for {}\n", pub.name());
                cb((pubs_.find(h))->second.i_,true);
                }
            return h;     // if already in collection and is local assume it has already set cb
        }
        h = publish(std::move(pub));
        if (h != 0) {
            // add delivery callback and expire it after default publifetime
            pubCbs_.addLocal(h, std::move(cb));
            auto cd = pubLifetime_ < cStateLifetime_ ? cStateLifetime_ : pubLifetime_;
            oneTime(cd, [this, h]{ doDeliveryCb(h, false); });
            // oneTime(pubLifetime_, [this, h]{ doDeliveryCb(h, false); });
        }
        return h;
    }

    /**
     * @brief sign then publish pub
     */
    PubHash signThenPublish(crData&& pub, DelivCb&& cb={}) {
        pubSigmgr_.sign(pub);
        if(cb)   return publish(std::move(pub), std::move(cb));
        return publish(std::move(pub));
    }

    /**
     * @brief deliver a publication to a subscription's callback
     *
     * Since pub content may be encrypted, handles decrypting a copy
     * of the pub before presenting it to the subscriber then deleting
     * the copy (plaintext versions of encrypted objects must be ephemeral).
     */
    void deliver(const rPub& pub, const SubCb& cb) {
        if (pubSigmgr_.encryptsContent() && pub.content().size() > 0) {
            Publication pcpy{pub};
            if (pubSigmgr_.decrypt(pcpy)) cb(pcpy);
            return;
        }
        cb(pub);
    }

    /**
     * @brief subscribe to a topic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     */
    auto& subscribe(crPrefix&& topic, SubCb&& cb) {
        // print("syncps::subscribe called for {}\n", (rPrefix)topic);
        // add to subscription dispatch table. If subscription is new,
        // 'cb' will be called with each matching item in the active
        // publication list. Otherwise subscription will be
        // changed to the new callback.
        if (auto t = subscriptions_.find(topic); t != subscriptions_.end()) {
            t->second = std::move(cb);
            return *this;
        }
        // deliver all active pubs matching this subscription
        for (const auto& [h, pe] : pubs_) if (pe.fromNet() && topic.isPrefix(pe.i_.name())) deliver(pe.i_, cb);

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
        // if a cState is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (registering_) return;

        scheduledCStateId_->cancel();
        nonce_ = rand32();
        auto rleiblt = (ignore_.size() > 0? (pubs_.iblt() + ignore_.iblt()) : pubs_.iblt()).rlEncode();
        face_.express(crState(collName_/rleiblt, cStateLifetime_, nonce_),
                        [this](auto /*csid*/) { sendCState(); } // cState timeout for local cStates
                    );
    }

    /**
     * @brief Send a cState after a random delay. If called again before timer expires
     * restart the time. (This is used to collect all the cAdds responding to a cState
     * before sending a new cState.)
     */
    void sendCStateSoon(std::chrono::milliseconds dly = 0ms) {
        scheduledCStateId_->cancel();
        scheduledCStateId_ = schedule(dly + std::chrono::milliseconds(randInt()), [this]{ sendCState(); });
    }

    auto name2iblt(const rName& name) const noexcept {
        IBLT<PubHash> iblt{};
        try { iblt.rlDecode(name.last().rest()); } catch (const std::exception& e) { }
        return iblt;
    }

    // remove expired, suppressed, ineligible pubs from a pubvector
    // the contains() check is needed for delayed sending, for meshing
    bool updatePV(PubHashVec& hv) {
        if (hv.empty()) return false;
        auto now = std::chrono::system_clock::now();
        for (auto it=hv.begin(); it != hv.end(); ) {
            auto h = *it;
            if (!pubs_.contains(h) || isExpired_(pubs_.at(h).i_) || pubs_.at(h).hold_ > now) {
                it = hv.erase(it);
            } else {
                ++it;
           }
        }
        return !hv.empty();
    }

    void doDeliveryCb(PubHash hash, bool arrived) {
        auto cb = pubCbs_.find(hash);
        if (cb == pubCbs_.end()) return;

        // there's a callback for this hash. do it if pub was ours and is still active
        if (auto p = pubs_.find(hash); p != pubs_.end() && p->second.local()) (cb->second.i_)(p->second.i_, arrived);
        pubCbs_.erase(hash);
    }

    auto handleDeliveryCb(const auto& iblt) {
        if (pubCbs_.size())
            for (const auto hash : (pubs_.iblt() - pubCbs_.iblt() - iblt).peel().second) doDeliveryCb(hash, true);
    }

    /**
     * @brief construct and send a cAdd appropriate for responding to cstate 'csName'
     * returns false if nothing was sent
     *
     * The cAdd's name is the same as csName except the final component is replaced
     * with a murmurhash3 32 bit hash of csName which serves as both a compact
     * representation of csName's iblt and as a PST key to retrieve the original
     * iblt should it be needed.
     *
     * The cAdd will contain all the pubs that will fit in the face's MTU minus
     * the space needed for cAdd container itself. The container is built early
     * so its size is known.
     */
    auto shipCAdd(const rName& csName, const PubVec& pv) noexcept {
        PubVec sv{};
        auto ht = std::chrono::system_clock::now() + distDelay_;   // set hold time for sent pubs
        // send all the newPubs that will fit into the cAdd
        crData cAdd{crName{csName.first(-1)}.append(tlv::csID, mhashView(csName)).done(), tlv::ContentType_CAdd};
        for (ssize_t sz = mtu() - cAdd.ssize() - pktSigmgr_.sigSpace(); const auto& p : pv) {
           if (sz < p.ssize()) continue;
           sz -= p.ssize();
           sv.emplace_back(p);
           pubs_.at(hashPub(p)).hold_ = ht;
        }
        if (sv.empty()) return false;
        cAdd.content(sv);
        if (! pktSigmgr_.sign(cAdd)) return false;
        face_.send(std::move(cAdd));
        //print("{:%M:%S} sent {}\n", std::chrono::system_clock::now(), cAdd.name());;
        return true;
    }

    // for effective meshing, need to send non-local pubs while avoiding broadcast storms
    // called when a timer expires and proceeds to create a cAdd for eligible pubs, if any
    // does not change cState sending unless the csId has not been removed but there are
    // no eligible pubs to send - this is done in case there is/are disconnected members
    void sendOthers(uint32_t csId) {
        // check that the pubs on list are still eligible to send and the
        // associated cstate still exists.
        auto it = pendOthers_.find(csId);
        if (it == pendOthers_.end()) return;
        auto& hv = it->second;
        const auto name = face_.hash2Name(csId);
        if (name.size() == 0) { // ||  !updatePV(hv)) {
            pendOthers_.erase(it);
            if (!updatePV(hv)) {
                face_.unsuppressCState(collName_/pubs_.iblt().rlEncode());
                sendCStateSoon(distDelay_);
            }
            return;
        }

        // send all the eligible matching non-local origin pubs for csId that fit in a cAdd packet
        // set hold time
        PubVec sv{};
        auto now = std::chrono::system_clock::now();
        for (const auto h : hv) { if ( pubs_.at(h).hold_ <= now) sv.emplace_back(pubs_.at(h).i_);}
        if (sv.empty() || !orderPub_(sv)) return;
        shipCAdd(name, sv);
        pendOthers_.erase(it);  // erases everything pending on csId so a new csId starts the hold clock again
    }

    bool handleCState(const rName& name) {
        // The last component of 'name' is the peer's iblt. 'Peeling'
        // the difference between the peer's iblt & ours gives two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        //
        // pubs_ contains all pubs we have so send the ones we have & the peer doesn't.
        netCState_ = true;
        auto iblt{name2iblt(name)};
        handleDeliveryCb(iblt);
        const auto& [have, need] = (pubs_.iblt() - iblt).peel();
        if (need.size() == 0 && have.size() == 0 ) return false;    // cState same as local collection

        // separate haves into local originated and other-originated
        PubVec pv{};
        PubHashVec phOth{};
        auto now = std::chrono::system_clock::now();
        for (const auto hash : have) {
            if (const auto& p = pubs_.find(hash); p != pubs_.end() ) {
                if (p->second.local()) {
                    if (p->second.hold_ > now) continue;     // sent this pub too recently to send again
                    pv.emplace_back(p->second.i_);
                } else if (p->second.fromNet()) {
                    phOth.emplace_back(hash);    // others get checked at their (delayed) send time
                }
            }
        }

        // if NO eligible local origin pubs to send, take care of needs and others and return
        if (pv.empty() || !orderPub_(pv)) {
            if (need.size() > 0) {
                face_.unsuppressCState(collName_/pubs_.iblt().rlEncode());
                if (unicast()) { sendCState(); return false;}
                sendCStateSoon();   // only waits the small random delay - may want to increase
            }
            // Next section of code is for sending non-local origin pubs for effective meshing
            //  only send others' pubs if the cState is from a member who has all my local origin pubs
            //  (may be overly conservative but avoids reacting to transitory cStates)
            // This may result in sending another's Pubs that it is suppressing after first send
            if (phOth.empty() || have.size() - phOth.size() > 0) return false;
            // set up a delayed send of others Pubs that are missing from this cState
            uint32_t csId = mhashView(name);
            if (!unicast() && pendOthers_.find(csId) == pendOthers_.end()) {
                pendOthers_.emplace(csId, phOth);
                oneTime(distDelay_ + std::chrono::milliseconds(randInt()), [this,csId]{ sendOthers(csId); });
            }
            return false;
         }

         // tries to ship all the local origin pubs that will fit in a cAdd packet
        if (! shipCAdd(name, pv) && need.size()) {
            // did not send Pubs but have needs from cState
            face_.unsuppressCState(collName_/pubs_.iblt().rlEncode());
            if (unicast()) { sendCState(); return false; }
            sendCStateSoon();     // only waits the small random delay - may want to increase
            return false;
        }
        if (need.size()) {  // check if this cState had Publications I need
            face_.unsuppressCState(collName_/pubs_.iblt().rlEncode());
            sendCStateSoon();
        } else {
            // delay long enough for recipients to send cStates reflecting the Pubs in the shipped cAdd
            sendCStateSoon(2*distDelay_);
        }
        return true;
    }

    /*
     * orderPubs puts oldest first
     */
    bool sendCAdd(const rName name) {
        // scheduledCStateId_->cancel();     // if a scheduleCStateId_ is set, cancel it

        auto iblt{name2iblt(name)}; // use the retrieved cState's iblt to find new pubs
        const auto& [have, need] = (pubs_.iblt() - iblt).peel();
        if (have.size() == 0) return false;    // no new pubs

        PubVec pv{};    // vector of locally created publications I have, oldest first
        auto now = std::chrono::system_clock::now();
        for (const auto hash : have) {
            if (const auto& p = pubs_.find(hash); p != pubs_.end()) {
                if (p->second.hold_ > now) continue;   // sent this pub too recently to send again
                if (p->second.local()) pv.emplace_back(p->second.i_);
            }
        }
        if (! orderPub_(pv))    return false;   //order priority returns all pubs to send in pv - puts older pubs first

        if (! shipCAdd(name, pv))   return false;   // if can't send anything delay in case of holds, etc

        sendCStateSoon(2*distDelay_); // delay long enough for recipients to send cStates reflecting the Pubs in the shipped cAdd
                                                          // and to remove hold times on the Pubs that were just sent
        return true;
    }

    /*
     * For publishing newly created, unsent publications
     * any cState will be missing new locally created Pubs
     */
    bool sendCAdd() {
        // look for a cState from network - would like to get most recent one from network
        const auto name  = face_.bestCState(collName_);
        if (name.size() == 0) return false;            // wait for a cState
        return sendCAdd(name);
    }

    /**
     * @brief Process cAdd after successful validation
     *
     * Add each item in cAdd content that we don't have to
     * our list of active publications then notify the
     * application about the updates.
     *
     * When onCAdd opportunistically processes *all* cAdds for this collection, should compare its iblt
     * against my current iblt with peel operation before pulling out content. I.e., if I "have"
     * everything in the iblt, don't process.
     *
     * Called for *any* cAdd in the collection, even if no matching cState in PST
     * Can result in a change in local cState if any of the pubs are "needed"
     * A needed pub can also cause a local publication in response to delivering_
     * If no change in local cState, then the current cState shedule should not be change
     *
     * If there's a cState fromNet_, new pub will go out and a new cState should be scheduled soonish
     * If there's no cState fromNet_, a new cState should be scheduled soonish to let collection members know
     * "soonish" should be long enough to 1) collect other local cState changes 2) let other members process
     * the just-sent pub 3) un-suppress the just-sent pub in case it was missed
     * If keep getting cAdds, may keep pushing out the new cState
     *
     * For meshing, tests to see if the cAdd's cState is on this member's pending pubs of others
     * and if so, supresses any pubs in the cAdd.
     * Might work to just remove that cState hash pub vector from the pending  map
     *
     * @param cState   cState for which we got the cAdd
     * @param cAdd     cAdd content
     */
    void onCAdd(const rData& cAdd) {
        // entry invariants:
        // - this routine is an upcall from the incoming pdu handler so shouldn't
        //   be called recursively. 'delivering_' is only true while this routine's
        //   main loop is executing so assert that it's not true on entry.
        assert(!delivering_);

        if (registering_) return;   // don't process cAdds till fully registered
        scheduledCStateId_->cancel();     // if a scheduleCStateId_ is set, cancel it

        // if publications result from handling this cAdd we don't want to
        // respond to a peer's cState until we've handled all of them.
        delivering_ = true;
        auto initpubs = publications_;

        // if this responds to a cState on pendOthers_,
        auto ci = cAdd.name().lastBlk().toNumber();
        // remove any pending response for this csId
        if ( auto it = pendOthers_.find(ci) != pendOthers_.end()) pendOthers_.erase(it);
        // sets the hold time on its Pubs to keep from resending too soon
         decltype(std::chrono::system_clock::now()) ht{};
         if (!pendOthers_.empty()) ht = std::chrono::system_clock::now() + distDelay_;

        auto ap = 0;    // count added pubs from this cAdd
        for (auto c : cAdd.content()) {
            if (! c.isType(tlv::Data)) continue;
            rData d(c);
            if (! d.valid()) {
                // XXX the current cAdd .valid() method only checks the form of the outer 'Data'
                // but not that the content section TLVs are all of type Data, are valid,  and
                // their sizes are correct. Until this is fixed we are 'shotgun parsing' and, if
                // the TLV format is adversarial, we may not be able to safely hash & ignore the pub.
                // For now we skip this pub and try to continue but getting a real cAdd valid()
                // method needs to happen ASAP. Once it does, this 'if' will go away since a cAdd
                // will never be passed up to here if any of its Data's are not valid.
                //print("doesn't pass basic structure test {}\n", d.name());
                continue;
            }
            auto h = hashPub(d);
            if (ignore_.contains(h)) continue;  // currently ignoring this pub

            //  puts hold on pubs others send that I already have in case it is on the pending list
            if (pubs_.contains(h)) { // && not local origin in case overhear a member resending my pubs?
                if (ht.time_since_epoch().count()) pubs_.at(h).hold_ = ht;
                continue;
            }

            if (d.size() > maxPubSize_ || isExpired_(d)) {
                 //print("pub {}: {}\n", isExpired_(d)? "expired":"exceeds maxPubSize", d.name());
                // unwanted pubs have to go in our iblt or we'll keep getting them
                ignorePub(d);
                continue;
            }
            if (! pubSigmgr_.validate(d)) {
                if (pubSigmgr_.haveSigner(d))
                    ignorePub(d); // already have this Pub's signing cert
                else if ( !addToNoSigner(crData(d)))
                    ignorePub(d);   // failed to add as inactive without signer
                continue;
            }

            // we don't already have this publication so add it to the
            // collection then deliver it to the longest match subscription.
            auto ph = addToActive(crData(d), false);
            if (ph == 0) {
                // print("addToActive failed: {}\n", d.name());
                continue;
            }
            ++ap;
            if (auto s = subscriptions_.findLM(d.name()); subscriptions_.found(s)) deliver(d, s->second);
            // else print("syncps::onCAdd: no subscription for {}\n", d.name());
        }
        delivering_ = false;
        if (ap == 0) {  // nothing I need in this cAdd, no change to local cState
            // consider skipping this for unicast
            sendCStateSoon(distDelay_); //canceled sending cState on entry, maybe make this sooner if there are "needs"
            return;
        }

        /* We've delivered all the publications in the cAdd.  There may be
         * additional inbound cAdds for the same cState so sending an updated
         * cState immediately will result in unnecessary duplicates being sent.
         * sendCStateSoon(0 delays a bit (should be min ~ distribution delay for this subnet) and
         * this gets canceled and rescheduled by each new cAdd arrival that has pubs I can use.
         *  XXX possibly need to not keep pushing cState out if this member has unsatisfied needs
         */

        // If the cAdd resulted in new outbound (locally originated) pubs, cAdd them for any pending peer CStates
        if (initpubs != publications_) {     // sending will schedule an updated cState
            const auto name  = face_.bestCState(collName_);
            if (name.size() == 0)   sendCAdd(cAdd.name());
            else    sendCAdd(name);
            return;
        }
        // changed local cState, send a confirming cState at a randomized delay - gets reset if more cAdds arrive
        sendCStateSoon(distDelay_);
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    /**
     * @brief ignore a publication by temporarily adding it to the our 'ignored' collection
     */
    void ignorePub(const PubHash h) {
        if (ignore_.contains(h)) return;
        ignore_.add(h);
        oneTime(1s, [this, h]{
                    ignore_.erase(h);
                    //print("{:%M:%S} ignorePub done ignoring ^{:x}\n", std::chrono::system_clock::now(), h);
                });
    }
    void ignorePub(const rPub& p) {
        auto h = hashPub(p);
        //print("{:%M:%S} ignorePub {} ^{:x}\n", std::chrono::system_clock::now(), p.name(), h);
        ignorePub(h);
    }

    /**
     * @brief startup related methods start and autoStart
     *
     * 'start' starts up the bottom half (network) communication by registering RST
     * callbacks for cStates matching this collection's prefix then sending an initial
     * 'cState' to solicit/distribute publications. Since the content of cAdd packets
     * can be encrypted, it's pointless to send a cState before obtaining the decryption
     * key. dct_model sets up an appropriate chain of callbacks such that 'start()' is
     * called after all the prerequisites for syncing this collection have been obtained.
     *
     * 'autoStart' gives the upper level control over whether 'start' is called automatically
     * after 'run()' is called (the default) or if it will be called explicitly
     */
    void start() {
        face_.addToRST(collName_,
                       [this, ncomp = collName_.nBlks()+1](auto /*prefix*/, auto s) {   // sCb
                           // cState must have one more name component (an iblt) than the collection name
                           // if this handleCState results in sending a cAdd, currently won't schedule a cState, may want to change
                           if (auto n = s.name(); n.nBlks() == ncomp) handleCState(n);
                       },
                       [this](auto rd) { // dCb: cAdd response to any active local cState in collName_
                            // print("syncps RST set Cb received cAdd: {}\n", rd.name());
                            if (! pktSigmgr_.validateDecrypt(rd)) {
                                // print("syncps invalid cAdd: {}\n", rd.name());
                                // Got an invalid cAdd so ignore the pubs it contains.
                                return;
                            }
                            onCAdd(rd);
                        },
                       [this](rName) -> void {
                           registering_ = false;
                           face_.unsuppressCState(collName_/pubs_.iblt().rlEncode()); // force sending initial state
                           sendCState();
                       });
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
        pubExpirationGB_ = time > maxClockSkew? maxClockSkew : time;
        return *this;
    }
    auto& signerHoldtime(std::chrono::milliseconds time) { signerHold_ = time; return *this; }
};

}  // namespace dct

#endif  // SYNCPS_SYNCPS_HPP
