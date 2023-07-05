#ifndef DCT_FACE_DIRECT_HPP
#define DCT_FACE_DIRECT_HPP
#pragma once
/*
 * Data Centric Transport 'direct face' abstraction (no NFD or forwarding agent)
 *
 * Copyright (C) 2021-2 Pollere LLC
 * @author: Pollere LLC <info@pollere.net>
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
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

/** DCT 'Direct' face
 *
 * A 'face' is the interface between an application and a particular packet
 * transport instance.  It handles the Interest & Data packet send/recv semantics
 * and provides the necessary application callbacks (e.g., when a matching Data arrives
 * for some pending Interest). Other NDN libraries delegate most of this work to
 * a 'forwarding agent' like NFD but this creates security, maintainability,
 * reliability and performance issues in an OT environment. Direct face implements
 * *all* of the NDN behavior used by DCT, allowing applications to be self-contained
 * and idempotent.
 *
 * 'Direct' interoperates with NFD at the NDN Interest/Data packet level thus
 * with DCT-compatible apps written using the ndn-ind or ndn-cxx libraries.  However,
 * introducing NFDs into a DCT direct system doubles packet processing costs (every packet
 * is sent & received twice - once by apps and once by NFD), makes it difficult to implement
 * app-based policies controlling which packets go where, and greatly increases the debugging
 * and attack surface (NFD + ndn-cxx is >50,000 lines of code vs. ~250 for Direct).
 */


#include <map>
#include <set>
#include <type_traits>
#include <unordered_set>

#include "transport.hpp"
#include "lpm_tables.hpp"

namespace dct {

using namespace std::literals;
using TimerCb = std::function<void()>;

/**
 * A DirectFace implements a subset of the NDN application-level API used by both the ndn-cxx
 * and ndn-ind libraries. It directly connects DCT-based applications to a network without
 * requiring a forwarding agent like NFD.
 */
class DirectFace {
  public:
    enum class cSts { UNCONNECTED = 1, REQUESTED = 2, CONNECTED = 3 };
    using enum cSts;
    using connectCbList = std::vector<std::pair<std::vector<uint8_t>, RegisterCb>>;

    boost::asio::io_context& ioContext_{getDefaultIoContext()};
    dct::Transport& io_;   // boost async I/O transport (defaults to UDP6 multicast)

    RIT rit_{}; // Registered Interest Table
    PIT pit_{}; // Pending Interest Table
    DIT dit_{}; // Duplicate Interest Table

    connectCbList ccb_;
    cSts cSts_{UNCONNECTED};

    auto rcvCb(auto pkt, auto len) -> void {
        // Packet receive handler: decode and process as Interest or Data (silently ignore anything else).
        // Since a matching interest might already be in the PIT or there might be
        // no matching interests for a data, don't do anything heavyweight here.
        if (tlv(pkt[0]) == tlv::Interest) handlecState({pkt, len});
        else if (tlv(pkt[0]) == tlv::Data) handlecAdd({pkt, len});
    }

    auto conCb() -> void {
        // 'onConnect' callback: invoke everything on the ccb list
        cSts_ = CONNECTED;
        for (const auto& [n, cb] : ccb_) cb(rName{n});
        ccb_.clear();
    }

    DirectFace() : io_{dct::transport([this](auto p, auto l){ rcvCb(p, l); }, [this]{ conCb(); })} {
        io_.connect();
    }

    DirectFace(std::string_view addr)
            : io_{dct::transport(addr, [this](auto p, auto l){ rcvCb(p, l); }, [this]{ conCb(); })} {
        io_.connect();
    }

    // Get the asio io_context used by this face
    boost::asio::io_context& getIoContext() const noexcept { return ioContext_; }

    constexpr size_t mtu() const noexcept { return io_.mtu(); }

    std::shared_ptr<Timer> schedule(std::chrono::microseconds delay, TimerCb&& cb) {
        auto timer = std::make_shared<Timer>(ioContext_, delay);
        timer->async_wait([cb=std::move(cb), timer](const auto& e) { if (e == boost::system::errc::success) cb(); });
        return timer;
    }

    void oneTime(std::chrono::microseconds delay, TimerCb&& cb) { schedule(delay, std::move(cb)); }

    auto timeOut(std::chrono::microseconds delay, TimerCb&& cb) {
        auto timer = std::make_unique<Timer>(ioContext_, delay);
        timer->async_wait([cb=std::move(cb)](const auto& e) { if (e == boost::system::errc::success) cb(); });
        return timer;
    }
    std::uniform_int_distribution<unsigned short> randInt_{10, 50}; // cstate publish randomization
    constexpr auto jitter() { return std::chrono::milliseconds(randInt_(randGen())); }

    // schedule or re-schedule PIT Interest Timeout callback
    void schedITO(PITentry& pe) {
        // if the interest is locally generated, the timeout upcall will generate a new pit
        // entry to replace the one being deleted.
        pe.timer(timeOut(pe.i_.lifetime() + jitter(), [this, idat=*pe.idat_] () mutable {
                                auto i = rInterest(idat);
                                pit_.itoCB(i); }
                         )
                );
    }

    /**
     * Send packet 'pkt' of length 'len' bytes
     */
    void send(const uint8_t* pkt, size_t len) { io_.send(pkt, len); }
    void send(const std::vector<uint8_t>& v) { send(v.data(), v.size()); }
    void send(const tlvParser& v) { send(v.data(), v.size()); }

    /**
     * Handle an interest registration.
     * - add the RIT entry
     * - Registration isn't successful until the network is connected.
     *   If not connected yet add the regDone callback to a deferal
     *   list handled on connection complete.
     * - Otherwise just call the regDone CB.
     */
    void addToRIT(const rName& p, InterestCb&& iCb, DataCb&& dCb, RegisterCb&& rCb) {
        rit_.add(RITentry{p, std::move(iCb), std::move(dCb)});
        if (cSts_ != CONNECTED) {
            // Call back when connected.  Have to copy prefix & rCB since the
            // backing store of p might go away on our return.
            ccb_.push_back(std::make_pair(p.asVec(), std::move(rCb)));
            return;
        }
        rCb(p);  // connected and all done
    }

    /**
     * Handle an interest outgoing from app.
     * - if it's already in the pit (from network peer), add the local origin information.
     * - Add it to the pit & dit then send it. Note that interest has to be sent
     *   even though it was multicast to the net to unblock completion callbacks
     *   at the origin. E.g., during cert dist peer sent this interest followed
     *   by pubs and it needs to hear pubs arrived.
     *
     *  May get multiple cStates broadcast if there are members missing different
     *  pubs after timeout collection subname is i.name().first(-1)
     */
    auto unsuppressCState(const rName& n) {
        if (auto pi = pit_.find(n); pit_.found(pi)) pi->second.onNet_ = 0;
    }

     // always sends a newly created cState (a new cState is always created after old one expired)
     // syncps resets the onNet_ before calling if a currentState must be put onNet
     // suppress sending if already exists (not the last cState locally received from others) and has been on network twice
    auto express(const rInterest& i, InterestTO&& ito) {
        if (cSts_ != CONNECTED) throw runtime_error("express: not connected");

        bool newCS = true;
        bool suppress = false;
        if (auto pi = pit_.find(i.name()); pit_.found(pi)) {
            const auto& pe = pi->second;
            // suppress if broadcast to domain at least twice (and not "close to" expiry?)
            if (pe.onNet_ > 1)  suppress = true;
            if (pe.ito_)  newCS = false;  // i is the same as last expressed cState
        }
        if (newCS) {
            // i is not the same as last expressed cState
            // find the previous local cState in PIT for this collection, if any,
            // and remove its local info so it doesn't get re-expressed at time out
            const auto c = i.name().first(-1);
            for (auto& [ih, pe] : pit_) {
                if (pe.ito_ && c.isPrefix(pe.i_.name())) {
                    pe.ito_ = {};
                    break;
                }
            }
        }
        auto res = pit_.add(i, std::move(ito)); // add or update with local info
        schedITO(res.first->second);  //  reschedule timeout
        if (suppress)  return;

        dit_.add(i);
        send(i);
    }

    /**
     * Handle a cState incoming from the network:
     *  - if it's a dup of a recent interest, ignore it.
     *  - if there's no RIT match, ignore it
     *  - add it to dup interest table.
     *  - add it to PIT then upcall RIT listener (has to be done in
     *    this order so if upcall results in a Data, PIT entry exists).
     */
    void handlecState(rInterest i) {
        if (! i.valid()) return;
        auto [isDup, h] = dit_.dupInterest(i);
        if (isDup) return;

        // check RIT first to see if we can handle this interest. If not,
        // ignore it (DON'T add it to the DIT because we might register
        // a handler soon and don't want future matching Interests suppressed).
        auto ri = rit_.findLM(rPrefix(i.name()));
        if (! rit_.found(ri)) return;

        dit_.add(h);    // detect future copies of i as dups

        // add to PIT as a from network interest, get iCb from the RIT match and give it to RIT's listener.
        schedITO(pit_.add(i).first->second);
        ri->second.iCb_(rName{*ri->second.name_}, i);
    }

    /**
     * Return the most recent pending interest matching prefix 'p'
     *
     * This is normally used to avoid waiting for the interest re-expression
     * callback when the app has new data to send.
     */
    auto bestCState(const rPrefix p) const noexcept {
        if (pit_.begin() == pit_.end()) return rName{};
        const PITentry* loc{};
        const PITentry* net{};
        for (const auto& [ih, pe] : pit_) {
            if (! p.isPrefix(pe.i_.name())) continue;
            if (pe.fromNet_ && (!net || pe.timer_->expiry() > net->timer_->expiry())) net = &pe;
            if (pe.ito_ && (!loc || pe.timer_->expiry() > loc->timer_->expiry())) loc = &pe;
        }
        if (!net && !loc) return rName{};
        return (net? net:loc)->i_.name();
    }

    /**
     * send an outgoing cAdd
     */
    void send(rData d) { send(d.data(), d.size()); }

    /**
     * Handle an incoming cAdd:
     *  - ignore if not structurally valid
     *  - complain if there's no pit entry for it
     *  - if the prefix is in the RIT, pass it to the associated data callback
     */
    void handlecAdd(rData d) {
        if (! d.valid()) return;
        // The last component of the name is a hash of the associated cState's name.
        // This hash is the pit lookup key. The 'valid()' above has checked that this
        // block exists. Now check that it has the correct type then deserialize it.
        auto ibh = d.name().lastBlk();
        if (ibh.size() > 8 || tlv(ibh.typ()) != tlv::Version) return;
        decltype((mhashView(ibh))) ihash = ibh.toNumber();
        // use the hash to get the cState PIT entry
        auto pi = pit_.find(ihash);
        if (!pit_.found(pi)) return; // we didn't hear this cState
        const auto& i = pi->second.i_;
        if (auto ri = rit_.findLM(rPrefix(d.name())); rit_.found(ri)) ri->second.dCb_(i, d);
    }

     // use the name hash to get the cState PIT entry's name
    auto hash2Name(uint32_t h) {
        auto pi = pit_.find(h);
        if (!pit_.found(pi)) {
            print("hash2Name: no PIT entry for {}\n", h);
            return rName{};
        }
        return pi->second.i_.name();
    }
};

static inline DirectFace& defaultFace() {
    static DirectFace* face{};
    if (face == nullptr) face = new DirectFace();
    return *face;
}

}  // namespace dct

#endif  // DCT_FACE_DIRECT_HPP
