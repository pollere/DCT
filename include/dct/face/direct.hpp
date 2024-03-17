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
 * transport instance.  It handles the cState & Data (cAdd) packet send/recv semantics
 * and provides the necessary application callbacks (e.g., when a matching Data arrives
 * for some pending cState). 
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
 * A DirectFace directly connects DCT-based applications to a network without
 * requiring a forwarding agent
 */
class DirectFace {
  public:
    enum class cSts { UNCONNECTED = 1, REQUESTED = 2, CONNECTED = 3 };
    using enum cSts;
    using connectCbList = std::vector<std::pair<std::vector<uint8_t>, RegisterCb>>;

    boost::asio::io_context& ioContext_{getDefaultIoContext()};
    dct::Transport& io_;   // boost async I/O transport (defaults to UDP6 multicast)

    RST rst_{}; // Registered State Table
    PST pst_{}; // Pending State Table
    DST dst_{}; // Duplicate State Table

    connectCbList ccb_;
    cSts cSts_{UNCONNECTED};

    auto rcvCb(auto pkt, auto len) -> void {
        // Packet receive handler: decode and process as Interest or Data (silently ignore anything else).
        // Since a matching interest might already be in the PIT or there might be
        // no matching interests for a data, don't do anything heavyweight here.
        // The handle* routines validity check all the contents of the cState/cAdd but the call
        // site here constructs the outer rInterest/rData and that can fail if the received
        // packet length 'len' doesn't agree with the outer TLV length in 'pkt'. The try..catch
        // makes sure that packets with this error are silently ignored.
        try {
            if (tlv(pkt[0]) == tlv::cState) handlecState({pkt, len});
            else if (tlv(pkt[0]) == tlv::Data) handlecAdd({pkt, len});
        } catch (const runtime_error& ) { }
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

    constexpr auto mtu() const noexcept { return io_.mtu(); }
    constexpr auto tts() const noexcept { return io_.tts(); }

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
    std::uniform_int_distribution<unsigned short> randInt_{10, 60}; // 35ms avg cstate publish randomization
    constexpr auto jitter() { return std::chrono::milliseconds(randInt_(randGen())); }

    // schedule or re-schedule PST cState Timeout callback
    void schedSTO(PSTentry& pe) {
        // if the cState is locally generated, the timeout upcall will generate a new pst
        // entry to replace the one being deleted. Wait a bit to delete entries from the net
        // in the hope they'll refresh theirs before we have to replace ours.
        auto to = pe.s_.lifetime();
        if (pe.fromNet_) to += jitter();
        pe.timer(timeOut(to, [this, sdat=*pe.sdat_] () mutable {
                                auto s = rState(sdat);
                                pst_.stoCB(s);
                            }));
    }

    /**
     * Handle a registration.
     * - add the RST entry
     * - Registration isn't successful until the network is connected.
     *   If not connected yet add the regDone callback to a deferal
     *   list handled on connection complete.
     * - Otherwise just call the regDone CB.
     */
    void addToRST(const rName& p, StateCb&& sCb, DataCb&& dCb, RegisterCb&& rCb) {
        rst_.add(RSTentry{p, std::move(sCb), std::move(dCb)});
        if (cSts_ != CONNECTED) {
            // Call back when connected.  Have to copy prefix & rCB since the
            // backing store of p might go away on our return.
            ccb_.push_back(std::make_pair(p.asVec(), std::move(rCb)));
            return;
        }
        rCb(p);  // connected and all done
    }

    /**
     * Handle a cState outgoing from app.
     * - if it's already in the pst (from network peer), add the local origin information.
     * - Add it to the pst & dst then send it. Note that cState has to be sent
     *   even though it was multicast to the net to unblock completion callbacks
     *   at the origin. E.g., during cert dist peer sent this cState followed
     *   by pubs and it needs to hear pubs arrived.
     *
     *  May get multiple cStates broadcast if there are members missing different
     *  pubs after timeout collection subname is i.name().first(-1)
     */
    auto unsuppressCState(const rName& n) {
        if (auto ps = pst_.find(n); pst_.found(ps)) ps->second.onNet_ = 0;
    }

     // always sends a newly created cState (a new cState is always created after old one expired)
     // syncps resets the onNet_ before calling if a currentState must be put onNet
     // suppress sending if already exists (not the last cState locally received from others)
     // and has been on network twice
    auto express(crState&& s, StateTO&& sto) {
        if (cSts_ != CONNECTED) throw runtime_error("express: not connected");

        bool newCS = true;
        bool suppress = false;
        if (auto ps = pst_.find(s.name()); pst_.found(ps)) {
            const auto& pe = ps->second;
            // suppress if broadcast to domain at least twice (and not "close to" expiry?)
            if (pe.onNet_ > 1)  suppress = true;
            if (pe.sto_)  newCS = false;  // s is the same as last expressed cState
        }
        if (newCS) {
            // s is not the same as last expressed cState
            // find the previous local cState in PST for this collection, if any,
            // and remove its local info so it doesn't get re-expressed at time out
            const auto c = s.name().first(-1);
            for (auto& [ih, pe] : pst_) {
                if (pe.sto_ && c.isPrefix(pe.s_.name())) {
                    pe.sto_ = {};
                    break;
                }
            }
        }
        auto res = pst_.add(s, std::move(sto)); // add or update with local info
        schedSTO(res.first->second);  //  reschedule timeout
        if (suppress) return;

        dst_.add(s);
        io_.send(std::move(s));
    }

    /**
     * Handle a cState incoming from the network:
     *  - if it's a dup of a recent cState, ignore it.
     *  - if there's no RST match, ignore it
     *  - add it to dup cState table.
     *  - add it to PST then upcall RST listener (has to be done in
     *    this order so if upcall results in a Data, PST entry exists).
     */
    void handlecState(rState s) {
        if (! s.valid()) return;
        auto [isDup, h] = dst_.dupState(s);
        if (isDup) return;

        // check RST first to see if we can handle this cState. If not,
        // ignore it (DON'T add it to the DST because we might register
        // a handler soon and don't want future matching cStates suppressed).
        auto rs = rst_.findLM(rPrefix(s.name()));
        if (! rst_.found(rs)) return;

        dst_.add(h);    // detect future copies of s as dups

        // add to PST as a from network cState, get sCb from the RST match and give it to RST's listener.
        schedSTO(pst_.add(s).first->second);
        rs->second.sCb_(rName{*rs->second.name_}, s);
    }

    /**
     * Return the most recent pending cState matching prefix 'p'
     *
     * This is normally used to avoid waiting for the cState re-expression
     * callback when the app has new data to send.
     */
    auto bestCState(const rPrefix p) const noexcept {
        if (pst_.begin() == pst_.end()) return rName{};
        const PSTentry* loc{};
        const PSTentry* net{};
        for (const auto& [ih, pe] : pst_) {
            if (!pe.timer_ || !p.isPrefix(pe.s_.name())) continue;
            auto e = pe.timer_->expiry();
            if (pe.fromNet_ && (!net || e > net->timer_->expiry())) net = &pe;
            if (pe.sto_ && (!loc || e > loc->timer_->expiry())) loc = &pe;
        }
        if (!net && !loc) return rName{};
        return (net? net:loc)->s_.name();
    }

    /**
     * send an outgoing cAdd
     */
    void send(crData&& d) { io_.send(std::move(d)); }

    /**
     * Handle an incoming cAdd:
     *  - ignore if not structurally valid
     *  - complain if there's no pst entry for it
     *  - if the prefix is in the RST, pass it to the associated data callback
     */
    void handlecAdd(rData d) {
        if (! d.valid()) return;
        // The last component of the name is a hash of the associated cState's name.
        // This hash is the pst lookup key. The 'valid()' above has checked that this
        // block exists. Now check that it has the correct type then deserialize it.
        auto sbh = d.name().lastBlk();
        if (sbh.size() > 8 || tlv(sbh.typ()) != tlv::csID) return;
        decltype((mhashView(sbh))) shash = sbh.toNumber();
        // use the hash to get the cState PST entry
        auto ps = pst_.find(shash);
        if (!pst_.found(ps)) return; // we didn't hear this cState
        const auto& s = ps->second.s_;
        if (auto rs = rst_.findLM(rPrefix(d.name())); rst_.found(rs)) rs->second.dCb_(s, d);
    }

     // use the name hash to get the cState PST entry's name
    auto hash2Name(uint32_t h) {
        auto ps = pst_.find(h);
        if (!pst_.found(ps)) {
            print("hash2Name: no PST entry for {}\n", h);
            return rName{};
        }
        return ps->second.s_.name();
    }
};

static inline DirectFace& defaultFace(const std::string& addr = "") {
    static DirectFace* face{};
    if (face == nullptr) {
        if(addr.empty()) face = new DirectFace();
        else face = new DirectFace(addr);
    }
    return *face;
}

}  // namespace dct

#endif  // DCT_FACE_DIRECT_HPP
