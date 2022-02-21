/*
 * Data Centric Transport 'direct face' abstraction (no NFD or forwarding agent)
 *
 * Copyright (C) 2021-2 Pollere LLC
 * @author: Pollere LLC <info@pollere.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

/** DCT 'Direct' face
 *
 * An NDN 'face' is the interface between an application and a particular packet
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

#ifndef DCT_FACE_DIRECT_HPP
#define DCT_FACE_DIRECT_HPP

#include <map>
#include <set>
#include <type_traits>
#include <unordered_set>

#include <ndn-ind/util/logging.hpp>

#include "asio.hpp"
#include "default-io-context.hpp"
#include "lpm_tables.hpp"

using namespace std::literals;

namespace ndn {
    using TimerCb = std::function<void()>;

INIT_LOGGER("ndn.DirectFace");

/**
 * A DirectFace implements a subset of the NDN application-level API used by both the ndn-cxx
 * and ndn-ind libraries. It directly connects DCT-based applications to an NDN network without
 * requiring a forwarding agent like NFD.
 */
class DirectFace {
  public:
    enum class cSts { UNCONNECTED = 1, REQUESTED = 2, CONNECTED = 3 };
    using enum cSts;
    using connectCbList = std::vector<std::pair<std::vector<uint8_t>, RegisterCb>>;

    boost::asio::io_context& ioContext_{getDefaultIoContext()};
    AsIO io_;   // boost async I/O transport (defaults to UDP6 multicast)

    RIT rit_{}; // Registered Interest Table
    PIT pit_{}; // Pending Interest Table
    DIT dit_{}; // Duplicate Interest Table

    connectCbList ccb_;
    cSts cSts_{UNCONNECTED};

    DirectFace(std::string_view addr = "default")
        :   io_{addr, ioContext_,
                // Packet receive handler: decode and process as Interest or Data (silently ignore anything else).
                // Since a matching interest might already be in the PIT or there might be
                // no matching interests for a data, don't do anything heavyweight here.
                [this](auto pkt, auto len) {
                    if (tlv(pkt[0]) == tlv::Interest) {
                        handleInterest({pkt, len});
                    } else if (tlv(pkt[0]) == tlv::Data) {
                        handleData({pkt, len});
                    } else {
                        _LOG_DEBUG(format("recv type {:x}: {} bytes", pkt[0], len));
                    }
                },
                // 'onConnect' callback: invoke everything on the ccb list
                [this] {
                    cSts_ = CONNECTED;
                    for (const auto& [n, cb] : ccb_) cb(rName{n});
                    ccb_.clear();
                }
            } { io_.connect(); }

    // Get the asio io_context used by this face
    boost::asio::io_context& getIoContext() const noexcept { return ioContext_; }

    constexpr size_t getMaxNdnPacketSize() const noexcept { return 1500 - 40 - 8; } //XXX

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

    // schedule or re-schedule PIT Interest Timeout callback
    void schedITO(PITentry& pe) {
        // if the interest is locally generated, the timeout upcall will generate a new pit
        // entry to replace the one being deleted. Otherwise give the remote peer's replacement
        // interest some extra time to get to us.
        auto lt = pe.i_.lifetime();
        if (! pe.dCb_) lt += 30ms;
        _LOG_DEBUG(format("sched ITO in {} {:x} {} bytes", pe.i_.lifetime(), pe.i_.nonce(), pe.i_.size()));
        pe.timer(timeOut(lt, [this, idat=*pe.idat_] () mutable {
                                auto i = rInterest(idat);
                                _LOG_DEBUG(format("ITO for {:x} {} bytes", i.nonce(), i.size()));
                                pit_.itoCB(i); }
                         )
                );
    }
    // schedule PIT Deferred Entry Delete
    void schedDED(PITentry& pe) {
        if (pe.ded_) return;  // already handled
        pe.ded_ = true;
        if (pe.timer()->expires_after(10ms) <= 0) return; // timer already expired
        pe.timer()->async_wait([this, idat=*pe.idat_](const auto& e) {
                                    if (e == boost::system::errc::success) {
                                        auto i = rInterest(idat);
                                        _LOG_DEBUG(format("DED for {:x} {} bytes", i.nonce(), i.size()));
                                        pit_.itoCB(i);
                                    }
                                });
    }

    void pitErase(PIT::iterator it) {
        if (it->second.timer_) {
            _LOG_DEBUG(format("cancel ITO for {:x} {} bytes", it->second.i_.nonce(), it->second.i_.size()));
            it->second.cancelTimer();
        }
        pit_.erase(it);
    };

    void pitErase(const rInterest& i) { if (auto it = pit_.find(rPrefix(i.name())); pit_.found(it)) pitErase(it); };

    /*
     * Send NDN packet 'pkt' of length 'len' bytes
     */
    void send(const uint8_t* pkt, size_t len) {
        //_LOG_DEBUG(format("send type {:x}: {} bytes", pkt[0], len));
        io_.send(pkt, len);
    }
    void send(const std::vector<uint8_t>& v) { send(v.data(), v.size()); }
    void send(const tlvParser& v) { send(v.data(), v.size()); }

    /*
     * Handle an interest registration.
     * - add the RIT entry
     * - Registration isn't successful until the network is connected.
     *   If not connected yet add the regDone callback to a deferal
     *   list handled on connection complete.
     * - Otherwise just call the regDone CB.
     */
    void addToRIT(const rName& p, InterestCb&& iCb, RegisterCb&& rCb) {
        //_LOG_DEBUG("addToRIT");
        rit_.add(RITentry{p, std::move(iCb)});
        if (cSts_ != CONNECTED) {
            // Call back when connected.  Have to copy prefix & rCB since the
            // backing store of p might go away on our return.
            ccb_.push_back(std::make_pair(p.asVec() ,std::move(rCb)));
            return;
        }
        rCb(p);  // connected and all done
    }

    /*
     * Handle an interest outgoing from app.
     * - if it's already in the pit (from network peer), add the local origin information.
     * - Add it to the pit & dit then send it. Note that interest has to be sent
     *   even though it was multicast to the net to unblock completion callbacks
     *   at the origin. E.g., during cert dist peer sent this interest followed
     *   by pubs and it needs to hear pubs arrived.
     */
    auto express(const rInterest& i, DataCb&& onD, InterestTO&& ito) {
        if (cSts_ != CONNECTED) throw runtime_error("express: not connected");
        auto res = pit_.add(i, std::move(onD), std::move(ito));
        schedITO(res.first->second);
        _LOG_DEBUG(format("send interest {:x}: {} bytes", i.nonce(), i.size()));
        dit_.add(i);
        send(i);    // XXX add time-based supression (maybe using dit or pit)
    }

    /**
     * Handle an interest incoming from the network:
     *  - if it's a dup of a recent interest, ignore it.
     *  - if there's no RIT match, ignore it
     *  - add it to dup interest table.
     *  - add it to PIT then upcall RIT listener (has to be done in
     *    this order so if upcall results in a Data, PIT entry exists).
     */
    void handleInterest(rInterest i) {
        auto [isDup, h] = dit_.dupInterest(i);
        if (isDup) {
            _LOG_DEBUG(format("recv dup interest {:x}: {} bytes", i.nonce(), i.size()));
            return;
        }
        _LOG_DEBUG(format("recv interest {:x}: {} bytes", i.nonce(), i.size()));

        // check RIT first to see if we can handle this interest. If not,
        // ignore it (DON'T add it to the DIT because we might register
        // a handler soon and don't want future matching Interests suppressed).
        auto ri = rit_.findLM(rPrefix(i.name()));
        if (! rit_.found(ri)) { _LOG_INFO("no rit entry"); return; }

        dit_.add(h);    // detect future copies of i as dups

        // add interest to PIT then give it to RIT's listener.
        schedITO(pit_.add(i).first->second);
        ri->second.iCb_(rName{*ri->second.name_}, i);
    }

    /**
     * Invoke unary predicate 'pred' on all pending interests matching prefix 'p'.
     *
     * This is normally used to avoid waiting for the interest re-expression
     * callback when the app has new data to send.
     */
    auto pendingInterests(const rName& p) const noexcept {
        std::vector<rName> vec{};
        pit_.findAll(rPrefix(p), [&vec](const auto& kv) {
                    const auto& [n, pe] = kv;
                    if (pe.fromNet_ && !pe.ded_) vec.emplace_back(pe.i_.name());
                });
        return vec;
    }
            
    //XXX temporary for debugging
    uint32_t hashIBLT(const rName& n) const {
        auto b = n.lastBlk().rest();
        return ndn::CryptoLite::murmurHash3(0x53a1df9a, b.data(), b.size());
    }

    /**
     * Handle an outgoing data:
     * - if it's not in the pit or not marked as 'fromNet', ignore it
     * - otherwise, delete the pit entry then send the packet.
     */
    void send(rData d) {
        //auto pi = pit_.findLM(rPrefix(d.name()));
        auto pi = pit_.find(rPrefix(d.name()));
        if (! pit_.found(pi) || ! pi->second.fromNet_) {
            _LOG_WARN(format("send unsolicited data: {:x} {} bytes", hashIBLT(d.name()), d.size()));
            return;
        }
        _LOG_DEBUG(format("send data for {:x}: {} bytes", pi->second.i_.nonce(), d.size()));
        pitErase(pi);
        send(d.data(), d.size());
    }

    /**
     * Handle an incoming data:
     *  - if it's not in the PIT ignore it (flow balance and dup suppression)
     *  - if there's no app callback, delete the pit entry and ignore it
     *    (data probably satisfied an interest from net)
     *  - otherwise background the pit entry (flow balance) and do the app callback.
     */
    void handleData(rData d) {
        //auto pi = pit_.findLM(rPrefix(d.name()));
        auto pi = pit_.find(rPrefix(d.name()));
        if (! pit_.found(pi)) {
            _LOG_DEBUG(format("recv unsolicited data: {:x} {} bytes", hashIBLT(d.name()), d.size()));
            return;
        }
        _LOG_DEBUG(format("recv data for {:x}: {} bytes", pi->second.i_.nonce(), d.size()));
        if (! pi->second.dCb_) { pitErase(pi); return; }

        // let the PIT entry hang around 'in the background' for a short time
        // to collect additional responses to the interest then delete it.
        _LOG_DEBUG("send data to app");
        auto& pe = pi->second;
        schedDED(pe);
        pe.dCb_(pe.i_, d);
    }

};

}  // namespace ndn

#endif  // DCT_FACE_DIRECT_HPP
