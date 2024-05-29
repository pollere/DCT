#ifndef WATCHER_HPP
#define WATCHER_HPP
#pragma once
/*
 * Async I/O and UDP6 multicast NDN packet watcher
 *
 * Copyright (C) 2021 Pollere LLC.
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
 *  This is not intended as production code.
 */

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <string_view>

#if 1
// As of Dec 2022, get spurious warnings when include boost asio
// because sprintf in deprecated (on mac os xcode 12+).
// Theses pragmas are to prevent the warning from this.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// XXX boost bug workaround: this should be defined for any c++17 or beyond compiler and is
// *required* for c++20 or beyond since std::result_of is gone.
// Broken in boost 1.77 and earlier
#if BOOST_ASIO_VERSION<102200
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#include "dct/face/default-io-context.hpp"
#include "dct/face/default-if.hpp"
#endif
#pragma GCC diagnostic pop
#endif

namespace dct {

using runtime_error = std::runtime_error;

struct AsIO {
    using onRcv = std::function<void(const uint8_t* pkt, size_t len, uint16_t sport, TimePoint when)>;

    boost::asio::ip::udp::endpoint listen_;
    boost::asio::ip::udp::endpoint sender_; // most recent received packet's sender
    boost::asio::ip::udp::socket rsock_;
    // rcv buffer no smaller than 1500 byte MTU - 40 IPv6 - 8 UDP = 1452 payload
    // but we hope for 9K MTU for local packets.
    std::array<uint8_t, 8192> rcvbuf_;
    onRcv rcb_;

    AsIO(boost::asio::io_context& ioc) : rsock_{ioc} { }

    void connect(const onRcv& rcb) {
        // XXX boost bug (up to at least 1.79) asio/detail/impl/socket_ops.ipp: inet_pton()
        // scope_id is not handled correctly for 'node_local' so we stick it in as a numeric value
        auto ifaddr = getIp6Addr(defaultIf());
        if (ifaddr.sin6_scope_id == 0) ifaddr.sin6_scope_id = if_nametoindex(defaultIf().c_str());
        auto dst = boost::asio::ip::make_address_v6(getenv("DCT_MULTICAST_ADDR")?
                           getenv("DCT_MULTICAST_ADDR") : "ff02::1234");
        dst.scope_id(ifaddr.sin6_scope_id);
        listen_ = boost::asio::ip::udp::endpoint(dst, 56362u);
        // multicast requires separate sockets for receive & transmit
        rsock_.open(listen_.protocol());
        rsock_.set_option(boost::asio::ip::v6_only(true));
        rsock_.set_option(boost::asio::ip::udp::socket::reuse_address(true)); // multiple listeners
        rsock_.bind(listen_);
        rsock_.set_option(boost::asio::ip::multicast::join_group(dst));

        rcb_ = rcb;
        issueRead();
    }

    void close() { rsock_.close(); }

    /**
     * issue a read for the next packet
     */
    void issueRead() {
        rsock_.async_receive_from(boost::asio::buffer(rcvbuf_), sender_,
                [this](boost::system::error_code ec, std::size_t len) {
                    if (ec) throw runtime_error(dct::format("receive_from failed: {} len {}", ec.message(), len));
                    rcb_(rcvbuf_.data(), len, sender_.port(), std::chrono::system_clock::now());
                    issueRead();
                });
    }
};

struct Watcher {
    using pktHandler = AsIO::onRcv;

    pktHandler handle_;
    AsIO aio_{getDefaultIoContext()};

    Watcher(pktHandler h) : handle_{h} { }

    void run() {
        aio_.connect(handle_);
        getDefaultIoContext().run();
    }
};

} // namespace dct

#endif // WATCHER_HPP
