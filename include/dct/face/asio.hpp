#ifndef DCT_FACE_ASIO_HPP
#define DCT_FACE_ASIO_HPP
/*
 * Async I/O transport for a Direct Face
 *
 * Copyright (C) 2021-2 Pollere LLC
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

// XXX boost bug workaround: this should be defined for any c++17 or beyond compiler and is
// *required* for c++20 or beyond since std::result_of is gone.
// Broken in boost 1.77 and earlier
#if BOOST_ASIO_VERSION<102200
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#include <boost/asio.hpp>
#endif

#include <dct/schema/rpacket.hpp>
#include "default-if.hpp"

struct AsIO {
    using onRcv = std::function<void(const uint8_t* pkt, size_t len)>;
    using onConnect = std::function<void()>;

    boost::asio::ip::udp::endpoint listen_;
    boost::asio::ip::udp::endpoint sender_;
    boost::asio::ip::udp::socket rsock_;
    boost::asio::ip::udp::socket tsock_;
    // rcv buffer no smaller than 1500 byte MTU - 40 IPv6 - 8 UDP = 1452 payload
    // but we hope for 9K MTU for local packets.
    std::array<uint8_t, 8192> rcvbuf_;
    onRcv rcb_;
    onConnect ccb_;

    AsIO(std::string_view , boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : rsock_{ioc}, tsock_{ioc}, rcb_{std::move(rcb)}, ccb_{std::move(ccb)} {

        auto dst = boost::asio::ip::make_address_v6(format("ff02::1234%{}", defaultIf()));
        // NFD uses port 56363. Use a different one because NFD doesn't handle multicast well:
        // lack of working dup suppression combined with its Content Store makes it babel.
        listen_ = boost::asio::ip::udp::endpoint(dst, 56362u);
        // multicast requires separate sockets for receive & transmit
        rsock_.open(listen_.protocol());
        rsock_.set_option(boost::asio::ip::v6_only(true));
        rsock_.set_option(boost::asio::ip::udp::socket::reuse_address(true)); // multiple listeners
        rsock_.bind(listen_);
        rsock_.set_option(boost::asio::ip::multicast::join_group(dst));

        tsock_.open(listen_.protocol());
        tsock_.set_option(boost::asio::ip::v6_only(true));
        // If there were only one app using DCT per machine, enabling this would cut down
        // on some dups but the win is small for the problems it can cause. It would be
        // better to fix the kernel to not loopback to the sending process.
        //tsock_.set_option(boost::asio::ip::multicast::enable_loopback(false));
    }

    void connect() {
        // datagram socket 'connects' immediately. handle connect callbacks before first read
        ccb_();
        issueRead();
    }

    void close() {
        rsock_.close();
        tsock_.close();
    }

    /**
     * issue a read for the next packet
     */
    void issueRead() {
        rsock_.async_receive_from(boost::asio::buffer(rcvbuf_), sender_,
                [this](boost::system::error_code ec, std::size_t len) {
                    if (ec) throw runtime_error(format("receive_from failed: {} len {}", ec.message(), len));
                    rcb_(rcvbuf_.data(), len);
                    issueRead();
                });
    }

    static void ehandler(const boost::system::error_code& ec, size_t len) {
        if (ec.failed()) throw runtime_error(format("send_to failed: {} len {}", ec.message(), len));
    }

    /*
     * Send NDN packet 'pkt' of length 'len' bytes
     */
    void send(const uint8_t* pkt, size_t len) {
        if (len > sizeof(rcvbuf_)) throw runtime_error( "send: packet too big");
        tsock_.async_send_to(boost::asio::buffer(pkt, len), listen_, ehandler);
    }
};

#endif  // DCT_FACE_ASIO_HPP
