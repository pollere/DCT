#ifndef DCT_FACE_TRANSPORT_HPP
#define DCT_FACE_TRANSPORT_HPP
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

#include <charconv>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

// XXX boost bug workaround: this should be defined for any c++17 or beyond compiler and is
// *required* for c++20 or beyond since std::result_of is gone.
// Broken in boost 1.77 and earlier
#if BOOST_ASIO_VERSION<102200
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#include <boost/asio.hpp>
#endif

#include <dct/schema/rpacket.hpp>
#include "default-if.hpp"
#include "default-io-context.hpp"

namespace dct {
    using namespace boost::asio::ip;

struct Transport {
    using onRcv = std::function<void(const uint8_t* pkt, size_t len)>;
    using onConnect = std::function<void()>;
    //
    // rcv buffer no smaller than 1500 byte MTU - 40 IPv6 - 8 UDP = 1452 payload
    // but we hope for 9K MTU for local packets.
    std::array<uint8_t, 8192> rcvbuf_;
    onRcv rcb_;
    onConnect ccb_;

    Transport(onRcv&& rcb, onConnect&& ccb) : rcb_{std::move(rcb)}, ccb_{std::move(ccb)} { }

    virtual void connect() = 0;
    virtual void send(const uint8_t* pkt, size_t len) = 0;
    virtual void close() = 0;

    static void ehandler(const boost::system::error_code& ec, size_t len) {
        if (ec.failed() && ec.value() != 61) // ECONREFUSED
            throw runtime_error(format("send_to failed: {} len {}", ec.message(), len));
    }
};

struct TransportMulticast final : Transport {
    udp::socket rsock_;
    udp::socket tsock_;
    udp::endpoint listen_;
    udp::endpoint our_;
    udp::endpoint sender_;

    TransportMulticast(std::string_view maddr, boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), rsock_{ioc}, tsock_{ioc} {

        // XXX boost bug (up to at least 1.79) asio/detail/impl/socket_ops.ipp: inet_pton()
        // scope_id is not handled correctly for 'node_local' so we stick it in as a numeric value
        auto ifaddr = getIp6Addr(defaultIf());
        auto dst = make_address_v6(maddr);
        dst.scope_id(ifaddr.sin6_scope_id);
        // NFD uses port 56363. Use a different one because NFD doesn't handle multicast well:
        // lack of working dup suppression combined with its Content Store makes it babel.
        listen_ = udp::endpoint(dst, 56362u);
        // multicast requires separate sockets for receive & transmit
        rsock_.open(listen_.protocol());
        rsock_.set_option(v6_only(true));
        rsock_.set_option(udp::socket::reuse_address(true)); // multiple listeners
        rsock_.bind(listen_);
        rsock_.set_option(multicast::join_group(dst));

        tsock_.open(listen_.protocol());
        tsock_.set_option(v6_only(true));
        auto a =  address_v6(std::to_array(ifaddr.sin6_addr.s6_addr));
        if (ifaddr.sin6_addr.s6_addr[0] == 0xfe) a.scope_id(ifaddr.sin6_scope_id);
        tsock_.bind(udp::endpoint(a, 0));
        our_ = tsock_.local_endpoint();
        // If there were only one app using DCT per machine, disabling loopback would cut
        // down on some dups but the win is small for the problems it can cause. It would be
        // better to fix the kernel to not loopback to the sending process.
        //tsock_.set_option(multicast::enable_loopback(false));
    }
    TransportMulticast(boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb) :
        TransportMulticast(getenv("DCT_LOCALHOST_MULTICAST")? "ff01::1234":"ff02::1234",
                            ioc, std::move(rcb), std::move(ccb)) {}

    void issueRead() noexcept {
        rsock_.async_receive_from(boost::asio::buffer(rcvbuf_), sender_,
            [this](boost::system::error_code ec, std::size_t len) {
                // multicast loops back packets to the sender so filter them out
                if (!ec && (sender_.port() != our_.port() || sender_.address() != our_.address())) {
                    rcb_(rcvbuf_.data(), len);
                }
                issueRead();
            });
    }

    void connect() {
        // datagram socket 'connects' immediately. Connect callbacks can do initialization
        // needed to handle i/o completions so call them before before doing first read.
        ccb_();
        issueRead();
    }

    void close() {
        rsock_.close();
        tsock_.close();
    }

    void send(const uint8_t* pkt, size_t len) {
        if (len > sizeof(rcvbuf_)) throw runtime_error( "send: packet too big");
        tsock_.async_send_to(boost::asio::buffer(pkt, len), listen_, ehandler);
    }
};

struct TransportUdp : Transport {
    udp::endpoint listen_;
    udp::endpoint sender_;
    udp::socket sock_;

    TransportUdp(boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), sock_{ioc} { }
    TransportUdp(uint16_t port, boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), listen_{udp::v6(), port}, sock_{ioc, listen_} { }

    void issueRead() {
        sock_.async_receive(boost::asio::buffer(rcvbuf_),
                [this](boost::system::error_code ec, std::size_t len) {
                    if (!ec && len > 0) rcb_(rcvbuf_.data(), len);
                    issueRead();
                });
    }

    void close() final { sock_.close(); }

    void send(const uint8_t* pkt, size_t len) final {
        if (len > sizeof(rcvbuf_)) throw runtime_error( "send: packet too big");
        sock_.async_send(boost::asio::buffer(pkt, len), ehandler);
    }
};

// Active (initiator) side of a unicast UDP association. Has to be given
// the address and port of a passive peer.
struct TransportUdpA final : TransportUdp {

    TransportUdpA(std::string_view host, std::string_view port, boost::asio::io_context& ioc,
            onRcv&& rcb, onConnect&& ccb) : TransportUdp(ioc, std::move(rcb), std::move(ccb)) {
        auto dst = udp::resolver(ioc).resolve(host, port, udp::resolver::query::numeric_service);
        boost::asio::connect(sock_, dst.begin());
    }

    void connect() {
        // Active-side datagram socket 'connects' immediately. Connect callbacks can do initialization
        // needed to handle i/o completions so call them before before doing first read.
        ccb_();
        issueRead();
    }
};

// Passive side of a unicast UDP association. Waits for incoming packet to learn address of peer.
struct TransportUdpP final : TransportUdp {

    TransportUdpP(uint16_t port, boost::asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : TransportUdp(port, ioc, std::move(rcb), std::move(ccb)) { }

    // Passive-side datagram socket waits for peer's packet to find out who it's connected to.
    // If incoming packet is acceptable the socket is connected to that peer, connect & receive
    // callbacks are invoked and the next (normal) read initiated..
    void issueInitialRead() {
        sock_.async_receive_from(boost::asio::buffer(rcvbuf_), sender_,
                [this](boost::system::error_code ec, std::size_t len) {
                    if (ec) throw runtime_error(format("receive_from failed: {} len {}", ec.message(), len));
                    sock_.connect(sender_);
                    ccb_();
                    rcb_(rcvbuf_.data(), len);
                    issueRead();
                });
    }

    void connect() { issueInitialRead(); }
};

/**
 * Return a transport connection as specified by 'addr'.
 *
 * Forms for 'addr' are;
 *
 *  null      - IP6 multicast connection on default interface
 *
 *  port      - (passive) unicast UDP connection listening on 'port'. Port
 *              must be a non-zero integer string or an error is thrown.
 *
 *  host:port - (active) unicast UDP connection to given host and port.
 *              Host may specified by name or address, port must be a
 *              non-zero integer string.
 */
//XXX should be constexpr but gcc 11.2 complains
[[maybe_unused]]
static Transport& transport(std::string_view addr, boost::asio::io_context& ioc,
                            Transport::onRcv&& rcb, Transport::onConnect&& ccb) {
    if (addr.size() == 0) return *new TransportMulticast(ioc, std::move(rcb), std::move(ccb));

    auto sep = addr.find(':');
    if (sep == addr.npos) {
        uint16_t port{};
        std::from_chars(addr.data(), addr.data()+addr.size(), port);
        if (port == 0) throw runtime_error(format("invalid Udp listen port {}", addr));
        return *new TransportUdpP(port, ioc, std::move(rcb), std::move(ccb));
    }
    return *new TransportUdpA(addr.substr(0, sep), addr.substr(sep+1), ioc, std::move(rcb), std::move(ccb));
}

[[maybe_unused]]
static Transport& transport(std::string_view addr, Transport::onRcv&& rcb, Transport::onConnect&& ccb) {
    return transport(addr, getDefaultIoContext(), std::move(rcb), std::move(ccb));
}

[[maybe_unused]]
static Transport& transport(Transport::onRcv&& rcb, Transport::onConnect&& ccb) {
    return *new TransportMulticast(getDefaultIoContext(), std::move(rcb), std::move(ccb));
}

} // namespace dct

#endif  // DCT_FACE_TRANSPORT_HPP
