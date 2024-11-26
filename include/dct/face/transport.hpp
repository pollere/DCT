#ifndef DCT_FACE_TRANSPORT_HPP
#define DCT_FACE_TRANSPORT_HPP
#pragma once
/*
 * Async I/O transport for a Direct Face
 *
 * Copyright (C) 2021-2 Pollere LLC
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
 *  This is not intended as production code.
 */

#include <cerrno>
#include <charconv>
#include <functional>
#include <invocable.h>
#include <memory>
#include <string>
#include <string_view>
#include <queue>

#include <boost/asio/version.hpp>
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
#endif
#include <boost/asio.hpp>
#pragma GCC diagnostic pop
#else
#include <boost/asio.hpp>
#endif

#include <dct/schema/crpacket.hpp>
#include "default-if.hpp"
#include "default-io-context.hpp"

namespace dct {

namespace asio = boost::asio;
using namespace asio::ip;

struct Transport {
    /*
     * Arrays are used as buffers so their max size has to known a compile time. Most local
     * net media can support 9K MTUs though almost all default to 1500 bytes for WAN
     * interoperability. IPv6 encap requires 40 bytes, UDP requires 8 and TCP requires at
     * least 32 (basic hdr + timestamp option) and 60 is recommended to leave room for
     * SACK blocks for efficient loss recovery. Thus 40+60 = 100 bytes of packet header
     * space are required leaving at least 1400 for payload.
     */
    static constexpr size_t max_pkt_size = 8192;
    using onRcv = std::function<void(const uint8_t* pkt, size_t len)>;
    using onConnect = std::function<void()>;

    // internal send completion callback. This would go away if c++ ever gets 'generics'
    using _sendCb = ofats::any_invocable<void(const boost::system::error_code& ec, size_t)>;

    onRcv rcb_;
    onConnect ccb_;

    Transport(onRcv&& rcb, onConnect&& ccb) : rcb_{std::move(rcb)}, ccb_{std::move(ccb)} { }

    /*
     * these are intended for a particular transport to inform DeftT as to the size of the MTU it
     * exchanges with the system network modules, specifically the space in the MTU available
     * for DeftT PDUs and the corresponding time to send that MTU.
     * The mtu should be in bytes; the tts in ms
     * This is usually quite straightforward but in the case of an interface to system network
     * modules that will be fragmenting the DeftT PDU, it may need to cover transmission of
     * multiple frames.
     * The mtu must be large enough to hold a max size cState and a minimum useful cAdd
     * (pubSize + cAdd name, etc + 80B for AEAD, 107B for EdDSA). Test this is syncps
     */
    virtual constexpr ptrdiff_t mtu() const noexcept = 0;
    virtual constexpr std::chrono::milliseconds tts() const noexcept = 0;
    virtual void connect() = 0;
    virtual void close() = 0;
    virtual void send_pkt(const uint8_t* pkt, size_t len, _sendCb&& cb) = 0;

    virtual constexpr bool unicast() const noexcept { return true; }

    /*
     * semantics of 'send' is that it takes a container (*not* a view), steals
     * its contents and async sends them. Since the contents have to stay around
     * until the send completes, they're stashed in the closure of the completion
     * lambda so they'll be destructed when the async op completes.
     */
    void send(auto&& v) {
        size_t len = v.size() * sizeof(v[0]);
        if (len > max_pkt_size) throw runtime_error( "send: packet too big");
        send_pkt((const uint8_t*)v.data(), len,
                [buf = std::move(v)](const boost::system::error_code& ec, size_t) {
                    if (ec.failed() && ec.value() != ECONNREFUSED)
                        //throw runtime_error(dct::format("send failed: {}", ec.message()));
                        print("send failed: {}", ec.message());
                });
    }
};

struct TransportUdp : Transport {
    udp::endpoint listen_;
    udp::endpoint sender_;  // sender of most recent datagram
    udp::endpoint peer_;    // our peer if connected
    udp::socket sock_;      // socket to peer if connected
    bool isConnected_{false};
    bool didCCB_{false};

    // rcv buffer no smaller than 1500 byte MTU - 40 IPv6 - 8 UDP = 1452 payload
    // but we hope for 9K MTU for local packets.
    std::array<uint8_t, max_pkt_size> rcvbuf_;

    // values should match ifconfig of interface: using 1500 for interface MTU and 1.2ms tts (10Mbps interface)
    // XXX had to remove "final" because of derived LoRa transport
    constexpr ptrdiff_t mtu() const noexcept final  { return 1500 - 40 - 8; }
    constexpr std::chrono::milliseconds tts() const noexcept final  { return std::chrono::milliseconds(1500/(10000/8)); }

    TransportUdp(asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), sock_{ioc} { }
    TransportUdp(uint16_t port, asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), listen_{udp::v6(), port}, sock_{ioc} { }

    void issueRead() {
        sock_.async_receive(asio::buffer(rcvbuf_),
                [this](boost::system::error_code ec, std::size_t len) {
                    if (ec.failed() && ec.value() != ECONNREFUSED)
                            throw runtime_error(dct::format("recv failed: {}", ec.message()));
                    //if (ec.failed()) print("recv failed: {} len {}\n", ec.message(), len);
                    if (len > 0) rcb_(rcvbuf_.data(), len);
                    issueRead();
                });
    }

    void close() {
        boost::system::error_code ec;
        sock_.close(ec);
    }

    void send_pkt(const uint8_t* pkt, size_t len, _sendCb&& cb) {
        sock_.async_send(asio::buffer(pkt, len), std::move(cb));
    }
};

struct TransportMulticast final : TransportUdp {
    udp::socket tsock_;
    udp::endpoint our_;

    constexpr bool unicast() const noexcept { return false; }

    // MESHTEST>0 adds special code to test the automatic peer-to-peer meshing
    // capabilities of DeftT. It does by accumulating a sorted list of all the
    // peer source address and port tuples. Since all peers will construct the
    // same list, self-consistent reachability relationships can be enforced
    // at each peer by some simple 'canHear(peer)' boolean function. For example
    // a linear chain can be created by saying each peer canHear the peers
    // immediately adjacent to it in the list.
#ifndef MESHTEST
#define MESHTEST 0
#endif
#if MESHTEST>0
    using peerID = std::pair<decltype(sender_.address()),decltype(sender_.port())>;
    std::vector<peerID> peerSort_{};
    size_t psid_{};   // this instance's index in peerSort_ 

    auto setLocalPeer() { peerSort_.emplace_back(our_.address(), our_.port()); }

    // a hack for creating topologies on a broadcast media for mesh testing
    // new peer ids are sorted as they arrive; this member records its vector position psid_
    // the sorted list position determines which members are considered in-range
    // returns true for members considered in-range
    bool canHear(const auto& sender) noexcept {
        // locate or place sender within the sorted vector. The vector must
        // already contain this instance so its size must be >0.
        assert(peerSort_.size() > 0);
        peerID s{sender.address(), sender.port()};
        size_t spos = 0;
        while (1) {
            if (s == peerSort_[spos]) break;
            if (s < peerSort_[spos]) {
                peerSort_.insert(peerSort_.begin() + spos, std::move(s));
                if (psid_ >= spos) ++psid_;
                break;
            }
            if (++spos >= peerSort_.size()) {
                peerSort_.push_back(std::move(s));
                break;
            }
        }
        if constexpr (MESHTEST == 1) {
            // this test checks if the sender is adjacent in a linear order
            return (spos == psid_ - 1 || spos == psid_ + 1);
        } else if constexpr (MESHTEST == 2) {
            // this test is for bifurcated topo with two members in both sides
            auto n = peerSort_.size();
            if (n < 3) return true;
            n >>= 1;
            return (psid_ >= n && spos >= n) || (psid_ <= n+1 && spos <= n+1);
        } else {
            return true;
        }
    }
#else // MESHTEST == 0
    auto setLocalPeer() { }
    constexpr bool canHear(const auto&) const noexcept { return true; }
#endif

    TransportMulticast(std::string_view maddr, asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : TransportUdp(ioc, std::move(rcb), std::move(ccb)), tsock_{ioc} {

        // XXX boost bug (up to at least 1.79) asio/detail/impl/socket_ops.ipp: inet_pton()
        // scope_id is not handled correctly for 'node_local' so we stick it in as a numeric value
        auto ifaddr = getIp6Addr(defaultIf());
        auto dst = make_address_v6(maddr);
        if (ifaddr.sin6_scope_id == 0) ifaddr.sin6_scope_id = if_nametoindex(defaultIf().c_str());
        dst.scope_id(ifaddr.sin6_scope_id);
        // NFD uses port 56363. Use a different one because NFD doesn't handle multicast well:
        // lack of working dup suppression combined with its Content Store makes it babble.
        listen_ = udp::endpoint(dst, 56362u);
        // multicast requires separate sockets for receive & transmit
        sock_.open(listen_.protocol());
        sock_.set_option(v6_only(true));
        sock_.set_option(udp::socket::reuse_address(true)); // multiple listeners
        sock_.bind(listen_);
        sock_.set_option(multicast::join_group(dst));

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
        setLocalPeer(); // for mesh testing (if enabled by Makefile)
    }
    TransportMulticast(asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb) :
        TransportMulticast(getenv("DCT_MULTICAST_ADDR")? getenv("DCT_MULTICAST_ADDR") : "ff02::1234",
                            ioc, std::move(rcb), std::move(ccb)) {}

    void issueRead() noexcept {
        sock_.async_receive_from(asio::buffer(rcvbuf_), sender_,
            [this](boost::system::error_code ec, std::size_t len) {
                // multicast loops back packets to the sender so filter them out
                if (!ec && (sender_.port() != our_.port() || sender_.address() != our_.address())) {
                    if (canHear(sender_)) rcb_(rcvbuf_.data(), len);
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
        boost::system::error_code ec;
        sock_.close(ec);
        tsock_.close(ec);
    }

    void send_pkt(const uint8_t* pkt, size_t len, _sendCb&& cb) {
        tsock_.async_send_to(asio::buffer(pkt, len), listen_, std::move(cb));
    }
};

// Active (initiator) side of a unicast UDP association. Has to be given
// the address and port of a passive peer.
struct TransportUdpA final : TransportUdp {

    TransportUdpA(std::string_view host, std::string_view port, asio::io_context& ioc,
            onRcv&& rcb, onConnect&& ccb) : TransportUdp(ioc, std::move(rcb), std::move(ccb)) {
        auto dst = udp::resolver(ioc).resolve(host, port, udp::resolver::query::numeric_service);
        asio::connect(sock_, dst.begin());
    }

    void connect() {
        // Active-side datagram socket 'connects' immediately. Connect callbacks can do initialization
        // needed to handle i/o completions so call them before before doing first read.
        ccb_();
        issueRead();
    }
};

/*
 * Passive side of a unicast UDP association.
 *
 * Logic is similar to passive TCP: Waits for incoming packet to learn address
 * of peer then 'connects' sock_ to peer and expects future packets to come
 * from peer's address and port.
 *
 * If active side restarts for any reason, its source port will change and the
 * 'connection' state on this side will be wrong. Passive side can't initiate a
 * reconnection so anything received from the active side's host but on a
 * different source port is assumed to be a 'reconnect' and the data socket,
 * sock_, is 'connected' to that new endpoint. (XXX Our intent is for the initial
 * packet from the active side to be a QUIC-like DTLS 1.3 0-RTT initial handshake
 * that both cryptographically identifies the peers and establishes an initial
 * shared encryption key for the session. Code for this isn't finished yet.)
 *
 * This code follows "established-over-unconnected" pattern described in
 * https://blog.cloudflare.com/everything-you-ever-wanted-to-know-about-udp-sockets-but-were-afraid-to-ask-part-1/
 */
struct TransportUdpP final : TransportUdp {
    udp::socket acceptor_;

    TransportUdpP(uint16_t port, asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : TransportUdp(port, ioc, std::move(rcb), std::move(ccb)), acceptor_{ioc, listen_} {
        acceptor_.set_option(udp::socket::reuse_address(true));
        sock_.open(listen_.protocol());
        sock_.set_option(udp::socket::reuse_address(true));
    }

    void finishRestart() {
        isConnected_ = true;
        issueRead();
        if (! didCCB_) {
            didCCB_ = true;
            ccb_();
        }
    }

    void startSession() {
        peer_ = sender_;
        boost::system::error_code ec;
        sock_.bind(listen_, ec);
        sock_.connect(peer_); // associate socket with the new peer_
        if (! isConnected_) finishRestart();
    }

    // Passive-side datagram socket waits for peer's packet to find out who it's connected to.
    // If incoming packet is acceptable the socket is connected to that peer, connect & receive
    // callbacks are invoked and the next (normal) read initiated..
    void issueInitialRead() {
        acceptor_.async_receive_from(asio::buffer(rcvbuf_), sender_,
                [this](boost::system::error_code ec, std::size_t len) {
                    if (ec) throw runtime_error(dct::format("receive_from failed: {} len {}", ec.message(), len));
                    startSession();
                    rcb_(rcvbuf_.data(), len);
                    issueInitialRead();
                });
    }

    void connect() { issueInitialRead(); }
};

struct TransportTcp : Transport {
    tcp::socket sock_;
    uint32_t sockId_{0};
    bool isConnected_{false};
    bool didCCB_{false};

    // Since packets aren't 1-1 with app-level send units, the receiving side needs to be aware of
    // the DCT cState/cAdd msg structure and split the incoming byte stream into those units. rcvsb_,
    // a stream buf bigger than the max DCT msg size for this transport instance, is used for this. 
    // Since tcp does 'reliable' sequenced delivery, sends can block waiting for tcp to free up
    // local socket buffer space. sndbuf_ is used to shield the app from this delay but this means
    // an app-level send while sndb_ is occupied is ignored. This should be rare and syncps will
    // repair any loss but if it becomes an issue, a more complex buffering model could address it.
    size_t roff_{0};
    std::array<uint8_t,max_pkt_size*2> rbuf_;

    // TCP is stream-oriented so max transport unit is fungible. Since the connection is shared
    // by multiple collections, larger mtu results in more jitter from head-of-line blocking
    // and less fairness while smaller mtu results in less efficiency due to a higher header
    // to data ratio. DCT's encap cost is ~100 bytes (due almost entirely to signing overhead -
    // 64 bytes of signature plus 32 bytes of key locator) so an 8K mtu results in 99% efficiency
    // with 65ms worst-case jitter on a 1Mbps backhaul.
    constexpr ptrdiff_t mtu() const noexcept final { return max_pkt_size - 128; }
    constexpr std::chrono::milliseconds tts() const noexcept final  { return std::chrono::milliseconds(1500/(1000/8)); }

    // Outgoing packet queue
    std::queue<ofats::any_invocable<void()>> outqueue_;
    // Maximum number of packets to keep in outgoing queue.
    // This number should not be too largem, otherwise the queue will take forever to flush
    // after a network partition that does not cause a TCP reset.
    static constexpr size_t outqueue_max_ = 128;

    TransportTcp(asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb)
        : Transport(std::move(rcb), std::move(ccb)), sock_{ioc} { }

    void close() {
        dct::log(L_INFO)("TransportTcp::close sock={}", sockId_);
        roff_ = 0;
        isConnected_ = false;
        sockId_++;
        while (!outqueue_.empty()) outqueue_.pop(); // clear
        boost::system::error_code ec;
        sock_.set_option(asio::socket_base::linger{false,0}, ec);
        sock_.close(ec);
    }

    void doAfter(std::chrono::milliseconds delay, auto cb) {
        using Timer = boost::asio::system_timer;
        auto timer = std::make_unique<Timer>(sock_.get_executor(), delay);
        timer->async_wait([t=std::move(timer),cb=std::move(cb)](const auto& e) { if (e == boost::system::errc::success) cb(); });
    }

    virtual void restart() = 0;

    void finishRestart() {
        dct::log(L_INFO)("TransportTcp::connected sock={}", sockId_);
        isConnected_ = true;
        issueRead();
        if (! didCCB_) {
            didCCB_ = true;
            ccb_();
        }
    }

    // check that the first byte of buffer 'd' is tlv type cState or cAdd and it plus the
    // tlv hdr fit in the max_pkt_size. Return the total tlv size if so and 0 otherwise.
    static constexpr auto tlvLength(const uint8_t* d) {
        if ((d[0] != 5 && d[0] != 6) || d[1] > 253) return 0ul;

        size_t l = d[1] == 253?  4ul + (d[2] << 8) + d[3] : 2ul + d[1];
        if (l > max_pkt_size) l = 0;
        return l;
    }

    void issueRead() {
        if (! isConnected_) return;
        sock_.async_read_some(asio::buffer(rbuf_) + roff_,
            [this, sockId=sockId_](const boost::system::error_code& ec, std::size_t rdlen) {
                if (!isConnected_ || sockId != sockId_) return; // connection changed

                if (ec) {
                    dct::log(L_WARN)("TransportTcp::read failed: {}", ec.message());
                    restart();
                    return;
                }
                const auto totlen = roff_ + rdlen;
                auto len = totlen;
                const uint8_t* d = rbuf_.data();
                while (len > 4) {
                    // there's enough data to get tlv type and length
                    const auto l = tlvLength(d);
                    if (l == 0) { // invalid TLV - restart connection
                        dct::log(L_ERROR)( "TransportTcp::read got invalid TLV, l={}", l);
                        restart();
                        return;
                    }
                    if (l > len) break; // don't have complete TLV
                    rcb_(d, l);
                    d += l;
                    len -= l;
                }
                if (totlen > len) {
                    // copy down any leftover tlv frag
                    if (len > 0) std::memmove(rbuf_.data(), rbuf_.data() + totlen - len, len);
                    roff_ = len;
                }
                issueRead();
            });
    }

    void outqueue_continue() {
        if (!outqueue_.empty()) outqueue_.pop();
        if (!outqueue_.empty()) outqueue_.front()();
    }

    void send_pkt(const uint8_t* pkt, size_t len, _sendCb&& cb) {
        if (! isConnected_) return;
        if (outqueue_.size() >= outqueue_max_) return;

        // It is likely pointless to send anything that has been queued
        // for too long; just skip these packets to make way for new ones
        auto expiry = std::chrono::system_clock::now() + std::chrono::seconds(6);

        outqueue_.push([this, pkt, len, cb = std::move(cb), expiry]() {
            if (expiry < std::chrono::system_clock::now()) return outqueue_continue();
            send_pkt_internal(pkt, len, cb);
        });
        if (outqueue_.size() == 1) outqueue_.front()();
    }

    void send_pkt_internal(const uint8_t* pkt, size_t len, const _sendCb& cb) {
        if (! isConnected_) return;
        asio::async_write(sock_, asio::buffer(pkt, len),
                            [this, len, &cb, sockId=sockId_](const boost::system::error_code& ec, std::size_t sent) {
                                if (!isConnected_ || sockId != sockId_) return; // connection changed

                                if (ec.failed()) {
                                    dct::log(L_WARN)("TransportTcp::write failed: {} ({})", ec.message(), ec.value());
                                    switch (ec.value()) {
                                        default:
                                            // throw std::runtime_error(dct::format("send failed: {}", ec.message()));

                                        case EPIPE: case ECONNRESET: case ECANCELED: case ETIMEDOUT:
                                            restart(); // try to reconnect
                                            return;
                                    }
                                    /*NotReached*/
                                }
                                if (sent < len) dct::log(L_TRACE)("TransportTcp::send batch: sent {} of {}", sent, len);
                                else outqueue_continue();
                            });
    }
};

// Active (initiator) side of a unicast TCP association. Needs the address and port of a passive peer.
struct TransportTcpA final : TransportTcp {
    tcp::endpoint peer_{};

    void on_connect(const boost::system::error_code& ec) {
        if (ec.failed()) {
            dct::log(L_WARN)("TransportTcpA tcp failed to connect to {}: {} ({})",
                     peer_.address().to_string(), ec.message(), ec.value());
            return doAfter(10s, [this](){ restart(); }); // prevent log spam
        }
        finishRestart();
    }

    void restart() {
        close();
        doAfter(100ms, [this](){
                           sock_.async_connect(peer_, [this](const boost::system::error_code& ec){ on_connect(ec); });
                        });
    }

    TransportTcpA(std::string_view host, std::string_view port, asio::io_context& ioc,
            onRcv&& rcb, onConnect&& ccb) : TransportTcp(ioc, std::move(rcb), std::move(ccb)) {
        boost::system::error_code ec{};
        auto dst = tcp::resolver(ioc).resolve(host, port, tcp::resolver::query::numeric_service, ec);
        if (ec.failed()) throw runtime_error(dct::format("resolve {} failed: {}", host, ec.message()));
        peer_ = dst.begin()->endpoint(); //XXX maybe try entire list?
    }

    void connect() {
        //asio::async_connect(sock_, peer_, [this](auto ec, auto ep){ on_connect(ec, ep); });
        sock_.async_connect(peer_, [this](auto ec){ on_connect(ec); });
    }
};

// Passive side of a unicast TCP association. Waits for incoming packet to learn address of peer.
struct TransportTcpP final : TransportTcp {
    tcp::endpoint listen_;
    tcp::acceptor acceptor_;

    void startSession(tcp::socket& socket) {
        sock_ = std::move(socket);
        boost::system::error_code ec;
        sock_.set_option(asio::socket_base::linger{false,0}, ec);
        finishRestart();
    }

    void doAccept() {
        acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
            if (ec.failed()) {
                dct::print("tcp accept failed: {}", ec.message());
                throw std::runtime_error(dct::format("accept failed: {}", ec.message()));
            }
            startSession(socket);;
        });
    }

    void restart() {
        close();
        doAccept();
    }

    TransportTcpP(uint16_t port, asio::io_context& ioc, onRcv&& rcb, onConnect&& ccb) :
        TransportTcp(ioc, std::move(rcb), std::move(ccb)), listen_{tcp::v6(), port}, acceptor_{ioc, listen_} { }

    void connect() { doAccept(); }
};

/**
 * Return a transport connection as specified by 'addr'.
 *
 * Forms for 'addr' are;
 *
 *  null      - IP6 multicast connection on default interface
 *
 *  port      - (passive) unicast connection listening on 'port'. Port
 *              must be a non-zero integer string or an error is thrown.
 *
 *  host:port - (active) unicast connection to given host and port.
 *              Host may specified by name or address, port must be a
 *              non-zero integer string.
 *
 * The last two forms can be preceded by an optional "udp:" or "tcp:" protocol
 * specifier. "udp:" is assumed if this is missing.
 */
//XXX should be constexpr but gcc 11.2 complains
[[maybe_unused]]
static Transport& transport(std::string_view addr, asio::io_context& ioc,
                            Transport::onRcv&& rcb, Transport::onConnect&& ccb) {
    if (addr.size() == 0) return *new TransportMulticast(ioc, std::move(rcb), std::move(ccb));
    if (addr.starts_with("ff01:") || addr.starts_with("ff02:")) {
        return *new TransportMulticast(addr, ioc, std::move(rcb), std::move(ccb));
    }

    bool isUdp{true};
    if (addr.starts_with("tcp:") || addr.starts_with("udp:")) {
        isUdp = addr.starts_with("udp:");
        addr = addr.substr(4);
    }
    // since ipv6 numeric addresses use colons, the last colon delimits the port number
    auto sep = addr.rfind(':');
    if (sep == addr.npos) {
        uint16_t port{};
        std::from_chars(addr.data(), addr.data()+addr.size(), port);
        if (port == 0) throw runtime_error(dct::format("invalid listen port {}", addr));
        if (!isUdp) return *new TransportTcpP(port, ioc, std::move(rcb), std::move(ccb));
        return *new TransportUdpP(port, ioc, std::move(rcb), std::move(ccb));
    }
    if (!isUdp) return *new TransportTcpA(addr.substr(0, sep), addr.substr(sep+1), ioc, std::move(rcb), std::move(ccb));
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
