//#include <iomanip>
#include <iostream>
//#include <sstream>

#include "dct/format.hpp"
#include "dctprint.hpp"

#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::FileSniffer;
using Tins::Packet;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::TCPIP::Stream;

static TimePoint last_packet_time{};

static constexpr auto tlvLength(const auto& d) {
    if ((d[0] != 5 && d[0] != 6) || d[1] > 253) return 0ul;

    size_t l = d[1] == 253?  4ul + (d[2] << 8) + d[3] : 2ul + d[1];
    if (l > 8192) l = 0;
    return l;
}

static void new_tcp_data(Stream& s, bool isClient) {
    const auto& dat = isClient? s.client_payload() : s.server_payload();
    if (dat.size() == 0) return;

    const auto p = isClient? s.client_port() : s.server_port();
    auto len = dat.size();
    const uint8_t* d = dat.data();
    while (len > 4) {
        // there's enough data to get tlv type and length
        const auto l = tlvLength(d);
        if (l == 0) { // invalid TLV
            // probably gap in data - need to find start of next DCT PDU
            //XXX restart();
            print(std::cerr, "invalid tlv sz {} off {} typ {}\n", dat.size(), d - dat.data(), d[0]);
            return;
        }
        if (l > len) break; // don't have complete TLV
        handlePkt(d, l, p, last_packet_time);
        d += l;
        len -= l;
    }
    //XXX PDU split across TCP buffers - need to put it back together
    if (len > 0) print(std::cerr, "frag {} from size {}, off {}\n", len, dat.size(), d - dat.data());
}

static void on_new_connection(Stream& s) {
    if (s.is_partial_stream()) {
        // We found a partial stream. This means this connection/stream had
        // been established before we started capturing traffic.
        //
        // In this case, we need to allow for the stream to catch up, as we
        // may have just captured an out of order packet and if we keep waiting
        // for the holes to be filled, we may end up waiting forever.
        //
        // Calling enable_recovery_mode will skip out of order packets that
        // fall withing the range of the given window size.
        // See Stream::enable_recover_mode for more information
        s.enable_recovery_mode(64 * 1024);
    }
    s.client_data_callback([](Stream& s) { new_tcp_data(s, true); });
    s.server_data_callback([](Stream& s) { new_tcp_data(s, false); });
}

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [-f|c|n] [-d|s|a] file port [regex]\n";
    exit(1);
}

int main(int argc, char* argv[])
{
    const char* pname = argv[0];
    while (--argc > 0 && **++argv == '-') {
        switch (argv[0][1]) {
            case 'a': doData = true;  doState = true; break;
            case 'c': ofmt = oFmt::compact; break;
            case 'd': doData = true;  doState = false; break;
            case 'f': ofmt = oFmt::full; break;
            case 'h': hashIBLT = true; break;
            case 'n': ofmt = oFmt::names; break;
            case 's': doData = false; doState = true; break;

            default: usage(pname);
        }
    }
    if (argc < 2) usage(pname);

    const char* file = *argv++; --argc;
    const char* port = *argv++; --argc;

    if (argc == 1) {
        filtering = true;
        filter = std::regex(argv[0]);
    }

    try {
        // Construct the sniffer configuration object
        SnifferConfiguration config;

        // Only capture TCP traffic sent from/to the given port
        config.set_filter(dct::format("tcp port {}", port));

        // Construct the sniffer we'll use
        //Sniffer sniffer(argv[1], config);
        FileSniffer sniffer(file, config);

        StreamFollower f;

        // We just need to specify the callback to be executed when a new 
        // stream is captured. In this stream, you should define which callbacks
        // will be executed whenever new data is sent on that stream 
        // (see on_new_connection)
        f.new_stream_callback(&on_new_connection);

        // Allow following partial TCP streams (e.g. streams that were
        // open before the sniffer started running)
        f.follow_partial_streams(true);

        // Now start capturing. Every time there's a new packet, call 
        // follower.process_packet
        sniffer.sniff_loop([&f](Packet& p) {
            last_packet_time = TimePoint(p.timestamp());
            f.process_packet(p);
            return true;
        });
    } catch (std::exception& ex) {
        //cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}
