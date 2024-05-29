/*
 *  tst_transport <addr> - test low-level transport
 *
 * Copyright (C) 2022 Pollere LLC
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
#include <charconv>
#include <chrono>
#include <string_view>
#include "dct/format.hpp"
#include "dct/face/default-io-context.hpp"
#include "dct/face/transport.hpp"

using namespace dct;

using Timer = boost::asio::system_timer;

using namespace std::literals::chrono_literals;

static int64_t getSysTime() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(now).count();
}

static auto tfmt(auto ts1, auto ts2) {
    auto t = double((int64_t)ts1 - (int64_t)ts2) / 1e3;
    int e{};
    double s{1};
    char suffix{' '};
    auto dt = std::abs(t);
    if (dt != 0.) {
        e = floor(log10(dt) * (1./3.));
        s = pow(10., e * 3);
        if (dt > 100e3) {
            // handle times >100s
            if (dt > 31536000e3) suffix = 'Y';
            else if (dt > 86400e3) suffix = 'D';
            else if (dt > 3600e3) suffix = 'H';
            else suffix = 'M';
        } else if (e < 1) suffix = "munpfa"[-e];
    }
    // fmt's alternate duration format ('#.3') gives 3 digits of precision but
    // puts a zero after the decimal point for values in the range [100,1000).
    auto r = dct::format("{:#.3}", t/s);
    if (r.size() != (t<0?6:5)) r.push_back(suffix);
    else r.back() = suffix;
    return r;
}

static auto tfmt(auto sent) { return tfmt(getSysTime(), sent); }

static dct::Transport* io;
static auto timer = std::unique_ptr<Timer>{};
static auto dat = std::vector<uint64_t>(4, 0);
static int nsend{};
static int burst{1};
static bool periodic{false};
static bool reply{false};
static bool initial{false};

static void doSend() {
    if (nsend <= 0) return;
    if (dat.size() >= 16384/sizeof(dat[0])) dat.pop_back();
    dat.insert(dat.begin(), getSysTime());
    // add a tlv header on the front so testing will work with stream transports
    // the header is 8 bytes of which 2 or 4 are the hdr and the rest become payload.
    auto pkt = dat;
    auto s = dat.size() * sizeof(dat[0]);
    uint64_t hdr{6};
    if (s < 253 - 6) {
        hdr |= (s + 6) << 8;
    } else {
        s += 4;
        hdr |= 253 << 8;
        hdr |= (s & 0xff00) << 8;
        hdr |= (s & 0xff) << 24;
    }
    pkt.insert(pkt.begin(), hdr);
    io->send(pkt);
    if (--nsend <= 0) {
        timer->expires_after(2s);
        timer->async_wait([](const auto&) { exit(0); });
    }
};

static void doSends() { for (int i = burst; --i >= 0; ) doSend(); }

void restartTimer() {
    timer->async_wait([](const auto& e) {
            if (e == boost::system::errc::success) doSends();
            if (nsend <= 0) return;
            timer->expires_after(1s);
            restartTimer();
        });
};

int main(int argc, const char* argv[]) {

    auto addr = "";
    if (argc < 1) {
        dct::print("- usage: {} [-n nsend] [-i|p|r] addr\n", argv[0]);
        exit(1);
    }
    while (argc > 1 && argv[1][0] == '-') {
        ++argv; --argc;
        if (argv[0][1] == 'i') initial = true;
        else if (argv[0][1] == 'p') periodic = true;
        else if (argv[0][1] == 'r') reply = true;
        else if (argv[0][1] == 's') {
            dat.resize(std::stoi(std::string{*++argv}) / sizeof(dat[0]));
            --argc;
        }
        else if (argv[0][1] == 'n') {
            nsend = std::stoi(std::string{*++argv});
            --argc;
        }
        else if (argv[0][1] == 'b') {
            burst = std::stoi(std::string{*++argv});
            --argc;
        }
    }
    if (argc > 1) addr = argv[1];
    boost::asio::io_context& ioc{getDefaultIoContext()};
    timer = std::make_unique<Timer>(ioc, 1s);
    if (nsend == 0 && reply && !periodic && !initial) nsend = 1000000;

    try {
        io = &dct::transport(addr, ioc,
                                [](auto pkt, auto len) {
                                    uint64_t ts;
                                    std::memcpy(&ts, pkt + 8, 8);
                                    dat.insert(dat.begin(), ts);
                                    dat.pop_back();
                                    dct::print("got {} bytes, {} transit, {} rtt\n", len, tfmt(dat[0]), tfmt(dat[1]));
                                    if (reply) doSend();
                                },
                                []{
                                    if (initial) doSends();
                                    if (periodic) restartTimer();
                                });
        io->connect();
        ioc.run();
    } catch (const std::runtime_error& se) { dct::print("error: {}\n", se.what()); }

    exit(0);
}
