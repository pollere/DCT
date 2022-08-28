/*
 * dctwatch - real-time printing of multicast NDN packets
 *
 * dctwatch passively listens to the default DCT network interface and prints
 * the contents of each NDN packet it sees. There are two output formats,
 * 'compact' (default) and 'full' ('-f' flag). The compact format prints one
 * line packet descriptions like:
 *   ...
 *   17:38:21.170  6.53M  I  59484  136 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   17:38:21.170  189.u  D  63441  416 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   ...
 * This example shows a 136 byte Interest expressed from src port 59484
 * arriving at time 17:38 after 6.53 Minutes of link idle time.  (Note:
 * suffix 'M' = Minutes; 'm' = milliseconds.) Then, 189us later, a
 * 416 byte Data from src port 63441 satisfies that Interest.
 *
 * The fields are: (1) the packet capture time, (2) time delta since last packet,
 * (3) packet type, I (Interest) or D (Data), (4) sender's UDP source port, (5) packet
 * length in bytes and (6) packet's Name TLV (components containing non-printing characters
 * are shown in hex and '^' is prepended to indicate this. Hex components longer than
 * 10 bytes are truncated to 8 bytes and '..' is appended to indicate this).
 *
 * The 'full' output format adds a dump of the contents of every TLV in the packet
 * after the one line summary. For example, the Interest above's full output was:
 *
 *   17:38:21.170  6.53M  I  59484  136 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   5 (Interest) size 134:
 *   | 7 (Name) size 118:
 *   | | 8 (Generic) size 8:  localnet
 *   | | 8 (Generic) size 8:  3346 962d d3a3 6377
 *   | | 8 (Generic) size 4:  cert
 *   | | 8 (Generic) size 90: 8901 6d09 5519 cc52  d566 8a01 6d09 5519  cc52 d566 8b01 1f60  0b8a f9d3 b024 8a01
 *   | |                      10fa 18b2 3f00 0366  9001 10fa 18b2 3f00  0366 8301 6d09 5519  cc52 d566 8d01 1f60
 *   | |                      0b8a f9d3 b024 8d01  10fa 18b2 3f00 0366  8d01 1f60 0b8a f9d3  b024
 *   | 33 (CanBePrefix) size 0:  
 *   | 18 (MustBeFresh) size 0:  
 *   | 10 (Nonce) size 4:  9ad2 8c04
 *   | 12 (InterestLifetime) size 2:  4789
 *
 * Each TLV's type and size are printed followed by a ':'. If the TLV *doesn't* contain other TLVs,
 * its content is printed after the ':'. Otherwise, a new line is started, the indent level is
 * increased and the nested TLV(s) are printed, then the indent level is restored. (The vertical
 * bars on the left show how deeply each TLV is nested.)
 *
 * In addition to the two format selection flags, three flags control what
 * packet types are printed: '-d' prints only Datas, '-i' prints only Interests,
 * '-a' (the default) prints all types.
 *
 * A non-flag argument is interpreted as an ECMAScript (ECMA-262) regular expression
 * filter on the printed format of the packet Name. For example:
 *
 *   dctwatch pubs                  only prints packets for the "pubs" sync collection
 *   dctwatch 'cert|keys'           prints packets for the cert or keys collections
 *   dctwatch '\^3346962dd3a36377'  prints packets associated with a particular trust schema
 *
 * (In the last example, note that the characters ^ $ \ . * + ? ( ) [ ] { } | are
 * meta-characters in ECMAScript REs and need to be escaped with \ to be matched.)
 *
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
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <chrono>
#include <cmath>
#include <iostream>
#include <regex>
#include <sstream>

#include "dct/format.hpp"
#include "dct/schema/rpacket.hpp"
#include "dissect.hpp"
#include "watcher.hpp"

using namespace std::literals;

static enum oFmt { compact, names, full } ofmt{compact};
static bool doData = true;
static bool doInterest = true;
static bool hashIBLT = false;
static bool filtering = false;
static std::regex filter{};

static Dissect di;

using durmilli = std::chrono::duration<double, std::milli>;
using durmicro = std::chrono::duration<double, std::micro>;

static auto tfmt(durmilli now) {
    static durmilli last{};
    if (last == decltype(last)::zero()) last = now;
    auto dt = (now - last).count();
    last = now;
    int e{};
    double s{1};
    char suffix{' '};
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
    auto r = format("{:#.3}", dt/s);
    if (r.size() != 5) r.push_back(suffix);
    else r.back() = suffix;
    return r;
}

static auto compactPrint(const uint8_t* d, size_t s, uint16_t sport) {
    auto now = std::chrono::system_clock::now();
    rName n{};
    const char* ptype{};
    switch (d[0]) {
        default:
            return ptype;
        case 5:
            try { n = rInterest(d, s).name(); } catch (const std::exception& e) { return ptype; }
            ptype = "St";
            break;
        case 6:
            try { n = rData(d, s).name(); } catch (const std::exception& e) { return ptype; }
            ptype = "Ad";
            break;
    }
    //XXX work-around for fmt chrono problems - want to print seconds to ms resolution but
    // fmt will only do this for durations with a floating pt rep. But chrono prints hours
    // for durations as if they were gmtime but we want localtime so we do H & M from the
    // sys time point and S from it converted to a duration. Ick.
    auto now2 = durmicro(now.time_since_epoch());
    print("{:%H:%M:}{:%S}  {}  {}  {:5} {:4}", now, now2, tfmt(now2), ptype, sport, s);
    if (hashIBLT) print("  {:08x} ", (uint32_t)std::hash<tlvParser>{}(n));
    print(" {}\n", n);
    return ptype;
}

static void fullPrint(const uint8_t* d, size_t s, uint16_t sport) {
    if (! compactPrint(d, s, sport)) return;
    di.dissect(std::cout, tlvParser(d, s));
    std::cout << '\n';
}

static void namePrint(const uint8_t* d, size_t s, uint16_t sport) {
    compactPrint(d, s, sport);
    if (d[0] != 6) return;

    auto rd = rData(d, s);
    if (rd.sigType() == 7/*AEAD*/) return;

    for (const auto c : rd.content()) {
        if (! c.isType(6)) return;
        rData p{c};
        if (! p.valid()) return;
        print(" | {}\n", p.name());
    }
}

static void handlePkt(const uint8_t* d, size_t s, uint16_t sport) {
    if (!doInterest && d[0] == 5) return;
    if (!doData && d[0] == 6) return;
    if (filtering) {
        auto n = d[0] == 5?  rInterest(d, s).name() : rData(d, s).name();
        if (! std::regex_search(format("{}", n), filter)) return;
    }
    switch (ofmt) {
        case oFmt::compact: compactPrint(d, s, sport); return;
        case oFmt::names: namePrint(d, s, sport); return;
        case oFmt::full: fullPrint(d, s, sport); return;
    }
}

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [-f|c|n] [-d|i|a] [regex]>\n";
    exit(1);
}

int main(int argc, char* argv[])
{
    const char* pname = argv[0];
    while (--argc > 0 && **++argv == '-') {
        switch (argv[0][1]) {
            case 'a': doData = true;  doInterest = true; break;
            case 'c': ofmt = oFmt::compact; break;
            case 'd': doData = true;  doInterest = false; break;
            case 'f': ofmt = oFmt::full; break;
            case 'h': hashIBLT = true; break;
            case 'i': doData = false; doInterest = true; break;
            case 'n': ofmt = oFmt::names; break;

            default: usage(pname);
        }
    }
    if (argc > 1) usage(pname);
    if (argc == 1) {
        filtering = true;
        filter = std::regex(argv[0]);
    }
    Watcher watcher(handlePkt);

    watcher.run();
    exit(0);
}
