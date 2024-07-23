/*
 * dctwatch - real-time printing of multicast DCT packets
 *
 * dctwatch passively listens to the default DCT network interface and prints
 * the contents of each DCT packet it sees. There are two output formats,
 * 'compact' (default) and 'full' ('-f' flag). The compact format prints one
 * line packet descriptions like:
 *   ...
 *   17:38:21.170  6.53M  St  59484  136 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   17:38:21.170  189.u  Ad  63441  416 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   ...
 * This example shows a 136 byte cState expressed from src port 59484
 * arriving at time 17:38 after 6.53 Minutes of link idle time.  (Note:
 * suffix 'M' = Minutes; 'm' = milliseconds.) Then, 189us later, a
 * 416 byte cAdd from src port 63441 satisfies that Interest.
 *
 * The fields are: (1) the packet capture time, (2) time delta since last packet,
 * (3) packet type, St (cState) or Ad (cAdd), (4) sender's UDP source port, (5) packet
 * length in bytes and (6) packet's Name TLV (components containing non-printing characters
 * are shown in hex and '^' is prepended to indicate this. Hex components longer than
 * 10 bytes are truncated to 8 bytes and '..' is appended to indicate this).
 *
 * The 'full' output format adds a dump of the contents of every TLV in the packet
 * after the one line summary. For example, the Interest above's full output was:
 *
 *   17:38:21.170  6.53M  St  59484  136 /localnet/^3346962dd3a36377/cert/^89016d095519cc52..
 *   5 (cState) size 134:
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
 * Copyright (C) 2021-3 Pollere LLC
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

#include <csignal>

#include "dctprint.hpp"
#include "watcher.hpp"

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [-f|c|n] [-d|s|a] [regex]>\n";
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
            case 'h': hashIBLT = !hashIBLT; break;
            case 'n': ofmt = oFmt::names; break;
            case 's': doData = false; doState = true; break;

            default: usage(pname);
        }
    }
    if (argc > 1) usage(pname);
    if (argc == 1) {
        filtering = true;
        filter = std::regex(argv[0]);
    }
    std::signal(SIGINT, [](int /*sig*/){ std::exit(1); });
    Watcher watcher(handlePkt);
    watcher.run();
    exit(0);
}
