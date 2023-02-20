/*
 * default_interface - print DCT's default interface name to stdout
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

#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
#include <linux/if_link.h>
#endif
#include <span>
#include "dct/format.hpp"
#include "dct/face/default-if.hpp"

using namespace dct;

bool verbose{false};

static void usage(std::string_view pname) {
        print("- usage: {} [-v]\n", pname);
        exit(1);
}


int main(int argc, const char* argv[]) {
    if (argc > 2) usage(argv[0]);
    if (argc == 2) {
        if (std::string_view("-v") != argv[1]) usage(argv[0]);
        verbose = true;
    }
    ifaddrs* ifaList{};
    if (::getifaddrs(&ifaList) < 0) {
        print("- error: getifaddrs failed\n");
        exit(1);
    }
    if (verbose) {
        for (auto ifa = ifaList; ifa; ifa = ifa->ifa_next) {
            //print("{} : {} {:x} {}", ifa->ifa_name, ifa->ifa_addr->sa_family, ifa->ifa_flags, ifa->ifa_data);
            print("{} : {} {:x}", ifa->ifa_name, ifa->ifa_addr->sa_family, ifa->ifa_flags);
            if ((ifa->ifa_flags & flagsMask) == flagsSet) print("*");
            if (ifa->ifa_addr->sa_family == AF_INET6) {
                auto addr = std::span(&((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr.s6_addr[0], 16);
                print("! {:x}", fmt::join(addr, ":"));
            }
            if (ifa->ifa_data) {
#ifdef __linux__
                const rtnl_link_stats& ifd = *(rtnl_link_stats*)ifa->ifa_data;
                print(" in {} out {} multicast {}", ifd.rx_packets, ifd.tx_packets, ifd.multicast);
#else
                const if_data& ifd = *(if_data*)ifa->ifa_data;
                print(" mtu {} in {} out {} min {} mout {}", ifd.ifi_mtu, ifd.ifi_ipackets, ifd.ifi_opackets,
                        ifd.ifi_imcasts, ifd.ifi_omcasts);
#endif
            }
            print("\n");
        }
    }
    std::string_view bestIf = "none";
    void* bestD{}, *ifd{};
    for (auto ifa = ifaList; ifa; ifa = ifa->ifa_next) {
        if ((ifa->ifa_flags & flagsMask) != flagsSet) continue;
        // When multiple candidate interfaces choose the busiest one.
        // MacOS and linux both supply an ifa entry containing inferface stats,
        // MacOS in AF_LINK (18) entry and linux in an AF_PACKET entry.
        if (ifa->ifa_data) ifd = ifa->ifa_data;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;
        if (! better(ifd, bestD)) continue;
        bestD = ifd;
        bestIf = ifa->ifa_name;
    }
    print("{}\n", bestIf);
    exit(0);
}
