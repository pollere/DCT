#ifndef DCT_FACE_DEFAULT_IF_HPP
#define DCT_FACE_DEFAULT_IF_HPP
/*
 * default_if - return DCT's default interface name
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

#include <net/if.h>
#include <ifaddrs.h>
#ifdef __linux__
#include <linux/if_link.h>
#endif
#include <array>
#include <string>
#include <string_view>

/*
 * Interface flag testing. Candidate interfaces must be:
 *   up, running, broadcast, multicast and NOT loopback, NOT pointToPoint, NOT promiscuous
 */
constexpr int flagsMask {
    IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST | IFF_LOOPBACK | IFF_POINTOPOINT | IFF_PROMISC
};
constexpr int flagsSet { IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST };

static bool better(void* n, void* o) {
    if (! o) return true;
#ifdef __linux__
    const auto& nd = *(rtnl_link_stats*)n;
    const auto& od = *(rtnl_link_stats*)o;
    if (nd.tx_packets > od.tx_packets || nd.rx_packets > od.rx_packets) return true;
#else
    const auto& nd = *(if_data*)n;
    const auto& od = *(if_data*)o;
    if (nd.ifi_imcasts > od.ifi_imcasts || nd.ifi_opackets > od.ifi_opackets) return true;
#endif
    return false;
}

static inline auto defaultIf() {
    // if specified in environment use that interface name
    if (auto ep = getenv("DCT_DEFAULT_IF"); ep) return std::string(ep);

    ifaddrs* ifaList{};
    if (::getifaddrs(&ifaList) < 0) throw runtime_error("error: getifaddrs failed");
    std::string_view bestIf = "none";
    void *bestD{}, *ifd{};
    for (auto ifa = ifaList; ifa; ifa = ifa->ifa_next) {
        if ((ifa->ifa_flags & flagsMask) != flagsSet) continue;
        // When multiple candidate interfaces choose the busiest one.
        // MacOS and linux both supply an ifa entry containing inferface stats,
        // MacOS in an AF_LINK (18) entry and linux in an AF_PACKET (17) entry.
        if (ifa->ifa_data) ifd = ifa->ifa_data;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;
        if (! better(ifd, bestD)) continue;
        bestD = ifd;
        bestIf = ifa->ifa_name;
    }
    auto res = std::string(bestIf);
    freeifaddrs(ifaList);
    return res;
}

static inline auto getIp6Addr(std::string_view ifnm) {
    ifaddrs* ifaList{};
    if (::getifaddrs(&ifaList) < 0) throw runtime_error("error: getifaddrs failed");

    auto ifa = ifaList;
    for (; ifa; ifa = ifa->ifa_next) {
        if (ifnm != ifa->ifa_name) continue;
        if (! ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;
        break;
    }
    if (! ifa) throw runtime_error(format("error: interface {} not found", ifnm));
    auto saddr = *(struct sockaddr_in6*)(ifa->ifa_addr);
    freeifaddrs(ifaList);
    return saddr;
}

#endif // DCT_FACE_DEFAULT_IF_HPP
