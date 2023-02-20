/*
 *  time_hashing <bundle> - time signing & validation of bundle's sigmgr
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
#include <getopt.h>
#include <algorithm>
#include <random>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include "murmurHash3.hpp"
#include "dct/format.hpp"

using namespace dct;

static struct option opts[] {
    {"niter", required_argument, nullptr, 'n'},
    {"maxsize", required_argument, nullptr, 'm'}
};

static auto usage(std::string_view pname) {
    print("- usage: {} [-m maxsize] [-n niter]\n", pname);
    exit(1);
}

static auto timeSM(const auto& rdat, const auto maxsize, const auto niter) {
    //ndn::Data pub{ndn::Name("/test/sigmgr/timing/padMult32.").appendTimestamp(std::chrono::system_clock::now())};
    murmurHash3 mh{};

    auto incr = maxsize / 128;
    if (incr < 1) incr = 1;
    for (auto sz = incr; sz <= maxsize; sz += incr) {
        uint32_t h1, h2;
        auto strt = std::chrono::system_clock::now();
        for (auto i = 0u; i < niter; i++) { h1 = ndn::CryptoLite::murmurHash3(0x53a1df9a, rdat, sz); }
        auto cpy = std::chrono::system_clock::now();
        for (auto i = 0u; i < niter; i++) { h2 = mh(0x53a1df9a, rdat, sz); }
        auto fins = std::chrono::system_clock::now();
        using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
        print("{} : {} {} {}\n", sz, h1 == h2, ticks(cpy - strt)/double(niter), ticks(fins - cpy)/double(niter));
    }
}

int main(int argc, char* const* argv) {
    size_t niter{1024*128};
    size_t maxsize{1024};

    //if (argc < 3) usage(argv[0]);

    for (int c; (c = getopt_long(argc, argv, "m:n:", opts, nullptr)) != -1; ) {
        switch (c) {
            case 'm':
                maxsize = std::stoul(optarg);
                if (maxsize <= 0) usage(argv[0]);
                break;
            case 'n':
                niter = std::stoul(optarg);
                if (niter <= 0) usage(argv[0]);
                break;
        }
    }

    // initialize random number generator and random pub content
    std::minstd_rand m_randGen{};
    std::uniform_int_distribution<uint64_t> m_randDist{};

    std::random_device rd;
    m_randGen.seed(rd());
    std::vector<uint64_t> rdat(maxsize/sizeof(uint64_t));

    std::generate(rdat.begin(), rdat.end(), [&m_randDist,&m_randGen]{return m_randDist(m_randGen);});

    try {
        timeSM((const uint8_t*)rdat.data(), maxsize,  niter);
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    exit(0);
}
