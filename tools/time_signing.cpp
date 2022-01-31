/*
 *  time_signing <bundle> - time signing & validation of bundle's sigmgr
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
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */
#include <getopt.h>
#include <algorithm>
#include <random>
#include "dct/format.hpp"
#include "dct/schema/dct_model.hpp"

static struct option opts[] {
    {"pub", required_argument, nullptr, 'p'},
    {"wire", required_argument, nullptr, 'w'},
    {"type", required_argument, nullptr, 't'},
    {"niter", required_argument, nullptr, 'n'},
    {"maxsize", required_argument, nullptr, 'm'}
};

static auto usage(std::string_view pname) {
    print("- usage: {} [-m maxsize] [-n niter] -p bundle | -w bundle | -t type\n", pname);
    exit(1);
}

static auto makeAEADkey() {
    std::vector<uint8_t> key(crypto_aead_chacha20poly1305_IETF_KEYBYTES);
    crypto_aead_chacha20poly1305_ietf_keygen(key.data());
    return key;
}

static auto enc(const DCTmodel::sPub& p) { return *p.wireEncode(); }

static auto timeSM(SigMgr& sm, const auto& rdat, const auto niter) {
    ndn::Data pub{ndn::Name("/test/sigmgr/timing/padMult32.").appendTimestamp(std::chrono::system_clock::now())};

    if (sm.type() == SigMgr::stAEAD) {
        // To handle encrypting/decrypting sigmgr which changes pubs
        // have to copy the pub in the loop and account for the copy cost.
        sm.addKey(makeAEADkey(), std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
    }
    auto incr = rdat.size() / 128;
    if (incr < 1) incr = 1;
    //XXX start sz at 'incr' since AEAD doesn't currently accept 0 length content
    for (auto sz = incr; sz <= rdat.size(); sz += incr) {
        pub.setContent((const uint8_t*)rdat.data(), sz*sizeof(rdat[0]));
        auto strt = std::chrono::system_clock::now();
        for (auto i = 0u; i < niter; i++) { decltype(pub) p2(pub); enc(p2); }
        auto cpy = std::chrono::system_clock::now();
        for (auto i = 0u; i < niter; i++) { decltype(pub) p2(pub); enc(p2); sm.sign(p2); }
        sm.sign(pub);
        auto fins = std::chrono::system_clock::now();
        for (auto i = 0u; i < niter; i++) { decltype(pub) p2(pub); enc(p2); sm.validateDecrypt(p2); }
        auto finv = std::chrono::system_clock::now();
        auto cc = cpy - strt;
        using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
        print("{} : {} {} {}\n", pub.wireEncode()->size(), ticks(fins - cpy - cc)/double(niter),
                ticks(finv - fins - cc)/double(niter), ticks(cc)/double(niter));
    }
}

int main(int argc, char* const* argv) {
    size_t niter{1024*128};
    size_t maxsize{syncps::maxPubSize};

    if (argc < 3) usage(argv[0]);

    DCTmodel* dm{};
    SigMgrAny sm;
    for (int c; (c = getopt_long(argc, argv, "n:p:s:t:w:", opts, nullptr)) != -1; ) {
        switch (c) {
            case 'm':
                maxsize = std::stoul(optarg);
                if (maxsize <= 0) usage(argv[0]);
                break;
            case 'n':
                niter = std::stoul(optarg);
                if (niter <= 0) usage(argv[0]);
                break;
            case 'p':
                if (! dm) dm = new DCTmodel(optarg);
                sm = dm->psm_;
                break;
            case 'w':
                if (! dm) dm = new DCTmodel(optarg);
                sm = dm->wsm_;
                break;
            case 't':
                sm = sigMgrByType(optarg);
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
        timeSM(sm.ref(), rdat, niter);
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    exit(0);
}
