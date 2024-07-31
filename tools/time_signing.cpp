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
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */
#include <getopt.h>
#include <algorithm>
#include <random>
#include <time.h>
#include "dct/format.hpp"
#include "dct/schema/dct_model.hpp"
#include "../examples/util/dct_example.hpp"
#include "performancecounters/event_counter.h"

using namespace dct;

static struct option opts[] {
    {"msg", required_argument, nullptr, 'm'},
    {"niter", required_argument, nullptr, 'n'},
    {"pdu", required_argument, nullptr, 'p'},
    {"maxsize", required_argument, nullptr, 's'},
    {"type", required_argument, nullptr, 't'},
};

static auto usage(std::string_view pname) {
    print("- usage: {} [-s maxsize] [-n niter] -m bundle | -p bundle | -t type\n", pname);
    exit(1);
}

static auto makeEncryptkey() {
    std::vector<uint8_t> key(crypto_aead_chacha20poly1305_IETF_KEYBYTES);
    crypto_aead_chacha20poly1305_ietf_keygen(key.data());
    return key;
}

event_collector collect;

static auto timeSM(SigMgr& sm, auto rdat, const auto niter) {
    if (sm.encryptsContent()) {
        sm.addKey(makeEncryptkey(), std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
    }
    // Make sure crypto lib does all its initialization. Since signing and validation
    // operations are almost always done on cached data, warm up the cache before measuring.
    for (int i = 10; --i > 0; ) {
        alignas(64) crData p2{crName{"1234"}};
        p2.content(rdat);
        sm.sign(p2);
        sm.validateDecrypt(p2);
    }
    // Out-of-order execution and 50 ns clock quantization make it impossible
    // to time individual steps so what's timed is many iterations of a loop.
    // All operations start with making a copy of the input state so have to
    // account for the cost of the copy which also includes loop overhead.
    //const auto nanos = []() -> uint64_t { return __builtin_readcyclecounter(); };
    //const auto nanos = []() -> uint64_t { return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); };
    //const auto nanos = []() -> uint64_t {
    //    timespec ts;
    //    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
          //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    //    return ts.tv_sec * 1000000000 + ts.tv_nsec;
    //};

    //auto incr = rdat.size() / 128;
    size_t incr = 1;
    if (incr < 1) incr = 1;
    // start sz at max and count down to minimize memory pool fragmentation
    for (int sz = rdat.size(); sz >= 0; sz -= incr) {
        // outer tlv hdr is 2-4 bytes & name takes 4 bytes so add a few bytes to align content
        alignas(64) crData pub{crName{"1234"}};
        auto ss = rdat.first(sz);
        pub.content(ss);
        auto pubsz = pub.size();

        event_aggregate cpy{};
        event_aggregate sgn{};
        event_aggregate val{};

        //uint64_t cpy = -nanos();
        for (int i = niter; --i > 0; ) {
            collect.start();
            alignas(64) auto p2 = pub;
            cpy << collect.end();
 
            collect.start();
            sm.sign(p2);
            sgn << collect.end();
 
            collect.start();
            sm.validateDecrypt(p2);
            val << collect.end();
        }

        print("cpy {} {} {} {} {} {} {}\n", pubsz, cpy.elapsed_ns(), cpy.instructions(), cpy.cycles(),
                                 cpy.best.elapsed_ns(), cpy.best.instructions(), cpy.best.cycles()); 
        print("sgn {} {} {} {} {} {} {}\n", pubsz, sgn.elapsed_ns(), sgn.instructions(), sgn.cycles(),
                                 sgn.best.elapsed_ns(), sgn.best.instructions(), sgn.best.cycles()); 
        print("val {} {} {} {} {} {} {}\n", pubsz, val.elapsed_ns(), val.instructions(), val.cycles(),
                                 val.best.elapsed_ns(), val.best.instructions(), val.best.cycles()); 
        //print("{} : {} {} {}\n", pubsz, 
         //       double(val - cpy)/double(niter),
          //      double(sgn - cpy)/double(niter),
           //     double(cpy)/double(niter));
    }
}


static auto& getDCTmodel(const char* bsfile) {
    static dct::DCTmodel* dm{};
    if (! dm) {
        dct::readBootstrap(bsfile);
        dm = new dct::DCTmodel(dct::rootCert, []{return dct::schemaCert();},
                                []{return dct::identityChain();}, []{return dct::getSigningPair();});
    }
    return *dm;
}


int main(int argc, char* const* argv) {
    size_t niter{1024*128};
    size_t maxsize{8192};

    if (argc < 3) usage(argv[0]);

    SigMgrAny* sm;
    for (int c; (c = getopt_long(argc, argv, "m:n:p:s:t:", opts, nullptr)) != -1; ) {
        switch (c) {
            case 's':
                maxsize = std::stol(optarg);
                if (maxsize <= 0 || maxsize >= 65536) usage(argv[0]);
                break;
            case 'n':
                niter = std::stol(optarg);
                if (niter <= 0) usage(argv[0]);
                break;
            case 'm':
                sm = &getDCTmodel(optarg).msm_;
                break;
            case 'p':
                sm = &getDCTmodel(optarg).psm_;
                break;
            case 't':
                sm = new SigMgrAny{sigMgrByType(optarg)};
                break;
        }
    }

    // initialize random number generator and random pub content
    std::minstd_rand m_randGen{};
    std::uniform_int_distribution<uint64_t> m_randDist{};

    std::random_device rd;
    m_randGen.seed(rd());
    alignas(64) std::array<uint64_t,65536/sizeof(uint64_t)> rdat;

    std::generate(rdat.begin(), rdat.end(), [&m_randDist,&m_randGen]{return m_randDist(m_randGen);});

    try {
        timeSM(sm->ref(), std::span{(const uint8_t*)rdat.data(), maxsize}, niter);
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    exit(0);
}
