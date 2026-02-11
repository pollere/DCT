/*
 * tst_sync - test delivery behavior of the syncps framework
 *
 * This module tests the behavior of collection syncing between peers
 * with different per-peer collection sizes to ensure that collections
 * eventually sync no matter how large their differences.
 *
 * Copyright (C) 2026 Pollere LLC
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
 *  tst_sync.cpp is not intended as production code.
 */

#include <algorithm>
#include <getopt.h>
#include <random>
#include <ranges>
#include <span>
#include <set>
#include <type_traits>

#include "dct/format.hpp"
#include "dct/rand.hpp"
#include "dct/schema/dct_cert.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"
#include "dct/syncps/syncps.hpp"

using namespace dct;

// command line args
static int nSent{};
static int nRcvd{};
static int nTotal{100};
static int batchSz{1};
static size_t contentSz{300u};
static tdv_clock::duration batchGap{20ms};
static tdv_clock::duration lifetime{300s};

static size_t verbose{0};

static auto now() { return std::chrono::system_clock::now(); }

static void report() {
    print("{:%T} {} sent {} rcvd {} pubs\n", now(), sysID(), nSent, nRcvd);
}

struct syncTst {    
    size_t csz_;   // pub content size in bytes
    crName pduPre_{"12345678/stPDU"};
    crName pubPre_{"syncTst"};
    SigMgrAny pduSM_{sigMgrByType("RFC7693")};
    SigMgrAny pubSM_{sigMgrByType("RFC7693")};
    DirectFace face_{};
    SyncPS sync_;
    dct::rand rand_{};

    syncTst(size_t csz) : csz_(csz), sync_(face_, pduPre_, pduSM_.ref(), pubSM_.ref()) { }

    // make a size csz_ byte vector and fill it with random bytes
    auto randVec() {
        std::vector<uint8_t> v;
        v.reserve(csz_);
        for (auto i = csz_; i-- > 0;) v.push_back(rand_(0, 256));
        return v;
    }
    // build and send one pub
    void sendPub() {
        if (nSent >= nTotal) return;
        sync_.signThenPublish(crData(pubPre_ / sysID() / nSent++ / now()).content(randVec()));
    }
    // build and send one batch of pubs then schedule the next batch send
    void sendBatch() {
        if (batchSz == 1) {
            sendPub();
        } else {
            sync_.batchPubs();
            for (int i = batchSz; --i >= 0; ) sendPub();
            sync_.batchDone(0);
        }
        if (nSent <  nTotal) {
            sync_.oneTime(batchGap, [this]{ sendBatch(); });
        } else {
            report();
            sync_.oneTime(5s, [this]{ sendBatch(); });
        }
    }
};

static struct option opts[] {
    {"batch", required_argument, nullptr, 'b'},
    {"content", required_argument, nullptr, 'c'},
    {"gap", required_argument, nullptr, 'g'},
    {"lifetime", required_argument, nullptr, 'l'},
    {"ntotal", required_argument, nullptr, 'n'},
    {"verbose", required_argument, nullptr, 'v'},
};

static auto usage(std::string_view pname) {
    print("- usage: {} [-b batch] [-c content] [-g gap] [-n published] [-v]\n", pname);
    exit(1);
}

static auto rcvPub(const auto& p) {
    ++nRcvd;
    if (verbose > 1) print("{} got {}\n", sysID(), p.name());
}

int main(int argc, char* const* argv) {

    for (int c; (c = getopt_long(argc, argv, "b:c:g:l:n:v", opts, nullptr)) != -1; ) {
        switch (c) {
            case 'b':
                batchSz = std::stol(optarg);
                if (batchSz <= 0) usage(argv[0]);
                break;
            case 'c':
                contentSz = std::stol(optarg);
                if (contentSz <= 0) usage(argv[0]);
                break;
            case 'g':
                batchGap = std::chrono::milliseconds(std::stol(optarg));
                if (batchGap < 0us) usage(argv[0]);
                break;
            case 'l':
                lifetime = std::chrono::milliseconds(std::stol(optarg));
                if (lifetime < 0us) usage(argv[0]);
                break;
            case 'n':
                nTotal = std::stoul(optarg);
                if (nTotal <= 0) usage(argv[0]);
                break;
            case 'v':
                ++verbose;
                break;
        }
    }
    syncTst st(contentSz);
    st.sync_.pubLifetime(lifetime);
    if (verbose > 1) {
        // print the run parameters and iblt layout
        //print("# {} items, {} split, {} overlap, {} add, {} mtu, {} htsize\n",
                //nitems, split, olap, nadd, mtu, ib.stsize_);
    }
    // Before doing any I/O, set up to receive peer pubs. Then add the first batch
    // of pubs to the collection (which also sets a timer for the next batch).
    // Finally, start handling I/O events.
    st.sync_.subscribe(st.pubPre_, [](const rPub& p){rcvPub(p);});
    st.sendBatch(); 
    st.sync_.run();
    exit(0);
}
