/*
 *  tst_iblt - test iblt encode / decode / peel behavior
 *
 * Copyright (C) 2024 Pollere LLC
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
#include <ranges>
#include <span>
#include <set>
#include <type_traits>
#include "dct/format.hpp"
#include "dct/syncps/iblt.hpp"

using namespace dct;

// command line args
static bool oneShot{false};
static bool encChk{false};
static bool peelTst{false};
static size_t iter{1};
static size_t mtu{1300};
static size_t nitems{100};
static size_t split{0};
static size_t olap{0};
static size_t nadd{3};
static size_t verbose{0};

static struct option opts[] {
    {"1", no_argument, nullptr, '1'},
    {"add", required_argument, nullptr, 'a'},
    {"encChk", no_argument, nullptr, 'e'},
    {"items", required_argument, nullptr, 'i'},
    {"mtu", required_argument, nullptr, 'm'},
    {"niter", required_argument, nullptr, 'n'},
    {"olap", required_argument, nullptr, 'o'},
    {"peelTst", no_argument, nullptr, 'p'},
    {"split", required_argument, nullptr, 's'},
};

static auto usage(std::string_view pname) {
    print("- usage: {} [-1] [-a add] [-e] [-i items] [-m mtu] [-n niter] [-o olap] [-p] [-s split] [-v]\n", pname);
    exit(1);
}

using std::min;
using std::ranges::for_each;
using std::views::take;
using std::views::drop;
using std::views::filter;

using PubHash = uint32_t;
using Set = std::set<PubHash>;

// a collection is a set of items together with the set's iblt
struct Coll {
    int sent_{};
    size_t dups_{};
    size_t blind_{};
    Set s_{};           // all items in the collection
    IBLT<PubHash> ib_;  // iblt of s_
    Set l_{};           // items of s_ *not* received from a peer
    decltype(l_)::const_iterator lastSent_{l_.cend()};
    const char* const nm_;  // name of this collection

    Coll(size_t mtu, const char* const nm) : ib_{mtu}, nm_{nm} { }

    void insert(PubHash v) {
        if (s_.contains(v)) print("error: {} already contains {}\n", nm_, v);
        s_.insert(v);
        ib_.insert(v);
    }
    void insert(std::ranges::input_range auto dat) { for_each(dat, [this](PubHash v){insert(v);}); }

    // insert a local pub
    void insertL(PubHash v) {
        if (l_.contains(v)) print("error: {} already contains local pub {}\n", nm_, v);
        l_.insert(v);
        insert(v);
    }

    void publishTo(PubHash v, Coll& dst) {
        // only send locally generated pubs
        if (!l_.contains(v)) {
            if (verbose > 0) print("      {}>{} looped {}\n", nm_, dst.nm_, v);
            return;
        }
        if (dst.contains(v)) {
            ++dups_;
            if (verbose > 2) print("      {}>{} dup {:x}\n", nm_, dst.nm_, v);
            return;
        }
        if (verbose > 2) print("      {}>{} snd {:x}\n", nm_, dst.nm_, v);
        ++sent_;
        dst.insert(v);
    }

    // publish the next N items of the l_ collection wrapping around at the end.
    void publishN(int n, Coll& dst) {
        if (l_.size() == 0) return;
        blind_ += n;
        while (--n >= 0) {
            if (lastSent_ == l_.cend()) lastSent_ = l_.cbegin();
            publishTo(*lastSent_++, dst);
        }
    }

    constexpr bool contains(PubHash v) const noexcept { return s_.contains(v); }
    constexpr auto size() const noexcept { return s_.size(); }
};

static constexpr auto difference = [](const Set& a, const Set& b) -> Set {
    Set i{};
    std::ranges::set_difference(a, b, std::inserter(i, i.begin()));
    return i;
};
const auto dSize = [](const Set& a, const Set& b) { return difference(a, b).size(); };
static constexpr auto intersection = [](const Set& a, const Set& b) -> Set {
    Set i{};
    std::ranges::set_intersection(a, b, std::inserter(i, i.begin()));
    return i;
};
const auto iSize = [](const Set& a, const Set& b) { return intersection(a, b).size(); };

template<typename T=size_t>
struct smry {
    T mn{};
    T sm{};
    T mx{};
    constexpr smry& operator+=(T v) {
        if (sm == 0) { mn = v; mx = v; }
        sm += v;
        if (mn > v) mn = v;
        if (mx < v) mx = v;
        return *this;
    }
};

int main(int argc, char* const* argv) {

    for (int c; (c = getopt_long(argc, argv, "1a:ei:m:n:o:ps:v", opts, nullptr)) != -1; ) {
        switch (c) {
            case '1':
                oneShot = !oneShot;
                break;
            case 'a':
                nadd = std::stoul(optarg);
                if (nadd <= 0) usage(argv[0]);
                break;
            case 'e':
                encChk = !encChk;
                break;
            case 'i':
                nitems = std::stoul(optarg);
                if (nitems <= 0) usage(argv[0]);
                break;
            case 'm':
                mtu = std::stoul(optarg);
                if (mtu <= 0) usage(argv[0]);
                break;
            case 'n':
                iter = std::stoul(optarg);
                if (iter <= 0) usage(argv[0]);
                break;
            case 'o':
                olap = std::stoul(optarg);
                if (olap < 0) usage(argv[0]);
                break;
            case 'p':
                peelTst = !peelTst;
                break;
            case 's':
                split = std::stoul(optarg);
                if (split <= 0) usage(argv[0]);
                break;
            case 'v':
                ++verbose;
                break;
        }
    }
    if (verbose > 1) {
        // print the run parameters and iblt layout
        IBLT<PubHash> ib{mtu};
        print("# {} items, {} split, {} overlap, {} add, {} mtu, {} htsize\n",
                nitems, split, olap, nadd, mtu, ib.stsize_);
    }

    // initialize random number generator and random pub content
    std::minstd_rand m_randGen{};
    std::random_device rd;
    m_randGen.seed(rd());

    std::vector<std::array<size_t,8>> pt{}; // 'peel test' summary statistics
    try {
        // Test iblt peeling of 'nitems' distinct random numbers split into two collections,
        // 'left' and 'right', where 'right' contains the first 'split' elements of 'dat' and
        // 'left' contains the remainer. Peeling 'right' from 'left' should result in all
        // of 'left' in the peel's 'have' set and 'right' in the 'need' set.
        for (size_t rnd = 0; rnd < iter; ++rnd) {
            Set dat{};          // all items
            Coll l{mtu, "l"};   // 'left' collection
            Coll r{mtu, "r"};   // 'right' collection
 
            // fill dat with nitems unique random values, l.s_ with the first nitems-split
            // of them and r.s_ with the remainder.
            for (size_t i = 0; i < nitems; ++i) {
                PubHash rval;
                do { rval = m_randGen(); } while (dat.contains(rval));
                dat.insert(rval);
            }
            for_each(dat | take(olap),[&r,&l](auto v){ r.insertL(v); l.insertL(v); });
            for_each(dat | drop(olap) | take(split - olap),[&r](auto v){ r.insertL(v); });
            for_each(dat | drop(split + olap),[&l](auto v){ l.insertL(v); });
            if (verbose > 3) {
                print("#{}: r {}, l {}, d {}, rl {}, rd {}, ld {}\n", rnd, r.s_.size(), l.s_.size(), dat.size(),
                        iSize(r.s_, l.s_), iSize(r.s_, dat), iSize(l.s_, dat));
                print("# r {::x}\n", r.s_);
                print("# l {::x}\n", l.s_);
            }

            auto enc = l.ib_.rlEncode();
            if (encChk) {
                // check that encode/decode are exact inverses
                IBLT<PubHash> ibltO{mtu};
                ibltO.rlDecode(enc);

                if (l.ib_ != ibltO) {
                    print("{}: {} items, {} bytesEnc, {} dec, {} mismatch\n", rnd,
                            l.ib_.size(), enc.size(), ibltO.size(), l.ib_.size()-ibltO.size());
                }
            }

            if (peelTst) {
                auto lrDif = l.ib_ - r.ib_;
                auto [sts,hs,ns] = lrDif.peel2();
                auto ds = dSize(l.s_, hs) + dSize(r.s_, ns);
                auto h = hs.size() + ns.size();
                if (verbose > 0) print("{}: {} items, {} enc, {} sts, {} h, {} hs, {} dif\n", rnd, nitems,
                                        enc.size(), sts, h, hs.size(), ds);
                pt.push_back({enc.size(), h, hs.size(), ds, 0, 0, 0, 0});
                continue;
            }
            // do the collection modifications corresponding to a cState from origin oc getting
            // a response from responder rc. On return, 0 to nadd items from rc will have been
            // added to oc. Return value:
            //   >0 : number of items added to oc
            //    0 : no more items to add
            //   -1 : peeling wedged
            const auto handleCstate = [](Coll& oc, Coll& rc) -> int {
                auto dif = oc.ib_ - rc.ib_;
                auto [c,h,n] = dif.peel2();
                if (n.size() == 0) {
                    // No 'needs'. Check whether that's because oc has everything from rc or
                    // because peeling failed. If everything peels, rc + have == oc + need ==
                    // totalItems. 
                    //if (h.size() + rc.size() == oc.size()) return 0;
                    if (verbose > 1) print("  b {}({})>{}({}), c {}, h {}, ds {}, di {} snd {} dup {} blnd {}\n",
                            rc.nm_, rc.size(), oc.nm_, oc.size(), c, h.size(), dif.size(), dif.items(),
                            rc.sent_, rc.dups_, rc.blind_);
                    //if (h.size() == 0 && rc.size() == oc.size() && rc.size() == dif.size()) return 0;
                    //if (rc.size() + h.size() == oc.size() && oc.size() == dif.size()) return 0;
                    if (c == 0 && rc.size() + h.size() == oc.size()) return 0;
                    rc.publishN(nadd, oc);
                    return -1;
                }
                if (verbose > 1) print("  n {}({})>{}({}), c {}, h {}, n {}, dif {} snd {} dup {} blnd {}\n",
                        rc.nm_, rc.size(), oc.nm_, oc.size(), c, h.size(), n.size(), dif.size(),
                        rc.sent_, rc.dups_, rc.blind_);
                for (auto m : n | take(nadd)) rc.publishTo(m, oc);
                return min(nadd, n.size());
            };

            // check that peeling works with this number of differences
            const auto [c,hs,ns] = (r.ib_ - l.ib_).peel2();
            if (oneShot) {
                print("{}:  s {}, c {}, h {}, n {}\n", rnd, r.s_.size(), c, hs.size(), ns.size());
                continue;
            }
            size_t nar{}, nfr{};
            size_t nal{}, nfl{};
            for (auto i = 0u; i <= l.ib_.size() * 8; ++i) {
                auto ar = handleCstate(r, l); if (ar < 0) { ++nfr; nar += nadd; } else { nar += ar; }
                auto al = handleCstate(l, r); if (al < 0) { ++nfl; nal += nadd; } else { nal += al; }
                if (verbose > 1) {
                    print("{}.{}: r {}, ar {}, l {}, al {},  i {}\n", rnd, i,
                            r.s_.size(), ar, l.s_.size(), al, iSize(r.s_, l.s_)); 
                }
                if (r.size() == nitems-olap && r.size() == l.size()) {
                    if (verbose) print("{}.{}: r {}, nr {}, fr {}, l {}, nl {}, fl {},  i {}\n", rnd, i,
                            r.s_.size(), nar, nfr, l.s_.size(), nal, nfl, iSize(r.s_, l.s_)); 

                    pt.push_back({enc.size(), i, nar, nal, r.dups_, l.dups_, r.blind_, l.blind_});
                    break;
                }
                if (i == l.ib_.size() * 8) {
                    print("stuck {}.{}: r {}, nr {}, fr {}, l {}, nl {}, fl {},  i {}\n", rnd, i,
                            r.s_.size(), nar, nfr, l.s_.size(), nal, nfl, iSize(r.s_, l.s_)); 
                }
            }
        }
    } catch (const std::runtime_error& se) { print("error: {}\n", se.what()); }

    if (pt.size()) {
        smry se, sp, sh, sd, srd, sld, srb, slb;

        for (auto [e, p, h, d, rd, ld, rb, lb] : pt) {
            se += e; sp += p; sh += h; sd += d; srd += rd; sld += ld; srb += rb; slb += lb;
        }
        auto ni = pt.size();
        auto n = double(ni);
        if (peelTst) {
            print("{} e {:.0f}-{}+{}, p {:.0f} {}-{}, h {:.0f} {}-{}, d {:.0f} {}-{}\n", nitems,
                    double(se.sm)/n, se.sm/ni - se.mn, se.mx - se.sm/ni, double(sp.sm)/n, sp.mn, sp.mx,
                    double(sh.sm)/n, sh.mn, sh.mx, double(sd.sm)/n, sd.mn, sd.mx);
        } else {
            print("{} e {:.0f}-{}+{}, rnds {:.0f}-{}+{},"
                  " l>r {:.0f}-{}+{} B {:.0f}-{}+{} D {:.0f}-{}+{},"
                  " r>l {:.0f}-{}+{} B {:.0f}-{}+{} D {:.0f}-{}+{}\n",
                    nitems,
                    double(se.sm)/n, se.sm/ni - se.mn, se.mx - se.sm/ni,
                    double(sp.sm)/n, sp.sm/ni - sp.mn, sp.mx - sp.sm/ni,
                    double(sh.sm)/n, sh.sm/ni - sh.mn, sh.mx - sh.sm/ni,
                    double(slb.sm)/n, slb.sm/ni - slb.mn, slb.mx - slb.sm/ni,
                    double(sld.sm)/n, sld.sm/ni - sld.mn, sld.mx - sld.sm/ni,
                    double(sd.sm)/n, sd.sm/ni - sd.mn, sd.mx - sd.sm/ni,
                    double(srb.sm)/n, srb.sm/ni - srb.mn, srb.mx - srb.sm/ni,
                    double(srd.sm)/n, srd.sm/ni - srd.mn, srd.mx - srd.sm/ni);
        }
    }
    exit(0);
}
