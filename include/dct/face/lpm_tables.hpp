#ifndef DCT_FACE_LPM_TABLES_HPP
#define DCT_FACE_LPM_TABLES_HPP
/*
 * Longest-Prefix-Match lookup tables implementing NDN Face Interest/Data semantics.
 *
 * Consists of: RIT - Registered Interest Table - LPM (Longest Prefix Match)
 *              PIT - Pending Interest Table - LPM or Exact-Match
 *              DIT - Duplicate Interest Table - Exact-Match
 *
 * Copyright (C) 2021-2 Pollere LLC
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
 *  This is not intended as production code.
 */

#include <map>
#include <set>
#include <type_traits>
#include <unordered_set>

#include <dct/face/api.hpp>

/**
 * Lookup table to do longest-prefix-match on wire-format NDN names. Both the RIT and PIT
 * are lookup tables containing name prefixes that must be matched against some name
 * (Interest name for RIT, Data name for PIT) and the longest or all matches returned.
 * The rName ordering operator is defined such that it collates prefixes in longest-match
 * order so either use case can be supported but both the RIT and PIT require longest
 * prefix exact match (a restricted instance of longest prefix match from the name's
 * point of view) so don't use of an 'all matches' method.
 *
 * Note that correct semantics only requires testing the target name against prefixes
 * that are <= its size to filter out matches where the name is a prefix of the prefix. 
 *
 * Note that since rName is just a view of the prefix, The caller of these routines must
 * guarantee that the data that backs the prefix exists unmodified during the lifetime
 * of each entry. (The backing data can be placed in the entry to assure this.)
 */
template<typename Prefix, typename Entry>
struct lpmLT {
    //std::unordered_map<Prefix,Entry> lt_{};
    std::map<Prefix,Entry> lt_{};
    std::map<uint16_t,int16_t,std::greater<uint16_t>> sz_{};  // key sizes, ordered longest first

    using iterator = typename decltype(lt_)::iterator;

    auto contains(const Prefix& n) const noexcept { return lt_.contains(n); }

    auto found(iterator it) noexcept { return it != lt_.end(); }

    /*
     * find exact match to name 'n'
     *
     * Returns iterator pointing to entry if found (should be tested
     * with 'found()' which checks against 'lt_.end()).
     */
    auto find(const Prefix& n) noexcept { return lt_.find(n); }

    /*
     * find longest match to name 'n'
     */
    auto findLM(const Prefix& n) noexcept {
        for (auto [sz, cnt] : sz_) {
            // Do an exact match lookup of n's prefix at each prefix size starting with longest.
            // This code is not currently taking advantage of the map's ordering and would work
            // as well with an unordered_map (but sacrifice 'findAllM()'). It could also be
            // rewritten to explicitly traverse the tree, matching prefixes on the fly, but
            // there's not yet performance data to justify this.
            if (sz > n.size()) continue;
            if (auto it = lt_.find(Prefix(n, sz)); it != lt_.end()) return it;
        }
        return lt_.end();
    }

    /*
     * invoke unary predicate 'pred' on all matches to prefix 'p'
     */
    template <typename Unary>
    auto findAll(const Prefix& p, Unary pred) const noexcept {
        auto sz = p.size();
        for (const auto& kv : lt_) {
            if (kv.first.size() >= sz && p == Prefix(kv.first, sz)) pred(kv);
        }
    }

    // add an entry for prefix 'p' to the map with arguments 'args'.
    template <typename... Args>
    auto add(const Prefix& p, Args&&... args) {
        auto res = lt_.try_emplace(p, std::forward<Args>(args)...);
        // if a new entry was added, note we have another entry of that size
        if (res.second) sz_[p.size()]++;
        return res;
    }
    template <typename... Args>
    auto add(Prefix&& p, Args&&... args) {
        auto res = lt_.try_emplace(std::move(p), std::forward<Args>(args)...);
        if (res.second) sz_[p.size()]++;
        return res;
    }

    void decrSize(size_t sz) {
        if (--sz_[sz] < 0) throw runtime_error(format("erasing deleted size {}", sz));
    }

    void erase(const Prefix& p) { if (lt_.erase(p) > 0) decrSize(p.size()); }

    void erase(iterator it) {
        decrSize(it->first.size());
        lt_.erase(it);
    }

    auto extract(const Prefix& p) {
        auto nh = lt_.extract(p);
        if (nh) decrSize(p.size());
        return nh;
    }

    auto extract(iterator it) {
        decrSize(it->first.size());
        return lt_.extract(it);
    }
};

/**
 * The Registered Interest Table (RIT) delivers incoming Interests to a
 * handler that may be able to satisfy them (respond with an appropriate
 * Data). The handler registers a prefix to match against incoming Interests
 * and a callback that's called with each matching Interest. RIT entries
 * persist until explicitly deleted.
 *
 * Since the key is a view (an rPrefix) its backing data needs to be preserved.
 * It can't go in the entry because the map item is built as a pair with the
 * prefix first so the name is copied to the heap with a pointer in the entry.
 */
struct RITentry {
    InterestCb iCb_;
    std::vector<uint8_t>* name_;    // The 'prefix' is supplied as an rName since that's needed for the callback.
                                    // Its backing data is copied to the heap with a pointer here.

    RITentry(const rName& n, InterestCb&& iCb) : iCb_{std::move(iCb)},
        name_{new std::vector<uint8_t>{n.m_blk.begin(), n.m_blk.end()}} { }
};

struct RIT : lpmLT<rPrefix, RITentry> {
    void add(RITentry&& e) { lpmLT<rPrefix, RITentry>::add(rPrefix{*e.name_}, std::move(e)); }
};

/**
 * The Duplicate Interest Table (DIT) keeps track of recently seen Interests
 * to filter out duplicates created by mis-behaving multicast implementations
 * and from the lack of any useful duplicate suppression in NFD. It uses the
 * fact that each Interest carries a randomly generated nonce so Interests
 * with the same name from different sources can be distinguished. The DIT
 * hashes each arriving Interest and compares it to a set recent hashes. If
 * the hash is not in the set it's accepted and added to the set. Otherwise
 * it's discarded.
 */
struct DIT : std::unordered_set<size_t> {
    std::unordered_set<size_t> ihash_{};

    auto hash(const rInterest& i) const { return std::hash<tlvParser>{}(i); }

    void add(size_t h) {
        // if too many entries, remove a random one
        if (ihash_.size() >= 256) {
            auto it = ihash_.begin();
            for (int b = h & 0xff; b-- > 0; it++) { }
            ihash_.erase(it);
        }
        ihash_.emplace(h);
    }
    void add(const rInterest& i) { add(hash(i)); }

    auto dupInterest(const rInterest& i) { auto h = hash(i); return std::pair(ihash_.contains(h), h); }
};

/**
 * The Pending Interest Table (PIT) records each outgoing Interest (one sent by the app)
 * together with a handler to call if an incoming Data satisfies the Interest (i.e., the
 * Interest's name is a prefix of the Data's name).
 *
 * There is also a PIT entry for each RIT-matching incoming Interest which allows any
 * matching Data generated by the RIT handler to be sent to the network.
 *
 * PIT entrys are deleted when satisfied by a Data or when they time out.
 *
 * All Interests and Datas are matched against the PIT.
 */
struct PITentry {
    using TOptr = std::unique_ptr<Timer>;

    std::unique_ptr<std::vector<uint8_t>> idat_{}; // bytes of the interest (backing store for prefix & interest_)
    rInterest i_{};
    DataCb dCb_{};
    InterestTO ito_{};
    TOptr timer_{};
    bool fromNet_{false};
    bool ded_{false};

    PITentry(const rInterest& i, DataCb&& dCb, InterestTO&& ito) :
                idat_{std::make_unique<std::vector<uint8_t>>(i.m_blk.begin(), i.m_blk.end())}, i_{*idat_},
                dCb_{std::move(dCb)}, ito_{std::move(ito)} { }

    PITentry(const rInterest& i) :
                idat_{std::make_unique<std::vector<uint8_t>>(i.m_blk.begin(), i.m_blk.end())}, i_{*idat_},
                fromNet_{true} { }

    auto& cancelTimer() {
        if (timer_) {
            timer_->cancel();
            timer_.reset();
        }
        return *this;
    }

    auto& timer() const noexcept { return timer_; }

    auto& timer(TOptr&& t) {
        cancelTimer();
        timer_ = std::move(t);
        return *this;
    }
};

struct PIT : lpmLT<rPrefix, PITentry> {
    using iterator = lpmLT<rPrefix, PITentry>::iterator;

    auto erase(const rInterest& i) { lpmLT<rPrefix, PITentry>::erase(rPrefix{i.name()}); }
    auto erase(iterator it) { lpmLT<rPrefix, PITentry>::erase(it); }

    // Interest Time-Out callback
    // The PIT entry needs to be deleted and, since the callback might want to reinstate it,
    // the entry has to be removed before the callback
    void itoCB(rInterest i) {
        auto nh = extract(rPrefix(i.name())); // remove entry from PIT
        //if (! nh) abort();
        if (! nh) return;
        if (auto& pe = nh.mapped(); pe.ito_) pe.ito_(rInterest(*pe.idat_));
    }

    /**
     * add a pit entry to the PIT. 
     *
     * The entry has to contain a copy of the Interest which may be large (e.g. Sync Interests
     * names contain an iblt of O(128) bytes) so we want to minimize copying. Also, the key is the
     * Interest name and we don't want two copies so the entry contains a pointer to a vector
     * containing the raw Interest and we build build the prefix from that.
     */
    auto add(PITentry&& e) {
        return lpmLT<rPrefix, PITentry>::add(rPrefix{e.i_.name()}, std::move(e));
    }

    /**
     * add Interest to PIT.
     *
     * If the entry doesn't exist it's created.
     *
     * If the entry exists (because it came in from the net or it was previously expressed
     * locally and hasn't timed out yet) a new entry is not created but the timeout of the
     * existing entry is updated and the new interest origin is recorded.
     *
     * returns 'true' if entry added (interest packet should be sent on) and false otherwise.
     */

    // add locally generated interest to PIT
    auto add(const rInterest& i, DataCb&& onD, InterestTO&& ito) {
        if (auto it = find(rPrefix(i.name())); found(it)) {
            // update existing entry
            auto& pe = it->second;
            pe.dCb_ = std::move(onD);
            pe.ito_ = std::move(ito);
            return std::pair<iterator,bool>{it, false};
        }
        return add(PITentry{i, std::move(onD), std::move(ito)});
    }

    // add network generated interest to PIT
    auto add(const rInterest& i) {
        if (auto it = find(rPrefix(i.name())); found(it)) {
            // update existing entry
            it->second.fromNet_ = true;
            return std::pair<iterator,bool>{it, false};
        }
        return add(PITentry{i});
    }
};

#endif  // DCT_FACE_LPM_TABLES_HPP
