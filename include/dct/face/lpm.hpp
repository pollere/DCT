#ifndef DCT_FACE_LPM_HPP
#define DCT_FACE_LPM_HPP
/*
 * Longest-Prefix-Match lookup template class
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
#include <type_traits>
#include "../schema/crpacket.hpp"

// need to be able to recognize containers that combine a view with its backing store
template<typename C> concept lpmCapable = std::is_convertible_v<const C &, const rPrefix&>;

/**
 * Lookup table to do longest-prefix-match on wire-format names. Both the RIT and PIT
 * are lookup tables containing name prefixes that must be matched against some name
 * (Interest name for RIT, Data name for PIT) and the longest match returned.
 * The rName ordering operator is defined such that it collates prefixes in longest-match
 * order to support these use cases when using std containers like map & set.
 *
 * Note that correct semantics requires testing the target name only against prefixes
 * that are <= its size to filter out matches where the name is a prefix of the prefix. 
 *
 * Note that since rName is just a view of the prefix, the caller of these routines must
 * guarantee that the data that backs the prefix exists unmodified during the lifetime
 * of each entry. Types that combine the backing data with the view (crName/crPrefix)
 * can be used to ensure this.
 */
template<typename Prefix, typename Entry> requires lpmCapable<Prefix>
struct lpmLT {
    struct cmp {
        using is_transparent = void;
        bool operator()(const rPrefix& p1, const rPrefix& p2) const { return p1 < p2; }
    };
    std::map<Prefix,Entry,cmp> lt_{};
    std::map<uint16_t,int16_t,std::greater<uint16_t>> sz_{};  // key sizes, ordered longest first

    using iterator = typename decltype(lt_)::iterator;

    auto end() const noexcept { return lt_.end(); }
    auto found(iterator it) const noexcept { return it != lt_.end(); }

     // find exact match to name 'n'.  Returns iterator pointing to entry if found.
    auto find(const rPrefix& n) noexcept { return lt_.find(n); }
    auto contains(const rPrefix& n) const noexcept { return lt_.contains(n); }

    /*
     * find longest match to name 'n'
     */
    auto findLM(rPrefix n) noexcept {
        for (auto [sz, cnt] : sz_) {
            // Do an exact match lookup of n's prefix at each prefix size starting with longest.
            // This code is not currently taking advantage of the map's ordering and would work
            // as well with an unordered_map (but sacrifice 'findAllM()'). It could also be
            // rewritten to explicitly traverse the tree, matching prefixes on the fly, but
            // there's not yet performance data to justify this.
            if (sz > n.size()) continue;
            if (auto it = lt_.find(rPrefix(n,sz)); it != lt_.end()) return it;
        }
        return lt_.end();
    }
    auto findLM(rName n) noexcept { return findLM(rPrefix{n}); }

    /*
     * invoke unary predicate 'pred' on all matches to prefix 'p'
     */
    template <typename Unary>
    auto findAll(const rPrefix& p, Unary pred) const noexcept {
        auto sz = p.size();
        for (const auto& kv : lt_) {
            if (kv.first.size() >= sz && p == Prefix(kv.first, sz)) pred(kv);
        }
    }

    // add an entry for prefix 'p' to the map with arguments 'args'.
    template <typename... Args>
    auto add(Prefix&& p, Args&&... args) {
        auto res = lt_.try_emplace(std::forward<Prefix>(p), std::forward<Args>(args)...);
        if (res.second) sz_[p.size()]++;
        return res;
    }

    void decrSize(size_t sz) {
        if (--sz_[sz] < 0) throw runtime_error(format("erasing deleted size {}", sz));
    }

    void erase(iterator it) {
        decrSize(it->first.size());
        lt_.erase(it);
    }

    // need C++23 to do this the right way:
    //void erase(const rPrefix& p) { if (lt_.erase(p) > 0) decrSize(p.size()); }
    void erase(const rPrefix& p) {
        if (auto it = lt_.find(p); it != lt_.end()) {
            decrSize(p.size());
            lt_.erase(it);
        }
    }

    auto extract(const rPrefix& p) {
        auto nh = lt_.extract(p);
        if (nh) decrSize(p.size());
        return nh;
    }

    auto extract(iterator it) {
        decrSize(it->first.size());
        return lt_.extract(it);
    }
};

#endif  // DCT_FACE_LPM_HPP
