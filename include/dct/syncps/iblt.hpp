/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Pollere LLC added (6/14/2020) checks for validity to file
 *
 * Copyright (c) 2014-2018,  The University of Memphis
 *
 * This file is part of PSync.
 * See AUTHORS.md for complete list of PSync authors and contributors.
 *
 * PSync is free software: you can redistribute it and/or modify it under the
 terms
 * of the GNU General Public License as published by the Free Software
 Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * PSync is distributed in the hope that it will be useful, but WITHOUT ANY
 WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * PSync, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *

 * This file incorporates work covered by the following copyright and
 * permission notice:

 * The MIT License (MIT)

 * Copyright (c) 2014 Gavin Andresen

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef SYNCPS_IBLT_HPP
#define SYNCPS_IBLT_HPP

#include <array>
#include <cmath>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "murmurHash3.hpp"

namespace dct {

/**
 * @brief Invertible Bloom Lookup Table (Invertible Bloom Filter)
 */
template<typename HashVal>
struct IBLT {
    /*
     * Optimal number of hashes is 3 or 4. 3 results in less computation and
     * fewer cache misses so this code uses 3 hashes. The following
     * declaration documents this fact but doesn't allow the number of
     * hashes to be changed.
     */
    static constexpr size_t N_HASH{3};
    static constexpr size_t N_HASHCHECK{0x53a1df9a}; // random bit string with half the bits set
    static constexpr size_t stsize = 19; // sub-table size (should be prime)
    static constexpr size_t nEntries = stsize * N_HASH; // must be <128
    static constexpr uint8_t MAXCNT = 0x80; // max run length & run start marker, must be > nEntries
    static constexpr murmurHash3 mh3{};

    template<typename V>
    static inline HashVal hashobj(const V& v) noexcept { return mh3(N_HASHCHECK, v.data(), v.size()); }

    struct HashTableEntry {
        int32_t count;
        HashVal keySum;
        HashVal keyCheck;

        bool isPure() const {
            return (count == 1 || count == -1) && mh3(uint64_t(keySum) | (N_HASHCHECK << 32)) == keyCheck;
        }
        bool isEmpty() const { return count == 0 && keySum == 0 && keyCheck == 0; }
    };

    using HashTable = std::array<HashTableEntry,nEntries>;
    HashTable hashTable_{};

    static constexpr int INSERT = 1;
    static constexpr int ERASE = -1;

    /**
     * @brief run-length encode this iblt into a byte vector.
     *
     * 'count' is encoded as a byte (assumes iblt max length < 128) then
     * keySum and keyCheck in little-endian order. Runs of zero entries are encoded as a 'count'
     * with the high bit set and the run length in the LSBs.
     */
    auto rlEncode() const noexcept {
        std::vector<uint8_t> rle{};
        uint8_t cnt{};
        for (const auto& e : hashTable_) {
            if (e.isEmpty()) {
                if (++cnt >= MAXCNT) { rle.emplace_back(cnt | MAXCNT); cnt = 0; }
                continue;
            }
            if (cnt != 0) { rle.emplace_back(cnt | MAXCNT); cnt = 0; }

            rle.emplace_back(e.count);

            rle.emplace_back(e.keySum);
            rle.emplace_back(e.keySum >> 8);
            rle.emplace_back(e.keySum >> 16);
            rle.emplace_back(e.keySum >> 24);

            rle.emplace_back(e.keyCheck);
            rle.emplace_back(e.keyCheck >> 8);
            rle.emplace_back(e.keyCheck >> 16);
            rle.emplace_back(e.keyCheck >> 24);
        }
        // trailing empty entry count is omitted except for
        // empty iblt (to avoid empty name component).
        if (rle.empty() && cnt != 0) rle.emplace_back(cnt | MAXCNT);
        return rle;
    }

    /**
     * @brief Populate the hash table using RLE compressed IBLT
     *
     * @param ibltName the Component representation of IBLT
     * @throws Error if size of values is not compatible with this IBF
     */
    void rlDecode(const std::span<const uint8_t> rle) {
        size_t i{};
        for (auto r = rle.begin(); r < rle.end(); ) {
            auto b = *r;
            if (b >= MAXCNT) {
                if (b > MAXCNT) b &= MAXCNT-1;
                i += b; // advance over zero entries
                if (i > nEntries) throw std::runtime_error("compressed IBLT too large");;
                ++r;
                continue;
            }
            // extract entry
            hashTable_[i].count = b;
            hashTable_[i].keySum   = r[1] | (r[2] << 8) | (r[3] << 16) | (r[4] << 24);
            hashTable_[i].keyCheck = r[5] | (r[6] << 8) | (r[7] << 16) | (r[8] << 24);
            if (++i > nEntries) throw std::runtime_error("compressed IBLT too large");;
            r += 9;
        }
    }

    /**
     * The hash table is split into N_HASH interleaved sub-tables with a
     * different hash for each (the interleaved tables provide slightly
     * better cache hit rates for small table sizes). Since the tables
     * are <<2^20 entries, a single 64-bit hash is computed and different
     * parts of it are used for per-table indices. Each entry is added/deleted
     * from all subtables.
     *
     * XXX hash index should be computed via Lemire's multiplicative method. See:
     *  https://github.com/lemire/fastmod/blob/master/include/fastmod.h
     *  https://arxiv.org/abs/1902.01961
     *  https://github.com/lemire/fastmod
     *  https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/
     */
    auto hash(size_t key) const noexcept
    {
        auto h = mh3(key);
        auto h0 = (h % stsize) * N_HASH;
        auto h1 = ((h >> 8) % stsize) * N_HASH + 1;
        auto h2 = ((h >> 16) % stsize) * N_HASH + 2;
        return std::tuple{h0, h1, h2};
    }

    /** validity checking for 'key' on peel or delete
     *
     * Try to detect a corrupted iblt or 'invalid' key (deleting an item
     * twice or deleting something that wasn't inserted). Anomalies
     * detected are:
     *  - one or more of the key's 3 hash entries is empty
     *  - one or more of the key's 3 hash entries is 'pure' but doesn't contain 'key'
     */
    bool chkPeer(size_t key, size_t idx) const noexcept {
        auto hte = getHashTable().at(idx);
        return hte.isEmpty() || (hte.isPure() && hte.keySum != key);
    }

    bool badPeers(size_t key) const noexcept {
        const auto [hash0, hash1, hash2] = hash(key);
        return chkPeer(key, hash0) || chkPeer(key, hash1) || chkPeer(key, hash2);
    }

    void insert(HashVal key) { update(INSERT, key); }

    void erase(HashVal key) {
        if (badPeers(key)) {
            std::cerr << "error - invalid iblt erase: badPeers for key " << std::hex << key << "\n";
            return;
        }
        update(ERASE, key);
    }

    /**
     * @brief "peel" entries from an iblt
     *
     * Typically called on a difference of two IBLTs: ownIBLT - rcvdIBLT
     * and returns a pair{have, need} where 'have' and 'need' are sets.
     * Entries listed in "have" are in ownIBLT but not in rcvdIBLT
     * Entries listed in "need"  are in rcvdIBLT but not in ownIBLT
     */
    auto peel() const noexcept {
        std::set<HashVal> have{};
        std::set<HashVal> need{};
        bool peeledSomething;
        IBLT peeled{*this};

        do {
            peeledSomething = false;
            for (const auto& entry : peeled.hashTable_) {
                if (! entry.isPure()) continue;

                if (peeled.badPeers(entry.keySum)) {
                    //std::cerr << "error - invalid iblt: badPeers for entry:" << entry << "\n";
                    std::cerr << "error - invalid iblt: badPeers for entry:" << entry.keySum << "\n";
                    peeledSomething = false;
                    break;
                }
                if (entry.count > 0) have.insert(entry.keySum); else need.insert(entry.keySum);
                peeled.update(-entry.count, entry.keySum);
                peeledSomething = true;
            }
        } while (peeledSomething);
        return std::pair{have, need};
    }

    IBLT operator-(const IBLT& other) const {
        IBLT result(*this);
        for (size_t i = 0; i < nEntries; i++) {
            HashTableEntry& e1 = result.hashTable_.at(i);
            const HashTableEntry& e2 = other.hashTable_.at(i);
            e1.count -= e2.count;
            e1.keySum ^= e2.keySum;
            e1.keyCheck ^= e2.keyCheck;
        }
        return result;
    }

    const HashTable& getHashTable() const noexcept { return hashTable_; }

    void update1(int plusOrMinus, HashVal key, size_t idx) {
        HashTableEntry& entry = hashTable_.at(idx);
        entry.count += plusOrMinus;
        entry.keySum ^= key;
        entry.keyCheck ^= mh3(uint64_t(key) | (N_HASHCHECK << 32));
    }
    void update(int plusOrMinus, HashVal key) {
        const auto [hash0, hash1, hash2] = hash(key);
        update1(plusOrMinus, key, hash0);
        update1(plusOrMinus, key, hash1);
        update1(plusOrMinus, key, hash2);
    }
};

template<typename T>
static inline bool operator==(const IBLT<T>& iblt1, const IBLT<T>& iblt2)
{
    return memcmp(iblt1.hashTable_.data(), iblt2.hashTable_.data(), iblt1.hashTable_.size()) == 0;
}

template<typename T>
static inline bool operator!=(const IBLT<T>& iblt1, const IBLT<T>& iblt2) { return !(iblt1 == iblt2); }

#if 0
template<typename T>
static inline std::ostream& operator<<(std::ostream& out, const IBLT<T>::HashTableEntry& hte) {
    out << std::dec << std::setw(5) << hte.count << std::hex << std::setw(9)
        << hte.keySum << std::setw(9) << hte.keyCheck;
    return out;
}
#endif

template<typename T>
static inline std::string prtPeer(const IBLT<T>& iblt, size_t idx, size_t rep) {
    if (idx == rep) return "";

    std::ostringstream rslt{};
    rslt << " @" << std::hex << rep;
    auto hte = iblt.getHashTable().at(rep);
    if (hte.isEmpty()) {
        rslt << "!";
    } else if (iblt.getHashTable().at(idx).keySum != hte.keySum) {
        rslt << (hte.isPure()? "?" : "*");
    }
    return rslt.str();
}

template<typename T>
static inline std::string prtPeers(const IBLT<T>& iblt, size_t idx) {
    auto hte = iblt.getHashTable().at(idx);
    // can only get the peers of 'pure' entries
    if (! hte.isPure()) return "";
    const auto [hash0, hash1, hash2] = iblt.hash(hte.keySum);
    return prtPeer(iblt, idx, hash0) + prtPeer(iblt, idx, hash1) + prtPeer(iblt, idx, hash2);
}

template<typename T>
static inline std::ostream& operator<<(std::ostream& out, const IBLT<T>& iblt) {
    out << "idx count keySum keyCheck\n";
    auto idx = 0;
    for (const auto& hte : iblt.getHashTable()) {
        out << std::hex << std::setw(2) << idx << hte << prtPeers(iblt, idx) << "\n";
        idx++;
    }
    return out;
}

}  // namespace dct

#endif  // SYNCPS_IBLT_HPP
