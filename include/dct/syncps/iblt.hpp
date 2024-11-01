#ifndef SYNCPS_IBLT_HPP
#define SYNCPS_IBLT_HPP
#pragma once
/*
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
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Pollere LLC made additions and bug fixes, Copyright (C) 2019-2024 Pollere LLC
 * These include:
 * (06/14/2020) checks for validity to file
 * (09/25/24) IBLT size made flexible up to 10,000 items and tests added
 * Pollere authors at info@pollere.net and Pollere code portions licensed as follows.
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
*/

#include <array>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
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
    static constexpr size_t stsize = 47; // sub-table size (should be prime)
    static constexpr size_t nEntries = stsize * N_HASH;
    static constexpr murmurHash3 mh3{};
    // limits on the iblt size due to packet MTU constraints
    static_assert(nEntries * 9 < 1300, "encoded iblt bigger than maxPubSize");

    template<typename V>
    static inline HashVal hashobj(const V& v) noexcept { return mh3(N_HASHCHECK, v.data(), v.size()); }
    static inline HashVal hashobj(const uint8_t* d, size_t s) noexcept { return mh3(N_HASHCHECK, d, s); }

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
    int nitems_{};

    constexpr auto size() const { return nitems_; }

    static constexpr int INSERT = 1;
    static constexpr int ERASE = -1;

    constexpr void update1(int plusOrMinus, HashVal key, size_t idx) {
        HashTableEntry& entry = hashTable_.at(idx);
        if (entry.count >= std::numeric_limits<decltype(entry.count)>::max())
            throw std::runtime_error("too many items in iblt hash bucket");
        entry.count += plusOrMinus;
        entry.keySum ^= key;
        entry.keyCheck ^= mh3(uint64_t(key) | (N_HASHCHECK << 32));
    }
    constexpr void update(int plusOrMinus, HashVal key) {
        nitems_ += plusOrMinus;
        const auto [hash0, hash1, hash2] = hash(key);
        update1(plusOrMinus, key, hash0);
        update1(plusOrMinus, key, hash1);
        update1(plusOrMinus, key, hash2);
    }

    /**
     * @brief run-length encoding definitions and helper functions
     *
     * All hash table entries start with a count of items xor'd into the entry followed
     * by the xor'd entry and a parity check value. In general, upper layers try to keep
     * iblts empty or lightly loaded so that transient applications don't have to spend
     * a lot of time receiving the current contents of the collection. This means that
     * counts are often zero or small so compression focuses on counts. There are two
     * different compression schemes: 'runs' of consecutive zero entries are replaced
     * with a single byte coding the length of the run and small counts are coded in
     * a single byte rather than four. The last 16 values of an 8-bit range (0xf0-0xff
     * or 240-255) are used by the two schemes to distinguish coded data from counts.
     *
     *  - Runs of 1-14 zero entries are encoded using a flag byte with the top 4 bits set
     *    (0xf0-0xfd or 240-253) and the run length - 1 in the lower 4 bits..
     *
     *  - For each entry with a non-zero count, the count is variable length encoded in
     *    1-5 bytes followd by 8 bytes of keySum and keyCheck in little-endian order.
     *    Counts less than the first flag value (0xf0 or 240) are coded as a single
     *    byte. Counts in the range 240 - 65535 are coded with a 0xfe (254) marker
     *    followed by the two bytes of the count in little-endian order. Counts >=
     *    65536 are coded with a 0xff marker followed by the four bytes of the count
     *    in little-endian order.
     */ 
    static constexpr uint8_t rleFlag{0xf0};
    static constexpr uint8_t rleFlag4B{rleFlag|0xf};
    static constexpr uint8_t rleFlag2B{rleFlag4B-1};
    static constexpr uint8_t rleFlagRun{rleFlag};
    static constexpr uint8_t rleRunOffset{rleFlagRun-1};
    static constexpr uint8_t rleMaxRuns{rleFlag2B-rleFlag};
    static constexpr bool needsFlag(auto v) { return v >= rleFlag; }
    static constexpr bool isFlag(uint8_t b) { return (b & rleFlag) == rleFlag; }
    static constexpr uint8_t cnt2run(auto c) { return c + rleRunOffset; }
    static constexpr uint8_t run2cnt(uint8_t b) { return b - rleRunOffset; }

    /**
     * @brief run-length encode this iblt into a byte vector.
     * 
     * Note: this routine can only be used on an iblt containing a set (all counts >= 0) and
     * not the set difference produced while 'peeling'.
     */
    auto rlEncode() const {
        std::vector<uint8_t> rle{};
        uint32_t cnt{};
        for (const auto& e : hashTable_) {
            if (e.count <= 0) {
                if (e.count < 0) throw std::runtime_error("negative count in iblt hash bucket");
                if (!e.isEmpty()) throw std::runtime_error("non-zero bits in empty iblt hash bucket");

                if (++cnt >= rleMaxRuns) { rle.emplace_back(cnt2run(cnt)); cnt = 0; }
                continue;
            }
            if (cnt != 0) { rle.emplace_back(cnt2run(cnt)); cnt = 0; }

            // counts that overlap flag values or are bigger than 1 byte must be multi-byte encoded
            if (e.count >= rleFlag) {
                if (e.count >= 65536) {
                    rle.emplace_back(rleFlag4B);
                    rle.emplace_back(e.count);
                    rle.emplace_back(e.count >> 8);
                    rle.emplace_back(e.count >> 16);
                    rle.emplace_back(e.count >> 24);
                } else {
                    rle.emplace_back(rleFlag2B);
                    rle.emplace_back(e.count);
                    rle.emplace_back(e.count >> 8);
                }
            } else {
                rle.emplace_back(e.count);
            }
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
        if (rle.empty() && cnt != 0) rle.emplace_back(cnt2run(cnt));
        return rle;
    }

    /**
     * @brief Populate the (empty) hash table using an RLE compressed IBLT
     *
     * This routine MUST be called on an empty iblt.
     *
     * @throws Error if size of values is not compatible with this IBF
     */
    void rlDecode(const std::span<const uint8_t> rle) {
        size_t i{};
        for (auto r = rle.begin(); r < rle.end(); ) {
            uint32_t b = *r++;
            switch (b) {
                // b represents 1-14 zero entries
                case rleRunOffset+1: case rleRunOffset+2: case rleRunOffset+3: case rleRunOffset+4:
                case rleRunOffset+5: case rleRunOffset+6: case rleRunOffset+7: case rleRunOffset+8:
                case rleRunOffset+9: case rleRunOffset+10: case rleRunOffset+11: case rleRunOffset+12:
                case rleRunOffset+13: case rleRunOffset+14:
                    i += run2cnt(b); // advance over zero entries
                    continue;

                // b is a 32 bit little-endian count
                case rleFlag4B:
                    b = r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24);
                    r += 4;
                    break;
                // b is a 16 bit little-endian count
                case rleFlag2B:
                    b = r[0] | (r[1] << 8);
                    r += 2;
                    break;
                // b is an 8 bit count
                default:
                    break;
            }
            // extract entry
            nitems_ += b;
            //print(" ht[{}] = {} of {}\n", i, b, nitems_);
            if (i >= nEntries) print("compressed IBLT too large {} {}\n", i, nEntries);
            if (i >= nEntries) throw std::runtime_error("compressed IBLT too large");
            hashTable_[i].count = b;
            hashTable_[i].keySum   = r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24);
            hashTable_[i].keyCheck = r[4] | (r[5] << 8) | (r[6] << 16) | (r[7] << 24);
            ++i;
            r += 8;
        }
        nitems_ /= N_HASH;
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
        auto hte = hashTable_.at(idx);
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
        if (other.size() == 0) return *this;

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

    IBLT operator+(const IBLT& other) const {
        if (other.size() == 0) return *this;

        IBLT result(*this);
        for (size_t i = 0; i < nEntries; i++) {
            HashTableEntry& e1 = result.hashTable_.at(i);
            const HashTableEntry& e2 = other.hashTable_.at(i);
            e1.count += e2.count;
            e1.keySum ^= e2.keySum;
            e1.keyCheck ^= e2.keyCheck;
        }
        return result;
    }
};

template<typename T>
static inline bool operator==(const IBLT<T>& iblt1, const IBLT<T>& iblt2)
{
    return iblt1.hashTable_.size() == iblt2.hashTable_.size() &&
           memcmp(iblt1.hashTable_.data(), iblt2.hashTable_.data(), iblt1.hashTable_.size()) == 0;
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
    auto hte = iblt.hashTable_.at(rep);
    if (hte.isEmpty()) {
        rslt << "!";
    } else if (iblt.hashTable_.at(idx).keySum != hte.keySum) {
        rslt << (hte.isPure()? "?" : "*");
    }
    return rslt.str();
}

template<typename T>
static inline std::string prtPeers(const IBLT<T>& iblt, size_t idx) {
    auto hte = iblt.hashTable_.at(idx);
    // can only get the peers of 'pure' entries
    if (! hte.isPure()) return "";
    const auto [hash0, hash1, hash2] = iblt.hash(hte.keySum);
    return prtPeer(iblt, idx, hash0) + prtPeer(iblt, idx, hash1) + prtPeer(iblt, idx, hash2);
}

template<typename T>
static inline std::ostream& operator<<(std::ostream& out, const IBLT<T>& iblt) {
    out << "idx count keySum keyCheck\n";
    auto idx = 0;
    for (const auto& hte : iblt.hashTable_) {
        out << std::hex << std::setw(2) << idx << hte << prtPeers(iblt, idx) << "\n";
        idx++;
    }
    return out;
}

}  // namespace dct

#endif  // SYNCPS_IBLT_HPP
