/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Pollere, Inc added (6/14/2020) checks for validity to file
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

#include <cmath>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <ndn-ind/name.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>

namespace syncps {

namespace bio = boost::iostreams;

/*
 * Optimal number of hashes is 3 or 4. 3 results in less computation and
 * fewer cache misses so this code uses 3 hashes. The following
 * declaration documents this fact but doesn't allow the number of
 * hashes to be changed.
 */
static constexpr size_t N_HASH{3};
static constexpr size_t N_HASHCHECK{11};

class HashTableEntry
{
   public:
    int32_t count;
    uint32_t keySum;
    uint32_t keyCheck;

    bool isPure() const
    {
        if (count == 1 || count == -1) {
            uint32_t check = ndn::CryptoLite::murmurHash3(N_HASHCHECK, keySum);
            return keyCheck == check;
        }
        return false;
    }
    bool isEmpty() const
    {
        return count == 0 && keySum == 0 && keyCheck == 0;
    }
};

class IBLT;
static inline std::ostream& operator<<(std::ostream& out, const IBLT& iblt);
static inline std::ostream& operator<<(std::ostream& out, const HashTableEntry& hte);

/**
 * @brief Invertible Bloom Lookup Table (Invertible Bloom Filter)
 *
 * Used by Partial Sync (PartialProducer) and Full Sync (Full Producer)
 */
class IBLT
{
  private:
    static constexpr int INSERT = 1;
    static constexpr int ERASE = -1;

  public:
    class Error : public std::runtime_error
    {
       public:
        using std::runtime_error::runtime_error;
    };

    /**
     * @brief constructor
     *
     * @param expectedNumEntries the expected number of entries in the IBLT
     */
    explicit IBLT(size_t expectedNumEntries)
    {
        // 1.5x expectedNumEntries gives very low probability of decoding failure
        size_t nEntries = expectedNumEntries + expectedNumEntries / 2;
        // make nEntries exactly divisible by N_HASH
        size_t remainder = nEntries % N_HASH;
        if (remainder != 0) {
            nEntries += (N_HASH - remainder);
        }
        m_hashTable.resize(nEntries);
    }

    IBLT(const std::vector<HashTableEntry>& hashTable) : m_hashTable(hashTable) {}

    /**
     * @brief Populate the hash table using the vector representation of IBLT
     *
     * @param ibltName the Component representation of IBLT
     * @throws Error if size of values is not compatible with this IBF
     */
    void initialize(const ndn::Name::Component& ibltName)
    {
        const auto& values = extractValueFromName(ibltName);

        if (3 * m_hashTable.size() != values.size()) {
            BOOST_THROW_EXCEPTION(Error("Received IBF cannot be decoded!"));
        }
        for (size_t i = 0; i < m_hashTable.size(); i++) {
            HashTableEntry& entry = m_hashTable.at(i);
            if (values[i * 3] != 0) {
                entry.count = values[i * 3];
                entry.keySum = values[(i * 3) + 1];
                entry.keyCheck = values[(i * 3) + 2];
            }
        }
    }

    /**
     * Entry Hash functions. The hash table is split into N_HASH
     * equal-sized sub-tables with a different hash function for each.
     * Each entry is added/deleted from all subtables.
     */
    auto hash0(size_t key) const noexcept
    {
        auto stsize = m_hashTable.size() / N_HASH;
        return ndn::CryptoLite::murmurHash3(0, key) % stsize;
    }
    auto hash1(size_t key) const noexcept
    {
        auto stsize = m_hashTable.size() / N_HASH;
        return ndn::CryptoLite::murmurHash3(1, key) % stsize + stsize;
    }
    auto hash2(size_t key) const noexcept
    {
        auto stsize = m_hashTable.size() / N_HASH;
        return ndn::CryptoLite::murmurHash3(2, key) % stsize + stsize * 2;
    }

    /** validity checking for 'key' on peel or delete
     *
     * Try to detect a corrupted iblt or 'invalid' key (deleting an item
     * twice or deleting something that wasn't inserted). Anomalies
     * detected are:
     *  - one or more of the key's 3 hash entries is empty
     *  - one or more of the key's 3 hash entries is 'pure' but doesn't
     *    contain 'key'
     */
    bool chkPeer(size_t key, size_t idx) const noexcept
    {
        auto hte = getHashTable().at(idx);
        return hte.isEmpty() || (hte.isPure() && hte.keySum != key);
    }

    bool badPeers(size_t key) const noexcept
    {
        return chkPeer(key, hash0(key)) || chkPeer(key, hash1(key)) ||
               chkPeer(key, hash2(key));
    }

    void insert(uint32_t key) { update(INSERT, key); }

    void erase(uint32_t key)
    {
        if (badPeers(key)) {
            std::cerr << "error - invalid iblt erase: badPeers for key "
                      << std::hex << key << "\n";
            return;
        }
        update(ERASE, key);
    }

    /**
     * @brief List all the entries in the IBLT
     *
     * This is called on a difference of two IBLTs: ownIBLT - rcvdIBLT
     * Entries listed in positive are in ownIBLT but not in rcvdIBLT
     * Entries listed in negative are in rcvdIBLT but not in ownIBLT
     *
     * @param positive
     * @param negative
     * @return true if decoding is complete successfully
     */
    bool listEntries(std::set<uint32_t>& positive,
                     std::set<uint32_t>& negative) const
    {
        IBLT peeled = *this;

        bool peeledSomething;
        do {
            peeledSomething = false;
            for (const auto& entry : peeled.m_hashTable) {
                if (entry.isPure()) {
                    if (peeled.badPeers(entry.keySum)) {
                        std::cerr << "error - invalid iblt: badPeers for entry:"
                            << entry << "\n";
                        return false;
                    }
                    if (entry.count == 1) {
                        positive.insert(entry.keySum);
                    } else {
                        negative.insert(entry.keySum);
                    }
                    peeled.update(-entry.count, entry.keySum);
                    peeledSomething = true;
                }
            }
        } while (peeledSomething);

        return true;
    }

    IBLT operator-(const IBLT& other) const
    {
        BOOST_ASSERT(m_hashTable.size() == other.m_hashTable.size());

        IBLT result(*this);
        for (size_t i = 0; i < m_hashTable.size(); i++) {
            HashTableEntry& e1 = result.m_hashTable.at(i);
            const HashTableEntry& e2 = other.m_hashTable.at(i);
            e1.count -= e2.count;
            e1.keySum ^= e2.keySum;
            e1.keyCheck ^= e2.keyCheck;
        }
        return result;
    }

    std::vector<HashTableEntry> getHashTable() const { return m_hashTable; }

    /**
     * @brief Appends self to name
     *
     * Encodes our hash table from uint32_t vector to uint8_t vector
     * We create a uin8_t vector 12 times the size of uint32_t vector
     * We put the first count in first 4 cells, keySum in next 4, and keyCheck
     * in next 4. Repeat for all the other cells of the hash table. Then we
     * append this uint8_t vector to the name.
     *
     * @param name
     */
    void appendToName(ndn::Name& name) const
    {
        size_t n = m_hashTable.size();
        size_t unitSize = (32 * 3) / 8;  // hard coding
        size_t tableSize = unitSize * n;

        std::vector<char> table(tableSize);

        for (size_t i = 0; i < n; i++) {
            // table[i*12],   table[i*12+1], table[i*12+2], table[i*12+3] -->
            // hashTable[i].count

            table[(i * unitSize)] = 0xFF & m_hashTable[i].count;
            table[(i * unitSize) + 1] = 0xFF & (m_hashTable[i].count >> 8);
            table[(i * unitSize) + 2] = 0xFF & (m_hashTable[i].count >> 16);
            table[(i * unitSize) + 3] = 0xFF & (m_hashTable[i].count >> 24);

            // table[i*12+4], table[i*12+5], table[i*12+6], table[i*12+7] -->
            // hashTable[i].keySum

            table[(i * unitSize) + 4] = 0xFF & m_hashTable[i].keySum;
            table[(i * unitSize) + 5] = 0xFF & (m_hashTable[i].keySum >> 8);
            table[(i * unitSize) + 6] = 0xFF & (m_hashTable[i].keySum >> 16);
            table[(i * unitSize) + 7] = 0xFF & (m_hashTable[i].keySum >> 24);

            // table[i*12+8], table[i*12+9], table[i*12+10], table[i*12+11] -->
            // hashTable[i].keyCheck

            table[(i * unitSize) + 8] = 0xFF & m_hashTable[i].keyCheck;
            table[(i * unitSize) + 9] = 0xFF & (m_hashTable[i].keyCheck >> 8);
            table[(i * unitSize) + 10] = 0xFF & (m_hashTable[i].keyCheck >> 16);
            table[(i * unitSize) + 11] = 0xFF & (m_hashTable[i].keyCheck >> 24);
        }
        bio::filtering_streambuf<bio::input> in;
        in.push(bio::zlib_compressor());
        in.push(bio::array_source(table.data(), table.size()));

        std::stringstream sstream;
        bio::copy(in, sstream);

        std::string compressedIBF = sstream.str();
        name.append((const uint8_t *)compressedIBF.data(), compressedIBF.size());
    }

    /**
     * @brief Extracts IBLT from name component
     *
     * Converts the name into a uint8_t vector which is then decoded to a
     * a uint32_t vector.
     *
     * @param ibltName IBLT represented as a Name Component
     * @return a uint32_t vector representing the hash table of the IBLT
     */
    std::vector<uint32_t> extractValueFromName(
        const ndn::Name::Component& ibltName) const
    {
        std::string compressed
          (ibltName.getValue().buf(),
           ibltName.getValue().buf() + ibltName.getValue().size());

        bio::filtering_streambuf<bio::input> in;
        in.push(bio::zlib_decompressor());
        in.push(bio::array_source(compressed.data(), compressed.size()));

        std::stringstream sstream;
        bio::copy(in, sstream);
        std::string ibltStr = sstream.str();

        std::vector<uint8_t> ibltValues(ibltStr.begin(), ibltStr.end());
        size_t n = ibltValues.size() / 4;

        std::vector<uint32_t> values(n, 0);

        for (size_t i = 0; i < 4 * n; i += 4) {
            uint32_t t = (ibltValues[i + 3] << 24) + (ibltValues[i + 2] << 16) +
                         (ibltValues[i + 1] << 8) + ibltValues[i];
            values[i / 4] = t;
        }
        return values;
    }

   private:
    void update(int plusOrMinus, uint32_t key)
    {
        size_t bucketsPerHash = m_hashTable.size() / N_HASH;

        for (size_t i = 0; i < N_HASH; i++) {
            size_t startEntry = i * bucketsPerHash;
            uint32_t h = ndn::CryptoLite::murmurHash3(i, key);
            HashTableEntry& entry =
                m_hashTable.at(startEntry + (h % bucketsPerHash));
            entry.count += plusOrMinus;
            entry.keySum ^= key;
            entry.keyCheck ^= ndn::CryptoLite::murmurHash3(N_HASHCHECK, key);
        }
    }

    std::vector<HashTableEntry> m_hashTable;
};

static inline bool operator==(const IBLT& iblt1, const IBLT& iblt2)
{
    auto iblt1HashTable = iblt1.getHashTable();
    auto iblt2HashTable = iblt2.getHashTable();
    if (iblt1HashTable.size() != iblt2HashTable.size()) {
        return false;
    }

    size_t N = iblt1HashTable.size();

    for (size_t i = 0; i < N; i++) {
        if (iblt1HashTable[i].count != iblt2HashTable[i].count ||
            iblt1HashTable[i].keySum != iblt2HashTable[i].keySum ||
            iblt1HashTable[i].keyCheck != iblt2HashTable[i].keyCheck)
            return false;
    }
    return true;
}

static inline bool operator!=(const IBLT& iblt1, const IBLT& iblt2)
{
    return !(iblt1 == iblt2);
}

static inline std::ostream& operator<<(std::ostream& out, const HashTableEntry& hte)
{
    out << std::dec << std::setw(5) << hte.count << std::hex << std::setw(9)
        << hte.keySum << std::setw(9) << hte.keyCheck;
    return out;
}

static inline std::string prtPeer(const IBLT& iblt, size_t idx, size_t rep)
{
    if (idx == rep) {
        return "";
    }
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

static inline std::string prtPeers(const IBLT& iblt, size_t idx)
{
    auto hte = iblt.getHashTable().at(idx);
    if (! hte.isPure()) {
        // can only get the peers of 'pure' entries
        return "";
    }
    return prtPeer(iblt, idx, iblt.hash0(hte.keySum)) +
           prtPeer(iblt, idx, iblt.hash1(hte.keySum)) +
           prtPeer(iblt, idx, iblt.hash2(hte.keySum));
}

static inline std::ostream& operator<<(std::ostream& out, const IBLT& iblt)
{
    out << "idx count keySum keyCheck\n";
    auto idx = 0;
    for (const auto& hte : iblt.getHashTable()) {
        out << std::hex << std::setw(2) << idx << hte << prtPeers(iblt, idx) << "\n";
        idx++;
    }
    return out;
}

}  // namespace syncps

#endif  // SYNCPS_IBLT_HPP
