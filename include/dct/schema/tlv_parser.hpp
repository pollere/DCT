#ifndef TLVPARSER_HPP
#define TLVPARSER_HPP
#pragma once
/*
 * Data Centric Transport TLV-encoded packet parser
 *
 * Copyright (C) 2020-2 Pollere LLC
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
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <span>
#include <stdexcept>
#include <utility>
#include <vector>
#include "dct/format.hpp"
#include "dct/tdv_clock.hpp"
#include "tlv.hpp"

namespace dct {

using runtime_error = std::runtime_error;

// routines for parsing NDN-style tlv blocks
struct tlvParser {
    static constexpr uint8_t extra_bytes_code{253};
    using Blk = std::span<const uint8_t>;
    Blk m_blk{};
    size_t m_off{}; 

    constexpr size_t size() const noexcept { return m_blk.size(); }
    constexpr ssize_t ssize() const noexcept { return m_blk.size(); }

    constexpr auto data() const noexcept { return m_blk.data(); }

    constexpr auto off() const noexcept { return m_off; }

    constexpr auto eof() const noexcept { return off() >= size(); }

    constexpr auto len() const noexcept { return size() - off(); }

    constexpr size_t typ() const {
        auto b = data()[0];
        if (b < extra_bytes_code) return b;
        if (b > extra_bytes_code) throw runtime_error("block type too large");
        return (data()[1] << 8) | data()[2];
    }

    constexpr Blk subspan(size_t off, size_t cnt = std::dynamic_extent) const noexcept { return m_blk.subspan(off, cnt); }

    constexpr Blk rest() const noexcept { return subspan(off()); }

    constexpr auto isType(uint8_t typ) const noexcept { return *data() == typ; }
    constexpr auto isType(tlv typ) const noexcept { return isType((uint8_t)typ); }

    constexpr uint8_t operator[](size_t off) const {
        if (off >= size()) throw runtime_error("read past end of tlv block");
        return m_blk[off];
    }

    constexpr uint8_t cur() const {
        if (off() >= size()) throw runtime_error("read past end of tlv block");
        return m_blk[off()];
    }

    constexpr tlvParser() = default;
    constexpr tlvParser(const tlvParser&) = default;
    constexpr tlvParser(tlvParser&&) = default;
    constexpr tlvParser& operator=(const tlvParser&) = default;
    constexpr tlvParser& operator=(tlvParser&&) = default;

    constexpr tlvParser(Blk blk, size_t off) noexcept : m_blk{blk}, m_off{off} { }

    // a tlvParser is intended to parse something wrapped in a tlv (starting
    // with a type & a length). It assumes they type has been checked and skips
    // it but does check that the length matches the (externally supplied) size.
    constexpr tlvParser(const uint8_t* p, size_t s, size_t off = 1) : tlvParser(Blk(p, s), off) {
        // check that size agrees with encoded tlv length (this will leave the offset at first content byte)
        auto len = blkLen();
        if (len + m_off != size())
            throw runtime_error(format("len {} != size {}", len + m_off, size()));
    }
    constexpr tlvParser(const std::vector<uint8_t>& v) : tlvParser(v.data(), v.size()) { }

    // this tlvParser parses a vector of tlv's (like the vector returned by
    // data.getContent()) starting at an explicit offset (usually 0) and
    // doesn't look for a type or length.
    constexpr tlvParser(const std::vector<uint8_t>& v, size_t off) : tlvParser(Blk(v.data(), v.size()), off) { }

    auto nextByte() {
        if (off() >= size()) throw runtime_error("read past end of tlv block");
        return m_blk[m_off++];
    }

    // decode the variable length 'lenth' field of the TLV. 'off' will end up
    // at the octet following the length (start of the block's content).
    size_t blkLen() {
        auto c = nextByte();
        if (c < extra_bytes_code) return c;
        if (c > extra_bytes_code) throw runtime_error("tlv length >64k");
        return (size_t(nextByte()) << 8) | nextByte();
    }

    /*
     * return a parser for the block starting at the current offset and advance
     * this block's offset over that block. The offset of the new block will be
     * set to its first content byte.
     *
     * If all the data in this block has been consumed, return a parser for an empty blk..
     */
    auto nextBlk() {
        if (eof()) return tlvParser{Blk{},0U};

        auto strt = m_off;  // remember start
        blkLen();           // skip over type
        auto len = blkLen();
        if (m_off + len > m_blk.size()) throw runtime_error("nested tlv block larger than parent");
        auto off = m_off - strt; // new block's tlv hdr size
        m_off += len;
        return tlvParser(subspan(strt, len + off), off);
    }

    /*
     * check that the block at the current offset is type 'typ' then return a parser for it.
     */
    auto nextBlk(uint8_t typ) {
        if (eof()) throw runtime_error(format("expected type {} block, got eof", typ));
        if (cur() != typ) throw runtime_error(format("expected type {} block, got {}", typ, cur()));
        return nextBlk();
    }
    auto nextBlk(tlv typ) { return nextBlk((uint8_t)typ); }

    // skip over 'n' bytes in the tlv. return 'this' to support method chaining.
    auto& skip(size_t s) {
        if (m_off + s > size()) throw runtime_error("skip past end of tlv block");
        m_off += s;
        return *this;
    }
    auto& skipTo(size_t off) {
        if (off > size()) throw runtime_error("skip past end of tlv block");
        m_off = off;
        return *this;
    }
    // return a parser for the block starting s bytes after the current offset
    // (generally used to skip over a name prefix)
    auto nextAt(size_t off) { return skipTo(off).nextBlk(); };

    auto nextAfter(size_t off) { return skip(off).nextBlk(); };

    // support c++17 or later range-based 'for' over contained tlv's
    struct tlvIter {
        tlvParser& p_;
        tlvIter(tlvParser& p) : p_{p} { }
        bool operator!=(unsigned long e) const { return p_.m_off < e; }
        void operator++() const { }
        auto operator*() { return p_.nextBlk(); }
    };
    auto begin() { return tlvIter(*this); }
    auto end() const { return size(); }

     // find the next block of type 'typ' and return a parser for it.
    auto findBlk(uint8_t typ) {
        for (auto blk : *this) if (blk[0] == typ) return blk;
        throw runtime_error(format("no type {} block found", typ));
    }
    auto findBlk(tlv typ) { return findBlk((uint8_t)typ); }

     // find the last block and return a parser for it.
    auto lastBlk() const {
        tlvParser b{*this};
        tlvParser blk{};
        for (auto i = b.begin(); i != b.end(); blk = *i) { }
        return blk;
    }

    // return the number of tlv blocks in this block 
    auto nBlks() const {
        size_t nblks{};
        tlvParser b{*this};
        for (auto i = b.begin(); i != b.end(); *i) ++nblks;
        return nblks;
    }

    // return a parser for the  n'th blk of the tlv without changing its state
    // (used, for example,  to get a particular component from a name).
    auto nthBlk(int blkIdx) const {
        int n{blkIdx};
        tlvParser b{*this};
        tlvParser blk{};
        for (auto i = b.begin(); i != b.end(); ) {
            blk = *i;
            if (--n < 0) return blk;
        }
        throw runtime_error(format("requested blk {} but only {} blks in TLV", blkIdx, blkIdx - n));
    };

    // return the entire Blk as a span
    constexpr auto asSpan() const noexcept { return m_blk; }

    // return the backing bytes of the entire block as a new vector
    auto asVec() const noexcept { return std::vector<uint8_t>(m_blk.begin(), m_blk.end()); }

    constexpr bool starts_with(Blk prefix, size_t off) const noexcept {
        return size() - off >= prefix.size() && std::equal(prefix.begin(), prefix.end(), m_blk.subspan(off).begin());
    }
    constexpr bool starts_with(Blk prefix) const noexcept { return starts_with(prefix, m_off); }

    // convert encoded integer in big-endian order to an uint64_t
    auto bsToUInt(auto l, auto o) const noexcept {
        uint64_t res{};
        const auto* cp = m_blk.data() + o;
        while (--l >= 0) { res <<= 8; res |= *cp++; } 
        return res;
    }

    // convert encoded integer to a microsecond timestamp
    auto bsToTS(auto l, auto o) const noexcept {
        return tdv_clock::time_point(std::chrono::microseconds(bsToUInt(l, o)));
    }

    // return contents of a 1 byte tlv block
    auto toByte() const {
        if (size() != 3) throw runtime_error("expected 1 byte of TLV content");
        return m_blk[2];
    }

    // return the contents of a tlv block as an uint64_t. An error is thrown if the block
    // contains more than 8 bytes.
    auto toNumber() const {
        auto o = off();
        int l = size() - o;
        if (l > 8) throw runtime_error("block too large to be a number");
        return bsToUInt(l, o);
    }

    // return the contents of a tlv block as a time point.
    // An error is thrown if the block is not a timestamp.
    auto toTimestamp() const {
        auto o = off();
        int l = size() - o;
        if (l <= 8 && isType(tlv::Timestamp)) return bsToTS(l, o);
        //XXX look for 'tagged' timestamps (should change to TLV and get rid of these)
        if (l != 9 || m_blk[o] != 0xfc || m_blk[o+1] != 0) throw runtime_error("block not a timestamp");
        return bsToTS(l-2, o+2);
    }

    // return the contents of the tlv block as a string_view.
    constexpr auto toSv() const noexcept { return std::string_view((const char*)(m_blk.data()+m_off), size() - off()); }

    // return the contents of the tlv block as a span of type T. An error is thrown
    // if the block doesn't contain an integral number of items (0 or more).
    template <typename T = uint8_t>
    constexpr auto toSpan() const noexcept(sizeof(T) == 1) {
        auto len = size() - off();
        if constexpr (sizeof(T) != 1) {
            if (len % sizeof(T) != 0) throw runtime_error("block content not integer multiple of item size");
        }
        return std::span<const T>((const T*)(m_blk.data()+m_off), len / sizeof(T));
    }

    // return a copy of the contents of the tlv block as a vector of type T. An error
    // is thrown if the block doesn't contain an integral number of items (0 or more).
    template <typename T = uint8_t>
    constexpr auto toVector() const noexcept(sizeof(T) == 1) {
        auto s = toSpan<T>();
        return std::vector<T>(s.begin(), s.end());
    }

    using ordering = std::strong_ordering;
    constexpr ordering operator<=>(const tlvParser& rhs) const noexcept {
        // order by size then content (not compatible with 'longest match'
        // but this is comparing packets, not names)
        auto sz = size();
        auto rsz = rhs.size();
        if (sz != rsz) return sz <=> rsz;
        auto res = std::memcmp(data(), rhs.data(), sz);
        if (res == 0) return sz <=> rsz;
        return res < 0? ordering::less : ordering::greater;
    }
};

// allow a tlv containing other tlvs to be accessed like a vector
// (e.g., the components of a name). It's assumed that m_off points to the
// start of the first contained tlv. Offsets to each tlv are recorded but
// a parser is only instantiated when that component is accessed.
// The state of the outer tlv is not modified.
struct tlvVec {
    tlvParser b_;   // copy of (outer) tlv being indexed
    std::vector<uint16_t> o_{}; // offset to start of each tlv contained in b_

    tlvVec(const tlvParser& b) : b_{b} {
        size_t off;
        while ((off = b_.off()) < b_.size()) {
            o_.emplace_back(off);
            b_.blkLen();        // skip over type
            b_.skip(b_.blkLen());  // skip over block contents
        }
        if (off != b_.size()) throw runtime_error("tlv larger than enclosing block");
    }
    // return the number of TLVs in the container TLV
    constexpr auto size() const { return o_.size(); }

    // return a tlv parser for component 'comp' of container. If 'comp' is negative,
    // the component returned is 'comp' back from the end.
    auto operator[](int comp) {
        if (comp < 0) comp += size();
        if (std::cmp_greater_equal(comp, size())) throw runtime_error("tlvVec component index too large");
        return b_.nextAt(o_[comp]);
    }

    // return the container tlv with the offset set to the first component
    auto& tlv() { b_.skipTo(o_[0]); return b_; }
};

} // namespace dct

template<> struct std::hash<dct::tlvParser> {
    constexpr size_t operator()(const dct::tlvParser& tp) const noexcept {
        return std::hash<std::u8string_view>{}({(char8_t*)tp.data(), tp.size()});
    }
};

#endif // TLVPARSER_HPP
