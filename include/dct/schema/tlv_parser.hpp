#ifndef TLVPARSER_HPP
#define TLVPARSER_HPP
/*
 * Data Centric Transport NDN packet parser
 *
 * Copyright (C) 2020-2 Pollere LLC
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

#include <span>
#include <stdexcept>
#include <vector>
#include "dct/format.hpp"
#include "tlv.hpp"
#include "ndn-ind/data.hpp"
#include "ndn-ind/interest.hpp"
using runtime_error = std::runtime_error;

// routines for parsing NDN tlv blocks
struct tlvParser {
    static constexpr uint8_t extra_bytes_code{253};
    using Blk = std::span<const uint8_t>;
    Blk m_blk{};
    size_t m_off{}; 

    constexpr size_t size() const noexcept { return m_blk.size(); }

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

    constexpr Blk subspan(size_t off, size_t cnt = std::dynamic_extent) const { return m_blk.subspan(off, cnt); }

    constexpr Blk rest() const { return subspan(off()); }

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

    constexpr tlvParser() { }

    constexpr tlvParser(Blk blk, size_t off) noexcept : m_blk{blk}, m_off{off} { }

    // a tlvParser is intended to parse something wrapped in a tlv (starting
    // with a type & a length). It assumes they type has been checked and skips
    // it but does check that the length matches the (externally supplied) size.
    tlvParser(const uint8_t* p, size_t s, size_t off = 1) : tlvParser(Blk(p, s), off) {
        // check that size agrees with encoded tlv length (this will leave the offset at first content byte)
        auto len = blkLen();
        if (len + m_off != size())
            throw runtime_error(format("len {} != size {}", len + m_off, size()));
    }
    tlvParser(const std::vector<uint8_t>& v) : tlvParser(v.data(), v.size()) { }

    tlvParser(const ndn::Data& d) : tlvParser(*d.wireEncode()) { }

    tlvParser(const ndn::Interest& i) : tlvParser(*i.wireEncode()) { }

    tlvParser(const ndn::Name& n) : tlvParser(*n.wireEncode()) { }

    // this tlvParser parses a vector of tlv's (like the vector returned by
    // data.getContent()) starting at an explicit offset (usually 0) and
    // doesn't look for a type or length.
    tlvParser(const std::vector<uint8_t>& v, size_t off) : tlvParser(Blk(v.data(), v.size()), off) { }

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

    // return the backing bytes of the block as a new vector
    auto asVec() const noexcept { return std::vector<uint8_t>(m_blk.begin(), m_blk.end()); }

    constexpr bool starts_with(Blk prefix, size_t off) const noexcept {
        return size() - off >= prefix.size() && std::equal(prefix.begin(), prefix.end(), m_blk.subspan(off).begin());
    }
    constexpr bool starts_with(Blk prefix) const noexcept { return starts_with(prefix, m_off); }

    // return the contents of a tlv block as an uint64_t. An error is thrown if the block
    // contains more than 8 bytes.
    auto toNumber() {
        auto len = size() - off();
        if (len > 8) throw runtime_error("block too large to be a number");
        uint64_t res{};
        while (! eof()) { res <<= 8; res |= nextByte(); } 
        return res;
    }

    // return the contents of the tlv block as a span of type T. An error is thrown
    // if the block doesn't contain an integral number of items (0 or more).
    template <typename T>
    auto toSpan() {
        auto len = size() - off();
        if (len % sizeof(T) != 0) throw runtime_error("block content not integer multiple of item size");
        return std::span<const T>((const T*)(m_blk.data()+m_off), len / sizeof(T));
    }

    using ordering = std::strong_ordering;
    ordering operator<=>(const tlvParser& rhs) const noexcept {
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

template<> struct std::hash<tlvParser> {
    size_t operator()(const tlvParser& tp) const noexcept {
        return std::hash<std::u8string_view>{}({(char8_t*)tp.data(), tp.size()});
    }
};

#endif // TLVPARSER_HPP
