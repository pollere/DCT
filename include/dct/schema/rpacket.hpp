#ifndef RPACKET_HPP
#define RPACKET_HPP
/*
 * Data Centric Transport NDN (raw) Interest and Data packet parsers
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

#include <compare>
#include <cstring>

#include "tlv_parser.hpp"

// return a parser for a Name object.
struct rName : tlvParser {
    rName() : tlvParser() { }
    rName(tlvParser n) : tlvParser(n) { }
    rName(const std::vector<uint8_t>& v) : tlvParser(v) { }
    rName(const ndn::Name& n) : tlvParser(n) { }

    // a name is valid if its length exactly covers its contained TLVs.
    bool valid() const {
        try {
            tlvParser t(*this);
            while (! t.eof()) t.nextBlk();
        } catch (const runtime_error& e) { return false; }
        return true;
    }

    // A name prefix is the body of a name. I.e., the list of component
    // tlv's without the leading tlv::name and length. Because of the leading
    // (variable length) length, names can't be easily longest-match ordered
    // but prefixes can.
    struct rPrefix : tlvParser {
        rPrefix() : tlvParser() { }
        rPrefix(const rName& n) : tlvParser(n.rest(), 0) { }
        rPrefix(rName&& n) : tlvParser(n.rest(), 0) { }
        rPrefix(const rPrefix& p, size_t sz) : tlvParser(tlvParser::Blk{p.data(), sz}, 0) { }
        rPrefix(rPrefix&& p, size_t sz) : tlvParser(tlvParser::Blk{p.data(), sz}, 0) { }

        using ordering = std::strong_ordering;
        auto operator<=>(const rPrefix& rhs) const noexcept {
            auto tsz = size();
            auto rsz = rhs.size();
            // binary compare using the length of the shorter name. if one name
            // is a prefix of the other the shorter is 'less'
            auto res = std::memcmp(data(), rhs.data(), tsz <= rsz? tsz : rsz);
            if (res == 0) return tsz <=> rsz;
            return res < 0? ordering::less : ordering::greater;
        }
        constexpr auto operator==(const rPrefix& rhs) const noexcept {
            if (size() != rhs.size()) return false;
            return std::memcmp(data(), rhs.data(), size()) == 0;
        }

        // 'true' if this prefix is a prefix of 'p'
        constexpr bool isPrefix(const rPrefix& p) const {
            auto tsz = size();
            auto psz = p.size();
            if (psz < tsz) return false;
            return std::memcmp(data(), p.data(), tsz) == 0;
        }
        bool isPrefix(const rName& n) const { return isPrefix(rPrefix{n}); }
    };

    auto operator<=>(const rName& rhs) const noexcept { return rPrefix(*this) <=> rPrefix(rhs); }
    auto operator==(const rName& rhs) const noexcept { return rPrefix(*this) == rPrefix(rhs); }

    // 'true' if this name is a prefix of 'nm'
    bool isPrefix(const rName& nm) const { return rPrefix(*this).isPrefix(rPrefix(nm)); }

    // convert raw to ndn::Name (ndn-ind backwards compat)
    auto r2n() const {
        ndn::Name n{};
        n.wireDecode(data(), size());
        return n;
    }

    // convert raw to shared_ptr<>& (ndn-ind backwards compat)
    auto r2spcn() const {
        ndn::Name n{};
        n.wireDecode(data(), size());
        return std::make_shared<const ndn::Name>(std::move(n));
    }
};
using rPrefix = rName::rPrefix;

template<> struct std::hash<rName> {
    size_t operator()(const rName& c) const noexcept { return std::hash<tlvParser>{}(c); }
};
template<> struct std::hash<rPrefix> {
    size_t operator()(const rPrefix& c) const noexcept { return std::hash<tlvParser>{}(c); }
};

struct rInterest : tlvParser {
    rInterest() : tlvParser() { }
    rInterest(tlvParser i) : tlvParser(i) { }
    rInterest(const uint8_t* pkt, size_t sz) : tlvParser(pkt, sz) { }
    rInterest(const std::vector<uint8_t>& v) : tlvParser(v) { }
    rInterest(const ndn::Interest& i) : tlvParser(i) { }

    auto name() const { return rName(tlvParser(*this).nextBlk(tlv::Name)); }

    auto nonce() const {
        tlvParser t(*this);
        auto n = t.findBlk(tlv::Nonce).rest();
        if (n.size() != 4) throw runtime_error("nonce length invalid");
        return uint32_t(n[0]) | n[1] << 8 | n[2] << 16 | n[3] << 24;
    }
    auto lifetime() const {
        tlvParser t(*this);
        auto lt = t.findBlk(tlv::InterestLifetime).toNumber();
        if (lt == 0 || lt > 1000*3600) throw runtime_error("interest lifetime invalid");
        return std::chrono::milliseconds(lt);
    }
    auto operator<=>(const rInterest& rhs) const noexcept { return name() <=> rhs.name(); }

    // convert raw to shared_ptr<Interest>& (ndn-ind backwards compat)
    auto r2spi() const {
        ndn::Interest i{};
        i.wireDecode(data(), size());
        return std::make_shared<ndn::Interest>(std::move(i));
    }
    auto r2spci() const {
        ndn::Interest i{};
        i.wireDecode(data(), size());
        return std::make_shared<const ndn::Interest>(i);
    }
    auto r2i() const {
        ndn::Interest i{};
        i.wireDecode(data(), size());
        return i;
    }
};

struct rData : tlvParser {
    rData() : tlvParser() { }
    rData(tlvParser d) : tlvParser(d) { }
    rData(const uint8_t* pkt, size_t sz) : tlvParser(pkt, sz) { }
    rData(const std::vector<uint8_t>& v) : tlvParser(v) { }
    rData(const ndn::Data& d) : tlvParser(d) { }

    // a Data is valid if it starts with the correct TLV, its name is valid and
    // it contains the 5 required TLV blocks in the right order and nothing else.
    bool valid() const {
        try {
            tlvParser t(*this);
            rName(t.nextBlk(tlv::Name)).valid();
            t.nextBlk(tlv::MetaInfo);
            t.nextBlk(tlv::Content);
            t.nextBlk(tlv::SignatureInfo);
            t.nextBlk(tlv::SignatureValue);
            if (! t.eof()) return false;
        } catch (const runtime_error& e) { return false; }
        return true;
    }

    auto name() const { return rName(tlvParser(*this).nextBlk(tlv::Name)); }

    auto metaInfo() const { return tlvParser(*this).findBlk(tlv::MetaInfo); }

    auto content() const { return tlvParser(*this).findBlk(tlv::Content); }

    auto sigInfo() const { return tlvParser(*this).findBlk(tlv::SignatureInfo); }

    auto signature() const { return tlvParser(*this).findBlk(tlv::SignatureValue); }

    auto sigType() const {
        auto st = tlvParser(*this).findBlk(tlv::SignatureInfo).findBlk(tlv::SignatureType);
        if (st.size() != 3) throw runtime_error("malformed Data: multi-byte signature type");
        return st[2];
    }

    auto thumbprint() const {
        static constinit std::array<uint8_t,4> kloc{ 28, 34, 29, 32 };
        auto si = sigInfo().findBlk(tlv::KeyLocator);
        if (memcmp(si.data(), kloc.data(), kloc.size()) != 0) throw runtime_error("KeyLocator not a DCT thumbprint");
        return si.data() + sizeof(kloc);
    }

    auto operator<=>(const rData& rhs) const noexcept { return name() <=> rhs.name(); }

    // convert raw to shared_ptr<cData>& (backwards compat)
    auto r2spd() const {
        ndn::Data d{};
        d.wireDecode(data(), size());
        return std::make_shared<ndn::Data>(std::move(d));
    }
    auto r2d() const {
        ndn::Data d{};
        d.wireDecode(data(), size());
        return d;
    }
};

struct crName : rName {
    std::vector<uint8_t> v_;    // backing store for name
    crName(const ndn::Name& n) : rName{*n.wireEncode()}, v_{*n.wireEncode()} { m_blk = Blk{v_.data(), v_.size()}; }
};

struct crPrefix : rPrefix {
    std::vector<uint8_t> v_;    // backing store for name
    crPrefix(const std::vector<uint8_t>& v) : v_{v} {
        // skip over the (variable length) type and value
        m_blk = Blk{v_.data(), v_.size()};
        m_off = 1; //skip over type
        auto len = blkLen();
        if (len + m_off != size()) throw runtime_error(format("crPrefix: len {} != size {}", len + m_off, size()));
        // the prefix object shouldn't include the TLV hdr
        m_blk = Blk{v_.data()+m_off, v_.size()-m_off};
        m_off = 0;
    }
    crPrefix(const ndn::Name& n) : crPrefix{*n.wireEncode()} { }
};

template<> struct fmt::formatter<rPrefix>: fmt::dynamic_formatter<> {
    template <typename FormatContext>
    auto format(const rPrefix& p, FormatContext& ctx) const -> decltype(ctx.out()) {
        auto np = [](auto s) -> bool { for (auto c : s) if (c < 0x20 || c >= 0x7f) return true; return false; };
        auto out = ctx.out();
        for (auto blk : rPrefix{p}) {
            auto s = blk.rest();
            // if there are any non-printing characters, format as hex. Otherwise format as a string.
            if (np(s)) {
                //XXX look for 'tagged' timestamps (should change to TLV and get rid of this)
                if (s.size() > 10) {
                    out = fmt::format_to(out, "/^{:02x}..", fmt::join(s.begin(), s.begin()+8, ""));
                } else if (s.size() == 9 && s[0] == 0xfc && s[1] == 0) {
                    auto us = ((uint64_t)s[2] << 48) | ((uint64_t)s[3] << 40) | ((uint64_t)s[4] << 32) |
                              ((uint64_t)s[5] << 24) | ((uint64_t)s[6] << 16) | ((uint64_t)s[7] << 8) | s[8];
                    auto ts = std::chrono::system_clock::time_point(std::chrono::microseconds(us));
                    if (std::chrono::system_clock::now() - ts < std::chrono::hours(12)) {
                        out = fmt::format_to(out, "/@{:%H:%M:}{:%S}", ts, ts.time_since_epoch());
                    } else {
                        out = fmt::format_to(out, "/{:%g-%m-%d@%R}", ts);
                    }
                } else {
                    out = fmt::format_to(out, "/^{:02x}", fmt::join(s, ""));
                }
            } else {
                out = fmt::format_to(out, "/{}", std::string_view((char*)s.data(), s.size()));
            }
        }
        return out;
    }
};

template<> struct fmt::formatter<rName>: formatter<rPrefix> {
    template <typename FormatContext>
    auto format(const rName& n, FormatContext& ctx) const -> decltype(ctx.out()) {
        return format_to(ctx.out(), "{}", rPrefix(n));
    }
};

#endif  // RPACKET_HPP
