#ifndef RPACKET_HPP
#define RPACKET_HPP
#pragma once
/*
 * DCT (raw) packet TLV parsing
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
#include <sstream>
#include "date/date.h" // XXX should be in <chrono>

#include "../sigmgrs/sigmgr_defs.hpp"
#include "tlv_parser.hpp"

namespace dct {

// return a parser for a Name object.
struct rName : tlvParser {
    constexpr rName() = default;
    constexpr rName(const rName&) = default;
    constexpr rName(rName&&) = default;
    constexpr rName& operator=(const rName&) = default;
    constexpr rName& operator=(rName&&) = default;

    constexpr explicit rName(tlvParser n) : tlvParser(n) { }
    constexpr rName(const std::vector<uint8_t>& v) : tlvParser(v) { }

    // a name is valid if its length exactly covers its contained TLVs.
    bool valid() const {
        try {
            tlvParser t(*this);
            while (! t.eof()) t.nextBlk();
        } catch (const runtime_error& e) { return false; }
        return true;
    }

    auto last() const { return lastBlk(); }

    constexpr auto operator<=>(const rName& rhs) const noexcept;

    constexpr auto operator==(const rName& rhs) const noexcept {
        if (size() != rhs.size()) return false;
        return std::memcmp(data(), rhs.data(), size()) == 0;
    }

    // return a tlvParser for component 'comp' of this. If 'comp' is negative,
    // the component is -comp from the end.
    auto operator[](int comp) const {
        if (comp < 0) comp += nBlks();
        return nthBlk(comp);
    }

    constexpr bool isPrefix(const rName& nm) const noexcept;
    constexpr auto first(int comp) const;
};

// A name prefix is the body of a name. I.e., the list of component
// tlv's without the leading tlv::name and length. Because of the leading
// (variable length) length, names can't easily be longest-match ordered
// but prefixes can.
struct rPrefix : tlvParser {
    constexpr rPrefix() = default;
    constexpr rPrefix(const rPrefix&) = default;
    constexpr rPrefix(rPrefix&&) = default;
    constexpr rPrefix& operator=(const rPrefix&) = default;
    constexpr rPrefix& operator=(rPrefix&&) = default;

    constexpr rPrefix(rName n) : tlvParser(n.rest(), 0) { }
    constexpr rPrefix(rPrefix p, size_t sz) : tlvParser(tlvParser::Blk{p.data(), sz}, 0) { }

    using ordering = std::strong_ordering;

    constexpr auto operator<=>(const rPrefix& rhs) const noexcept {
        auto tsz = size();
        auto rsz = rhs.size();
        auto msz = tsz <= rsz? tsz : rsz;
        if (msz == 0) return tsz <=> rsz;
        // binary compare using the length of the shorter name. if one name
        // is a prefix of the other the shorter is 'less'
        auto res = std::memcmp(data(), rhs.data(), msz);
        if (res == 0) return tsz <=> rsz;
        return res < 0? ordering::less : ordering::greater;
    }
    constexpr auto operator==(const rPrefix& rhs) const noexcept {
        if (size() != rhs.size()) return false;
        return std::memcmp(data(), rhs.data(), size()) == 0;
    }

    // 'true' if this prefix is a prefix of 'p'
    constexpr bool isPrefix(const rPrefix& p) const noexcept {
        auto tsz = size();
        auto psz = p.size();
        if (psz < tsz) return false;
        return std::memcmp(data(), p.data(), tsz) == 0;
    }
    constexpr bool isPrefix(const rName& n) const noexcept { return isPrefix(rPrefix{n}); }

    // return a tlvParser for component 'comp' of this. If 'comp' is negative,
    // the component is -comp from the end.
    auto operator[](int comp) const {
        if (comp < 0) comp += nBlks();
        return nthBlk(comp);
    }

    // return an rprefix for the first 'comp' components of this. If 'comp' is negative,
    // the parser contains all components up to -comp from the end.
    constexpr auto first(int comp) const {
        auto n = nBlks();
        if (comp < 0) comp += n;
        if (comp == 0) throw runtime_error("rPrefix::first: zero length prefix requested");
        if (std::cmp_greater(comp, n)) throw runtime_error("rPrefix::first: component index too large");
        if (std::cmp_equal(comp, n)) return rPrefix{*this};
        return rPrefix(*this, nthBlk(comp).data() - data());
    }
};

// name ordering is lexicographic, not shortest first
constexpr auto rName::operator<=>(const rName& rhs) const noexcept { return rPrefix(*this) <=> rPrefix(rhs); }

constexpr bool rName::isPrefix(const rName& nm) const noexcept { return rPrefix(*this).isPrefix(rPrefix(nm)); }
constexpr auto rName::first(int comp) const { return rPrefix(*this).first(comp); }

} // namespace dct

template<> struct std::hash<dct::rName> {
    size_t operator()(const dct::rName& c) const noexcept { return std::hash<dct::tlvParser>{}(c); }
};
template<> struct std::hash<dct::rPrefix> {
    size_t operator()(const dct::rPrefix& c) const noexcept { return std::hash<dct::tlvParser>{}(c); }
};


/* ---------
 * Name formatters are defined here since later routines in this header want
 * to use them. They have to be defined outside of the dct namespace so we
 * leave it then re-enter it after these defs.
 */

template<> struct dct::formatter<dct::rPrefix> {
    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
        //if (ctx.begin() != ctx.end()) throw_format_error("invalid format");
        return ctx.end();
    }
    auto format(const dct::rPrefix& p, format_context& ctx) const -> format_context::iterator {
        auto np = [](auto s) -> bool { for (auto c : s) if (c < 0x20 || c >= 0x7f) return true; return false; };
        auto out = ctx.out();
        for (auto blk : dct::rPrefix{p}) {
            auto s = blk.rest();
            if (blk.isType(dct::tlv::Timestamp)) {
                auto ts = blk.toTimestamp();
                out = dct::format_to(out, "/{:%g-%m-%d@%T}", ts);
            } else if (np(s)) {
                // if there are any non-printing characters, format as hex. Otherwise format as a string.
                //XXX look for 'tagged' timestamps (should change to TLV and get rid of this)
                if (s.size() > 10) {
                    out = dct::format_to(out, "/^{:02x}..", fmt::join(s.begin(), s.begin()+8, ""));
                } else if (s.size() == 9 && s[0] == 0xfc && s[1] == 0) {
                    auto us = ((uint64_t)s[2] << 48) | ((uint64_t)s[3] << 40) | ((uint64_t)s[4] << 32) |
                              ((uint64_t)s[5] << 24) | ((uint64_t)s[6] << 16) | ((uint64_t)s[7] << 8) | s[8];
                    auto ts = dct::tdv_clock::time_point(std::chrono::microseconds(us));
                    out = dct::format_to(out, "/{:%g-%m-%d@%T}", ts);
                } else {
                    out = dct::format_to(out, "/^{:02x}", fmt::join(s, ""));
                }
            } else {
                out = dct::format_to(out, "/{}", std::string_view((char*)s.data(), s.size()));
            }
        }
        return out;
    }
};

template<> struct dct::formatter<dct::rName> {
    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
        //if (ctx.begin() != ctx.end()) throw_format_error("invalid format");
        return ctx.end();
    }
    auto format(const dct::rName& n, format_context& ctx) const -> format_context::iterator {
        return format_to(ctx.out(), "{}", dct::rPrefix(n));
    }
};

namespace dct {

struct rState : tlvParser {
    constexpr rState() = default;
    rState(const rState&) = default;
    rState(rState&&) = default;
    rState& operator=(const rState&) = default;
    rState& operator=(rState&&) = default;

    rState(tlvParser i) : tlvParser(i) { }
    rState(const uint8_t* pkt, size_t sz) : tlvParser(pkt, sz) { }
    rState(const std::vector<uint8_t>& v) : tlvParser(v) { }

    // a cState is valid if it starts with the correct TLV, its name is valid and
    // it contains the 3 required TLV blocks in the right order and nothing else.
    // A cState name must contain at least 3 components (schema ID, collection name
    // and iblt) and the iblt must be non-zero.
    bool valid() const {
        try {
            tlvParser t(*this);
            auto n = rName(t.nextBlk(tlv::Name));
            if (! n.valid() || n.nBlks() < 3 || n[-1].size() == 0) return false;
            t.nextBlk(tlv::Nonce);
            t.nextBlk(tlv::Lifetime);
            if (! t.eof()) return false;
        } catch (const runtime_error& e) { return false; }
        return true;
    }

    auto name() const { return rName(tlvParser(*this).nextBlk(tlv::Name)); }

    auto nonce() const {
        tlvParser t(*this);
        auto n = t.findBlk(tlv::Nonce).rest();
        if (n.size() != 4) throw runtime_error("nonce length invalid");
        return uint32_t(n[0]) | n[1] << 8 | n[2] << 16 | n[3] << 24;
    }
    auto lifetime() const {
        tlvParser t(*this);
        auto lt = t.findBlk(tlv::Lifetime).toNumber();
        if (lt == 0 || lt > 1000*3600) throw runtime_error("cState lifetime invalid");
        return std::chrono::milliseconds(lt);
    }
    auto operator<=>(const rState& rhs) const noexcept { return name() <=> rhs.name(); }
};

struct rData : tlvParser {
    constexpr rData() = default;
    rData(const rData&) = default;
    rData(rData&&) = default;
    rData& operator=(const rData&) = default;
    rData& operator=(rData&&) = default;

    rData(tlvParser d) : tlvParser(d) { }
    rData(const uint8_t* pkt, size_t sz) : tlvParser(pkt, sz) { }
    rData(const std::vector<uint8_t>& v) : tlvParser(v) { }

    // a cAdd is valid if it starts with the correct TLV, its name is valid and
    // it contains the 5 required TLV blocks in the right order and nothing else.
    // A cAdd name must contain at least 3 components (schema ID, collection name
    // and iblt hash). The iblt hash must be type 'Version' and < 9 bytes.
    bool valid() const {
        try {
            tlvParser t(*this);
            auto n = rName(t.nextBlk(tlv::Name));
            if (! n.valid() || n.nBlks() < 3) return false;
            t.nextBlk(tlv::MetaInfo);
            t.nextBlk(tlv::Content);
            t.nextBlk(tlv::SignatureInfo);
            t.nextBlk(tlv::SignatureValue);
            if (! t.eof()) return false;
        } catch (const runtime_error& e) { return false; }
        return true;
    }

    auto name() const { return rName(tlvParser(*this).nextBlk(tlv::Name)); }

    auto metainfo() const { return tlvParser(*this).findBlk(tlv::MetaInfo); }

        auto contentType() const { return metainfo().findBlk(tlv::ContentType).toByte(); }

    auto content() const { return tlvParser(*this).findBlk(tlv::Content); }

    auto sigInfo() const { return tlvParser(*this).findBlk(tlv::SignatureInfo); }

        auto sigType() const { return sigInfo().findBlk(tlv::SignatureType).toByte(); }

        auto& signer() const {
            static constinit std::array<uint8_t,4> kloc{ 28, thumbPrint_s+2, 29, thumbPrint_s };
            auto si = sigInfo().findBlk(tlv::KeyLocator);
            if (memcmp(si.data(), kloc.data(), kloc.size()) != 0)
                throw runtime_error("KeyLocator not a DCT thumbprint");
            return *(thumbPrint*)(si.data() + sizeof(kloc));
        }

        thumbPrint computeTP() const {
            thumbPrint tp;
            crypto_hash_sha256(tp.data(), data(), size());
            return tp;
        }

    auto signature() const { return tlvParser(*this).findBlk(tlv::SignatureValue); }

    auto operator<=>(const rData& rhs) const noexcept { return name() <=> rhs.name(); }
};

// Cert validity periods use a time point encoded in ISO 8601-1:2019 format (the 2014
// and later versions of the standard *require* that lexicographic order correspond
// to chronological order (e.g., pad with leading zeros, not spaces). This is a struct
// so it can include its ordering operators
struct iso8601 : std::array<uint8_t,15> {
    iso8601(std::chrono::system_clock::time_point tp) {
        auto s = dct::format("{:%G%m%dT%H%M%S}", fmt::gmtime(tp));
        std::copy(s.begin(), s.begin()+this->size(), this->begin());
    }
    auto toTP() const {
        std::chrono::system_clock::time_point tp{};
        std::istringstream is(std::string((const char*)data(), size()));
        date::from_stream(is, "%Y%m%dT%H%M%S", tp);
        return tp;
    }
    using ordering = std::strong_ordering;
    auto operator<=>(const iso8601& rhs) const noexcept {
        auto res = std::memcmp(data(), rhs.data(), size());
        return res == 0? ordering::equal : res < 0? ordering::less : ordering::greater;
    }
    auto operator==(const iso8601& rhs) const noexcept {
        return std::memcmp(data(), rhs.data(), size()) == 0;
    }
};

// An rCert is an rData with a particular structure.  This class validates that structure.
struct rCert : rData {
    constexpr rCert() = default;
    rCert(rData d) : rData{d} { }

    // The cert's rData validity was checked on arrival. Check that its content type is
    // Key and its sigInfo contains a validity period.
    bool validForm() const noexcept {
        // Since the rData is valid none of the following should throw
        if (contentType() != uint8_t(tlv::ContentType_Key)) return false;
        // a DCT cert siginfo is constant size so its entire structure can be
        // checked at once
        static const std::array<uint8_t,4> si0{22, 81, 27, 1};
        static const std::array<uint8_t,4> si5{28, thumbPrint_s+2, 29, thumbPrint_s};
        static const std::array<uint8_t,8> si41{253, 0, 253, 38, 253, 0, 254, 15};
        static const std::array<uint8_t,4> si64{253, 0, 255, 15};
        const auto si = sigInfo().data();
        if (std::memcmp(si+0, si0.data(), si0.size()) || std::memcmp(si+5, si5.data(), si5.size()) ||
            std::memcmp(si+41, si41.data(), si41.size()) || std::memcmp(si+64, si64.data(), si64.size())) {
            print("validForm: {} invalid\n", name());
            return false; 
        }
        return true;
    }

    // NOTE: the following five routines *assume* that rCert validity has been checked with .validForm()
    // and will misbehave badly if that is not true.

    auto validAfter() const noexcept { return ((const iso8601*)(sigInfo().data() + 49))->toTP(); }
    auto validUntil() const noexcept { return ((const iso8601*)(sigInfo().data() + 68))->toTP(); }

    bool expired() const noexcept {
        auto now = iso8601(std::chrono::system_clock::now());
        return std::memcmp(sigInfo().data()+68, now.data(), now.size()) < 0;
    }
    bool notValidYet() const noexcept {
        auto now = iso8601(std::chrono::system_clock::now());
        return std::memcmp(now.data(), sigInfo().data()+49, now.size()) < 0;
    }
    bool validNow() const noexcept {
        auto now = iso8601(std::chrono::system_clock::now());
        const auto si = sigInfo().data();
        if (std::memcmp(now.data(), si+49, now.size()) < 0) {
            print("validNow: {} not valid until {}\n", name(), validAfter());
            return false;
        }
        if (std::memcmp(si+68, now.data(), now.size()) < 0) {
            print("validNow: {} expired {}\n", name(), validUntil());
            return false;
        }
        return true;
        //return std::memcmp(si+68, now.data(), now.size()) >= 0 && std::memcmp(now.data(), si+49, now.size()) >= 0;
    }

    // check that cert's sigInfo is formatted correctly and that it's within its validity period.
    bool valid() const noexcept { return validForm() && validNow(); }

    // check that cert is valid and its signing type matches 'sType'
    // (which is usually the schema's required cert signing type).
    bool valid(uint8_t sType) const noexcept {
        if (sigType() != sType) print("rcert::valid: signing type is {} should be {}\n", sigType(), sType);
        return valid() && sigType() == sType;
    }
};

} // namespace dct

#endif  // RPACKET_HPP
