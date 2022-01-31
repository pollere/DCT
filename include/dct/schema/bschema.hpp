#ifndef BSCHEMA_HPP
#define BSCHEMA_HPP

/*
 * Definitions for reading and writing binary schemas.
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
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <bit>
#include <iostream>
#include <map>
#include <type_traits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include <unordered_map>
#include "dct/format.hpp"

namespace bschema {

// TLV assignments for binary schema encoding. The top level block has
// type 'schema'. The remaining TLVs are blocks contained in it. For the
// schema to be valid, all of those blocks must be present and they must
// be in TLV order. This ordering allows blocks to be validated as they
// are decoded. It is determined by the dependencies between different
// sections and SHOULD NOT BE CHANGED.
//
// Individual items in the interior blocks are not TLV encoded. They
// take one of two forms:
//  - blocks of fixed-size items are just an array of items with
//    the number of items computed from the block type and size.
//  - blocks of variably sized items have an item size (encoded as a
//    tlv length) followed by the many bytes of item data.

enum class sTLV : uint8_t { none = 0,
    schema = 131, str, tok, cert, chain, cor, tag, tmplt, vlist, disc, pub
};

struct schema_error : std::runtime_error { using std::runtime_error::runtime_error; };

// types related to schema items and item indices

// 'tokens' (strings) used by the schema. The strings are all
// concatenated and stored in the string table (stab_). Each token is a
// string_view of the appropriate sequence of characters in stab. The
// token table, tok_, is a vector of these views. Internally, all tokens
// are identified by their index in this vector. The string_view is only
// used to translate between internal and external schema representations.
using bTok = std::string_view;

// schema name component. Encodes component type & value using
// a variable length code.
using bComp = uint8_t;

// schema name component types (encoded in upper 3 bits of byte)
static constexpr int maxTok = 128; // max string tokens with 8 bit tokens
static constexpr uint8_t SC_LIT   = 0x00;
static constexpr uint8_t SC_PARAM = 0x80;
static constexpr uint8_t SC_COR   = 0xA0;
static constexpr uint8_t SC_CALL  = 0xC0;
static constexpr uint8_t SC_INDEX = 0xE0; // E0-FE reserved for runtime tokens
static constexpr uint8_t SC_ANON  = 0xFF;
static constexpr uint8_t SC_VALUE = 0x1F; // payload of non-string tokens

static constexpr bool isLit(bComp c) noexcept { return (c & 0x80) == 0x00; }
static constexpr bool isParam(bComp c) noexcept { return (c & 0xE0) == 0x80; }
static constexpr bool isCor(bComp c) noexcept { return (c & 0xE0) == 0xA0; }
static constexpr bool isCall(bComp c) noexcept { return (c & 0xE0) == 0xC0; }
static constexpr bool isIndex(bComp c) noexcept { return (c & 0xE0) == 0xE0; }
static constexpr bool isAnon(bComp c) noexcept { return c == 0xFF; }
static constexpr bComp typeValue(bComp c) noexcept { return c & SC_VALUE; }
static constexpr bool validType(bComp c) noexcept { return  c < SC_INDEX || c == SC_ANON; }

using bName = std::vector<bComp>;
using compidx = uint8_t;
using certidx = uint8_t;
using tagidx = uint8_t;
using parmBM = uint16_t;
using chainidx = uint8_t;
using bChain = std::vector<chainidx>;
using chainBM = uint8_t; // bitmap of bchain indices
//using corItem = struct{certidx ct1; compidx co1; certidx ct2; compidx co2;}; 
struct corItem {certidx ct1; compidx co1; certidx ct2; compidx co2;}; 
using chainCor = std::vector<corItem>;  // one chain's corespondences
using coridx = uint8_t;
using discidx = uint8_t;
using discBM = uint64_t;
using bVLidx = uint8_t;
using pubidx = uint8_t;
using tmpltidx = uint8_t;
struct tDiscrim {chainBM cbm; tmpltidx tmpl; tagidx disc; bVLidx vl; coridx cor;};
struct tPub {parmBM par; bComp pub; tagidx tag; discBM d;};

static inline constexpr bool operator<(const corItem& l, const corItem& r) {
    return std::tie(l.ct1, l.ct2, l.co1, l.co2) < std::tie(r.ct1, r.ct2, r.co1, r.co2);
}
static inline constexpr bool operator<(const tDiscrim& l, const tDiscrim& r) {
    return std::tie(l.cbm, l.tmpl, l.disc, l.vl, l.cor) < std::tie(r.cbm, r.tmpl, r.disc, r.vl, r.cor);
}
static inline constexpr bool operator<(const tPub& l, const tPub& r) {
    return std::tie(l.par, l.pub, l.tag, l.d) < std::tie(r.par, r.pub, r.tag, r.d);
}

static inline const std::map<sTLV,const char*> tlvName{
    {sTLV::none, "none"},
    {sTLV::schema, "schema"},
    {sTLV::str, "str"},
    {sTLV::tok, "tok"},
    {sTLV::cert, "cert"},
    {sTLV::chain, "chain"},
    {sTLV::cor, "cor"},
    {sTLV::tag, "tag"},
    {sTLV::tmplt, "tmplt"},
    {sTLV::vlist, "vlist"},
    {sTLV::disc, "disc"},
    {sTLV::pub, "pub"}
};

struct bSchema {

    std::string stab_{};
    std::vector<bTok> tok_{};
    std::vector<bName> cert_{};
    std::vector<bChain> chain_{};
    std::vector<chainCor> cor_{};
    std::vector<bName> tag_{};
    std::vector<bName> tmplt_{};
    std::vector<bName> vlist_{};
    std::vector<tDiscrim> discrim_{};
    std::vector<tPub> pub_{};
    std::unordered_map<bTok,bComp> tm_{};
    std::vector<uint8_t> schemaTP_{};

    // return the name of the pub at index 'i'
    bTok pubName(pubidx i) const {
        if (i >= pub_.size()) throw schema_error(format("no pub with index {} in schema", i));
        return tok_[pub_[i].pub];
    }

    // return index of pub with name 'nm'
    auto findPub(bTok nm) const {
        for (pubidx n = pub_.size(), i = 0; i < n; ++i) if (tok_[pub_[i].pub] == nm) return i;
        throw schema_error(format("no pub {} in schema", nm));
    }
    // return the first (or only) template of pub 'i'
    const bName& pubTmpl0(pubidx i) const {
        if (i >= pub_.size()) throw schema_error(format("no pub with index {} in schema", i));
        auto t = discrim_[std::countr_zero(pub_[i].d)].tmpl;
        return tmplt_[t];
    }
    auto bNameToStr(const bName& bnm) const {
        std::string res{};
        for (auto c : bnm) {
            res += '/';
            if (c < tok_.size()) {
                res += tok_[c];
            } else {
                res += format("{:02x}", c);
            }
        }
        return res;
    }
    // return the value of a pub's first template as a string
    std::string pubVal(bTok nm) const { return bNameToStr(pubTmpl0(findPub(nm))); }

    auto tagNames(bTok nm) const {
        std::vector<std::string> res{};
        for (const auto& t : tag_[pub_[findPub(nm)].tag]) res.emplace_back(tok_[t]);
        return res;
    }

    auto paramNames(bTok nm) const {
        std::vector<std::string> res{};
        const auto& p = pub_[findPub(nm)];
        const auto pbm = p.par;
        const auto& tag = tag_[p.tag];
        for (size_t t = 0; t < tag.size(); t++) if (pbm & (1u << t)) res.emplace_back(tok_[tag[t]]);
        return res;
    }

    // tokens are string_views so their addresses have to be fixed when copying another schema
    void _fixup_tok(const bSchema& other) {
        stab_ = other.stab_;
        tok_ = other.tok_;
        cert_ = other.cert_;
        chain_ = other.chain_;
        cor_ = other.cor_;
        tag_ = other.tag_;
        tmplt_ = other.tmplt_;
        vlist_ = other.vlist_;
        discrim_ = other.discrim_;
        pub_ = other.pub_;
        schemaTP_ = other.schemaTP_;;
        tm_.clear();
        auto off = stab_.data() - other.stab_.data();
        for (size_t i = 0, n = tok_.size(); i < n; i++) {
            auto& otok = other.tok_[i];
            tok_[i] = bTok(otok.data() + off, otok.size());
            tm_.emplace(tok_[i], i);
        }
    }
    bSchema() = default;

    bSchema(bSchema&& other) = default;

    bSchema(const bSchema& other) { _fixup_tok(other); }

    bSchema& operator=(const bSchema& other) {
        if (this != &other) { _fixup_tok(other); }
        return *this;
    }
};

} //namespace bschema

template<>
struct fmt::formatter<bschema::corItem>: fmt::dynamic_formatter<> {
    auto format(const bschema::corItem& v, format_context& ctx) -> decltype(ctx.out()) const {
        return fmt::format_to(ctx.out(), "{}.{}={}.{}", v.ct1, v.co1, v.ct2, v.co2);
    }
};
template<>
struct fmt::formatter<bschema::tDiscrim>: fmt::dynamic_formatter<> {
    auto format(const bschema::tDiscrim& v, format_context& ctx) -> decltype(ctx.out()) const {
        return fmt::format_to(ctx.out(), "(chns#{}, tmpl={}, comp={}, vals={}, cor={})", v.cbm, v.tmpl, v.disc, v.vl, v.cor);
    }
};
template<>
struct fmt::formatter<bschema::tPub>: fmt::dynamic_formatter<> {
    auto format(const bschema::tPub& v, format_context& ctx) -> decltype(ctx.out()) const {
        return fmt::format_to(ctx.out(), "(par#{:x}, disc#{:x}, tok={}, tags={})", v.par, v.d, v.pub, v.tag);
    }
};

#endif // BSCHEMA_HPP
