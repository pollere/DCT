#ifndef NAMES_HPP
#define NAMES_HPP
/*
 * names - Definitions related to schema parser 'Names'
 *
 * Copyright (C) 2019-2022 Pollere LLC.
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
 *  This is not intended as production code.
 *
 *
 *  NDN 'Name' objects are validated against trust schema names so
 *  they have to be comparable. Like NDN Names, schema names are an
 *  array of 'Components' where each of must be one of:
 *
 *   1. a literal NDN Name Component (TLV blob)
 *   2. a schema-unique name used to specify that components
 *      in different names must have the same value.
 *   3. a schema-unique name used to specify a component that
 *      is deliberately not validated by the schema.
 *
 *  E.g., the schema:
 *    name1: "foo"/"bar"/"baz"/d/_e
 *    name2: "foo"/"baz"/d
 *  says that name1's first 3 components must be the string TLVs "foo",
 *  "bar" & "baz", the 4th component must be identical to the 3rd
 *  component of name2 and the 5th component is a run-time parameter that
 *  can't be verified by the schema.
 *
 *  A schema name encodes allowed variants using '|'. E.g.,
 *    name3 = a/b/(p/q | r/s)/y/z
 *  says that the 3rd & 4th components of name3 must be either
 *  "p/q" or "r/s".
 *
 *  Since most components are used in more than one name, a level of
 *  indirection between definition & use saves substantial memory.
 *  Component values are stored in a single 'stringTable' (an array of
 *  arrays) and names reference them via their stringTable index (a
 *  small integer) so names are simply an array of small integers.
 *
 *  The types for schema Name/Component/etc. start with 's' so they
 *  won't be confused with NDN types.
 */

#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include "dct/format.hpp"

using sCompString = std::string;
using sCompId = std::uint16_t;
using namespace std::string_literals;

class sComp {
  public:
    using cFlag = std::uint8_t;
    // top 4 bits are flags
    constexpr static cFlag fNone    = 0x00;
    constexpr static cFlag fLit     = 0x80;
    constexpr static cFlag fIndex   = 0x40;
    constexpr static cFlag fParam   = 0x20;
    constexpr static cFlag fValid   = 0x10;
    // bottom 4 bits are token type. types that can be name components must be listed first
    // then 'operators' that have to be evaluated. 'isOp()' depends on this ordering.
    constexpr static cFlag fStr     = 0x00;
    constexpr static cFlag fReplace = 0x01;
    constexpr static cFlag fCall    = 0x02;
    // component/operator boundary followed by operators
    constexpr static cFlag fIsOp    = 0x02; // last non-operator value
    constexpr static cFlag fUnify   = 0x03;
    constexpr static cFlag fResolve = 0x04;
    constexpr static cFlag fStruct  = 0x05;
    constexpr static cFlag fField   = 0x06;

    constexpr static cFlag fFunc    = 0x0f; //mask to extract func field

    sComp(sCompId i = 255, cFlag f = fNone) : id_(i), flags_(f) { }
    auto id() const noexcept { return id_; }
    auto flags() const noexcept { return flags_; }
    auto func() const noexcept { return flags_ & fFunc; }
    sComp& setFlags(cFlag f) noexcept { flags_ = f; return *this; }
    sComp& addFlags(cFlag f) noexcept { flags_ |= f; return *this; }
    auto isLit() const noexcept { return (flags_ & fLit) != 0; }
    auto isStr() const noexcept { return (flags_ & (fLit|fFunc)) == 0; }
    auto isIndex() const noexcept { return (flags_ & fIndex) != 0; }
    auto isValid() const noexcept { return (flags_ & fValid) != 0; }
    auto isParam() const noexcept { return (flags_ & fParam) != 0; }
    auto isAnon() const noexcept { return id_ == 0; }
    auto isOp() const noexcept { return func() > fIsOp; }
    auto isUnify() const noexcept { return func() == fUnify; }
    auto isResolve() const noexcept { return func() == fResolve; }
    auto isCall() const noexcept { return func() == fCall; }
    auto isField() const noexcept { return func() == fField; }
    auto isStruct() const noexcept { return func() == fStruct; }
    auto flags_string() const noexcept {
        std::string s;
        if (isLit()) s += "'";
        if (isIndex()) s += "@";
        if (isValid()) s += "";
        if (isUnify()) s += "&";
        if (isResolve()) s += "|";
        if (isField()) s += ":";
        if (isStruct()) s += ",";
        //if (isCall()) s += "?";
        return s;
    }
    auto to_string() const noexcept { return flags_string() + std::to_string(id_); }
    bool operator== (const sComp b) const noexcept { return (id_ == b.id_) && (flags_ == b.flags_); }
    bool operator!= (const sComp b) const noexcept { return (id_ != b.id_) || (flags_ != b.flags_); }
    bool operator< (const sComp b) const noexcept { return id_ < b.id_ || (id_ == b.id_ && flags_ < b.flags_); }

  private:
    sCompId id_;
    cFlag flags_;
};

using sName = std::vector<sComp>;

// Implement the 1-1 relation between comp strings & the
// small integers that represent them. This could be a
// boost bimap but that adds another code dependency so
// a standard library map and vector are used instead.
class sCompTab {
  public:
    auto operator[] (const sCompString& key) {
        if (! s2c_.contains(key)) add(key);
        return s2c_[key];
    }
    const auto& operator[] (const sComp key) const { return c2s_.at(key.id()); }
    const auto& operator[] (const sCompId id) const { return c2s_.at(id); }
    auto to_string(const sComp key) const { return key.to_string() + c2s_.at(key.id()); }
    auto size() const noexcept { return c2s_.size(); }

    void add(const sCompString& key, sComp::cFlag f = sComp::fNone) {
        // add element to end of vector & remember its position.
        sComp c(c2s_.size(), f);
        s2c_.emplace(key, c);
        c2s_.emplace_back(key);
    }
    sCompTab() {
        // 0th entry is always the anonymous param "_"
        add("_"s, sComp::fValid);
    }

  private:
    std::map<sCompString, sComp> s2c_;
    std::vector<sCompString> c2s_;
};

template <>
struct fmt::formatter<sComp> {
    // presentation format: 's' - as string, 'd' - raw data
    char presentation = 's';
    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
        auto it = ctx.begin(), end = ctx.end();
        if (it != end && (*it == 's' || *it == 'd')) presentation = *it++;
        if (it != end && *it != '}') throw format_error("invalid format");

        // Return an iterator past the end of the parsed range:
        return it;
    }
    auto format(const sComp& c, format_context& ctx) const -> format_context::iterator {
        if (presentation == 'd') return format_to(ctx.out(), "({:02x},{:d})", c.flags(), c.id());
        return format_to(ctx.out(), "{}", c.to_string());
    }
};

#endif // ! NAMES_HPP
