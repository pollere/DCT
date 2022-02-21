#ifndef SYMTAB_HPP
#define SYMTAB_HPP
/*
 * symtab - symbol table for the DCT trust schema parser
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
 */

#include <map>
#include <string>
#include <vector>
#include "names.hpp"
#include "parser.hpp"

struct symTab
{
    bool contains(const sComp key) const noexcept {
        return c2n_.contains(key.id());
    }
    void add(const sComp key, const sName& value) {
        if (value.size() == 0) {
            throw_error("assigning empty Name to " + to_string(key));
        }
        if (contains(key)) {
            throw_error("key " + to_string(key) + " already defined");
        }
        c2n_.emplace(key.id(), value);
    }
    void replace(const sComp key, sName&& value) {
        if (value.size() == 0) {
            throw_error("assigning empty Name to " + to_string(key));
        }
        if (! contains(key)) {
            throw_error("key " + to_string(key) + " not defined");
        }
        c2n_.insert_or_assign(key.id(), value);
    }
    auto operator[] (const sComp key) const {
        if (! contains(key)) {
            return sName{key};
        }
        return c2n_.at(key.id());
    }
    std::string bare_string(const sComp key) const {
        return comp_[key];
    }
    std::string bare_string(const sCompId id) const {
        return comp_[id];
    }
    std::string to_string(const sComp key) const {
        return key.flags_string() + comp_[key];
    }
    auto str2comp(const sCompString key) { return comp_[key]; }

    void throw_error(const std::string& s) const {
        throw yy::parser::syntax_error(loc_, s);
    }
    yy::location& location() { return loc_; }

    sCompTab comp_{};
    std::map<sComp, sName> c2n_{};
    yy::location loc_{yy::position()};
};

#endif  // ! SYMTAB_HPP
