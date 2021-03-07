#ifndef CERTSTORE_HPP
#define CERTSTORE_HPP
/*
 * Certificate store abstraction used by schemas
 *
 * Copyright (C) 2020 Pollere, Inc.
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

#include <algorithm>
#include <set>
#include <span>
#include <string>
#include <vector>
#include "ndn-ind/name.hpp"
#include "bschema.hpp"

using certName = ndn::Name;
using certVec = std::vector<certName>;

struct certStore : std::set<certName> {
    using std::set<certName>::set;

    certVec  chain_{};

    const auto& signingChain() const noexcept { return chain_; }
    auto& signingChain(const certVec& chain) { chain_ = chain; return *this; }
    auto& signingChain(certVec&& chain) { chain_ = std::move(chain); return *this; }

    template<class Pred>
    certVec copy_if(Pred pred) const {
        certVec cv{};
        for (const auto& n : *this) if (pred(n)) cv.emplace_back(n);
        return cv;
    }
    certVec ends_with(const certName& substr) const {
        return copy_if([substr](auto c){ return c.getSubName(-substr.size()) == substr; });
    }
    certVec starts_with(const certName& substr) const {
        return copy_if([substr](auto c){ return c.getPrefix(substr.size()) == substr; });
    }
    certVec match(const certName& substr) const {
        return copy_if([substr](auto c){
                for (int i = 0, n = c.size() - substr.size(); i < n; i++) {
                    if (c.getSubName(i, substr.size()) == substr) return true; 
                }
                return false;
            });
    }
};

static inline certVec match(certVec&& in, const certName& substr) {
    certVec cv{};
    for (const auto& c : in) {
        for (int i = 0, n = c.size() - substr.size(); i < n; i++) {
            if (c.getSubName(i, substr.size()) == substr) { cv.emplace_back(c); break; }
        }
    }
    return cv;
}

#endif // CERTSTORE_HPP
