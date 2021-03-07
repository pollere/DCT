#ifndef DCTMODEL_HPP
#define DCTMODEL_HPP
/*
 * Data Centric Transport schema policy model abstraction
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
#include <functional>
#include <string_view>
#include <utility>
#include "dct/format.hpp"
#include "buildpub.hpp"
#include "pibcerts.hpp"
#include "getschema.hpp"

using Publication = ndn::Data;

static inline const bSchema& loadSchema(const std::string& schema) {
    // map containing schemas loaded so far
    static std::unordered_map<std::string,bSchema> schemas{};

    // if the schema has been loaded just return it
    if (auto s = schemas.find(schema); s != schemas.end()) return s->second;

    // find certs containing the schema name that are also schemas then load and validate the first.
    auto nms = match(pibCerts().match(schema), "schema");;
    if (nms.size() == 0) throw schema_error(format("no schema certs matching {}", schema));
    schemas.emplace(schema, getSchema(nms[0]));
    return schemas[schema];
}

static inline certStore findKeys(const std::string& /*prefix*/, const std::string& /*role*/) {
    throw schema_error("findKeys not implemented yet"); //XXX
}

static inline auto fakeCerts(const bSchema& bs, const std::string& role) {
    certStore cs{};
    certVec cv{};
    //XXX should build the certs from schema info but hardwire for now
    auto prefix = bs.pubVal("#pubPrefix");
    auto rolecert = prefix + '/' + role;
    cv.emplace_back(rolecert);
    cv.emplace_back(prefix);
    cs.signingChain(cv);
    return cs;
}

static inline auto getSigMgr(const bSchema& bs) { return sigMgrByType(bs.pubVal("#pubValidator").substr(1)); }
static inline auto getWireSigMgr(const bSchema& bs) { return sigMgrByType(bs.pubVal("#wireValidator").substr(1)); }

static inline auto defaultPub(const bSchema& bs, const std::string& role) {
    // If the validator needs key(s) find potential signing keys.
    // Otherwise, create a certstore faking the role's signing chain.
    auto sigm = getSigMgr(bs);;
    auto cs = sigm.ref().needsKey()? findKeys(bs.pubVal("#pubPrefix"), role) : fakeCerts(bs, role);
    return pubBldr(bs, cs, bs.pubName(0));
}

//template<typename sPub>
struct DCTmodel {
    const bSchema& bs_;
    SigMgrAny psm_;
    SigMgrAny wsm_;
    pubBldr<false> bld_;
    static inline std::function<size_t(std::string_view)> _s2i;

    DCTmodel(const std::string& schema, const std::string& role) :
        bs_{loadSchema(schema)}, psm_{getSigMgr(bs_)},  wsm_{getWireSigMgr(bs_)}, bld_{defaultPub(bs_, role)}
    { _s2i = std::bind(&decltype(bld_)::index, bld_, std::placeholders::_1); }

    template<typename... Rest>
    auto name(Rest&&... rest) { return bld_.name(std::forward<Rest>(rest)...); }

    template<typename... Rest>
    auto defaults(Rest&&... rest) { return bld_.defaults(std::forward<Rest>(rest)...); }

    template<typename... Rest>
    auto pub(std::span<const uint8_t> content, Rest&&... rest) {
        Publication pub(name(std::forward<Rest>(rest)...));
        psm_.ref().sign(pub.setContent(content.data(), content.size()));
        return pub;
    }
    auto wirePrefix() const { return bs_.pubVal("#wirePrefix"); }
    SigMgr& wireSigMgr() { return wsm_.ref(); }
    SigMgr& pubSigMgr() { return psm_.ref(); }
    auto pubPrefix() const { return bs_.pubVal("#pubPrefix"); }

    struct sPub : Publication {
        using Publication::Publication;
        sPub(const Publication& p) { *(Publication*)(this) = p; }
        sPub(Publication&& p) { *(Publication*)(this) = std::move(p); }

        // accessors for name components of different types

        size_t index(size_t s) const { return s;  }
        size_t index(std::string_view s) const { return _s2i(s); }

        std::string string(auto c) const {
            auto v = getName()[index(c)].getValue();
            return std::string((const char*)v.buf(), v.size());
        }
        uint64_t number(auto c) const { return getName()[index(c)].toNumber(); }
        using clock = std::chrono::system_clock;
        clock::time_point time(auto c) const { return getName()[index(c)].toTimestamp(); }
        double timeDelta(auto c, clock::time_point tp = clock::now()) const {
                    return std::chrono::duration_cast<std::chrono::duration<double>>
                                (tp - getName()[index(c)].toTimestamp()).count();
        }
        auto operator[](auto c) const { return string(c); }
    };
};

#endif // DCTMODEL_HPP
