#ifndef BUILDPUB_HPP
#define BUILDPUB_HPP
#pragma once
/*
 * Use a schema to build and sign publication objects
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

#include <algorithm>
#include <array>
#include <bitset>
#include <chrono>
#include <set>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include "certstore.hpp"
#include "dct/format.hpp"
#include "dct/utility.hpp"
#include "rdschema.hpp"
#include "rpacket.hpp"

// parameter types allowed
namespace dct {
    using timeVal = tdv_clock::time_point;
    using paramVal = std::variant<std::monostate, std::string, std::string_view, uint64_t, timeVal>;
    using parItem = std::pair<std::string_view, paramVal>;
}

// XXX these should be in <variant> but currently aren't
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

template<>
struct dct::formatter<dct::paramVal> {
    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator {
        //if (ctx.begin() != ctx.end()) throw_format_error("invalid format");
        return ctx.end();
    }
    auto format(const dct::paramVal& v, format_context& ctx) const -> format_context::iterator {
        return std::visit(overloaded {
            [&](const std::monostate&) { return dct::format_to(ctx.out(), "(empty)"); },
            [&](const auto& val) { return dct::format_to(ctx.out(), "{}", val); },
        }, v);
    }
};

namespace dct {

    using namespace std::string_literals;

// template describing one viable pub for some particular signing chain.
// An array of such templates is the primary structure used by both the
// pub builder and verifier.
struct pTmplt {
    using valSet = std::bitset<sizeof(uint64_t)*8>;

    valSet vs_{};    // set of distinguishing parameter values
    bName tmplt_{};  // cor-resolved template for pub
    compidx dpar_{}; // index of template's distinguishing parameter
};

template<bool pbdebug = false>
struct pubBldr {
 
    // A paramVal is a variant type capable of holding any type that can
    // be put in a crName component. Params is a vector of paramVals the
    // same size as the pub template. Thus pub tag, template and Param
    // indices are the same making it easy to build pubs and detect
    // missing or duplicate params in build calls.
    using Params = std::vector<paramVal>;

    struct tagMap : std::unordered_map<bTok,compidx> {
        using std::unordered_map<bTok,compidx>::unordered_map;
        compidx operator[](bTok key) const {
            if (const auto& v = find(key); v != end()) return v->second;
            throw schema_error(dct::format("no {} parameter for pub", key));
        }
    };

    bName tag_;                 // pub's tags
    tagMap tm_{};               // tag name-to-component-index map
    std::vector<pTmplt> pt_{};  // viable templates for pub
    Params pdefault_{};
    parmSet parmbm_{};
    chainBM cbm_{};
    const bSchema& bs_;
    const certStore& cs_;
    const tdv_clock& tdvc_;
    std::unordered_map<bTok,bComp> ptm_{}; // pub-specific token map
    std::vector<bTok> ptok_{};
    std::string pstab_{};       // pub-specific string table
    int pidx_{-1};              // pub's index in bs_.pub_

    // make a 'builder' for pub 'pub' of binary schema 'bs' using certificate store 'cs'.
    pubBldr(const bSchema& bs, const certStore& cs, const tdv_clock& tdvc, bTok pub) : bs_{bs}, cs_{cs}, tdvc_{tdvc} {
        pidx_ = bs_.findPub(pub);
        if (pidx_ < 0) throw schema_error(dct::format("pub {} not found", pub));
        makePubTmplts(findCerts());
    }

    template <typename... T>
    static inline void dprint(fmt::format_string<T...> format_str, T&&... args) {
        if constexpr (pbdebug) print(format_str, std::forward<T>(args)...);
    }

    std::string formatTok(bComp c) const {
        constexpr static const std::array calls {
            "timestamp","sysID","c2","c3","c4","c5","c6","c7","c8","c9","c10","c11","c12","c13","c14","c15",
            "c16","c17","c18","c19","c20","c21","c22","c23", "c24","c25","c26","c27","c28","c29","c30","c31",
        };
        std::string res{};
        if (c < maxTok) {
            res = bs_.tok_[c];
        } else if (isIndex(c)) {
            res = ptok_[typeValue(c)];
        } else if (isCall(c)) {
            res = dct::format("{:s}()", calls[typeValue(c)]);
        } else if (c == SC_ANON) {
            res = "_";
        } else {
            res = dct::format("{:02x}", c);
        }
        return res;
    }
    std::string formatName(const bName& nm) {
        std::string res{};
        for (auto c : nm) {
            res += '/';
            res += formatTok(c);
        }
        return res;
    }
    bool matches(tlvVec& cert, const bName& bcert) const {
       if (cert.size() != bcert.size()) return false;
       auto ntok = bs_.tok_.size();
       for (auto n = cert.size(), i=0ul; i < n; i++) {
           if (bcert[i] < ntok && cert[i].toSv() != bs_.tok_[bcert[i]]) return false;
       }
       return true;
    }
    bool matches(certVec& chain, const bChain& bchain) const {
       if (chain.size() != bchain.size()) return false;
       for (auto n = chain.size(), i=0ul; i < n; i++) {
           if (! matches(chain[i], bs_.cert_[bchain[i]])) return false;
       }
       return true;
    }
    // find the first signing chain in the certStore consistent with the
    // schema and use it to initialize the 'cert_' array.
    auto findCerts() {
        // candidate chains are 'or' of this pub's cor chain bitmaps
        const auto& [param,pub,tagi,disc] = bs_.pub_[pidx_];
        discSet ds{disc};
        for (size_t d = 0, de = bs_.discrim_.size(); d < de; d++) if (ds[d]) cbm_ |= bs_.discrim_[d].cbm;
        if (cbm_ == 0) {
            dprint("chain: not needed\n");
            return cbm_;
        }
        // find the first chain matching the cert store signing chain
        auto cbm = cbm_;
        auto schain = cs_.signingChain();
        for (auto bm = cbm; bm != 0; ) {
            auto c = std::countr_zero(bm);
            bm &=~ (1u << c);
            if (!matches(schain, bs_.chain_[c])) cbm &=~ (1u << c);
        }
        if constexpr (pbdebug) {
            if (cbm != 0) dprint("chain: {}, signer: {}\n", std::countr_zero(cbm), rName{schain[0].tlv()});
        }
        return cbm;
    }

    // add token 'tok' to the pub-specific token table and return its value.
    // 'tok' must not be in the table. If tok's character sequence is in the string table, it's
    // used to back the tok. Otherwise the char sequence is added to the pub-specific string
    // table and used to back tok.
    bComp newTok(bTok ntok) {
        bComp t = ptok_.size();
        if (t > SC_VALUE) throw schema_error(dct::format("no room for token {}", ntok));
        bTok tok{};
        if (auto p = bs_.stab_.find(ntok); p == std::string::npos) {
            // add to pub-specific strings
            pstab_.reserve(1024); //XXX try to avoid reallocs (need better way)
            p = pstab_.size();
            pstab_.append(ntok);
            tok = bTok(pstab_.data() + p, ntok.size());
        } else {
            tok = bTok(bs_.stab_.data() + p, ntok.size());
        }
        t |= SC_INDEX;
        ptok_.emplace_back(tok);
        ptm_.emplace(tok, t);
        return t;
    }

    // find or add token 'tok'
    bComp findOrAddTok(bTok tok) {
        if (auto t = bs_.tm_.find(tok); t != bs_.tm_.end()) return t->second;
        if (auto t = ptm_.find(tok); t != ptm_.end()) return t->second;
        return newTok(tok);
    }

    // return value of cert[chain[idx]] component 'c' under corespondence 'cor'.
    // If the cor isn't for a pub or the pub's c component doesn't match
    // 'cor' an error is thrown.
    auto mapCor(auto idx, auto c, auto cor) {
        c &= SC_VALUE;
        auto cert = cs_.signingChain();
        for (const auto& [cert1, comp1, cert2, comp2] : bs_.cor_[cor]) {
            if (cert1 == idx && c == comp1) return findOrAddTok(cert[cert2-1][comp2].toSv());
        }
        throw schema_error(dct::format("no corespondence for {:02x}({})", c, tag_[typeValue(c)]));
    }

    int exists(const pTmplt& pt) const noexcept {
        for (int i = 0, n = pt_.size(); i < n; i++) {
            if (pt.dpar_ == pt_[i].dpar_ && pt.tmplt_ == pt_[i].tmplt_) return i;
        }
        return -1;
    }
    // build a pub-specific template given the skeleton index 'tmplt',
    // the discriminator component index 'comp', the list of expected
    // comp values 'vlist' and the pub's corespondences 'cor'. The
    // resulting template will be complete except for parameter values
    // which are supplied to the build* calls.
    void addTemplate(auto tmplt, auto comp, auto vlist, auto cor) {
        pTmplt pt{};
        pt.dpar_ = comp;
        // build valset bitmap from vlist. A bit will be set for every
        // valid value of 'comp' in this pub.
        if (vlist < maxTok) {
            pt.vs_[vlist] = 1;
        } else {
            for (const auto v : bs_.vlist_[vlist & 0x7f]) pt.vs_[v] = 1;
        }
        // got through components filling in cors from cert chain
        for (auto c : bs_.tmplt_[tmplt]) {
            if (isCor(c)) c = mapCor(0, c, cor);
            pt.tmplt_.emplace_back(c);
        }
        if (int i = exists(pt); i >= 0) {
            // this pt just adds more values to an existing pt
            pt_[i].vs_ |= pt.vs_;
        } else {
            pt_.emplace_back(pt);
        }
    }

    // inspection interface
    auto tagNames() const noexcept {
        std::vector<std::string> res{};
        for (size_t t = 0; t < tag_.size(); t++) res.emplace_back(bs_.tok_[tag_[t]]);
        return res;
    }

    auto paramNames() const noexcept {
        std::vector<std::string> res{};
        for (size_t t = 0; t < parmbm_.size(); t++) if (parmbm_[t]) res.emplace_back(bs_.tok_[tag_[t]]);
        return res;
    }

    void printPubTemplates() {
        if constexpr (pbdebug) {
            if (parmbm_.any()) {
                dprint("parameters: ");
                for (size_t t = 0; t < parmbm_.size(); t++) if (parmbm_[t]) print(" {}({})", bs_.tok_[tag_[t]], t);
                dprint("\n");
            }
            for (const auto& pt : pt_) {
                auto n = formatName(pt.tmplt_);
                ((n.size()+1) & 7) > 4? dprint(" {}   \t", n) : dprint(" {}\t", n);
                if (pt.dpar_ >= bs_.tok_.size()) {
                    // template accepts all parameters
                    dprint("*");
                } else if (pt.vs_ == 1u) {
                    // parameter pt.dpar_ must match its value in the template
                    dprint("T");
                } else {
                    dprint("{}({})=", bs_.tok_[tag_[pt.dpar_]], pt.dpar_);
                    auto c = '{';
                    for (size_t t = 0; t < pt.vs_.size(); t++) {
                        if (pt.vs_[t]) {
                            dprint("{}{}", c, bs_.tok_[t]);
                            c = '|';
                        }
                    }
                    dprint("}}");
                }
                dprint("\n");
            }
        }
    }
    // construct all the pub templates compatible with cert chains specified
    // by 'cbm'. At this point, all the certs from these chains are
    // available in the certStore cs_ so 'correspondences' between pub
    // and cert name components can be resolved. The resulting templates
    // will be complete except for parameter values and 'call' ops.
    void makePubTmplts(chainBM cbm) {
        const auto& [param,pub,tagi,disc] = bs_.pub_[pidx_];
        discSet dset{disc};
        parmbm_ = param;
        // build tagmap
        tag_ = bs_.tag_[tagi];
        for (int i=0, n=tag_.size(); i < n; ++i) tm_.emplace(bs_.tok_[tag_[i]], i);

        for (size_t d = 0, de = bs_.discrim_.size(); d < de; d++) {
            if (! dset[d]) continue;
            const auto& [chainbm,tmplt,comp,vlist,cor] = bs_.discrim_[d];
            // if template needs to be signed but not with our key, skip it.
            if (chainbm && (cbm & chainbm) == 0) continue;
            addTemplate(tmplt, comp, vlist, cor);
        }
        // templates sorted so most specific match is first
        std::sort(pt_.begin(), pt_.end(), [](const auto& a, const auto& b) { return a.vs_.count() > b.vs_.count(); });
        printPubTemplates();
    }

    // routines to build and sign pubs

    // common routine for checking and adding one parameter value 'val' at component index 'c' of 'par'
    void doOneParam(Params& par, compidx c, paramVal val) {
        if (c >= parmbm_.size() || !parmbm_[c]) throw schema_error(dct::format("component {} isn't a parameter", c));
        if (par[c].index() != 0)  throw schema_error(dct::format("param {} set twice", c));
        par[c] = val;
    }

    // doParam converts build API variadic calls (zero or more 'tag, value'
    // or 'compidx, value' argument pairs) into a filled-in Params
    // array. The variadic calls are handled via a recursive template
    // that picks off arguments two at a time until there are no args
    // left. If the caller supplies an odd number of arguments, the
    // compiler will spew reams of confusing error messages (until we
    // can take advantage of c++20 'Concepts' to say what's really wrong).
    void doParam(Params&) {}
    template<typename... Rest>
    void doParam(Params& par, compidx c, const paramVal& val, Rest... rest) {
        doOneParam(par, c, val);
        doParam(par, rest...);
    }
    template<typename... Rest>
    void doParam(Params& par, std::string_view tag, Rest... rest) { doParam(par, tm_[tag], rest...); }

    auto appendComp(const Params& par, bComp c, crName res) const {
        if (isLit(c)) return res / bs_.tok_[c];
        if (isIndex(c)) return res / ptok_[typeValue(c)];
        if (isParam(c)) return std::visit(overloaded {
                            [&res](std::monostate) { return res / "(empty)"; },
                            [&res](std::string_view val) { return res / val; },
                            [&res](std::string val) { return res / val; },
                            [&res](timeVal val) { return res / val; },
                            [&res](uint64_t val) { return res / val; },
                        }, par[typeValue(c)]);
        if (!isCall(c)) throw schema_error(dct::format("invalid comp {} in template", c));
        // handle 'call()' ops
        c = typeValue(c);
        if (c == 0) return res / tdvc_.now();
        if (c == 1) return res / sysID();
        throw schema_error(dct::format("invalid call {} in template", c));
    }
    crName fillTmplt(const Params& par, pTmplt pt) const {
        crName res{};
        for (auto c : pt.tmplt_) res = appendComp(par, c, res);
        return crName(res);
    }
    bComp parToTok(const Params& par, compidx c) const {
        auto pval = dct::format("{}", par[c]);
        if (const auto v = bs_.tm_.find(pval); v != bs_.tm_.end()) return v->second;
        return maxTok;
    }
    bool checkParVal(const Params& par, const pTmplt& pt, compidx c) const noexcept {
        // assert(parmbm_[c] == true)
        auto cv = pt.tmplt_[c];
        if (isParam(cv)) return true;     // template doesn't constrain value
        if (auto v = parToTok(par, c); v == cv) return true; // value must match template
        if (isIndex(cv)) return ptok_[typeValue(cv)] == dct::format("{}", par[c]); // value must match cor
        return false;
    }
    // check that all literal params in the template match the correponding user pars
    bool checkPars(const Params& par, const pTmplt& pt) const noexcept {
        for (auto c = 0u; c < par.size(); c++) if (parmbm_[c] && !checkParVal(par, pt, c)) return false;
        return true;
    }
    const auto& matchTmplt(const Params& par) const {
        for (const auto& pt : pt_) {
            // if template has no discriminator or the discrim is in the template,
            // and if template literal components match pars, use it
            if ((pt.dpar_ >= bs_.tok_.size() || pt.vs_ == 1u) && checkPars(par, pt)) return pt;
 
            // template must have a discrim in the valset, check it and the template lits
            if (auto t = parToTok(par, pt.dpar_); t != maxTok && pt.vs_[t] && checkPars(par, pt)) return pt;
        }
        throw schema_error("no matching pub template");
    }

    crName completeTmplt(Params& par) const {
        // make sure all parameters were supplied or defaulted
        for (auto c = 0u; c < par.size(); c++) {
            if (parmbm_[c] && par[c].index() == 0) {
                if (c >= pdefault_.size() || pdefault_[c].index() == 0)
                    throw schema_error(dct::format("param {} missing", bs_.tok_[tag_[c]]));
                par[c] = pdefault_[c];
            }
        }
        return fillTmplt(par, matchTmplt(par));
    }

    // defaults(name, value ...) - set default pub parameter value(s)
    //
    // called with zero or more argument pairs where each pair has the form '<tag name>, <value>'
    // or '<comp index>, <value>'.  E.g., default("_target", "local") makes "local" a default for the
    // "_target" parameter. Defaults are used when name() calls are missing the associated parameter.
    //
    // Each tag or component index must refer to one of the pub's parameters or an error is thrown.
    template<typename... Rest>
    auto& defaults(const Rest... rest) {
        static_assert((sizeof...(Rest) & 1) == 0, "must supply *pairs* of name,value arguments");
        Params par{};
        par.resize(tag_.size());
        doParam(par, rest...);
        pdefault_ = std::move(par);
        return *this;
    }
    auto& defaults(const std::vector<parItem>& pvec) {
        Params par{};
        par.resize(tag_.size());
        for (const auto& [tag, val] : pvec) doOneParam(par, tm_[tag], val);
        pdefault_ = std::move(par);
        return *this;
    }

    const auto& defaults() const noexcept { return pdefault_; }

    // construct complete pub name given its parameters.
    //
    // called with zero or more argument pairs where each pair has
    // the form '<tag name>, <value>' or '<comp index>, <value>'.
    // E.g., name("_target", "local", 6, 1234u) constructs a name with
    // the _target component containing the string "local" and the 6th
    // component containing a Segment number 1234.
    //
    // Each tag or component index must refer to one of the pub's
    // parameters and values for all the pub's parameters must be supplied.
    // An error is thrown otherwise.
    template<typename... Rest> requires ((sizeof...(Rest) & 1) == 0)
    crName name(Rest&&... rest) {
        static_assert((sizeof...(Rest) & 1) == 0, "must supply name,value argument pairs");
        Params par{};
        par.resize(tag_.size());
        doParam(par, std::forward<Rest>(rest)...);
        // find a matching template, fill in params then return it
        return completeTmplt(par);
    }

    // construct complete pub name given vector of <tag name> <value> pairs
    //
    // Each tag must refer to one of the pub's parameters and values for all
    // the pub's parameters must be supplied.  Errors are thrown otherwise.
    crName name(const std::vector<parItem>& pvec) {
        Params par{};
        par.resize(tag_.size());
        for (auto& [tag, val] : pvec) doOneParam(par, tm_[tag], val);
        return completeTmplt(par);
    }

    // tag name to component index
    auto index(std::string_view s) const { return tm_[s]; }
};

} // namespace dct
 
#endif // BUILDPUB_HPP
