#ifndef DRIVER_HPP
#define DRIVER_HPP
/*
 * driver - routines to support parser reductions
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

#include <array>
#include <bitset>
#include <iostream>
#include <set>
#include <utility>

#include <boost/version.hpp>
#if BOOST_VERSION < 108100
// boost 1.80 bug workaround for deprecated std::unary_function removal in c++17
#define BOOST_NO_CXX98_FUNCTION_BASE 0
#endif
#include <boost/dynamic_bitset.hpp>

#include "dct/format.hpp"
#include "dct/schema/bschema.hpp"
#include "dag.hpp"
#include "parser.hpp"
#include "symtab.hpp"

namespace bschema = dct::bschema;

// -v (verbose) output levels
static constexpr int V_QUIET  = 0;
static constexpr int V_MIN    = V_QUIET+1;
static constexpr int V_FULL   = V_MIN+1;
static constexpr int V_DETAIL = V_FULL+1;
static constexpr int V_DEBUG  = V_DETAIL+1;

//using compSet = std::bitset<64>;
struct compSet : public boost::dynamic_bitset<> {
    compSet() : boost::dynamic_bitset<>(16384) {}

    template<typename UnOp>
    void for_each(UnOp op) const noexcept { for (auto b = find_first(); b != npos; b = find_next(b)) { op(b); }; }

    template<typename UnOp>
    auto remove_if(UnOp op) const noexcept {
        auto res{*this};
        for (auto b = res.find_first(); b != npos; b = res.find_next(b)) if (op(b)) res[b] = 0;
        return res;
    }

    template<typename T, typename BinOp>
    T reduce(T init, BinOp op) const noexcept {
        for (auto b = find_first(); b != npos; b = find_next(b)) { init = op(init, b); };
        return init;
    }
};

using sNameVec = std::vector<sName>;
using certSet = std::set<int>;
using certidx = bschema::certidx;
using compidx = bschema::compidx;
using chainCor = bschema::chainCor;
using corItem = bschema::corItem;
using tmplidx = uint8_t;
using tmplCert = std::tuple<tmplidx,compidx,certSet>;
using discrimMap = std::map<tmplCert,compSet>;
using certDag = DAG<sComp>;

struct tagmap : public std::multimap<sComp,uint8_t> {
    tagmap init(const sName& nm) {
        for (size_t i = 0; i < nm.size(); ++i) emplace(nm[i], i);
        return *this;
    }
    sName tags() const {
        sName ret(size());
        for (auto [c, i] : *this) ret.at(i) = c;
        return ret;
    }
    uint8_t operator[](const sComp& key) const {
        auto i = find(key);
        if (i == end()) {
            std::cerr << "- error: no tag " << key.to_string() << "\n";
            abort();
        }
        return i->second;
    }
};

struct driver {
    std::set<sComp> pubs_{};                    // publications defined
    std::set<sComp> primary_{};                 // primary publications defined
    std::map<sComp,sComp> parent_{};            // pub's parent pub
    std::map<sComp,sName> children_{};          // list of primary's children
    std::map<sComp,tagmap> tags_{};             // pub's tags (component names)
    std::map<sComp,sName> signer_{};            // pub's signed-by certs
    std::map<sComp,sName> constraints_{};       // pub's constraints
    std::set<sComp> conDone_{};                 // pub's constraints have be computed
    std::set<sName> certchains_{};              // cert signing chains
    certDag certDag_{};                         // DAG of all certs

    // different pubs and different expansions of the same pub can have different signing chains.
    // A chain is referenced by its index in this vector. Each entry is a vector of the cert names
    // comprising the chain from pub to trust anchor.
    sNameVec chains_{};                         // pub signing chains
    std::map<sComp,certSet> signers_{};         // per-pub signers
    std::map<sComp,sNameVec> certs_{};          // full expanded form of pubs & certs

    std::map<sComp,std::vector<compSet>> entropy_{}; // per-primary vectors of per-component entropy
    std::map<sName,uint8_t> compressible_{};    // template compressible on given component
 
    std::vector<chainCor> corespondences_{};

    // every legal pub has a template giving its fully expanded form (not including params which
    // are filled in at runtime) and a discriminator predicate specifying the combination of
    // parameter value(s) and signing cert(s) that use this template.  Multiple discriminators
    // can use a template so they're are referenced by index in this vector.
    sNameVec templates_{};                      // all pub templates
    std::map<sComp,discrimMap> discrim_{};      // per-pub discriminators
    std::string input_{}; // The name of the file being parsed.
    std::string output_{}; // binary schema output file name
    symTab symtab_;
    int verbose_{1};
    bool printDag_{false};

    static inline const std::array<std::string,8> fn2str_{
        "timestamp","sysId","pid","host","uid","seq","",""
    };
    static inline const std::map<std::string,u_int8_t> str2fn_{
        {"timestamp", 0 }, {"sysId", 1 }, {"pid", 2 }, {"host", 3 }, {"uid", 4 }, {"seq", 5 }
    };

    symTab& symtab() { return symtab_; }
    void symtab(symTab&& s) { symtab_ = std::move(s); }
    yy::location& location() { return symtab().location(); }
    const sNameVec& chains() const { return chains_; }
    uint8_t comp2fn(const sComp c) const { return str2fn_.at(symtab_.to_string(c)); }

    const std::string& input() const { return input_; }
    void input(std::string_view f) { input_ = f; }
    void output(std::string_view ofile) { output_ = ofile; }
    const std::string& output() { return output_; }

    // Construct a parser symbol from a character
    auto tokFromChar(unsigned char c) {
        yy::location l = location();
        return yy::parser::symbol_type(yy::parser::token_type(c), std::move(l));
    }

    auto isParent(const sComp comp) const { return parent_.contains(comp) && parent_.at(comp) == comp; }

    auto isPrimary(const sComp comp) const noexcept { return (symtab_.bare_string(comp)[0] == '#'); }

    auto isParam(const sComp comp) const noexcept {
        const auto& s = symtab_.bare_string(comp);
        return ((comp.isStr() && !comp.isValid() && !comp.isAnon() && s[0] != '_' && s[0] != '.') || comp.isParam());
    }

    bool contains(const sName& nm, const sComp comp) const noexcept {
        for (const auto c : nm) if (c == comp) return true;
        return false;
    }

    // actions used by parser reductions

    auto makeParent(sComp child, sComp parent) {
        if (parent_.contains(child)) {
            if (parent_[child] == parent) return;
            symtab_.throw_error(format("redefining parent of {}: {} to {}", to_string(child),
                                       to_string(parent_[child]), to_string(parent)));
        }
        parent_[child] = parent;
    }
    auto makeParent(sComp comp) { makeParent(comp, comp); }

    auto handleSigner(const sComp comp, const sName& certs) { signer_[comp] = certs; }

    auto handleDef(const sComp comp, const sName& nm) {
        if (contains(nm, comp)) symtab_.throw_error("recursive definition");
        symtab_.add(comp, nm);
        if (isPrimary(comp)) {
            primary_.emplace(comp);
            makeParent(comp);
        } else if (nm.size() == 1 && nm[0].isStr()) {
            makeParent(comp, nm[0]);
            // parent might not be defined yet so tags & other
            // properties are filled in at eof.
        }
        return sName({comp});
    }

    auto handleDef(const sComp comp, const sName& nm, const sName& cons) {
        auto res = handleDef(comp, nm);
        constraints_[comp] = cons;
        return res;
    }

    auto handleRef(sComp comp) const { return sName({comp}); }

    auto handleLit(sComp comp) const { return sName({comp.setFlags(sComp::fLit)}); }

    sName handleBinOp(const sName& a, const sName& b, sComp::cFlag op) const {
        // each binary operator term starts with a marker giving the number of components
        // (not including the marker) followed by that term's components.
        sName res{sComp(a.size(), op)};
        res.insert(res.end(), a.begin(), a.end());
        res.emplace_back(sComp(b.size(), op));
        res.insert(res.end(), b.begin(), b.end());
        return res;
    }

    sName handleResolve(const sName& a, const sName& b) const { return handleBinOp(a, b, sComp::fResolve); }

    sName handleUnify(const sName& a, const sName& b) const { return handleBinOp(a, b, sComp::fUnify); }

    sName handleOr(const sName& a, const sName& b) const { return handleBinOp(a, b, sComp::fResolve); }

    sName handleAnd(const sName& a, const sName& b) const { return handleBinOp(a, b, sComp::fUnify); }

    sName handleField(sComp a, const sName& b) const { return handleBinOp(sName({a}), b, sComp::fField); }

    sName handleStruct(const sName& a, const sName& b) const { return handleBinOp(a, b, sComp::fStruct); }

    sName finishStruct(const sName& a) const { return sName{a}; }

    sName handleSlash(const sName& a, const sName& b) const {
        sName res(a);
        res.insert(res.end(), b.begin(), b.end());
        return res;
    }

    std::string toDecString(const sName& n) const {
        std::string res;
        for (size_t i = 0; i < n.size(); i++) {
            res += " ";
            res += n[i].to_string();
        }
        return res;
    }

    std::string to_string(const sComp c) const { return symtab_.to_string(c); }

    std::string to_string(const sName& n) const {
        std::string res{};
        for (size_t i = 0; i < n.size(); i++) {
            if (n[i].isResolve()) {
                res += " |" + std::to_string(n[i].id()) + " ";
            } else if (n[i].isUnify()) {
                res += " &" + std::to_string(n[i].id()) + " ";
            } else if (n[i].isStruct()) {
                res += " ," + std::to_string(n[i].id()) + " ";
            } else if (n[i].isField()) {
                res += " :" + std::to_string(n[i].id()) + " ";
            } else if (n[i].isLit()) {
                res += "/\"" + symtab_.bare_string(n[i]) + "\"";
            } else if (n[i].isCall()) {
                res += "/" + symtab_.to_string(n[i]) + "()";
            } else {
                res += "/" + symtab_.to_string(n[i]);
            }
        }
        return res;
    }

    std::string to_string(const sNameVec& nvec) const noexcept {
        std::string res{};
        for (const auto& nm : nvec) res += to_string(nm) + '\n';
        return res;
    }

    sNameVec append(sNameVec&& o1, sNameVec&& o2) const {
        if (o1.size() == 0) return std::move(o2);
        o1.insert(o1.end(), std::make_move_iterator(o2.begin()), std::make_move_iterator(o2.end()));
        return std::move(o1);
    }

    sNameVec crossprod(sNameVec&& o1, sNameVec&& o2) const {
        if (o1.size() == 0) return std::move(o2);
        if (o2.size() == 0) return std::move(o1);
 
        sNameVec res{};
        // concatenate every piece of o1 & o2 and put the result in res
        for (auto i : o1) {
            for (auto j : o2) {
                auto c = i;
                c.insert(c.end(), j.begin(), j.end());
                res.emplace_back(c);
            }
        }
        return res;
    }

    // construct the final form of a name.
    //
    // The 'final form' of a name has all references replaced with
    // their definition and 'or' operators turned into a list.
    //
    // n is the name to be expanded.
    //
    // b and e give the part of n to expand as the range [b,e)
    //
    // (In c++20 and beyond, these 3 parameters should be replaced
    // with a range view but ranges aren't part of the standard yet).
    // The range is needed to pull branches of an 'or' out of n since
    // they're expanded independently.
    sNameVec expand_name(const sName& n, int b, int e) const {
        sNameVec res{};
        if (b >= e) return res;
 
        if (n[b].isStruct() || n[b].isField()) return res;
        if (n[b].isUnify()) {
            int b1 = b + 1;
            int e1 = b1 + n[b].id();
            int b2 = e1 + 1;
            int e2 = b2 + n[e1].id();
            b = e2;
            res = append(expand_name(n, b1, e1), expand_name(n, b2, e2));
        } else if (n[b].isResolve()) {
            // expand the first & second branches of the 'or' then 
            // concatenate the result
            int b1 = b + 1;
            int e1 = b1 + n[b].id();
            int b2 = e1 + 1;
            int e2 = b2 + n[e1].id();
            b = e2;
            res = append(expand_name(n, b1, e1), expand_name(n, b2, e2));
        } else if (!(n[b].isLit()) && symtab_.contains(n[b])) {
            // a defined reference - expand the definition of the ref.
            auto ref = n[b++];
            auto s = symtab_[ref];
            res = expand_name(s, 0, s.size());
        } else {
            // a literal or undefined reference
            res.emplace_back(sName{n[b++]});
        }
        // if the above advanced to the end of the name, we're done.
        // otherwise expand what remains then join it to what we
        // did above as a cross product.
        if (b >= e) return res;

        return crossprod(std::move(res), expand_name(n, b, e));
    }

    // expand the alternatives (terms separated by '|') but not
    // definitions.
    sNameVec expand_or(const sName& n, int b, int e) const {
        sNameVec res{};
        if (b >= e) return res;

        if (n[b].isResolve()) {
            // expand the first & second branches of the 'or' then 
            // concatenate the result
            int b1 = b + 1;
            int e1 = b1 + n[b].id();
            int b2 = e1 + 1;
            int e2 = b2 + n[e1].id();
            b = e2;
            res = append(expand_or(n, b1, e1), expand_or(n, b2, e2));
        } else if ((n[b].isStr()) && symtab_.contains(n[b]) && symtab_[n[b]][0].isResolve()) {
            // definition starts with '|' - expand it.
            auto ref = n[b++];
            auto s = symtab_[ref];
            res = expand_or(s, 0, s.size());
        } else {
            // copy everything else
            res.emplace_back(sName{n[b++]});
        }
        // if the above advanced to the end of the name, we're done.
        // otherwise expand what remains then join it to what we
        // did above as a cross product.
        if (b >= e) return res;

        return crossprod(std::move(res), expand_or(n, b, e));
    }

    sNameVec expand_name(const sName& nm) const { return expand_name(nm, 0, nm.size()); }

    sNameVec expand_name(const sComp comp) const {
        // undefined reference is itself
        if (! symtab_.contains(comp)) return sNameVec{sName({comp})};
        return expand_name(symtab_[comp]);
    }

    void printCert(const sComp cert) const {
        std::cout << to_string(cert) << " = {\n";
        for (auto i : expand_name(cert)) std::cout << "  " << to_string(i) << '\n';
        std::cout << "}\n";
    }

    sName handleCert(const sComp a) const { return sName({a}); }

    sName handleChain(const sName& a, const sComp b) const {
        sName res{a};
        res.emplace_back(b);
        return res;
    }

    void finishChain(const sName& a) {
        // note an explicit parent signing chain
        if (isParent(a[0])) signer_[a[0]] = sName{a[1]};
        certchains_.emplace(a);
    }

    sName handleCall(sComp func) const {
        // return a name containing a 'Call' operator and the function
        auto f = str2fn_.find(symtab_.to_string(func));
        if (f == str2fn_.end()) symtab_.throw_error("calling unknown function " + symtab_.to_string(func));
        func.setFlags(sComp::fCall);
        return sName({func});
    }

    auto termLimits(const sName& nm, int b, int e) const {
        int b1 = b + 1;
        int e1 = b1 + nm[b].id();
        int b2 = e1 + 1;
        int e2 = b2 + nm[e1].id();
        if (e1 > e || e2 > e) symtab_.throw_error("inconsistent limits expanding" + to_string(nm));
        return std::tuple<int,int,int,int>{b1, e1, b2, e2};
    }

    sNameVec handleConstraints(const sNameVec& nms, const sComp def, const sName& con, int b, int e) {
        sNameVec res{nms};
        if (b >= e) return res;
 
        // 'constraints' of def consist of 'struct' and 'and' operators
        // which tie together a list of 'fields'. Each field consists of
        // a tag (which resolves to a component index in 'res') and a value
        // (which replaces whatever's at that index in 'res').
        if (con[b].isStruct() || con[b].isUnify()) {
            // evaluate the first & second branches of the connector, merging results
            auto [b1, e1, b2, e2] = termLimits(con, b, e);
            res = handleConstraints(res, def, con, b1, e1);
            res = handleConstraints(res, def, con, b2, e2);
            //print("u\n{}\n", to_string(res));
        } else if (con[b].isResolve()) {
            // An 'or' results in two duplicates of 'res', each with the
            // constrains from one branch of the 'or'. These are concatenated.
            auto [b1, e1, b2, e2] = termLimits(con, b, e);
            res = append(handleConstraints(res, def, con, b1, e1), handleConstraints(res, def, con, b2, e2));
            //print("or\n{}\n", to_string(res));
        } else if (con[b].isField()) {
            // next two components are tag name & value
            auto [b1, e1, b2, e2] = termLimits(con, b, e);
            auto tags = tags_.at(def);
            auto tag = con[b1];
            if (! tags.contains(tag)) {
                symtab_.throw_error(format("error: {} has no component named {}", to_string(def), to_string(tag)));
            }
            int t = tags[tag];

            // apply this change to all the names in 'res'
            sNameVec r2{};
            for (auto& r : res) {
                // If the replacement text is one token just put it in the name.
                // Otherwise create a new definition for it and put that in the name.
                if (e2 - b2 == 1) {
                    r[t] = con[b2];
                } else {
                    auto it = r.erase(r.begin() + t);
                    r.insert(it, con.begin()+b2, con.begin()+e2);
                }
                auto rex = expand_or(r, 0, r.size());
                r2.insert(r2.end(), rex.begin(), rex.end());
            }
            res = r2;
            //print("f{}\n{}\n", t, to_string(res));
        } else {
            // unknown operator
            symtab_.throw_error(format("error: {} contains invalid operator {}", to_string(def), to_string(con[b])));
        }
        return res;
    }

    sName flatten(const sNameVec& nv) {
        if (nv.size() == 0) return sName{};
        if (nv.size() == 1) return nv[0];
        auto res = handleOr(nv[0], nv[1]);
        for (size_t i = 2; i < nv.size(); ++i) res = handleOr(res, nv[i]);
        return res;
    }

    sName handleConstraints(const sName& nm, const sComp def, const sName& con) {
        auto nv = handleConstraints(expand_or(nm, 0, nm.size()), def, con, 0, con.size());
        //print("constraints {}:\n{}\n", to_string(def), to_string(nv));
        return flatten(nv);
    }

    // insert the constraints into definition 'def'
    void handleConstraints(sComp def) {
        if (conDone_.contains(def)) return; // constraints handled
        auto parent = parent_[def];
        if (parent != def) handleConstraints(parent);
        auto con = constraints_[def];
        symtab_.replace(def, handleConstraints(symtab_[parent], def, con));
        conDone_.emplace(def);
    }

    sName expand_tags(const sName& cur) const {
        sName exp{};
        for (size_t i = 0; i < cur.size(); ++i) {
            auto c = cur[i];
            if (!(c.isLit()) && symtab_.contains(c) && symtab_[c].size() > 1) {
                // name with multi-component expansion
                auto s = symtab_[c];
                exp.insert(exp.end(), s.begin(), s.end());
            } else {
                exp.emplace_back(c);
            }
        }
        return exp;
    }

    void finishTags(const auto& comp) {
        if (tags_.contains(comp)) return;
        const auto& parent = parent_[comp];
        if (comp != parent) finishTags(parent);
        //print("finish tags for {} from {}\n", to_string(comp), to_string(parent));
        tags_[comp] = tags_[parent];
    }

    void finishTags() {
        // set up self-linkage and tags for parents that didn't know they were parents
        for (const auto& [child, parent] : parent_) {
            if (child != parent && !parent_.contains(parent)) {
                //print("make root {} for {}\n", to_string(parent), to_string(child));
                makeParent(parent, parent);
            }
        }
        // set up tags for parents that didn't know they were parents
        for (const auto& [child, parent] : parent_) {
            if (child == parent && !tags_.contains(parent)) {
                // 'parent' definitions are their own parent and 'nm' is used
                // both as their definition and tags.  Derived definitions have
                // the name of their parent in 'nm' and inherit its tags.
                //print("make tags for {}\n", to_string(parent));
                tags_[parent] = tagmap().init(symtab_[parent]);
            }
        }
        // all 'root' parent entries are done. Fill in child tags by propagating
        // down from the root.
        for (const auto& [child, parent] : parent_) {
            finishTags(child);
        }
        // go through all the comps with tags and expand any multi-component defs
        for (const auto& [comp, tm] : tags_) {
            auto cur = tm.tags();
            auto exp = expand_tags(cur);
            if (exp.size() > cur.size()) {
                // tags are parent's initial value - have to fix that too
                tags_[comp] = tagmap().init(exp);
                symtab_.replace(comp, std::move(exp));
            }
        }
    }

    bool isExported(const auto& comp) {
        if (isPrimary(comp)) return true;
        if (! parent_.contains(comp)) return false;
        const auto& parent = parent_[comp];
        if (parent == comp) return false;
        return isExported(parent);
    }

    // return the root pub of a derivation chain. assumes that 'isExported'
    // is true so there is such a pub.
    auto rootComp(const auto& comp) {
        if (isPrimary(comp)) return comp;
        const auto& parent = parent_[comp];
        if (parent == comp) return comp;
        return rootComp(parent);
    }

    void finishDefs() {
        finishTags();

        // Check that the parent is defined for child definitions.
        // Child inherits parent's tags (parent's tags were set up
        // when parent defined).
        for (const auto& [comp, parent] : parent_) {
            if (comp != parent) {
                if (! symtab_.contains(parent)) {
                    std::cerr << "error: " << to_string(comp) << " parent " <<  to_string(parent) << " not defined\n";
                    continue;
                }
            }
            handleConstraints(comp);
            // process all children of exported pubs
            if (isExported(comp)) pubs_.emplace(comp);
        }
        for (const auto& pri : primary_) pubs_.emplace(pri);
    }

    void printGraph(const certDag& g, const auto& nodes) const {
        static const std::array nattr = { "", " [shape=octagon,color=\"gray\",fontcolor=\"gray\"]",
                                          " [color=\"red\",penwidth=2]" };
        static const std::array eattr = { "", " [style=dashed,color=\"gray\"]", " [color=\"red\",penwidth=2]" };
        print("digraph certDag {{\n");
        for (const auto& src : nodes) {
            // filter out some things based on verbosity level
            if (verbose_ < V_FULL && g.attr(src) == 1) continue;
            if (verbose_ < V_DETAIL && to_string(src) == "#chainInfo"s) continue;

            if (g.attr(src) != 0) print("  \"{}\"{};\n", to_string(src), nattr[g.attr(src)]);

            const auto& l = g.links().at(src);
            if (l.size() == 0) {
                print("  \"{}\";\n", to_string(src));
                continue;
            }
            for (const auto& dst : l) print("  \"{}\" -> \"{}\"{};\n", to_string(src), to_string(dst),
                                            eattr[g.attr(src)]);
        }
        print("}}\n");
    }

    sName childrenOf(const sComp pub) const {
        sName children{};
        for (const auto& [c, p] : parent_) if ( p == pub && c != pub) children.emplace_back(c);
        return children;
    }

    void finishCerts() {
        // Cert chains define a DAG for the 'signed by' relation. To avoid redundency,
        // the schema specifies partial chains which are used to build the complete DAG. 
        certDag dag{};

        // certchains_ gives signing chain fragments (one path through the DAG), each
        // expressed as an sName containing sComps of cert definitions in 'signed by' order.
        for (const auto& chain : certchains_) {
            for (const auto& cert : expand_or(chain, 0, chain.size())) dag.add(cert);
        }
        // signer_ gives the signing alternatives for each publication expressed as an sName
        // containing the sComps of each alternative's definition.
        // These specify a set of out-edges from the pub, not a path.
        //for (const auto& [c,p] : parent_) print("c {} p {}\n", to_string(c), to_string(p));
        for (auto& [pub,signers] : signer_) {
            //print("pub {} signer {}\n", to_string(pub), to_string(signers));
            sName pubs({pub});
            // if pub has children, its signers implicitly sign its children so make that explicit.
            // replace signed parent by 'or' of its children
            if (isParent(pub) && childrenOf(pub).size() > 0) {
                pubs = childrenOf(pub);
                //print("childrenOf pub {} : {}\n", to_string(pub), to_string(pubs));
            }
 
            // if the signer is a parent, any of that parent's children can sign.
            // replace the pub with its children
            if (signers.size() == 1 && isParent(signers[0])) {
                //auto s = signers[0];
                signers = childrenOf(signers[0]);
                //print("childrenOf signer {} : {}\n", to_string(s), to_string(signers));
            }
 
            for (auto&& c : pubs) {
                if (parent_.contains(c)) {
                    if (auto parent = parent_.at(c); parent != c) {
                        dag.add(rootComp(c), c);
                        // mark this as a type-to-instance relationship rather than
                        // the default instance-to-signer relationship.
                        dag.attr(rootComp(c), 1);
                    }
                }
                for (auto&& signer : signers) dag.add(c, signer);
            }
        }
        // verify that there are no cycles, a single trust root, and every leaf has paths to the root.
        if (const auto cycle = dag.hasCycle(); cycle.size() > 0) {
            auto src = cycle.back();
            auto dst = std::find_if(cycle.rbegin(), cycle.rend(), [&src,&dag](auto n){ return dag.linked(src, n);});
            print("error: cycle in cert chain due to edge from {} to {}\n", to_string(src), to_string(*dst));
            dag.attr(src, 2);
            printGraph(dag, dag.nodes());
            exit(1);
        }
        if (verbose_ >= V_DEBUG || printDag_) {
            printGraph(dag, dag.topo());
            if (printDag_) exit(0);
        }
        certDag_ = dag;
        auto sinks = dag.sinks();
        if (sinks.size() > 1) symtab_.throw_error(format("multiple trust anchors: {}", sinks));
        if (sinks.size()) {
            sComp root = *(sinks.cbegin());;
     
            // add each publication's cert chains to the pub-to-cert relation.
            for (const auto& pub : pubs_) {
                if (signer_.contains(pub)) {
                    for (auto&& chain : dag.paths(pub, root)) {
                        chains_.emplace_back(chain);
                        //print("pub {} chain {}\n", to_string(pub), to_string(chain));
                    }
                }
            }
        }
    }

    void printChildren() {
        print("Children\n");
        for (const auto& [c, n] : children_) print(" {} : {}\n", to_string(c), to_string(n));
    }

    void expand_names(const sComp cert) {
        if (certs_.contains(cert)) return; // already done
 
        const auto& nm = symtab_[cert];
        certs_[cert] = expand_name(nm, 0, nm.size());
        //print("expand {} : {}\n", to_string(cert), to_string(certs_[cert]));
        if (parent_.contains(cert)) {
            // record each parent's children
            auto root = rootComp(cert);
            children_[root].emplace_back(cert);

            if (isExported(cert)) {
                // update the per-component variation using the expanded names
                const auto& root = rootComp(cert);
                const auto ncomp = tags_[root].size();
                if (! entropy_.contains(root)) entropy_[root] = std::vector<compSet>(ncomp);
                auto& ent = entropy_[root];
                for (auto nm : certs_[cert]) {
                    for (size_t c = 0; c < ncomp; c++) ent[c].set(nm[c].id());
                }
            }
        }
    }

    void computeCompressible() {
        std::map<sComp, std::map<sName,std::pair<size_t,compSet>>> compVar{};
        for(const auto& [cert, nms] : certs_) {
            if (! isExported(cert)) continue;
            const auto& root = rootComp(cert);
            // count the variants per component
            const auto ncomp = tags_[root].size();
            for (auto nm : nms) {
                for (size_t c = 0; c < ncomp; c++) {
                    if (entropy_[root][c].count() == 1) continue;
                    auto sv = nm[c];
                    if (!sv.isLit()) continue;
                    nm[c] = bschema::maxTok;
                    ++compVar[root][nm].first;
                    compVar[root][nm].second.set(sv.id());
                    nm[c] = sv;
                }
            }
        }
        for (const auto& [p, v] : compVar) {
            auto maxc = std::max_element(v.cbegin(), v.cend(), [](const auto& a, const auto& b) {
                    return a.second.first < b.second.first; })->second.first;
            if (maxc <= 1) continue;
            for (const auto& [nm, cntcs] : v) {
                const auto& [cnt, cs] = cntcs;
                if (cnt < maxc) continue;
                // these templates can be compressed
                auto n{nm};
                auto c = std::find(n.begin(), n.end(), bschema::maxTok) - n.begin();
                cs.for_each([this,&n,c](auto b) { n[c] = sComp(b, sComp::fLit); compressible_.emplace(n, c); });

                if (verbose_ >= V_DEBUG) {
                    n[c] = tags_[p].tags()[c];
                    print("{}[{}]: {} var of {}\n", to_string(p), to_string(n[c]), cnt, to_string(n));
                }
            }
        }
    }

    void finishExpand() {
        // Statements in the the schema language can be in any order (e.g., a reference can be used before it's
        // defined). To allow this, nothing in the parse tree is expanded until input EOF. Expand the full cert
        // definitions now so we can validate and output them.
        int i{};
        for (const auto& chain : chains_) {
            signers_[chain[0]].insert(i++);
            for (const auto cert : chain) expand_names(cert);
        }

        // primaries that aren't signed weren't handled above (won't be in children_).
        // If primary doesn't have children expand it. Otherwise expand the children.
        for (auto pub: pubs_) {
            if (children_.contains(pub)) continue;
            if (isExported(pub) && childrenOf(pub).size() != 0) continue;
             expand_names(pub);
        }
        computeCompressible();

        if (verbose_ >= V_DEBUG) {
            print("Per-component instances:\n");
            for (const auto& [p, e] : entropy_) {
                print(" {}: ", to_string(p));
                const auto tags = tags_[p].tags();
                const auto n = tags.size();
                for (size_t c = 0; c < n; c++) {
                    auto cnt = e[c].count();
                    if (cnt > 1) print(" {}: {}", to_string(tags[c]), cnt);
                }
                print("\n");
            }
            print("\n");
        }
        //printChildren();
    }

    // routine run at end of input
    void finish() {
        finishDefs();
        finishCerts();
        finishExpand();
    }
};

static inline driver drv_{};

template <typename... T>
static inline void dprint(fmt::format_string<T...> format_str, T&&... args) {
    if (drv_.verbose_ >= V_DEBUG) print(format_str, std::forward<T>(args)...);
}

#ifdef notyet
template <>
struct fmt::formatter<sComp> {
    // presentation format: 's' - as string, 'd' - raw data
    char presentation = 's';
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        auto it = ctx.begin(), end = ctx.end();
        if (it != end && (*it == 's' || *it == 'd')) presentation = *it++;
        if (it != end && *it != '}') throw format_error("invalid format");

        // Return an iterator past the end of the parsed range:
        return it;
    }
    template <typename FormatContext>
    auto format(const sComp& c, FormatContext& ctx) const -> decltype(ctx.out()) {
        if (presentation == 'd') return format_to(ctx.out(), "({:02x},{:d})", c.flags(), c.id());
        return format_to(ctx.out(), "{}", drv_.symtab().bare_string(c));
    }
};
#endif

template<>
struct fmt::formatter<compSet>: fmt::dynamic_formatter<> {
    template <typename FormatContext>
    auto format(const compSet& v, FormatContext& ctx) const -> decltype(ctx.out()) {
        std::set<std::string> s{};
        v.for_each([&s](auto b){ s.emplace(drv_.symtab().bare_string(b)); });
        return fmt::format_to(ctx.out(), "{}", s);
    }
};

// Give Flex the yylex prototype ...
#define YY_DECL yy::parser::symbol_type yylex(driver& drv)
// ... and declare it for the parser's sake.
YY_DECL;

#endif  // ! DRIVER_HPP
