#ifndef SEMANTICS_HPP
#define SEMANTICS_HPP
/*
 * semantics - validate and interpret the result of a DCT trust schema parse
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
#include <algorithm>
//#include <bitset>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include "driver.hpp"

// where (which component) does each comp appear in a name
using IdxByComp = std::map<sCompId,compSet>;

// map of all the component references in a collection of names
struct refMap {
    std::map<int,IdxByComp> ic_{};
    std::map<int,compSet> all_{};

    unsigned int idx(sComp def, sCompId v) const { return (def.id() << 8) | v; }

    auto sComp2c(sComp def, sCompId v, sComp c) const { return ic_.at(idx(def, v)).at(c.id()); }

    auto allComps(sComp def, sCompId v) const { return all_.at(idx(def, v)); }

    void add(sComp def, sCompId v, const sName& nm) {
        auto& ic = ic_[idx(def, v)];
        auto& all = all_[idx(def, v)];
        for (compidx c = 0u; c < nm.size(); ++c) {
            if (nm[c] == 0) continue;
            ic[nm[c].id()].set(c); // remember name component(s) where each sComp appears
            all.set(nm[c].id());
        }
    }
};

struct semantics {
    // check if reference component ref appears in any of the certs of chain[1..]
    bool validRef(const sName& chain, const sComp ref, const refMap& rm) {
        // look at all the certs in the chain
        for (size_t c = 1; c < chain.size(); ++c) {
            const auto cert = chain[c];
            // tag name defines 'type' of a component so ref ok if it matches tag
            if (drv_.tags_.contains(cert) && drv_.tags_.at(cert).contains(ref)) return true;
 
            // ref ok if it appears in some variant of this cert
            for (size_t v = 0; v < drv_.certs_[cert].size(); ++v) {
                if (rm.allComps(cert, v).test(ref.id())) return true;
            }
        }
        return false;
    }

    bool validatePub(const sName& chain, const refMap& rm) {
        // all Pub name fields must be literals, explicitly marked
        // 'pre-validated' or validated by something higher in the chain.
        auto ret = true;
        const sComp pkt = chain[0];
        for (const auto& var : drv_.certs_[pkt]) {
            for (size_t i = 0; i < var.size(); ++i) {
                auto f = var[i].flags();
                if (drv_.isParam(var[i]) || (f & (sComp::fLit|sComp::fIndex|sComp::fValid|sComp::fFunc)) ||
                    (f == sComp::fNone && validRef(chain, var[i], rm))) {
                    continue;
                }
                std::cerr << "unvalidated component '" << to_string(var[i]) << "' in "
                          << drv_.to_string(var) << " in chain " << to_string(chain) << '\n';
                std::cerr << "  cert " << drv_.to_string(var) << '\n';
                ret = false;
            }
        }
        return ret;
    }

    bool validateCert(sComp cert, const refMap& rm) {
        // all variants must have the same number of components and all
        // components in common must be in the same place.
        const auto var = drv_.certs_[cert];
        if (var.size() <= 1) return true;
 
        // look at all the variants of this cert, collect the common components and make
        // sure they're in the same place in all variants.
        auto common = rm.allComps(cert, 0);
        for (size_t v = 1; v < var.size(); ++v) {
            if (var[0].size() != var[v].size()) {
                std::cerr << "cert " << to_string(cert) << " variants have different sizes\n";
                return false;
            }
            common &= rm.allComps(cert, v);
        }
        for (size_t v = 1; v < var.size(); ++v) {
            for (size_t c = 0; c < var[0].size(); ++c) {
                const auto v0c = var[0][c];
                if (v0c == var[v][c] || !common.test(v0c.id())) continue;
                // either name might have used the common sComp multiple places. That's
                // ok as long as least one place is in common.
                if ((rm.sComp2c(cert, 0, v0c) & rm.sComp2c(cert, v, v0c)).any()) continue;

                std::cerr << "cert " << to_string(cert) << " variants have different layouts\n";
                return false;
            }
        }
        return true;
    }

    void addRefs(refMap& rm, const sComp def, const sNameVec& var) const {
        sCompId v{};
        for (const auto& nm : var) {
            if (0 && drv_.tags_.contains(def)) {
                rm.add(def, v, drv_.tags_.at(def).tags());
            } else {
                rm.add(def, v, nm);
            }
            v++;
        }
    }

    refMap mkRefMap(const sName& chain) const {
        refMap rm;
        for (auto def : chain) {
            auto nms = drv_.symtab()[def];
            addRefs(rm, def, drv_.expand_name(nms, 0, nms.size()));
        }
        return rm;
    }

    compSet allParams(const sComp pri) const {
        compSet params;
        auto nm = drv_.symtab()[pri];
        for (size_t i = 0; i < nm.size(); ++i) if (drv_.isParam(nm[i]) && !nm[i].isAnon()) params.set(i);
        return params;
    }

    struct uniqueTmpl : std::map<sName,tmplidx> {
        tmplidx add(const sName& t) {
            if (auto i = find(t); i != end()) return i->second;

            auto tindx = drv_.templates_.size();
            drv_.templates_.emplace_back(t);
            emplace(t, tindx);
            return tindx;
        }
    };

    // construct templates that discriminate between the children of one primary pub
    void buildDiscrim(const sComp parent, const sName& children) {
        const auto params = allParams(parent);
        const auto tags = drv_.tags_.at(parent).tags();
        const auto& ent = drv_.entropy_.at(parent);
        discrimMap dmap{};
        uniqueTmpl tuniq{};
        for (const auto& pub : children) {
            const auto& signers = drv_.signers_[pub];
            for (const auto& var : drv_.certs_.at(pub)) {
                if (drv_.compressible_.contains(var)) {
                    auto c = drv_.compressible_.at(var);
                    auto tmpl{var};
                    auto val = tmpl[c];
                    tmpl[c] = tags[c];
                    dmap[{tuniq.add(tmpl),c,signers}].set(val.id()); 
                    //print("{} {} {} : {}\n", to_string(tmpl), c, signers, to_string(val));
                    continue;
                }
                // not part of a set. check for a high entropy literal parameter
                auto emax = params.reduce(0u, [&var, &ent](compidx idx, auto b) -> int {
                                    if (var[b].isLit() && ent[b].count() > ent[idx].count()) idx = b;
                                    return idx;
                        });
                if (emax > 0) {
                    dmap[{tuniq.add(var),emax,signers}].reset();
                    //print("{} {} {} : ({})\n", to_string(var), emax, signers, to_string(var[emax]));
                    continue;
                }
                // nothing distinguishing
                dmap[{tuniq.add(var),bschema::maxTok,signers}].reset();
                //print("{} {} {} : nothing\n", to_string(var), "-", signers);
            }
        }
        drv_.discrim_.emplace(parent, std::move(dmap));
    }

    void printDiscrim(const sComp pri) const {
        std::cout << "  templates:\n";
        auto tags = drv_.tags_.at(pri).tags();
        for (const auto& [tps,cs] : drv_.discrim_.at(pri)) {
            const auto& [t, p, s] = tps;
            print("    {} {{ ", to_string(drv_.templates_[t]));
            for (auto chn : s) print("{} ", to_string(drv_.chains()[chn][1]));
            print("}}\n      [ ");
            if (p == bschema::maxTok) {
                print("*");
            } else {
                print("{}", to_string(tags[p]));
            }
            if (p != bschema::maxTok && cs.count() == 0) {
                print(": ({})", to_string(drv_.templates_[t][p].id()));
            } else if (cs.count() > 0) {
                cs.for_each([this,sep=": "](sCompId b) mutable {
                        print("{}{}", sep, to_string(b));
                        sep = " | ";
                    });
            }
            print(" ]\n");
        }
    }

    void printPub(const sComp pub) const {
        std::cout << "Publication " << to_string(pub) << ":\n";
        std::cout << "  parameters:";
        //for (auto t : drv_.symtab()[pub]) if (drv_.isParam(t)) std::cout << ' ' << to_string(t);
        auto tags = drv_.tags_.at(pub).tags();
        for (auto t : tags) if (drv_.isParam(t)) std::cout << ' ' << to_string(t);
        std::cout << "\n  tags: " << to_string(tags) << '\n';
    }

    void printPubs() const {
        // print primary pubs and their parameters
        for (auto pub: drv_.pubs_) {
            if (drv_.isPrimary(pub)) {
                printPub(pub);
                if (drv_.verbose_ >= V_FULL) printChains(pub);
                if (drv_.verbose_ >= V_DETAIL) printDiscrim(pub);
                std::cout << '\n';
            }
        }
    }

    void printCerts() const {
        // print cert templates in cert dag topological order
        std::set<sComp> needed{};
        for (const auto& [cert,nms] : drv_.certs_) {
            // ignore if pub, not a cert
            if (drv_.isExported(cert)) continue;

            if (nms.size() == 0) {
                print("cert {} undefined\n", drv_.to_string(cert));
                continue;
            }
            if (nms.size() > 1) {
                print("cert {} multiply ({}) defined: {}\n", drv_.to_string(cert), nms.size(), drv_.to_string(nms));
                continue;
            }
            needed.emplace(cert);
        }
        std::cout << "Certificate templates:\n";
        for (const auto& cert : drv_.certDag_.topo()) {
            if (! needed.contains(cert)) continue;
            const auto& nm = drv_.certs_.at(cert)[0];
            print("  cert {}: {}\n", to_string(cert), to_string(nm));
        }
        std::cout << '\n';
    }

    void printChain(int indx) const {
        const auto chain = drv_.chains_[indx];
        print("    chain {}: {}", indx, to_string(chain[0]));
        for (size_t i = 1, n = chain.size(); i < n; ++i) {
            std::cout << " <= " << to_string(chain[i]);
        }
        if (drv_.verbose_ >= V_DETAIL && drv_.corespondences_[indx].size() > 0) {
            // print component corespondences
            std::cout << "\n              ";
            for (const auto& [cert1,comp1,cert2,comp2] : drv_.corespondences_[indx]) {
                print("  {}[{}]=={}[{}]", to_string(drv_.chains_[indx][cert1]), comp1,
                      to_string(drv_.chains_[indx][cert2]), comp2);
            }
        }
        std::cout << '\n';
    }

    void printChains(const sComp pub) const {
        bool needHdr{1};
        for (size_t n = drv_.chains_.size(), i{}; i < n; i++) {
            if (drv_.rootComp(drv_.chains_[i][0]) == pub) {
                if (needHdr) {
                    std::cout << "  signing chains:\n";
                    needHdr = 0;
                }
                printChain(i);
            }
        }
    }

    // all non-literal components of name n must be unique
    bool checkUnique(const sName& n, const std::string& typ) const {
        auto ret = true;
        compSet compbm;
        for (const auto c : n) {
            if (c.isLit() || c.isAnon()) continue;
            if (compbm.test(c.id())) {
                std::cerr << "duplicate component " << to_string(c) << " in "
                          << to_string(n[0]) << " " << typ << '\n';
                ret = false;
            }
            compbm.set(c.id());
        }
        return ret;
    }

    // Cert chain component corespondence mapping
 
    using corComp = std::pair<certidx,compidx>;
    using corMap = std::multimap<sComp,corComp>; // compName, location

    bool isVar(const sComp& c) const noexcept {
        return (c.flags() == 0 && !c.isAnon() && !drv_.isParam(c));
    }

    // add the potential cor components cert with chain index 'cert' and 
    // name 'nm' to correspondence map 'cm'
    void addCorsToMap(auto cert, const auto& certnm, auto& cm) const {
        const sName& nm = drv_.certs_.at(certnm)[0];
        const sName& tags = cert > 0 && drv_.tags_.contains(certnm)?  drv_.tags_.at(certnm).tags() : nm;
        //print("{} {}:\n nm  {}\n tags {} : ", cert, to_string(certnm), to_string(nm), to_string(tags));

        for (size_t comp = 0, n = tags.size(); comp < n; comp++) {
            const auto c = tags[comp];
            if (isVar(c)) {
                cm.emplace(c, corComp{ cert, comp });
                //print(" {}", to_string(c));
            }
            if (c != nm[comp] && isVar(nm[comp])) {
                cm.emplace(nm[comp], corComp{ cert, comp });
                //print(" +{}", to_string(nm[comp]));
            }
        }
        //print("\n");
    }

    // record the potential cor components of all the certs in 'chain'
    corMap buildCorMap(const auto& chain) const {
        corMap cm{};
        for (size_t cert = 0, nc = chain.size(); cert < nc; cert++) addCorsToMap(cert, chain[cert], cm);
        return cm;
    }

    // return 'true' if all the cors of chain 'chn' from 'l' to 'u' are bound to the same literal
    auto allBound(const auto& chn, auto l, auto u) const {
        auto [cert, comp] = l->second;
        const auto& c = drv_.certs_.at(chn[cert])[0][comp];
        if (! c.isLit()) return false;
        return std::all_of(l, u, [&chn,&c](const auto& i) {
                                    auto [ce, co] = i.second;
                                    return c == drv_.certs_.at(chn[ce])[0][co];
                                 });
    }

    // build the component corespondence map for signing chain 'chain'
    void corespondenceMap(size_t chain) const {
        const auto& chn = drv_.chains_[chain];
        const auto cm = buildCorMap(chn);
        chainCor cc{};
        for (auto l = cm.cbegin(), u = cm.end(); l != cm.cend(); l = u) {
            u = cm.upper_bound(l->first);
            if (std::distance(l, u) > 1) {
                if (allBound(chn, l, u)) continue;
                auto c1 = l->second;
                for (auto i = ++l; i != u; ++i) {
                    auto c2 = i->second;
                    auto [cert1,comp1] = c1;
                    auto [cert2,comp2] = c2;
                    cc.emplace_back(corItem{cert1,comp1,cert2,comp2});
                    c1 = c2;
                }
            }
        }
        if (drv_.corespondences_.size() <= chain) drv_.corespondences_.resize(drv_.chains_.size());
        drv_.corespondences_[chain] = std::move(cc);
    }

    bool analyze() {
        // 'chains' is a vector of all the schema's certificate chains, one element per chain. Elements of each
        // chain are the names of the pub & cert(s) in the chain, starting with the pub and ending with the
        // trust anchor.
        //  - All chains must have the same trust anchor
        //  - All elements of each chain must be unique
        const auto& chains = drv_.chains();
        for (const auto& chain : chains) {
            if (chain.back() != chains[0].back()) {
                std::cerr << "trust chains have different anchors\n";
                //return false;
            }
            if (!checkUnique(chain, "chain")) { /*return false;*/ }
        }

        // pubs and certs are validated per trust chain since correspondences are between elements of the same chain.
        for (const auto& chain : chains) {
            auto rm = mkRefMap(chain);
            // the first element of most chains is a pub which have additional constraints.
            if (drv_.certDag_.isSource(chain[0]) && !validatePub(chain, rm)) { /*return false;*/ }
            for (const auto cert : chain) if (!validateCert(cert, rm)) { /*return false;*/ }
        }
        // for each signing chain, make a corespondence map of cert componenent names
        for (size_t n = drv_.chains_.size(), i{}; i < n; i++) corespondenceMap(i);

        // collect all the variants of each primary pub and make sure they're distinguishable.
        for (const auto& [pri,lst] : drv_.children_) {
            if (! drv_.isExported(pri)) continue;
            auto root = drv_.rootComp(pri);
            buildDiscrim(root, lst);
        }
        if (drv_.verbose_ >= V_MIN) {
            printPubs();
            printCerts();
        }
        return true;
    }

    std::string to_string(sComp c) const { return drv_.symtab().to_string(c); }
    std::string to_string(sCompId i) const { return drv_.symtab().bare_string(i); }
    std::string to_string(const sName& n) const { return drv_.to_string(n); }
    std::string to_string(compSet set) const {
        std::string s{};
        for (sCompId b=0; b < set.size(); ++b) if (set.test(b)) s += " " + to_string(b);
        return s;
    }
};

#endif  // ! SEMANTICS_HPP
