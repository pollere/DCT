#ifndef OUTPUT_HPP
#define OUTPUT_HPP
/*
 * output - routines to output a DCT binary schema
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
#include <array>
#include <compare>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <type_traits>
#include <utility>
#include "dct/schema/bschema.hpp"
#include "dct/schema/rdschema.hpp"

using namespace bschema;

// Return tlv length 'len' encoded according to NDN packet format spec.
// Lengths >= 64K are not allowed.
static inline void encodeLen(std::ostream& os, int len) {
    if (len < 0 || len >= (1 << 16)) {
        print("-error: invalid tlv length {}\n", len);
        abort();
    }
    if (len >= 253) {
        os.put(char(253));
        os.put(char(len >> 8));
    }
    os.put(char(len));
}

// helper to write encoded length & data of vec/string/span/etc. item
static auto vecItem = [](std::ostream& os, const auto& i) {
    auto len = i.size() * sizeof(i[0]);
    encodeLen(os, len);
    os.write(reinterpret_cast<const char*>(i.data()), len);
    return len;
};

// write vector 'v' in TLV format to stream 'os'
template<typename Tout>
static void writeTLV(std::ostream& os, const Tout& v, sTLV tlv) {
    auto strt = os.tellp();
    os.put(char(tlv));
    auto len = vecItem(os, v);
    dprint("wrote {}({}) bytes for tlv {}({})\n", os.tellp()-strt, len, tlvName.at(tlv), (uint8_t)tlv);
}

// map data items of type Td with keys of type Tk to a dense
// representation (vector<Td>) with index type Ti. The Tk to
// Ti mapping is remembered. Only unique values of Td are
// stored in the vector but multiple Tk keys can map to them.
template <typename Td, typename Tk, typename Ti, sTLV tlv = sTLV::none>
struct mapper {
    std::vector<Td> v_;   // data, indexed by type Ti (int)
    std::map<Tk,Ti> m_;   // parser key to output indx map
    std::map<Td,Ti> vi_;  // data value to index (dup suppression) 

    Ti add(Tk key, Td item) {
        Ti i;
        if (auto vi = vi_.find(item); vi != vi_.end()) {
            i = vi->second;
        } else {
            i = v_.size();
            v_.emplace_back(item);
            vi_.emplace(item, i);
        }
        m_.emplace(key, i);
        return i;
    }

    Ti add(Td item) { return add(item, item); }

    template<typename Tin, class uOp>
    Ti addx(Tk key, Tin vec, uOp op = [](auto i){return i;}) {
        Td item{};
        for (const auto& i : vec) item.emplace_back(op(i));
        return add(key, item);
    }
    auto size() const noexcept { return v_.size(); }
    const Td operator[](Ti idx) const { return v_[idx]; }
    const Ti operator[](Tk key) const { return m_.at(key); }

    void write(std::ostream& os) const {
        static_assert(tlv != sTLV::none, "no tlv specified");
        writeTLV(os, v_, tlv);
    }

    template<class uOp = decltype(vecItem)>
    void writex(std::ostream& os, uOp op = vecItem) const {
        static_assert(tlv != sTLV::none, "no tlv specified");
        std::ostringstream ss{};
        for (const auto& i : v_) op(ss, i);
        writeTLV(os, ss.str(), tlv);
    }
};

struct schemaOut {

    using pChain = int; // index into parser's drv_.chains_
    using pTmplt = int; // index into parser's drv_.templates_

    const sComp anon_;
    std::string stab_{};                    // all strings used by schema
    mapper<bTok,bTok,bComp,sTLV::tok> tok_{};
    mapper<bName,sComp,certidx,sTLV::cert> cert_{};
    mapper<bChain,pChain,chainidx,sTLV::chain> chain_{};
    mapper<chainCor,pChain,coridx,sTLV::cor> cor_{};
    mapper<bName,sComp,tagidx,sTLV::tag> tags_{};
    mapper<bName,pTmplt,tmpltidx,sTLV::tmplt> template_{};
    mapper<bName,compSet,bVLidx,sTLV::vlist> discVals_{};
    mapper<tDiscrim,tDiscrim,discidx,sTLV::disc> discrim_{};
    mapper<tPub,sComp,pubidx,sTLV::pub> pub_{};

    explicit schemaOut() : anon_{drv_.symtab().str2comp("_")} {};

    auto bareString(const sComp c) const { return drv_.symtab().bare_string(c); }
    auto bareString(const sCompId i) const { return drv_.symtab().bare_string(i); }

    // map & rank function for sorting the token table
    using ssCmp = std::function<bool (const std::string &, const std::string &)>;
    using tokStringSet = std::set<std::string, ssCmp>;
    std::map<std::string,sComp> s2c_{};

    int addStr(tokStringSet& ss, sComp c) noexcept {
        if (c.isCall() || c.isValid() || c.isIndex()) return 0;
        auto s = bareString(c);
        if (s2c_.contains(s)) {
            if (s2c_.at(s) != c) print("mult types for {}: {} & {}\n", s, s2c_.at(s), c);
            return 1;
        } else {
            s2c_[s] = c;
        }
        ss.emplace(bareString(c));
        return 1;
    }
    int addStr(tokStringSet& ss, const sName& nm) noexcept {
        int res{};
        for (const auto c : nm) {
            res += addStr(ss, c);
        }
        return res;
    }
    /*
     * create a table containing strings used by the run time schema
     *
     * The token table is ordered to make the run-time schema compact
     * and efficient. The ordering constraints are:
     *  - pub names and parameters should be in the first 1/8th of the table.
     *  - all the elements of a multi-element discriminator should
     *    be grouped together.
     */
    void makeStringTable() {
        // token ranking and ordering functions
        auto cRank = [this](const std::string& s) {
            const sComp& c = s2c_.at(s);
            if (c == anon_) return 1;
            if (c.isLit()) return 2;
            if (s[0] == '_') return 10;  // id
            if (s[0] == '#') return 40;  // pub
            return 20; // parameter
        };
        auto cLess = [cRank](const std::string& l, const std::string& r) {
            // order by highest rank then lexically within rank
            int i = cRank(l) - cRank(r);
            if (i > 0) return true;
            if (i < 0) return false;
            return l < r;
        };
        ssCmp cmp = [cLess](const std::string& l, const std::string& r)->bool { return cLess(l, r); };

        tokStringSet ss(cmp); // set of all strings used

        // get all strings used in certs
        for (const auto& chain : drv_.chains_) {
            for (const auto cert : chain) {
                auto nm = drv_.symtab()[cert];
                for (const auto& n : drv_.expand_name(nm, 0, nm.size())) addStr(ss, n);
            }
        }
        // get all primary pub names and their tags, templates and discrim values
        for (const auto p : drv_.primary_) {
            addStr(ss, p);
            addStr(ss, drv_.tags_.at(p).tags());
            for (const auto& [tpcer, cs] : drv_.discrim_.at(p)) {
                const auto& [t, p, cer] = tpcer;
                addStr(ss, drv_.templates_[t]);
                cs.for_each([this,&ss](auto val){ addStr(ss,sComp(val,sComp::fLit)); });
            }
        }

        // get strings sorted by length, longest first, and total size
        std::multimap<int,const std::string&,std::greater<int>> lm;
        for (const auto& s : ss) lm.emplace(s.size(), s);

        // stab is built longest first to maximize chance of finding
        // that a new string is a substring of an existing string. New
        // strings are inserted at the beginning of the stab to minimize
        // the token offset encoding length.
        int n = 0, u = 0, b = 0;
        for (const auto& [len, str] : lm) {
            b += len;
            if (stab_.find(str) == std::string::npos) {
                ++u;
                stab_.insert(0, str);
            }
            ++n;
        }
        if (drv_.verbose_ >= V_FULL) {
            print("{} strings, {} bytes ({} overlaps, {} bytes in stab)\n", n, b,
                    n - u, stab_.size());
        }
        // tokens need to be created in the ranked order that 'ss' was
        // constructed.
        for (const auto& s : ss) {
            auto p = stab_.find(s);
            auto tok = bTok(stab_.data() + p, s.size());
            tok_.add(tok);
            dprint("{}: {}:{} {}\n", tok_.size()-1, p, tok.size(), tok);
        }
    }
    uint8_t find(const sComp c, const sName& nm) const noexcept {
        for (uint8_t n = nm.size(), i = 0; i < n; i++) {
            if (c == nm[i]) return i;
        }
        print("error: no token {} in name {}\n", drv_.symtab().to_string(c), drv_.to_string(nm));
        abort();
    }
    uint8_t rawTok(const sComp c) const noexcept {
        auto s = bareString(c);
        if (! tok_.m_.contains(s)) {
            print("error: token table missing token \"{}\"\n", s);
            abort();
        }
        return tok_[s];
    }
    uint8_t rawTok(size_t c) const noexcept { return rawTok(sComp(c, sComp::fLit)); }

    uint8_t mapTok(const sComp c, const sName& nm) const noexcept {
        if (c == anon_) return SC_ANON;
        if (c.isCall()) return drv_.comp2fn(c) | SC_CALL;
        if (c.isIndex()) return c.id() | SC_INDEX;
        auto oc = rawTok(c);
        if (c.isLit() || drv_.isParam(c)) return oc;
        if (!c.isStr()) {
            print("error: unexpected token type {}\n", drv_.symtab().to_string(c));
            abort();
        }
        // must be a cor - encode its position in the name
        return find(c, nm) | SC_COR;
    }
    /*
     * Create a table of templates for all the certs used by this
     * schema. Compiler token numbers are mapped to stab tokens.
     * Schema runtime validation needs to check that cert chains contain
     * no loops and all terminate on the same root key. To make these
     * checks cheap, the cert indices are required to be assigned 
     * such that all certs are signed by something with a larger index.
     * I.e., certs in a topological order determined by the signing DAG.
     */
    void makeCertTable() {
        std::set<sComp> needed{};
        for (const auto& [cert,nms] : drv_.certs_) {
            if (drv_.isExported(cert)) continue; // pub, not a cert
 
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
        /*
         *
         * It's possible for two or more certs to have the same components
         * but different paths through the signing DAG (e.g., if their
         * components are determined via parent correspondences but different
         * parents have different signing chains). The duplicate(s) are not
         * placed in certvec_ so their parent dependencies have to be added to the
         * DAG to get a correct topological ordering.
         */
        auto dag = drv_.certDag_;
        auto rdag = dag.reverse();
        for (const auto& cert : dag.topo()) {
            if (! needed.contains(cert)) continue;
            // since a node may be represented by its base class, make sure any signing
            // dependencies include the base class of the signer.
            for (const auto& signer : dag.links(cert)) {
                for (const auto& base : rdag.links(signer)) {
                    if (dag.attr(base) == 1 && !dag.linked(base, cert)) {
                        dag.add(cert, base);
                        //print(" \"{}\" -> \"{}\";\n", drv_.to_string(cert), drv_.to_string(base));
                    }
                }
            }
        }
        for (const auto& cert : dag.topo()) {
            if (! needed.contains(cert)) continue;
            const auto& nm = drv_.certs_.at(cert)[0];
            cert_.addx(cert, nm, [this,&nm](auto c){ return mapTok(c, nm); });
            auto i = cert_[cert];
            dprint("cert {}({}): {}   {::x}\n", i, drv_.to_string(cert), drv_.to_string(nm), cert_.v_[i]);
        }
    }
    /*
     * add all the cert chains used by 'pub' to the chain map.
     */
    void addPubChains(sComp pub) {
        for (pChain i{}, n = drv_.chains_.size(); i < n; i++) {
            if (drv_.rootComp(drv_.chains_[i][0]) != pub) continue;

            const auto& nm = drv_.chains_[i];
            chain_.addx(i, sName(nm.cbegin()+1, nm.cend()), [this](auto c){ return cert_[c]; });
            cor_.add(i, drv_.corespondences_[i]);

            dprint("chain {}({}): {}: {}  ", i, drv_.to_string(drv_.chains_[i][0]),
                   chain_[i], fmt::join(chain_[chain_[i]],"<"));
            dprint("cor {}: {}\n", cor_[i], fmt::join(cor_[cor_[i]],","));
        }
    }
    // set of 'discrimnator' values for some parameter. Since most of
    // these sets contain one value, multi-value sets are indicated by
    // setting the high bit of the return value with the remaining bits
    // giving the index of set in discVals_. Otherwise the entry is the
    // token index of value to compare with.
    bVLidx dValList(const compSet& vs) {
        if (vs.none()) return 0;
        if (vs.count() == 1) return rawTok(vs.find_first());

        bName vals{};
        vs.for_each([this,&vals](auto v){ vals.emplace_back(rawTok(v));});
        return discVals_.add(vs, vals) | 0x80;
    }
    // add one discrim entry to output schema
    auto addDiscrim(auto cbm, auto tmplt, auto par, auto val, auto lcor) {
        dprint("tmplt {}: {:02x}, cor {}, chainBM {:02x}, ", tmplt,
                fmt::join(template_[tmplt],"/"), lcor, cbm);
        auto d = discrim_.add(tDiscrim{cbm, tmplt, par, val, lcor});
        dprint("discrim {}: {}\n", d, discrim_[d]);
        return d;
    }
    discBM addPubDiscrim(sComp pub, parmBM param) {
        discBM discbm{};
        for (const auto& [tpcer, vals] : drv_.discrim_.at(pub)) {
            const auto& [t, par, cer] = tpcer;
            // map the template
            const auto& nm = drv_.templates_[t];
            const auto tmplt = template_.addx(t, nm, [this,&nm](auto c){ return mapTok(c, nm); });
            // convert params in the template to their component index
            for (int n = template_[tmplt].size(), i{}; i < n; i++) {
                if ((param & (1 << i)) == 0 || nm[i].isLit() || (nm[i].isStr() && !drv_.isParam(nm[i]))) continue;
                template_.v_[tmplt][i] = i | SC_PARAM;
            }
            // 'cer' is a set of indices of the cert chains that can sign this template.
            // collect chains with the same cors into chain set bitmap 'cs' then output
            // a discrim for each.
            chainBM cbm{};
            coridx lcor{0xff};
            for (auto ch : cer) {
                if (cor_[ch] != lcor) {
                    // different cors for this chain. If discrim in progress output it then
                    // start accumulating chains with new cor.
                    if (lcor != 0xff) discbm |= 1ul << addDiscrim(cbm, tmplt, par, dValList(vals), lcor);
                    lcor = cor_[ch];
                    cbm = 0;
                }
                auto c = chain_[ch];
                if (c > sizeof(cbm)*8) {
                    print("error: chain index too large ({} when max is {})\n", c, sizeof(cbm)*8);
                    abort();
                }
                cbm |= 1 << c;
            }
            if (lcor == 0xff) lcor = 0;
            discbm |= 1ul << addDiscrim(cbm, tmplt, par, dValList(vals), lcor);
        }
        return discbm;
    }

    /*
     * Create a table of params, tags and templates for all the pubs
     * used by this schema. Compiler token numbers are mapped to stab tokens.
     */
    void addPub(sComp pub) {
        // add the pub's tags
        auto const& tmap = drv_.tags_[pub];
        auto tags = tmap.tags();
        auto tx = tags_.addx(pub, tags, [this](auto c){ return rawTok(c); });
        dprint("tags {}: {}\n  {}\n", tx, drv_.to_string(tags), fmt::join(tags_[tx],"/"));

        // add the pub's params
        parmBM param{};
        auto p = drv_.symtab()[pub];
        for (auto t : p) if (drv_.isParam(t)) param |= 1 << tmap[t];
        dprint("param {:04x}\n", param);
 
        addPubChains(pub);
        auto discbm = addPubDiscrim(pub, param);
        pub_.add(pub, {param, rawTok(pub), tx, discbm});
        dprint("pub {}({}): {}\n", pub_[pub], drv_.to_string(pub), pub_[pub_[pub]]);
    }

    void makePubTable() { for (auto pub: drv_.pubs_) if (drv_.isPrimary(pub)) addPub(pub); }

    void writeSchema() const {
        std::ostringstream os{};

        writeTLV(os, stab_, sTLV::str);
        tok_.writex(os, [this](auto& ss, const auto& t) {
                encodeLen(ss, t.data()-stab_.data()); ss.put(char(t.size())); });
        cert_.writex(os);
        chain_.writex(os);
        cor_.writex(os);
        tags_.writex(os);
        template_.writex(os);
        discVals_.writex(os);
        discrim_.write(os);
        pub_.write(os);
        print("binary schema {} is {} bytes\n", drv_.output(), os.str().size());

#ifdef notyet
        if (drv_.certInstall_) {
            std::istringstream is(os.str());
            rdSchema rs(is);
            auto bs = rs.read();
            schemaInstall(bs, os.str());
        }
#endif
        if (! drv_.output().empty()) {
            std::ofstream of(drv_.output(), std::ios::binary|std::ios::trunc);
            writeTLV(of, os.str(), sTLV::schema);
            of.close();
        }
    }

    void construct()
    {
        makeStringTable();
        makeCertTable();
        makePubTable();
        writeSchema();
    }
};

#endif  // ! OUTPUT_HPP
