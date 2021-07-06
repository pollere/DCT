#ifndef RDSCHEMA_HPP
#define RDSCHEMA_HPP
/*
 * Read and validate a binary (compiled) schema
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

#include <bit>
#include <bitset>
#include <iostream>
#include <istream>
#include <map>
#include <type_traits>
#include <version>
#include "bschema.hpp"
#include "dct/format.hpp"

using namespace bschema;

using parmSet = std::bitset<sizeof(parmBM)*8>;
using chainSet = std::bitset<sizeof(chainBM)*8>;
using discSet = std::bitset<sizeof(discBM)*8>;

template<bool rsdebug = false>
struct rdSchema {
    explicit rdSchema(std::istream& is) : is_(is), remaining_{65535} {}

    // ------ helper routines start here ------
    template <typename... T>
    static inline void dprint(fmt::format_string<T...> format_str, T&&... args) {
        if constexpr (rsdebug) print(format_str, std::forward<T>(args)...);
    }
    std::string formatTok(bComp c) const {
        std::string res{};
        if (c < maxTok) {
            res = bs_.tok_[c];
#if 0
        } else if (isIndex(c)) {
            res = ptok_[typeValue(c)];
#endif
        } else if (c == SC_ANON) {
            res = "_";
        } else {
            res = format("{:02x}", c);
        }
        return res;
    }
    std::string formatName(const bName& nm) {
        std::string res{};
        for (int n = nm.size(), i = 0; i < n; i++) {
            res += '/';
            res += formatTok(nm[i]);
        }
        return res;
    }
    std::string formatNameVec(const std::vector<bName>& nms) {
        std::string res{};
        for (int n = nms.size(), i = 0; i < n; i++) res += format(" {}: {}\n", i, formatName(nms[i]));
        return res;
    }

    void decrRemaining(int len = 1) {
        if (len > remaining_) throw schema_error("tlv bigger than its container");
        remaining_ -= len;
    }
    uint8_t getByte() {
        decrRemaining();
        return (uint8_t)is_.get();
    }
    static constexpr uint8_t extra_bytes_code{253};
    int decodeLen() {
        auto c = getByte();
        if (c < extra_bytes_code) return c;
        if (c > extra_bytes_code) throw schema_error("tlv length >64k");
        auto msb = uint16_t(getByte()) << 8;
        return msb | getByte();
    }
    int getLenAndDecr() {
        int len = decodeLen();
        decrRemaining(len);
        return len;
    }
    void checkTLV(sTLV typ) {
        auto x = getByte();
        if (sTLV(x) != typ) throw schema_error(format("wrong tlv {} not {}", x, typ));
    }
    int checkHDR(sTLV typ) {
        checkTLV(typ);
        int len = decodeLen();
        if (len > remaining_) throw schema_error("tlv bigger than its container");
        return len;
    }

    // ------ template routines to read either fixed or variable length ------
    // ------ items while maintaning an appropriate level of paranoia   ------

    // read one vector or scalar item.
    template<typename Tin,typename Tout=typename std::decay_t<Tin>::value_type>
    Tout getItem(int last) {
        // test if Tout is a vector (or string)
        constexpr bool is_vec = requires(const Tout& t) { t.data(); };
        if constexpr (is_vec) {
            // read a length followed by that many component tokens.
            auto len = decodeLen();
            if (len > last - is_.tellg()) throw schema_error("vec too long");
            using iType = typename std::decay_t<Tout>::value_type;
            if (len % sizeof(iType) != 0) throw schema_error("length not multiple of item size");
            Tout dat(len / sizeof(iType));
            if (len > 0) is_.read((char*)(&dat[0]), len);
            return dat;
        } else {
            if (last - int(sizeof(Tout)) < is_.tellg()) throw schema_error("item truncated");
            Tout dat;
            is_.read((char*)(&dat), sizeof(Tout));
            return dat;
        }
    }

    // read TLV 'tlv' which contains a 'vector' of type 'Tout' items.
    template<typename Tout, class Getter>
    void readVec(sTLV tlv, std::vector<Tout>& vec, Getter getItem) {
        int last = checkHDR(tlv) + is_.tellg();
        while (is_.tellg() < last) {
            vec.emplace_back(getItem(last));
        }
    }

    // ------ routines to read and validate schema sections start here ------

    void readStr() {
        // the string table (stab) is a single array of characters.
        int len = checkHDR(sTLV::str);
        decrRemaining(len);
        bs_.stab_.insert(0, len + 1, char(0));
        is_.read(&bs_.stab_[0], len);
    }
    void readTok() {
        // tokens are a (variable length encoded) offset followed by a one byte length. The entire token
        // must be within the stab.  They are converted to a vector of stab string_views and a map
        // from a string to a token index.
        auto& vec = bs_.tok_;
        readVec(sTLV::tok, vec,
            [this,&vec,stablen=bs_.stab_.size()](int /*last*/) {
                size_t off = decodeLen();
                auto siz = getByte();
                if (off + siz > stablen) throw schema_error("token outside stab");
                if (vec.size() >= maxTok) throw schema_error("too many tokens");
                auto tok = bTok(bs_.stab_.data() + off, siz);
                bs_.tm_.emplace(tok, vec.size());
                dprint("tok {}: {}\n", vec.size(), tok);
                return tok;
            });
    }
    void readCert() {
        // each cert has a length followed by that many component tokens. Each token must be
        // in the token table and must be a LIT, COR or ANON.
        auto& vec = bs_.cert_;
        readVec(sTLV::cert, vec,
            [this,ntok=bs_.tok_.size()](int last) {
                auto n = getItem<decltype(vec)>(last);
                for (auto c : n) if (!(c < ntok || isCor(c) || isAnon(c))) throw schema_error("invalid cert component");
                return n;
            });
        dprint("certs\n{}", formatNameVec(bs_.cert_));
    }
    void readChain() {
        // each chain has a length followed by that many cert indices.  Each index must be in cert_ and,
        // to detect & prevent loops in a chain, larger than the index preceding it (compiler is
        // required to topo order certs in vec).
        dprint("chains\n");
        auto& vec = bs_.chain_;
        readVec(sTLV::chain, vec,
            [this,&vec,ncert=bs_.cert_.size()](int last) {
                auto item = getItem<decltype(vec)>(last);
                // All chains must end with the same trust anchor.
                if (vec.size() > 0 && vec[0].back() != item.back()) throw schema_error("multiple trust anchors");
                for (int prev = -1; const auto& c : item) {
                    if (!(c < ncert && prev < c)) throw schema_error("invalid chain cert order");
                    prev = c;
                }
                dprint(" {}: {}\n", vec.size(), item);
                return item;
            });
    }
    void readCor() {
        // 'cor' items are a vector of <cert1,comp1,cert2,comp2> tuples asserting that
        // cert[cert1][comp1] == cert[cert2][comp2] for the certs of some trust chain.  They need the 'discrim'
        // items that bind them to their chain and template so they're validated in chkconsist after eof.
        dprint("correspondences\n");
        auto& vec = bs_.cor_;
        readVec(sTLV::cor, vec,
            [this,&vec](int last) {
                auto n = getItem<decltype(vec)>(last);
                dprint(" {}: {}\n", vec.size(), n);
                return n;
            });
    }
    void readTag() {
        // Each tag has a length followed by that many component tokens.
        // Each token must be in the token table (all tags are strings).
        auto& vec = bs_.tag_;
        readVec(sTLV::tag, vec,
            [this,ntok=bs_.tok_.size()](int last) {
                auto n = getItem<decltype(vec)>(last);
                for (auto c : n) if (c >= ntok) throw schema_error("invalid component in tag");
                return n;
            });
        dprint("tags\n{}", formatNameVec(bs_.tag_));
    }
    void readTmplt() {
        // each template has a length followed by that many component tokens.
        // Each token must be in the token table and must be valid.
        auto& vec = bs_.tmplt_;
        readVec(sTLV::tmplt, vec,
            [this,ntok=bs_.tok_.size()](int last) {
                auto n = getItem<decltype(vec)>(last);
                for (auto c : n) if (!(c < ntok || validType(c))) throw schema_error("invalid template component");
                return n;
            });
        dprint("templates\n{}", formatNameVec(bs_.tmplt_));
    }
    void readVlist() {
        // each varlist has a length followed by that many component tokens.
        // Each token must be in the token table and must be valid.
        auto& vec = bs_.vlist_;
        readVec(sTLV::vlist, vec,
            [this,ntok=bs_.tok_.size()](int last) {
                auto n = getItem<decltype(vec)>(last);
                for (auto c : n) if (!(c < ntok && isLit(c))) throw schema_error("invalid varlist component");
                return n;
            });
        dprint("varLists {}\n", bs_.vlist_);
    }
    void readDiscrim() {
        // Each discriminator is a 5-tuple containing the information
        // needed to build and validate one variant of a publication.
        dprint("discrim\n");
        auto& vec = bs_.discrim_;
        readVec(sTLV::disc, vec,
            [this,&vec](int last) {
                auto n = getItem<decltype(vec)>(last);
                dprint(" {}: {}\n", vec.size(), n);
                const auto& [chain,tmplt,comp,vlist,cor] = n;
                for (auto chn = chain; chn != 0; ) {
                    size_t c = std::countr_zero(chn);
                    if (c >= bs_.chain_.size()) throw schema_error("invalid discrim chain index");
                    chn &=~ 1u << c;
                }
                if (tmplt >= bs_.tmplt_.size()) throw schema_error("invalid discrim template index");

                // 'comp' needs to be in pub's param set which can't be checked until
                // discrim's pub is read so it's handled later in chkconsist.

                // 'vlist' is what value(s) comp must have to match this discrim. It's either a token
                // index or the index of a vector of tokens, depending on whether the high bit is set.
                if ((vlist & (maxTok-1)) >= (vlist < maxTok? bs_.tok_.size() : bs_.vlist_.size()))
                    throw schema_error("invalid discrim vlist index");

                // 'comp' == maxTok means no val(s) to check, 'vlist' should be 0 in this case
                if (comp == maxTok && vlist != 0) throw schema_error("discrim vlist index should be zero");

                // 'cor' is an index of the cert chain component correspondences that must hold
                // for a publication with this discrim.
                if (cor >= bs_.cor_.size() && cor > 0) throw schema_error(format("invalid discrim cor index {}", cor));
                return n;
            });
    }
    void readPub() {
        // Each pub is a 4-tuple containing the information needed to build and validate all its variants.
        auto& vec = bs_.pub_;
        readVec(sTLV::pub, vec,
            [this](int last) {
                auto n = getItem<decltype(vec)>(last);
                const auto& [param,disc,pub,tagi] = n;
                if (pub >= bs_.tok_.size()) throw schema_error("invalid pub tok index");
                if (tagi >= bs_.tag_.size()) throw schema_error("invalid pub tag index");

                // disc is a bitmap where a set bit indicates the pub uses the discrim with that index.
                // validate that the MSB falls within the discrim vec
                // XXX MacOS clang11 misnames std::bit_width as log2p1, fixed in clang12. The <version>
                // defines are still broken in Apple's clang12 so we have to test the wrong define.
//#if defined(__APPLE__) && !defined(__cpp_lib_bitops)
#if defined(__APPLE__) && !defined(__cpp_lib_bounded_array_traits)
                if (std::log2p1(disc) - 1u >= bs_.discrim_.size()) throw schema_error("invalid pub discrim index");
#else
                if (std::bit_width(disc) - 1u >= bs_.discrim_.size()) throw schema_error("invalid pub discrim index");
#endif

                // param is a bitmask with each bit corresponding to one component of the pub.
                // A bit is set if that component is a pub parameter so each set bit position
                // must be < #pub components. Each parameter must also be marked as such in the
                // pub's templates but this is validated in chkconsist.
                for (auto par = param; par != 0; ) {
                    size_t p = std::countr_zero(par);
                    if (p >= bs_.tag_[tagi].size()) throw schema_error("invalid pub param index");
                    par &=~ 1u << p;
                }
                return n;
            });
    }
    const bName& corName(const bName& tmplt, chainidx c, certidx cert, compidx comp) {
        const auto& chain = bs_.chain_[c];
        const auto& n = (cert == 0)? tmplt : bs_.cert_[chain[cert - 1]];
        if (comp >= n.size()) throw schema_error("cor component index too big");
        return n;
    }
    void chkCor(chainBM chainbm, const bName& tmplt, const chainCor& chnCor) {
        while (chainbm != 0) {
            auto c = std::countr_zero(chainbm);
            chainbm &=~ 1u << c;
            for (auto [cert1,comp1,cert2,comp2] : chnCor) {
                if (cert1 >= cert2) throw schema_error("cor cert indices error");
                auto c1 = corName(tmplt, c, cert1, comp1);
                auto c2 = corName(tmplt, c, cert2, comp2);
                // first cert comp must be a cor. second cert can be a cor or a lit but must match first if a cor.
                if (!isCor(c1[comp1])) throw schema_error("template cor not marked as cor");
                if (typeValue(c1[comp1]) != comp1) throw schema_error("template cor index mismatch");
                if (isCor(c2[comp2]) && typeValue(c2[comp2]) != comp2) throw schema_error("cert cor index mismatch");
            }
        }
    }
    void chkConsist() {
        int pubidx{};
        for (const auto& [param,disc,pub,tagi] : bs_.pub_) {
            dprint("pub {}: {}\n", bs_.tok_.at(pub), bs_.pub_[pubidx++]);
            discSet ds{disc};
            for (size_t d = 0, de = bs_.discrim_.size(); d < de; d++) {
                if (ds[d] == 0) continue;
                const auto& [chainbm,tmplt,comp,vlist,cor] = bs_.discrim_[d];
                // all params have to be in the template and there should be no other params
                parmSet pset{param};
                const auto tmpl = bs_.tmplt_[tmplt];
                for (int c = 0, n = tmpl.size(); c < n; c++) {
                    // comps in the param set must be literals, params or cors
                    if (pset[c] && !isParam(tmpl[c]) && !isCor(tmpl[c]) && tmpl[c] >= bs_.tok_.size())
                            throw schema_error("parameter not in template");
                    if (!pset[c] && isParam(tmpl[c])) throw schema_error("template param not in param set");
                    if (isParam(tmpl[c]) && typeValue(tmpl[c]) != c) throw schema_error("param value wrong");
                }
                // a comp to test must be in the param set
                if (comp < maxTok && !pset[comp]) throw schema_error("discrim's component not in param set");

                // comp of maxTok means no component is a discrim. Comp = maxTok+n indicates a 'replace'
                // operator that will take a pub name with 'n' components as its only argument and will
                // put each of those components into the corresponding param slot.
                if (comp > maxTok && typeValue(comp) >= tmpl.size()) throw schema_error("'replace' size error");
 
                // validate the cor entry.  Each item in it is a correspondence vector for one named field
                // containing the chain's cert index and cert's component index of each place the field appears.
                // Check that there are at least two elements in each field's entry and that all the indices
                // are with the item they index.  Note that cor chain indices include the pub as item 0 (i.e.,
                // real chain_ index + 1);
                if (chainbm != 0) chkCor(chainbm, tmpl, bs_.cor_[cor]);

                dprint(" {}: {:02x} {}", d, chainbm, formatName(bs_.tmplt_[tmplt]));
                if (comp < maxTok) {
                    dprint(" {}: ", bs_.tok_[bs_.tag_[tagi][comp]]);
                    if (vlist == 0) dprint("{}", bs_.tok_[tmpl[comp]]);
                    else if (vlist < maxTok) dprint("{}", bs_.tok_[vlist]);
                    else dprint("@{}", typeValue(vlist));
                }
                if (chainbm != 0) dprint(" {}", bs_.cor_[cor]);
                dprint("\n");
            }
        }
    }
    bSchema read() {
        remaining_ = checkHDR(sTLV::schema);
        readStr();
        readTok();
        readCert();
        readChain();
        readCor();
        readTag();
        readTmplt();
        readVlist();
        readDiscrim();
        readPub();
        chkConsist();
        return bs_;
    }

    std::istream& is_;
    int remaining_{};
    bSchema bs_{};
};

#endif // RDSCHEMA_HPP
