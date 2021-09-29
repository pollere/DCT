#ifndef VALIDATE_PUB_HPP
#define VALIDATE_PUB_HPP
/*
 * structural (schema-based) publication validation
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
#include <set>
#include <unordered_map>
#include <utility>
#include "buildpub.hpp"
#include "certstore.hpp"
#include "dct/format.hpp"
#include "dct/utility.hpp"
#include "validate_bootstrap.hpp"
#include "dct/distributors/dist_cert.hpp"
#include "dct/distributors/dist_gkey.hpp"

struct pubValidator {
    std::vector<pTmplt> ptmplts_;
    std::unordered_map<bTok,bComp> ptm_;    // pub-specific token map
    std::vector<bTok> ptok_;                // pub-specific tokens
    std::string pstab_;                     // pub-specific string table
 
    pubValidator(std::vector<pTmplt>&& pt, std::unordered_map<bTok,bComp>&& ptm,
                 std::vector<bTok>&& ptok, std::string&& pstab) :
                    ptmplts_{std::move(pt)}, ptm_{std::move(ptm)}, ptok_{std::move(ptok)}, pstab_{std::move(pstab)} {
        // specialize templates for validation (vs construction)
        for (auto& pt : ptmplts_) {
            //assert(pt.dpar_ != maxTok || pt.vs_.to_ulong() == 0ul);
            for (auto& c : pt.tmplt_) {
                //assert(! isCor(c));
                //XXX eventually want type checking here
                if (isParam(c) || isCall(c)) c = SC_ANON;
            }
        }
    }

    using Name = ndn::Name;
    using Comp = Name::Component;

    // convert a name component to a string_view
    static inline auto to_sv(const Comp& comp) {
        const auto& b = *comp.getValue();
        return std::string_view((const char*)b.data(), b.size());
    }

    // Map 'nm' component 'c' to a template token number.
    // Returns the token number if found, maxTok otherwise.
    bComp compToTok(const bSchema& bs, std::string_view pval) const noexcept {
        if (const auto v = bs.tm_.find(pval); v != bs.tm_.end()) return v->second;
        return maxTok;
    }
    // Match Name component 'nmc' to template component 'pt[c]'
    // Different types of template components have different matching rules:
    //  - 'param', 'call' or 'anon' match anything
    //  - a literal or template-specific literal matches exactly
    //  - a value set matches any member of the set
    bool matchCompVal(const bSchema& bs, const Comp& nmc, const bComp ptc) const noexcept {
        if (isAnon(ptc)) return true;     // template doesn't constrain value
        auto pval = to_sv(nmc);
        if (isLit(ptc)) return pval == bs.tok_[ptc];    // comp must match template literal
        if (isIndex(ptc)) return pval == ptok_[typeValue(ptc)]; // value must match cor literal
        return false;
    }
    // check that everything in the template matches its correponding name component
    bool matchComps(const bSchema& bs, const Name& nm, const pTmplt& pt) const noexcept {
        for (auto c = 0u; c < nm.size(); c++) if (!matchCompVal(bs, nm[c], pt.tmplt_[c])) return false;
        return true;
    }
    // check that Name 'nm' matches one of our pub templates
    bool matchTmplt(const bSchema& bs, const Name& nm) const noexcept {
        for (const auto& pt : ptmplts_) {
            // if template has a discriminator check it first
            if (pt.vs_.to_ulong() > 1ul) {
                if (auto t = compToTok(bs, to_sv(nm[pt.dpar_])); t == maxTok || !pt.vs_[t]) continue;
            }
            if (matchComps(bs, nm, pt)) return true;
        }
        return false;
    }
};

// syncps validates each arriving publication using the 'validate' method of
// the 'psig' argument given its constructor. Pub *cryptographic* validation
// is specified by the schema's "#pubValidator" definition. Pub *structural*
// validataion (i.e., its conformance to to the schema) is done by this
// pseudo-sigmgr ('pseudo' the sense that it does only validation, not signing). 
//
// Since syncps does only one 'validate' call per arriving publication, this
// routine does both cryptographic validation (using the schema specified pubValidator)
// and structural validation. As usual, the signing cert thumbprint in the arriving
// pub is used to lookup its signing cert in the certStore to get the public key
// needed for signature validation.
//
// DCT's thumbPrint definition ensures that every valid signing cert is a member of
// exactly one schema signing chain and that chain is completely determined by
// the thumbPrint. The cert structural validator uses this property to validate
// each complete signing chain against the schema before installing a signing
// cert. Since a particular signing chain completely determines the form of the
// pubs that can be signed by that chain's signing cert, when the signing chain
// is validated, a 'pub validator' is constructed that matches a pub only if
// it conforms to the schema's constraints on pubs that can be signed by that
// chain. The cert validator stores this validator in the DCTmodel instance
// in a map indexed by signing cert thumbPrints. This map is passed to the
// SigMgrSchema constructor below so it can find the appropriate validator
// for each arriving Pub.

using tpToValidator = std::unordered_map<thumbPrint,pubValidator>;

struct SigMgrSchema final : SigMgr {
    SigMgr& pubsm_;
    const bSchema& bs_;
    const tpToValidator& pv_;

    SigMgrSchema(SigMgr& pubsm, const bSchema& bs, const tpToValidator& pv) :
        SigMgr(pubsm.type(), pubsm.getSigInfo()), pubsm_{pubsm}, bs_{bs}, pv_{pv} { }

    bool validate(const ndn::Data& data) override final {
        // cryptographically validate 'data'
        if (! pubsm_.validate(data)) {
            //print("invalid sig {}\n", data.getName().toUri());
            return false;
        }
        // structurally validate 'data'
        try {
            const auto& pubval = pv_.at(dctCert::getKeyLoc(data));
            auto valid = pubval.matchTmplt(bs_, data.getName());
            //if (!valid) print("invalid str {}\n", data.getName().toUri());
            return valid;
        } catch (std::exception&) {}
        return false;
    }
};

#endif // VALIDATE_PUB_HPP
