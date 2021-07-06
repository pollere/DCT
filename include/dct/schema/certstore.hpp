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
#include "bschema.hpp"
#include "dct_cert.hpp"

using certName = ndn::Name;
using certVec = std::vector<certName>;
using certChain = std::vector<thumbPrint>;
using keyVal = std::vector<uint8_t>;
using certAddCb = std::function<void(const dctCert&)>;
using chainAddCb = std::function<void(const dctCert&)>;

struct certStore {
    std::unordered_map<thumbPrint,dctCert> certs_{}; // validated certs
    std::multimap<certName,thumbPrint> certnames_{}; // name-to-validated cert(s)
    std::unordered_map<thumbPrint,keyVal> key_{};    // cert-to-key (for signing certs)
    certChain chains_{}; // array of signing chain heads (thumbprints of signing certs)
    certAddCb addCb_{[](const dctCert&){}};          // called when a cert is added
    chainAddCb chainAddCb_{[](const dctCert&){}};    // called when a new signing chain is added

    void dumpcerts() const {
        print("Cert Dump\n");
        int i = 0;
        for (const auto& [tp, cert] : certs_) print("{} {} tp {:x}\n", i++, cert.getName().toUri(), fmt::join(tp," "));
    }

    auto begin() const { return certs_.cbegin(); }
    auto end() const { return certs_.cend(); }

    // lookup a cert given its thumbprint
    const dctCert& get(const thumbPrint& tp) const { return certs_.at(tp); }
    const auto& operator[](const thumbPrint& tp) const { return get(tp); }

    auto contains(const thumbPrint& tp) const noexcept { return certs_.contains(tp); }

    // lookup the signing cert of 'data'
    const dctCert& signingCert(const ndn::Data& data) const {
        const auto& tp = dctCert::getKeyLoc(data);
        return dctCert::selfSigned(tp)? reinterpret_cast<const dctCert&>(data) : get(tp);
    }
    const auto& operator[](const ndn::Data& data) const { return signingCert(data); }

    const auto& key(const thumbPrint& tp) const { return key_.at(tp); }
    auto canSign(const thumbPrint& tp) const { return key_.contains(tp); }

    auto finishAdd(auto it) {
        if (it.second) {
            const auto& [tp, cert] = *it.first;
            certnames_.emplace(cert.getName(), tp);
            addCb_(cert);
        }
        return it;
    }
    // Routines to add a cert to the store. The first two add non-signing certs.
    // The third adds a signing cert with its secret key. If the thumbprint is
    // already in the store, nothing is added or changed (since the thumbprint
    // is a 1-1 mapping to its cert, it should be an error for the mapping
    // to change but this is not currently checked).
    // All return an <iterator,status> pair the points to the element added with
    // 'status' true if the element was added and false if it was already there.
    auto add(const dctCert& c) { return finishAdd(certs_.try_emplace(c.computeThumbPrint(), c)); }
    auto add(dctCert&& c) { return finishAdd(certs_.try_emplace(c.computeThumbPrint(), std::move(c))); }

    auto add(const dctCert& c, const keyVal& k) {
        auto it = finishAdd(certs_.try_emplace(c.computeThumbPrint(), c));
        if (k.size() && it.second) {
            const auto& [tp, cert] = *it.first;
            key_.try_emplace(tp, k);
        }
        return it;
    }

    // construct a vector of the names of each cert in cert's signing chain.
    certVec chainNames(const dctCert& cert) const {
        certVec cv{};
        const auto* c = &cert;
        cv.emplace_back(c->getName());
        for (const auto* tp = &c->getKeyLoc(); !dctCert::selfSigned(*tp); tp = &c->getKeyLoc()) {
            c = &get(*tp);
            cv.emplace_back(c->getName());
        }
        return cv;
    }

    auto signingChain() const { return chains_.empty()? certVec{} : chainNames(get(chains_[0])); } //XXX

    void addChain(const dctCert& cert) {
        chains_.emplace_back(cert.computeThumbPrint());
        chainAddCb_(cert);
    }
    const auto& Chains() const { return chains_; }
    //auto& Chains(const certChain& chain) { chains_ = chain; return *this; }
    //auto& Chains(certChain&& chain) { chains_ = std::move(chain); return *this; }


    // routines to return the *names* of validated certs matching some predicate
    template<class Pred>
    certVec copy_if(Pred pred) const {
        certVec cv{};
        for (const auto& [n, tp] : certnames_) if (pred(n)) cv.emplace_back(n);
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

    //default just calls the start callback with true (e.g., okay to start)
    virtual void start(std::function<void(bool)>&& scb) { scb(true); }
};

static inline certVec match(const certVec& in, const certName& substr) {
    certVec cv{};
    for (const auto& c : in) {
        for (int i = 0, n = c.size() - substr.size(); i < n; i++) {
            if (c.getSubName(i, substr.size()) == substr) { cv.emplace_back(c); break; }
        }
    }
    return cv;
}

#endif // CERTSTORE_HPP
