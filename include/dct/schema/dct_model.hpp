#ifndef DCTMODEL_HPP
#define DCTMODEL_HPP
#pragma once

/*
 * Data Centric Transport schema policy model abstraction
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
#include "validate_pub.hpp"
#include "dct/distributors/dist_cert.hpp"
#include "dct/distributors/dist_gkey.hpp"
#include "dct/distributors/dist_sgkey.hpp"

using namespace std::literals;

namespace dct {

//template<typename sPub>
struct DCTmodel {
    certStore cs_{};        // certificates used by this model instance
    std::unordered_multimap<thumbPrint,dctCert> pending_{};
    const bSchema& bs_;     // trust schema for this model instance
    pubBldr<false> bld_;    // publication builder/verifier
    SigMgrAny psm_;         // publication signing/validation
    SigMgrAny csm_;         // cert signing/validation (XXXX currently limited to EdDSA)
    SigMgrAny wsm_;         // wire packet signing/validation
    SigMgrSchema syncSm_;   // syncps pub validator
    SyncPS m_sync;  // sync collection for pubs
    static inline std::function<size_t(std::string_view)> _s2i;
    DistCert m_ckd;         // cert collection distributor
    DistGKey* m_gkd{};      // group key distributor (if needed)
    DistSGKey* m_sgkd{};    // subscriber group key distributor (if needed)
    DistGKey* m_pgkd{};      // pubs group key distributor (if needed)
    DistSGKey* m_psgkd{};    // pubs subscriber group key distributor (if needed)
    tpToValidator pv_{};    // map signer thumbprint to pub structural validator

    SigMgr& wireSigMgr() { return wsm_.ref(); }
    SigMgr& pubSigMgr() { return psm_.ref(); }
    SigMgr& certSigMgr() { return csm_.ref(); }
    auto pubPrefix() const { return crName{bs_.pubVal("#pubPrefix")}; }

    // all cState/cAdd packet names start with the first 8 bytes
    // of the schema cert thumbprint to make them trust-zone specific.
    auto wirePrefix() const { return crName()/std::span(bs_.schemaTP_).first(8); }

    const auto& certs() const { return cs_; }

    bool isSigningCert(const dctCert& cert) const {
        // signing certs are the first item each signing chain so go through
        // all the chains and see if the first item matches 'cert'
        for (const auto& chn : bs_.chain_) {
            if (chn.size() == 0) continue;
            if (matches(bs_, cert.name(), chn[0])) return true;
        }
        return false;
    }

    // setup the information needed to validate pubs signed with the cert
    // associated with 'tp' which is the head of schema signing chain 'chain'.
    void setupPubValidator(const thumbPrint& tp) {
        //XXX this is a hack and should be refactored
        // Make a temporary builder to construct the pub templates associated
        // with this signing chain. To do this we need a *copy* of the current
        // certstore with its signing chain 0 set to 'tp'.
        certStore cs = cs_;
        cs.chains_[0] = tp;
        pubBldr bld(bs_, cs, bs_.pubName(0));
        pv_.emplace(tp, pubValidator(std::move(bld.pt_), std::move(bld.ptm_),
                                     std::move(bld.ptok_), std::move(bld.pstab_)));
    }

    // Check if newly added cert 'tp' allows validation of pending cert(s)
    // Validating and adding a pending cert may allow others to be validated
    // so this routine can get called recursively but the recursion depth
    // should be at most the schema's max signing chain length - 2.
    void checkPendingCerts(const dctCert& cert, const thumbPrint& tp) {
        auto [b, e] = pending_.equal_range(tp);
        if (b == e) return;
        std::vector<dctCert> pv{};
        for (auto i = b; i != e; ++i) {
            if (certSigMgr().validate(i->second, cert)) pv.emplace_back(std::move(i->second));
        }
        pending_.erase(tp);
        for (auto p : pv) addCert(p);
    }

    // Cryptographically and structurally validate a cert before adding it to the
    // cert store. Since certs can arrive in any order, a small number of certs
    // are held pending their signing cert's arrival.
    void addCert(rData d) {
        const auto tp = dctCert::computeThumbPrint(d);
        if (cs_.contains(tp)) return;
        // check if cert is consistent with the schema:
        //  - cert metainfo must say it's a key
        //  - siginfo has to include a validity period and now must be within the period
        //  - signature type must match schema requirement
        //  - name has to match some cert template in the schema
        //  - can't be a root cert or a trust schema
        // (new root certs and schemas are currently ignored because they often result from
        // a configuration error (e.g., updating a schema in some but not all id bundles.)
        // XXX eventually need tools to securely check/update certs & bundles
        try {
            auto cert = rCert{d};
            if (! cert.valid(certSigMgr().type())) return;
            auto cname = tlvVec(cert.name());
            if (matchesAny(bs_, cname) < 0) return; // name doesn't match schema

            const auto& stp = cert.thumbprint();
            if (dctCert::selfSigned(stp)) return; // can't add new root cert

            if (cname.size() >= 7 && cname[-6].toSv() == "schema") return; // can't add new schema
 
            // cert is structurally ok so see if it crytographically validates
            if (! cs_.contains(stp)) {
                // don't have cert's signing cert - check it when that arrives
                if (pending_.size() > 64) {
                    // XXX too many pending certs - drop something
                } 
                pending_.emplace(stp, cert);
                return;
            }
            if (! certSigMgr().validate(cert, cs_[stp])) return;

            if (isSigningCert(cert)) {
                // we validated a signing cert which means we have its entire chain
                // in the certstore so we can validate all the names in the chain
                // against the schema. If the chain is ok, set up structural validation
                // state for pubs signed with this thumbprint.
                if (validateChain(bs_, cs_, cert) < 0) return; // chain structure invalid
                cs_.add(cert);
                setupPubValidator(tp);
                return; // done since nothing can be pending on a signing cert
            }
            cs_.add(cert);
            checkPendingCerts(cert, tp);
        } catch (const std::exception&) {};
    }

    // schedule a call to 'cb' in 'd' microseconds (cannot be canceled)
    auto oneTime(std::chrono::microseconds delay, TimerCb&& cb) { m_sync.oneTime(delay, std::move(cb)); }

    void getNewSP(const pairCb& spCb) {
        auto sp = spCb();       //new signing key pair
        auto sc = sp.first;     // public cert of pair
        auto now = std::chrono::system_clock::now();
        auto nt = rCert(sc).validUntil() - 10s;   // reschedule before expiration time
        if (nt <= now)
            std::runtime_error("getNewSP was handed an expired cert");
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(nt-now);
        oneTime(time, [this,spCb]{getNewSP(spCb);});    //schedule re-keying

        auto addKP = [this](auto& sp){
            auto sc = sp.first;
            cs_.add(sc, sp.second);   //add this signing cert
            // make it a signing chain head
            if (validateChain(bs_, cs_, sc) < 0) throw schema_error(format("cert {} signing chain invalid", sc.name()));
            cs_.insertChain(sc);
            // pass new signing pair to sigmgrs and distributors
            pubSigMgr().updateSigningKey(sp.second, sc);
            wireSigMgr().updateSigningKey(sp.second, sc);
            // update cAdd group key distributors if any
            if (m_gkd)   m_gkd->updateSigningKey(sp.second, sc);
            else if (m_sgkd) m_sgkd->updateSigningKey(sp.second, sc);
            // update Publication group key distributors if any
            if (m_pgkd)   m_pgkd->updateSigningKey(sp.second, sc);
            else if (m_psgkd) m_psgkd->updateSigningKey(sp.second, sc);
        };

        if (rCert(sc).validAfter() > now) {
            // schedule usage of the new pair once validity period starts
            auto time = rCert(sc).validAfter() - now;
            auto timeMillis = std::chrono::duration_cast<std::chrono::milliseconds>(time);
            oneTime(timeMillis, [addKP,sp] { addKP(sp); } );
        } else
            addKP(sp);  // within new cert validity period, add to certstore and use
    }

    // create a new DCTmodel instance and pass the callbacks to access required certs to
    // "bootstrap" this new transport instance
    // optional string for face name
    DCTmodel(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, DirectFace& face = defaultFace()) :
            bs_{validateBootstrap(rootCb, schemaCb, idChainCb, signIdCb, cs_)},
            bld_{pubBldr(bs_, cs_, bs_.pubName(0))},
            psm_{getSigMgr(bs_)},
            csm_{getCertSigMgr(bs_)},
            wsm_{getWireSigMgr(bs_)},
            syncSm_{psm_.ref(), bs_, pv_},
            m_sync{face, wirePrefix()/"pubs", wireSigMgr(), syncSm_},
            m_ckd{ face, pubPrefix(), wirePrefix()/"cert",
                   [this](auto cert){ addCert(cert);},  [](auto /*p*/){return false;} }
    {
        // pub sync session is started after distributor(s) have completed their setup
        m_sync.autoStart(false);
        if(wsm_.ref().encryptsContent()) {
            if (matchesAny(bs_, pubPrefix()/"CAP"/"KM"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                throw schema_error("Encrypted CAdds require that some entity(s) have KeyMaker capability");
            }
            if (! wsm_.ref().subscriberGroup()) {
                m_gkd = new DistGKey(face, pubPrefix(), wirePrefix()/"keys"/"pdus",
                             [this](auto gk, auto gkt){ wsm_.ref().addKey(gk, gkt);}, certs());
            } else {
                if (matchesAny(bs_, pubPrefix()/"CAP"/"SG"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                    // schema doesn't contain an SG member so PP won't work XXXX should extract name of group from schema
                    throw schema_error("PPSIGNED/PPAEAD require that some entity(s) have Subscriber capability");
                }
                m_sgkd = new DistSGKey(face, pubPrefix(), wirePrefix()/"keys"/"pdus",
                             [this](auto gpk, auto gsk, auto ct){ wsm_.ref().addKey(gpk, gsk, ct);}, certs());
            }
        }
        //encryption methods for pubs MUST be signed versions
        if(psm_.ref().encryptsContent()) {
            if (matchesAny(bs_, pubPrefix()/"CAP"/"KMP"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                // schema doesn't contain a "KeyMaker" capability cert so AEAD won't work
                throw schema_error("pub content encryption requires that some entity(s) have KeyMaker capability");
            }
            if ( psm_.ref().subscriberGroup()) {
                if (matchesAny(bs_, pubPrefix()/"CAP"/"SG"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                    // schema doesn't contain a member with subscriber  ability so PPAEAD won't work
                    throw schema_error("PPSIGNED requires that some entity(s) have Subscriber capability");
                }
                // XXXX instead of pubs could be name of subscriber group
                m_psgkd = new DistSGKey(face, pubPrefix(), wirePrefix()/"keys"/"pubs",
                             [this](auto gpk, auto gsk, auto ct){ psm_.ref().addKey(gpk, gsk, ct);}, certs());
            } else {
                m_pgkd = new DistGKey(face, pubPrefix(), wirePrefix()/"keys"/"pubs",
                             [this](auto gk, auto gkt){ psm_.ref().addKey(gk, gkt);}, certs());
            }
        }

        // cert distributor needs a callback when cert added to certstore.
        cs_.addCb_ = [&ckd=m_ckd] (const dctCert& cert) { ckd.publishCert(cert); };

        for (const auto& [tp, cert] : cs_) m_ckd.initialPub(cert);

        // pub and wire sigmgrs each need its signing key setup and its validator needs
        // a callback to return a public key given a cert thumbprint.
        const auto& tp = cs_.Chains()[0]; // thumbprint of signing cert
        pubSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
  //      certSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);    //do I need this?
        wireSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
        pubSigMgr().setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });
        wireSigMgr().setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });

        // SPub need access to builder's 'index' function to translate component names to indices
        _s2i = std::bind(&decltype(bld_)::index, bld_, std::placeholders::_1);

        // set up timer to request a new signing pair before this pair expires
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(rCert(cs_[tp]).validUntil() - std::chrono::system_clock::now() - 10s);
        oneTime(time , [this, signIdCb] {getNewSP(signIdCb);});    //schedule re-keying
    }

    // export the syncps API
 
    auto run() { m_sync.run(); };
    auto stop() { m_sync.stop(); };

    auto& subscribe(const Name& topic, SubCb&& cb) {
        m_sync.subscribe(crPrefix{topic}, std::move(cb));
        return *this;
    }
    auto& unsubscribe(const Name& topic) {
        m_sync.unsubscribe(crPrefix{topic});
        return *this;
    }
    auto publish(Publication&& pub) { return m_sync.publish(std::move(pub)); }

    auto publish(Publication&& pub, DelivCb&& cb) { return m_sync.publish(std::move(pub), std::move(cb)); }
    auto orderPub(OrderPubCb&& cb) { return m_sync.orderPubCb(std::move(cb));}
    auto& pubLifetime(std::chrono::milliseconds t) {
        m_sync.pubLifetime(t);
        return *this;    
    }

    // Can be used by application to schedule a cancelable timer. Note that
    // this is expensive compared to a oneTime timer and should be used
    // only for timers that need to be canceled before they fire.
    auto schedule(std::chrono::microseconds delay, TimerCb&& cb) { return m_sync.schedule(delay, std::move(cb)); }


    // construct a pub name from pairs of tag, value parameters
    template<typename... Rest> requires ((sizeof...(Rest) & 1) == 0)
    auto name(Rest&&... rest) { return bld_.name(std::forward<Rest>(rest)...); }

    // construct a publication with the given content using rest of args to construct its name
    template<typename... Rest> requires ((sizeof...(Rest) & 1) == 0)
    auto pub(std::span<const uint8_t> content, Rest&&... rest) {
        Publication pub(name(std::forward<Rest>(rest)...));
        pub.content(content);
        pubSigMgr().sign(pub);
        return pub;
    }

    auto name(const std::vector<parItem>& pvec) { return bld_.name(pvec); }

    auto pub(std::span<const uint8_t> content, const std::vector<parItem>& pvec) {
        Publication pub(name(pvec));
        pub.content(content);
        pubSigMgr().sign(pub);
        return pub;
    }

    // set defaults to be used when constructing pub names
    template<typename... Rest>
    auto defaults(Rest&&... rest) { return bld_.defaults(std::forward<Rest>(rest)...); }

    // set start callback for shims that have a separate connect/start like mbps
    // Note: this can get much simpler when distributors derive from a common class
    void start(connectedCb&& cb) {
        auto pdu_dist = m_gkd == NULL? m_sgkd != NULL :  true;
        auto pub_dist = m_pgkd == NULL ? m_psgkd != NULL :  true;
        if (!pdu_dist && !pub_dist) {
            m_ckd.setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
            return;
        }

        // complete pdu key distribution before pub key distribution
        if ( pdu_dist && !pub_dist ) {
            m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                        if (!c) { cb(false); return; }
                        if (m_gkd) {
                            m_gkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                        } else { // must be m_sgkd
                            m_sgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                        }
                    });
            return;
        } else  if ( !pdu_dist && pub_dist) {
             m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                        if (!c) { cb(false); return; }
                        if (m_pgkd) {
                            m_pgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                        } else { // must be m_psgkd
                            m_psgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                        }
                    });
            return;
        } else {    //both pdus and pubs have a distributor
           m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                        if (!c) { cb(false); return; }
                        if (m_gkd) {
                            m_gkd->setup([this,cb=std::move(cb)](bool c){
                                if (!c) { cb(false); return; }  // check if pdu distributor returns false
                                if (m_pgkd)
                                    m_pgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                                else    // must be m_psgkd
                                    m_psgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                           });
                        } else { // must be m_sgkd
                           m_sgkd->setup([this,cb=std::move(cb)](bool c){
                                if (!c) { cb(false); return; }  // check if pdu distributor returns false
                                if (m_pgkd)
                                    m_pgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                                else    // must be m_psgkd
                                    m_psgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                           });
                        }
                    });
        }
    }

    // inspection API to extract information from the schema.

    // return a vector containing the tag or parameter names for the default pub
    // or a named pub.
    auto tagNames() const { return bld_.tagNames(); }
    auto paramNames() const { return bld_.paramNames(); }

    auto tagNames(std::string_view pubnm) const { return bs_.tagNames(pubnm); }
    auto paramNames(std::string_view pubnm) const { return bs_.paramNames(pubnm); }

    // return the 'value' of some publication in the schema, either as a Name or,
    // if a tag for the pub is given, the value of that component. This is intended
    // to extract information from parameter-less meta-information pubs like
    // #pubPrefix or #chainInfo. If used on a pub that requires parameters it
    // will throw an error.
    auto pubVal(std::string_view pubnm) const {
        auto cs{cs_};
        pubBldr<false> bld{bs_, cs, pubnm};
        return bld.name();
    }
    auto pubVal(std::string_view pubnm, std::string_view fldNm) const {
        auto cs{cs_};
        pubBldr<false> bld{bs_, cs, pubnm};
        return std::string(bld.name().nthBlk(bld.index(fldNm)).toSv());;
    }

    struct sPub : Publication {
        using Publication::Publication;
        sPub(const Publication& p) { *this = reinterpret_cast<const sPub&>(p); }
        sPub(Publication&& p) { *this = std::move(reinterpret_cast<sPub&&>(p)); }

        // accessors for name components of different types

        size_t index(size_t s) const { return s;  }
        size_t index(std::string_view s) const { return _s2i(s); }

        auto string(auto c) const { return std::string(name().nthBlk(index(c)).toSv()); }

        uint64_t number(auto c) const { return name().nthBlk(index(c)).toNumber(); }
        auto time(auto c) const { return name().nthBlk(index(c)).toTimestamp(); }
        double timeDelta(auto c, std::chrono::system_clock::time_point tp = std::chrono::system_clock::now()) const {
                    return std::chrono::duration_cast<std::chrono::duration<double>>(tp - time(c)).count();
        }
        auto operator[](auto c) const { return string(c); }
    };
};

} // namespace dct

#endif // DCTMODEL_HPP
