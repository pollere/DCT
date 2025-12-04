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
#include "dct/distributors/dist_logs.hpp"
#include "dct/distributors/dist_tdvc.hpp"
#include "dct/distributors/dist_gkey.hpp"
#include "dct/distributors/dist_sgkey.hpp"
#include "dct/rand.hpp"

using namespace std::literals;

namespace dct {

// format for logging events - may want to add src if including in name is not sufficiently rigorous
using logEvCb = std::function<void(crName&&, std::span<const uint8_t>)>;

//template<typename sPub>
struct DCTmodel {
    certStore cs_{};        // certificates used by this model instance
    std::unordered_multimap<thumbPrint,dctCert> pending_{};
    const bSchema& bs_;     // communications schema for this model instance
    DirectFace face_;
    pubBldr<false> bld_;    // publication builder/verifier
    SigMgrAny msm_;         // msgs publication signing/validation
    SigMgrAny csm_;         // cert publication signing/validation
    SigMgrAny psm_;         // pdu signing/validation
    SigMgrSchema syncSm_;   // msgs syncps pub validator
    SyncPS m_sync;  // sync collection for msgs
    static inline std::function<size_t(std::string_view)> _s2i;
    DistCert m_ckd;         // cert collection distributor
    DistLogs* lgd_{};         // logs collection distributor
    DistTDVC* m_vcd{};     // virtual clock distributor
    DistGKey* m_gkd{};      // group key distributor (if needed)
    DistSGKey* m_sgkd{};    // subscriber group key distributor (if needed)
    DistGKey* m_pgkd{};      // msgs group key distributor (if needed)
    DistSGKey* m_psgkd{};    // msgs subscriber group key distributor (if needed)
    tpToValidator pv_{};    // map signer thumbprint to pub structural validator
    bool m_virtClk{false};     // true if using trust domain virtual clock distributor
    bool logging_{false};   // true if using the logs distributor
    bool vcInit_{false};   // becomes true after initial TD VClk calibration has been done
    logEvCb logsCb_;
    pTimer makeSP_{std::make_shared<Timer>(getDefaultIoContext())}; // timer for making next signing pair

    // Trust Domain Virtual Clock access is via face (many things need its 'now()' method)
    auto tdvcNow() const noexcept { return face_.tdvcNow(); }
    auto tdvcAdjust() const noexcept { return face_.tdvcAdjust(); }
    tdv_clock::duration tdvcAdjust(tdv_clock::duration  dur) noexcept { return face_.tdvcAdjust(dur); }
    void tdvcReset() noexcept { return face_.tdvcReset(); }
    auto tdvcToSys(tdv_clock::time_point tp) const noexcept { return face_.tdvcToSys(tp); }

    SigMgr& pduSigMgr() { return psm_.ref(); }
    SigMgr& msgSigMgr() { return msm_.ref(); }  // sigmgr for publications that carry application msgs
    SigMgr& certSigMgr() { return csm_.ref(); }
    auto pubPrefix() const { return crName{bs_.pubVal("#pubPrefix")}; } // prefix for all publications

    // all cState/cAdd packet names start with the first 8 bytes
    // of the schema cert thumbprint to make them trust-zone specific.
    auto pduPrefix() const { return crName()/std::span(bs_.schemaTP_).first(8); }
    auto maxInfoSize() const { return m_sync.maxInfoSize_; }

    const auto& certs() const { return cs_; }

    bool isSigningCert(const dctCert& cert) const {
        // signing certs are the first item each signing chain so go through
        // all thetemplate chains and see if the first item matches 'cert'
        for (const auto& chn : bs_.chain_) {
            if (chn.size() == 0) continue;
            if (matches(bs_, cert.name(), chn[0])) return true;
        }
        return false;
    }

    // setup the information needed to validate msgs pubs signed with the cert
    // associated with 'tp' which is the head of schema signing chain 'chain'.
    void setupPubValidator(const thumbPrint& tp) {
        //XXX this is a hack and should be refactored
        // Make a temporary builder to construct the pub templates associated
        // with this signing chain. To do this we need a *copy* of the current
        // certstore with its signing chain 0 set to 'tp'.
        certStore cs = cs_;
        cs.chains_[0] = tp;
        pubBldr bld(bs_, cs, face_.tdvclk_, bs_.pubName(0));
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
            else print("checkPendingCerts: {} didn't validate with {}\n", i->second.name(), cert.name());
        }
        pending_.erase(tp);
        for (auto p : pv) addCert(p);
    }

    // For certs received externally
    // Cryptographically and structurally validate a cert before adding it to the
    // cert store. Since certs can arrive in any order, a small number of certs
    // are held pending their signing cert's arrival.
    // XXX Need to replace identity certs that get "decommissioned"
    void addCert(rData d) {
        const auto tp = d.computeTP();
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
            if (m_virtClk && !vcInit_ && isSigningCert(cert)) {
                 if (! cert.valid(certSigMgr().type(), tdvcAdjust(), false)) return; //don't check the validity period until clock calibration
            } else if (! cert.valid(certSigMgr().type())) return;
            auto cname = tlvVec(cert.name());
            if (matchesAny(bs_, cname) < 0) return; // name doesn't match schema

            const auto& stp = cert.signer();    // cert's signer's thumbprint
            if (dctCert::selfSigned(stp)) return; // can't add new root cert
            if (cname.size() >= 7 && cname[-6].toSv() == "schema") return; // can't add new schema

            // check if receiving a cert signed by my identity, implying an earlier signing cert of my identity
            if (!cs_.contains(cs_.chains_[0])) std::runtime_error ("DCTmodel::addCert: this member has no signing cert");
            if ( (cs_.get(cs_.chains_[0])).signer() == stp) return;
 
            // cert is structurally ok so see if it crytographically validates
            if (! cs_.contains(stp)) {
                // don't have cert's signing cert - check it when that arrives
                // XXX too many pending certs - drop something
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
                cs_.add(cert, !(m_virtClk & !vcInit_)); // second arg true => no check of validNow
                setupPubValidator(tp);
                // let all attached collections know there is a new signer in case have pending Publications
                // start with PDU key collection, then Pub key collection, then msgs collection
                if (m_virtClk) m_vcd->m_sync.newSigner(tp);
                if (logging_) lgd_->m_sync.newSigner(tp);
                if (m_gkd)   m_gkd->m_sync.newSigner(tp);
                else if (m_sgkd) m_sgkd->m_sync.newSigner(tp);
                if (m_pgkd)   m_pgkd->m_sync.newSigner(tp);
                else if (m_psgkd) m_psgkd->m_sync.newSigner(tp);
                m_sync.newSigner(tp);
                return; // done since signing cert validation completes the chain
            }
            cs_.add(cert);  //non-signing cert
            checkPendingCerts(cert, tp);
        } catch (const std::exception&) {
        dct::print("addCert:: {} CATCH rejects sc {}\n", cs_[cs_.Chains()[0]].name().nthBlk(2).toSv(), d.name());
        };
    }

    // schedule a call to 'cb' in 'd' microseconds (cannot be canceled)
    auto oneTime(auto delay, TimerCb&& cb) {
        m_sync.oneTime(std::chrono::duration_cast<std::chrono::microseconds>(delay), std::move(cb));
    }

    // Can be used by application to schedule a cancelable timer. Note that
    // this is expensive compared to a oneTime timer and should be used
    // only for timers that need to be canceled before they fire.
    auto schedule(std::chrono::microseconds delay, TimerCb&& cb) { return m_sync.schedule(delay, std::move(cb)); }

    /*
     *  called to get a new signing pair
     *
     * Handles adding the new cert to cs_, publishing it, and making it the new signing key  and informing the group key distributors, if any
     * Waits for a publication confirmation before making this pair the new signing pair and calling the group key distributors
     *
     *  new SPs should be created as valid certOverlap/2 before systime+tdvcAdjust
     *  and are valid for certOverlap plus certLifetime after that
     *
     * Configured certs should be made on devices with calibrated clocks; assuming system clock for signing certs
     * If tdvcAdjust() is on the order of certOverlap or larger, creates issues
     * Pass tdvcAdjust value to the spCb() with default of 0 and the SP-making function must add it to the system clock
     * and must return a pair that is currently in its validity period
     * Instead of checking for "expired" need to check for "valid" in case tdvc has been adjusted
    */

    void expireTmSP(const rCert& sc, const pairCb& spCb) {
        auto now = std::chrono::system_clock::now();
        // next rekey time is certOverlap before expiration time
        auto rktm = (rCert(sc).validUntil() - now) - certOverlap - tdvcAdjust();
        // schedule should cancel pending
        makeSP_ = schedule(rktm, [this, spCb](){getNewSP(spCb);});    //schedule new signing pair
    }
    void getNewSP(const pairCb& spCb) {
        auto sp = spCb(tdvcAdjust());       //new signing key pair callback
        auto sc = sp.first;     // public cert of pair
        if (!rCert(sc).valid(certSigMgr().type()) || !rCert(sc).validNow(tdvcAdjust()))    // should check if cert is valid at tdvcNow
            std::runtime_error("dct_model::getNewSP received signing cert that is not valid at (virtual) now\n");
        expireTmSP(sc, spCb);    //schedules next getNewSP based on expiration time of new cert

        cs_.addNewSP(sc, sp.second);   //add this signing pair to cs_ but do not publish
        m_ckd.publishConfCert(sc, [this, sp](const rData& c, bool acked){    //publish with conf cb
                if (!acked) return;   // unlikely unless became entirely disconnected and cert expired
                auto sc = sp.first;
                if (sc.computeTP() != c.computeTP())  std::runtime_error("dct_model:getNewSP:addKP confirmed cert does not match passed in cert");
                // should be no issue with chain since it hasn't changed so may skip this
                if (validateChain(bs_, cs_, sc) < 0) throw schema_error(format("getNewSP:addKP cert {} signing chain invalid", sc.name()));
                cs_.insertChain(sc);                // make it a signing chain head
                // a good time to check my cert store for expired certs unless using virt clk and not initialized
                if (!m_virtClk || vcInit_) cs_.removeExpired();

                // pass new signing pair to sigmgrs and distributors
                msgSigMgr().updateSigningKey(sp.second, sc);
                pduSigMgr().updateSigningKey(sp.second, sc);
                if (m_virtClk) m_vcd->updateSigningKey(sp.second, sc);
                if (logging_) lgd_->updateSigningKey(sp.second, sc);
                // update group key distributors for cAdds, if any
                if (m_gkd)   m_gkd->updateSigningKey(sp.second, sc);
                else if (m_sgkd) m_sgkd->updateSigningKey(sp.second, sc);
                // update Publication group key distributors, if any
                if (m_pgkd)   m_pgkd->updateSigningKey(sp.second, sc);
                else if (m_psgkd) m_psgkd->updateSigningKey(sp.second, sc);
            });
    }
    // checks if capability c is present and, if so, returns its argument (as a stringview)
    auto capArgument(std::string_view c) {
        const auto& tp = cs_.Chains()[0];  // thumbprint of newest signing cert
        // returns empty span if capability wasn't found or has bad argument content
       auto arg = (Cap::getval(c, pubPrefix(), cs_)(tp)).toSv();
        if (arg.empty()) std::runtime_error("DCTmodel: no capability or no address in capability cert");
        //XXXX hack for working without transport.hpp changes
        if (c == "RLY")
            if (!arg.starts_with("tcp:") && !arg.starts_with("udp:") && !arg.starts_with("ff02") && !arg.starts_with("ff01")) arg = "";
        // dct::print ("DCTmodel:capArgument: {} capability argument is {}\n", c, arg);
        return arg;
    }


    // create a new DCTmodel instance and pass the callbacks to access required certs to
    // "bootstrap" this new transport instance
    // Pass in a face address callback or default to empty for default face
    DCTmodel(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, std::string_view addr = "") :
            bs_{validateBootstrap(rootCb, schemaCb, idChainCb, signIdCb, cs_)},
            face_{(addr == "" || addr.size() > 6)? addr : capArgument(addr)},   // hack assumes capability tags are a few chars
            bld_{pubBldr(bs_, cs_, face_.tdvclk_, bs_.pubName(0))},
            msm_{getSigMgr(bs_)},
            csm_{getCertSigMgr(bs_)},
            psm_{getPduSigMgr(bs_)},
            syncSm_{msm_.ref(), bs_, pv_},
            m_sync{face_, pduPrefix()/"msgs", pduSigMgr(), syncSm_},
            m_ckd{face_, pubPrefix(), pduPrefix()/"cert", [this](auto cert){ addCert(cert);}}
    {
        // sync session for msgs pubs is started after distributor(s) have completed their setup
        m_sync.autoStart(false);

        if (m_virtClk)  // check if using trust domain virtual clock
            m_vcd = new DistTDVC(face_, pubPrefix(), pduPrefix()/"tdvc", certs(),  [this, signIdCb](){getNewSP(signIdCb);},
                                [this, signIdCb](const rCert& c){ expireTmSP(c, signIdCb); });
        if (logging_)   // check if logging enabled
            lgd_ = new DistLogs(face_, pubPrefix(), pduPrefix()/"logs", certs());
        if(psm_.ref().encryptsContent()) {
            if (matchesAny(bs_, pubPrefix()/"CAP"/"KM"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                throw schema_error("Encrypted CAdds require that some entity(s) have KeyMaker capability");
            }
            if (! psm_.ref().subscriberGroup()) {
                m_gkd = new DistGKey(face_, pubPrefix(), pduPrefix()/"keys"/"pdus",
                             [this](auto gk, auto gkt){ psm_.ref().addKey(gk, gkt);}, certs());
            } else {
                if (matchesAny(bs_, pubPrefix()/"CAP"/"SG"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                    // schema doesn't contain an SG member so PP won't work XXXX should extract name of group from schema
                    throw schema_error("PPSIGNED/PPAEAD require that some entity(s) have Subscriber capability");
                }
                m_sgkd = new DistSGKey(face_, pubPrefix(), pduPrefix()/"keys"/"pdus",
                             [this](auto gpk, auto gsk, auto ct){ psm_.ref().addKey(gpk, gsk, ct);}, certs());
            }
        }
        //encryption methods for pubs in msgs collection MUST be signed versions
        if(msm_.ref().encryptsContent()) {
            if (matchesAny(bs_, pubPrefix()/"CAP"/"KMP"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                // schema doesn't contain a "KeyMaker" capability cert so AEAD won't work
                throw schema_error("pub content encryption requires that some entity(s) have KeyMaker capability");
            }
            if ( msm_.ref().subscriberGroup()) {
                if (matchesAny(bs_, pubPrefix()/"CAP"/"SG"/"_"/"KEY"/"_"/"dct"/"_") < 0) {
                    // schema doesn't contain a member with subscriber  ability so PPAEAD won't work
                    throw schema_error("PPSIGNED requires that some entity(s) have Subscriber capability");
                }
                // XXXX instead of msgs could be name of subscriber group
                m_psgkd = new DistSGKey(face_, pubPrefix(), pduPrefix()/"keys"/"msgs",
                             [this](auto gpk, auto gsk, auto ct){ msm_.ref().addKey(gpk, gsk, ct);}, certs());
            } else {
                m_pgkd = new DistGKey(face_, pubPrefix(), pduPrefix()/"keys"/"msgs",
                             [this](auto gk, auto gkt){ msm_.ref().addKey(gk, gkt);}, certs());
            }
        }

        if (m_virtClk) cs_.clkAdjustCb_ = [this](){ return tdvcAdjust(); };
        // cert distributor needs a callback when cert added to certstore.
        cs_.addCb_ = [&ckd=m_ckd] (const dctCert& cert) { ckd.publishCert(cert); };
        // cert distributor needs a callback to remove pubValidator for expiring signing certs
        cs_.certRemoveCb_ = [this](const thumbPrint& tp) {
                if (pv_.contains(tp)) std::erase_if(pv_, [&tp](const auto& i){ return i.first == tp; });
            };

        for (const auto& [tp, cert] : cs_) m_ckd.initialPub(cert);

        // pub and pdu sigmgrs each need its signing key setup and its validator needs
        // a callback to return a public key given a cert thumbprint.
        const auto& tp = cs_.Chains()[0]; // thumbprint of signing cert
        msgSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
        pduSigMgr().updateSigningKey(cs_.key(tp), cs_[tp]);
        msgSigMgr().setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });
        pduSigMgr().setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });

        // SPub need access to builder's 'index' function to translate component names to indices
        _s2i = std::bind(&decltype(bld_)::index, bld_, std::placeholders::_1);

        // set up timer to request a new signing pair before this pair expires (getNewSP sets up subsequent rekeys)
        // uses system clock as no tdvc possible yet
        // XXX this first signing key could have an extended lifetime if clock drifts are expected to be extreme
        // but also need to use a wider range when testing the signing chain of other members
        makeSP_ = schedule( rCert(cs_[tp]).validUntil() - std::chrono::system_clock::now() - dct::certOverlap,
                 [this, signIdCb] {getNewSP(signIdCb);});
    }

    const auto& getFace() { return face_; }

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
        m_sync.pubExpirationGB(t);
        return *this;    
    }

    // construct a pub name from pairs of tag, value parameters
    template<typename... Rest> requires ((sizeof...(Rest) & 1) == 0)
    auto name(Rest&&... rest) { return bld_.name(std::forward<Rest>(rest)...); }

    // construct a publication with the given content using rest of args to construct its name
    template<typename... Rest> requires ((sizeof...(Rest) & 1) == 0)
    auto pub(std::span<const uint8_t> content, Rest&&... rest) {
        Publication pub(name(std::forward<Rest>(rest)...));
        pub.content(content);
        msgSigMgr().sign(pub);
        return pub;
    }

    auto name(const std::vector<parItem>& pvec) { return bld_.name(pvec); }

    auto pub(std::span<const uint8_t> content, const std::vector<parItem>& pvec) {
        Publication pub(name(pvec));
        pub.content(content);
        msgSigMgr().sign(pub);
        return pub;
    }

    // set defaults to be used when constructing pub names
    template<typename... Rest>
    auto defaults(Rest&&... rest) { return bld_.defaults(std::forward<Rest>(rest)...); }

    auto defaults(const std::vector<parItem>& pvec) { return bld_.defaults(pvec); }

    // set start callback for shims that have a separate connect/start like mbps
    // Note: this can get much simpler when distributors derive from a common class
    void start(connectedCb&& cb) {
        auto pdu_dist = m_gkd == NULL? m_sgkd != NULL :  true;
        auto pub_dist = m_pgkd == NULL ? m_psgkd != NULL :  true;
        if (logging_) // logs callback - if not set uses  default no-op
            logsCb_ = [lgd=lgd_] (crName&& ln, std::span<const uint8_t> c) mutable { lgd->publishLog(std::move(ln), c); };

        if (!pdu_dist && !pub_dist) {
            m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                if (!c) { cb(false); return; }
                if (logging_) {
                    lgd_->setup([this,cb=std::move(cb)](bool c) {
                               if (!c) { dct::print("logs distributor failed to initialize, no logging\n"); logging_ = false; }
                               else { // set logs callback for distributors
                                   if (m_virtClk) m_vcd->logsCb_ = logsCb_;
                               }
                     });
                }
                if (!m_virtClk) { cb(c); if (c) m_sync.start(); }
                else m_vcd->setup([this,cb=std::move(cb)](bool c){ cb(c); if (c) { vcInit_ = true; m_sync.start(); }});
            });
            return;
        }

        // complete pdu key distribution before pub key distribution
        if ( pdu_dist && !pub_dist ) {
            m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                       if (!c) { cb(false); return; }
                       if (logging_) {    // log distributor should always return true but go ahead and continue without logging
                           lgd_->setup([this,cb=std::move(cb)](bool c) {
                               if (!c) { dct::print("logs distributor failed to initialize, no logging\n"); logging_ = false; }
                               else { // set logs callback for distributors
                                   if (m_virtClk) m_vcd->logsCb_ = logsCb_;
                               }
                           });
                       }
                       if (m_virtClk) {
                           m_vcd->setup([this,cb=std::move(cb)](bool c){
                                    if (!c) { cb(false); return; }
                                    vcInit_ = true;    // first vc calibration finished
                                    if (m_gkd)  // check if pdu distributor returns false
                                        m_gkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                                    else    // must be m_psgkd
                                        m_sgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                                });
                       } else {    //no tdvc distributor
                           if (m_gkd) m_gkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                           else m_sgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); }); // must be m_sgkd
                       }
             });
            return;
        } else  if ( !pdu_dist && pub_dist) {
             m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                       if (!c) { cb(false); return; }
                       if (logging_) {    // log distributor should always return true but go ahead and continue without logging
                           lgd_->setup([this,cb=std::move(cb)](bool c) {
                               if (!c) { dct::print("logs distributor failed to initialize, no logging\n"); logging_ = false; }
                               else  if (m_virtClk) m_vcd->logsCb_ = logsCb_; // set logs callback for distributors
                           });
                       }
                       if (m_virtClk) {
                            m_vcd->setup([this,cb=std::move(cb)](bool c){
                                if (!c) { cb(false); return; }
                                 vcInit_ = true;    // first vc calibration finished
                                if (m_pgkd)   // check if pdu distributor returns false
                                    m_pgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                                else    // must be m_psgkd
                                    m_psgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                           });
                       } else {    //no tdvc distributor
                            if (m_pgkd) {
                                m_pgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                            } else { // must be m_psgkd
                                m_psgkd->setup([this,cb=std::move(cb)](bool c){ cb(c); m_sync.start(); });
                            }
                        }
                    }); // end of ckd setup
            return;
        } else {    //both pdus and msgs have a distributor
           m_ckd.setup([this, cb=std::move(cb)](bool c) mutable {
                    if (!c) { cb(false); return; }
                    if (logging_) {    // log distributor should always return true but go ahead and continue without logging
                           lgd_->setup([this,cb=std::move(cb)](bool c) {
                               if (!c) { dct::print("logs distributor failed to initialize, no logging\n"); logging_ = false; }
                               else { // set logs callback for distributors
                                   if (m_virtClk) m_vcd->logsCb_ = logsCb_;
                               }
                           });
                    }
                    if (m_virtClk) {
                        m_vcd->setup([this,cb=std::move(cb)](bool c){
                         if (!c) { cb(false); return; }
                         vcInit_ = true;    // first vc calibration finished
                         if (m_gkd) {    // check if gk distributor returns false
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
                    } else { // no tdvc
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
        pubBldr<false> bld(bs_, cs_, face_.tdvclk_, pubnm);
        return bld.name();
    }
    auto pubVal(std::string_view pubnm, std::string_view fldNm) const {
        pubBldr<false> bld(bs_, cs_, face_.tdvclk_, pubnm);
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
        auto operator[](auto c) const { return string(c); }
    };
};

} // namespace dct

#endif // DCTMODEL_HPP
