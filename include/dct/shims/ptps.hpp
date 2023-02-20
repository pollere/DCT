#ifndef PTPS_HPP
#define PTPS_HPP
#pragma once
/*
 * passPub.hpp: Publication-based pub/sub API for DCT
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
 *  This proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <algorithm>
#include <bitset>
#include <functional>
#include <getopt.h>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <dct/syncps/syncps.hpp>
#include <dct/schema/dct_model.hpp>

namespace dct {

//if not using syncps defaults, set these here
static constexpr size_t MAX_CONTENT=768; //max content size in bytes, <= maxPubSize in syncps.hpp
static constexpr size_t MAX_SEGS = 64;  //max segments of a msg, <= maxDifferences in syncps.hpp

using error = std::runtime_error;
using addChnCb = std::function<void(const rData, const certStore&)>;
struct ptps;
using ptPub = DCTmodel::sPub;
using connectCb = std::function<void()>;
using pubCb = std::function<void(ptps*, const Publication&)>;
using chnCb = std::function<void(ptps*, const rData, const certStore&)>;

/* 
 * ptps (pass-through publish/subscribe) provides a DeftT pub/sub
 * API where the information unit is the same as that used by the
 * sync protocol, i.e., a Publication.
 * Its intended use is a pass-through shim for a relay connecting different
 * Faces under the same trust domain
 */

 /*
  * Pass-throughs enable trust-based relay of pubs, certs, and keys between different
  * network interfaces, identified by a string of protocol//host:<opt>port or default, that
  * is used to create a particular Face. Thus a few additions to DCTmodel are required.
  * DCTmodelPT is derived from DCTmodel and adds tracking of relayed certs, a test of
  * validity of outgoing pubs against this dct_model's trust schema, and a "validate only"
  * version of the pub validator since relays do not decrypt pubs but pass through as long
  * as they cryptographically validate.
  */
struct DCTmodelPT final : DCTmodel  {
    SigMgrPT ptPubSm_;     // sigmgr for validating but not decrypting pubs
    SyncPS* m_gkSync{};
    std::unordered_map<thumbPrint,bool> m_rlyCerts {};
    bool m_pubDist;
    addChnCb m_rlyCertCb{};  //used to relay validated cert chain to shim

    bool wasRelayed(thumbPrint tp) { return m_rlyCerts.count(tp);}
    void addRelayed(thumbPrint tp) { m_rlyCerts[tp] = true;}

    // ensure a publication is valid on the outgoing DeftT
    bool isValidPub(const Publication& pub) {
        // structurally validate 'pub'
        try {
            const auto& pubval = pv_.at(dctCert::getKeyLoc(pub));
            return pubval.matchTmplt(bs_, pub.name());
        } catch (std::exception&) {}
        // print("isValidPub pub {} doesn't validate\n", pub.name());
        return false;
    }
    // ensure publication's signer is in cert store of this outgoing DeftT
    bool publishKnownSigner(const Publication&& pub) {
        if (m_pubDist && cs_.contains(pub.thumbprint())) {
             m_gkSync->publish(std::move(pub));
            return true;
        }
        return false;
    }

  // create a DCTmodelPT instance using the certs in the bootstrap bundle file 'bootstrap'
  // optional string for face name
    DCTmodelPT(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, DirectFace& face,
               addChnCb&& rcb = nullptr) : DCTmodel(rootCb, schemaCb, idChainCb, signIdCb, face),
               ptPubSm_{psm_.ref()}
    {
        // reset  m_sync.pubSigmgr_ to syncPTSm_ to use the pass-through version
        syncSm_.setSigMgr(ptPubSm_);
        // callbacks to relay for certs and pub key distributors
        m_rlyCertCb = std::move(rcb);
        m_pubDist = m_pgkd == NULL ? m_psgkd != NULL :  true;
        // if there's distributor for publication group keys need
        // to pass those to the relay via the appropriate syncps.
        if (m_pubDist) m_gkSync = (m_pgkd == NULL)?  &(m_psgkd->m_sync) : &(m_pgkd->m_sync);

        // change the cert store's callback so adding a valid cert will relay the signing cert chain 
        cs_.addCb_ = [this, &ckd=m_ckd] (const dctCert& cert) {
                           ckd.publishCert(cert);
                           if (isSigningCert(cert) && !wasRelayed(cert.computeThumbPrint())) {
                               //pass the signing cert and the cert store containing its chain
                               m_rlyCertCb(cert, certs());
                           }
                       };
    }
};

struct ptps
{   
    connectCb m_connectCb;
    DirectFace m_face;
    DCTmodelPT m_pb;
    crName m_pubpre{};     // full prefix for Publications
    Timer* m_timer;
    chnCb m_chCb;                 // call back to app when this DefTT's cert distributor gets a fully validated signing cert that arrived from its syncps
    pubCb m_gkCb;            // call back for Publication group key distributor pubs
    pubCb m_failCb;           // call back to app when publication fails if confirmation was requested on publication
    std::string m_label;        // label for the transport to be used by this face
    uint64_t m_success{};
    uint64_t m_fail{};
    bool m_connected{false};
    bool isConnected() const { return m_connected; }
    const auto& schemaTP() { return m_pb.bs_.schemaTP_; }

    ptps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb,
             const std::string& fl, const chnCb& certHndlr = {}, const pubCb& distCb = {}, const pubCb& failCb={}) :
        m_face{fl},
        m_pb{rootCb, schemaCb, idChainCb, signIdCb, m_face, [this](const rData c, const certStore& cs){ m_chCb(this, c, cs); } },
        m_pubpre{m_pb.pubPrefix()},
        m_chCb{certHndlr},
        m_gkCb{distCb},
        m_failCb{failCb},
        m_label{fl.size()? fl : "default"} {}

    void run() { m_pb.run(); }
    const auto& pubPrefix() const noexcept { return m_pubpre; }
    const std::string& label() { return m_label; }
    const auto& face() { return m_face; }
    auto failCnt() { return m_fail; }
    auto successCnt() { return m_success; }
    void clearFailures() { m_fail = 0; }

    // relies on trust schema using convention of collecting all the signing chain
    // identity information (e.g., _role, _roleId) in pseudo-pub "#chainInfo" so
    // the app can extract what it needs to operate.
    auto attribute(std::string_view v) const { return m_pb.pubVal("#chainInfo", v); }

    /*
     * Kicks off the set up necessary to publish or receive Publications.
     * A DefTT is considered "connected" once communications are
     * initialized which may include key distribution and/or acquisition.
     *
     * The success callback scb is where the application starts work that involves communication.
     * If m_pb.start results in a callback indicating success, m_connectCb is invoked.
     * If fails, throws an error.
     * Set up the pass-through subscribe to distributor (if any) publications after successful start()
     * (pubPrefix() is used for distributor pubprefix when created in DCTmodel)
     *
     * connect does not timeout; if there is a wait time limit meaningful to an
     * application it should set its own timeout.
     */

    void connect(connectCb&& scb)
    {
        //libsodium set up
        if (sodium_init() == -1) throw error("Connect unable to set up libsodium");
        m_connectCb = std::move(scb);

        // call start() with lambda to confirm success/failure
        m_pb.start([this](bool success) {
                if (!success) {
                    throw runtime_error("ptps failed to initialize connection");
                } else {
                    m_connected = true;
                     if(m_pb.m_pubDist)
                         m_pb.m_gkSync->subscribe(m_pb.pubPrefix(),  [this](const rData p){ m_gkCb(this, p);});
                    m_connectCb();
                }
            });
    }

    /*
     * Subscribe to all topics in the pub Collection with a single callback.
     * Another option for relay based on tags in Name is to subscribe by topic and
     * use different callbacks that relay to a subset of available Faces
    */
    ptps& subscribe(const pubCb& ph)    {
        m_pb.subscribe(pubPrefix(), [this,ph](auto p) {ph(this, p);});
        return *this;
    }
    // distinguish subscriptions further by topic or topic/location
    ptps& subscribe(const std::string& suffix, const pubCb& ph)    {
        m_pb.subscribe(pubPrefix()/suffix, [this,ph](auto p) {ph(this, p);});
        return *this;
    }

    /*
     * p is a complete trust-schema compliant Publication on the input Face and goes directly to the syncps
     * Call this if the same trust schema (or a superset) is applied on the output Face
     */
    void publish(Publication&& p)
    {
        if(m_failCb) {    //if a fail callback is set, request confirmation
            m_pb.publish(std::move(p), [this](auto p, bool s){confirmPublication(Publication(p), s);});
            // [ch=std::move(ch)](auto p, bool s) { ch(p,s);});
        } else {
            m_pb.publish(std::move(p));
        }
        return;
    }
    /*
     * p is a complete trust-schema compliant Publication for the input DeftT
     * A sub-trust schema can be used to limit Publications that are accepted from relay by a DeftT
     * This allows checking of the Publication against this outgoing DeftT's trust schema
     * Thus "failed to validate" is desired behavior if using schema to limit some publications
     *
     * Returns true if p was passed to syncps, false otherwise
     */
    bool publishValid(Publication&& p)
    {      
        if(m_pb.isValidPub(p)) {
            publish(std::move(p));
            return true;
        } else {
            // print("publishValid failed to validate {}\n", p.name());     // this pub isn't in the schema for this DeftT
            return false;
        }
    }
      /*
     * p is a complete trust-schema compliant Publication on the input Face
     * This is used to pass the publications of a pub gk distributor
     * This allows checking of the Publication against this outgoing Face's trust schema
     * Returns true if p was passed to gk syncps, false otherwise
     */
    bool publishKnown(Publication&& p)
    {
        return m_pb.publishKnownSigner(std::move(p));
    }
    /*
     * Use if a failure callback was set for this shim when constructed. Confirms whether Publication made it to the Collection.
     * For DefTT on a point-to-point link, this confirms the publication reached the other side
     * or can indicate a failure.
     *
     * success  = true means appeared in some other entity's state
     *          = false means Publication timed out without appearing in another entity's state
     */
    void confirmPublication(const Publication &p, bool success) {
        if(success) {
            m_success++;
        } else {
            m_fail++;
            m_failCb(this, p);
        }
    }
    /*
     * Add a cert chain relayed from another DefTT's cert store (cs)  to mine. Traverses the chain and adds each cert.
     *
     * Calls the dct model's checker m_pb.addCert(&c) just like is done on reception from wire
     * which will check the cert for validity against this DefTT's trust schema.
     * In smart "trust-based" pass through, the cert gets checked against the
     * trust schema before it is published to this DefTT's cert collection
     * rather than simply moving any cryptographically valid cert to other attached transports.
     * The thumbprint of the signing cert is added to the DCT model's relayed chain list so it can both
     * be distinguished from chains that arrived via this DefTT's cert distributor and tested to
     * see if this DefTT already was relayed this chain. (Local relayed chain list could hold tps of
     * all signing certs and have 0 or "false" if locally received, but currently that is tested in
     * basicRelay by not calling this method for chains that arrive locally
     *
     * Although the passed in cert should be valid against the trust schema of the originating DeftT,
     * this is only useful for the case of identical trust schema for all DefTTs so is both
     * less general and not "belt and suspenders" security
     */
    void addRelayedChain(const rData c, const auto& cs) {
        auto tp = c.computeTP();
        if (m_pb.certs().contains(tp)) return;   //already have this signing chain

        m_pb.addRelayed(tp);    // add to list of signing chains that were relayed to this DeftT
        // for each cert on signing chain
        cs.chain_for_each(tp, [this](const auto &c) { m_pb.addCert(c);  }  );
        // m_pb.certs().dumpcerts();
    }

    // Can be used by application to schedule a cancelable timer. Note that
    // this is expensive compared to a oneTime timer and should be used
    // only for timers that need to be canceled before they fire.
    pTimer schedule(std::chrono::microseconds d, TimerCb&& cb) { return m_pb.schedule(d, std::move(cb)); }

    // schedule a call to 'cb' in 'd' microseconds (cannot be canceled)
    void oneTime(std::chrono::microseconds d, TimerCb&& cb) { m_pb.oneTime(d, std::move(cb)); }
};

} // namespace dct

#endif
