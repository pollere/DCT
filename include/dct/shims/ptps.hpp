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
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <dct/syncps/syncps.hpp>
#include <dct/schema/dct_model.hpp>

namespace dct {

using error = std::runtime_error;
using addChnCb = std::function<void(const rData, const certStore&)>;
struct ptps;
using ptPub = DCTmodel::sPub;
using connectCb = std::function<void()>;
using pubCb = std::function<void(ptps*, const Publication&)>;
using chnCb = std::function<void(ptps*, const rData, const certStore&)>;
using bytpCb = std::function<void(thumbPrint)>;

/* 
 * ptps (pass-through publish/subscribe) provides a DeftT pub/sub
 * API where the information unit is the same as that used by the
 * sync protocol, i.e., a Publication.
 * Its intended use is a pass-through shim for a relay connecting different
 * Faces under the same trust domain
 */

 /*
  * Pass-throughs enable trust-based relay of Publications (in msgs, certs, and keys
  * collections) between different network interfaces,
  * identified by a string of protocol//host:<opt>port or default, that
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
    addChnCb m_rlyCertCb{};        //used to relay validated cert chain to shim
    thumbPrint m_tp{};                  // for testing for capability

    bool wasRelayed(thumbPrint tp) { return m_rlyCerts.contains(tp);}
    void addRelayed(const thumbPrint tp, const dctCert& c) { m_rlyCerts[tp] = true;  addCert(c); }  // if c valid, add to certstore
    const auto& keysColl() { return m_gkSync; }
    auto& certColl() { return m_ckd.m_sync; }
    const auto& msgsColl() { return m_sync; }

    // ensure a publication is *structurally* valid on the outgoing DeftT
    bool isValidPub(const Publication& pub) {
       // if (!certs().contains(pub.signer()))
            // print ("DCTmodelPT::isValidPub: this DeftT's cert store does not contain signer of {}\n", pub.name());
        try {
            const auto& pubval = pv_.at(pub.signer());
            return pubval.matchTmplt(bs_, pub.name());  // structurally validate 'pub'
        } catch (std::exception&) { print("DCTmodelPT:isValidPub: no pub validator found for signer\n"); }
        return false;
    }
    // checking if key/msgs Publication's signer is in cert store of this outgoing DeftT
    // used as a way to remove unneeded Pubs, but may be problematic
    bool publishKey(const Publication&& pub) {
        if (m_pubDist /*&& cs_.contains(pub.signer())*/) {
             m_gkSync->publish(std::move(pub));
            return true;
        }
        return false;
    }

    // domain virtual clock methods
    void setRlyCbVC(std::function<void(dct::thumbPrint, int64_t, size_t, size_t)> rcb) { if (m_vcd) m_vcd->setRelayCb(rcb); }
    size_t vcSetSz() { if (m_vcd) return m_vcd->getSetSize(); else return 0; }
    void vcRound(uint8_t s, std::chrono::microseconds a, size_t n) { if(m_vcd) m_vcd->publishRound(s,a,n);}
    void vcCalibrate() { if (m_vcd) m_vcd->calibrateClock(); }
    dct::tdv_clock::duration  vcComputeDly() {  if (m_vcd) return m_vcd->getComputeDly(); else return 0ms; }
    dct::tdv_clock::duration vcNhdDly() { if(m_vcd) return m_vcd->getNhdDly(); else return 0ms; }
    void finishCalibrateVC( std::chrono::microseconds adj, uint8_t n) { if (m_vcd) m_vcd->finishCalibration(adj, n); }


  // create a DCTmodelPT instance using the certs in the bootstrap bundle file 'bootstrap'

    DCTmodelPT(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb,
               std::string_view addrLoc, addChnCb&& rcb = nullptr) :
            DCTmodel(rootCb, schemaCb, idChainCb, signIdCb,  addrLoc ),
            ptPubSm_{msm_.ref()}
    {
        m_sync.tdvcReset(); //VCTEST - resets the vc if dctmodel changed it
        m_tp = cs_.Chains()[0]; // thumbprint of signing cert
        // reset  m_sync.pubSigmgr_ to syncPTSm_ to use the pass-through version
        syncSm_.setSigMgr(ptPubSm_);
        // callbacks to relay for certs and pub key distributors
        m_rlyCertCb = std::move(rcb);
        m_pubDist = m_pgkd == NULL ? m_psgkd != NULL :  true;
        // if there's distributor for publication group keys need
        // to pass those to the relay via the appropriate syncps.
        if (m_pubDist) m_gkSync = (m_pgkd == NULL)?  &(m_psgkd->m_sync) : &(m_pgkd->m_sync);

        // changes the cert store's callback so adding a valid cert will relay the signing cert chain
        cs_.addCb_ = [this, &ckd=m_ckd] (const dctCert& cert) {
                           auto tp = cert.computeTP();
                           if (wasRelayed(tp)) {
                                   ckd.publishRlyCert(cert);
                           } else { //not a relayed cert - from local subnet
                               ckd.publishCert(cert);
                               if (isSigningCert(cert))
                                   m_rlyCertCb(cert, certs());  //pass the signing cert and the cert store containing its chain
                           }
                       };
    }
};

struct ptps
{   
    connectCb m_connectCb;
    DCTmodelPT m_pb;
    crName m_pubpre{};     // full prefix for Publications
    chnCb m_chCb;             // call back to app when this DefTT's cert distributor gets a fully validated signing cert that arrived from its syncps
    pubCb m_gkCb;            // call back for Publication group key distributor pubs
    pubCb m_failCb;           // call back to app when publication fails if confirmation was requested on publication
    Cap::capChk m_relayChk; // true if the identity chain has the relay (RLY) capability
    uint64_t m_success{};
    uint64_t m_fail{};
    bool m_connected{false};
    bool isConnected() const { return m_connected; }
    const auto& schemaTP() { return m_pb.bs_.schemaTP_; }

    auto startMsgsBatch() { return m_pb.m_sync.batchPubs(); }
    void endMsgsBatch(size_t n) { m_pb.m_sync.batchDone(n); }
    auto msgsBatching() { return m_pb.m_sync.batching_; }
    auto startCertBatch() { return m_pb.certColl().batchPubs(); }
    void endCertBatch(size_t n) { m_pb.certColl().batchDone(n); }
    auto certBatching() { return m_pb.certColl().batching_; }
    auto startKeysBatch() { return m_pb.keysColl()->batchPubs(); }
    void endKeysBatch(size_t n) { m_pb.keysColl()->batchDone(n); }
     auto keysBatching() { return m_pb.keysColl()->batching_; }
     static constexpr std::chrono::microseconds m_batchDly = 1ms;   // amount of time relayed Pubs can accumulate

     // virtual clock
     pTimer m_tdvcTimer{std::make_shared<Timer>(getDefaultIoContext())};
     bool haveVC() { return m_pb.m_virtClk; }
     void setupVC(std::function<void(dct::thumbPrint, int64_t, size_t, size_t)> rcb) {
         m_pb.setRlyCbVC(std::move(rcb));
     }
    void calibrate() { m_pb.vcCalibrate(); }
    void finishCalibrate( std::chrono::microseconds adj, uint8_t n) { m_pb.finishCalibrateVC(adj, n); }
    auto tdvcNow() { return m_pb.tdvcNow(); }
    auto tdvcAdjust() const noexcept { return m_pb.face_.tdvcAdjust(); }
    dct::tdv_clock::duration tdvcAdjust(tdv_clock::duration  dur, int8_t n) noexcept
    {
        if (m_pb.m_vcd) m_pb.m_vcd->vs_.nbrs = n;
        return m_pb.face_.tdvcAdjust(dur);
    }
    auto vcIsStarted() { if(m_pb.m_vcd) return m_pb.m_vcd->isStarted(); return false; }
    void vcRound(size_t r, std::chrono::microseconds a, uint8_t n) { m_pb.vcRound(r, a, n); }
    auto vcSetSz() { return m_pb.vcSetSz(); }
    dct::tdv_clock::duration vcComputeDly() { return m_pb.vcComputeDly(); }
    dct::tdv_clock::duration vcNhdDly() { return m_pb.vcNhdDly(); }
    auto vcMgr() { return m_pb.m_vcd; }

    ptps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb,
             std::string_view addrLoc, const chnCb& certHndlr = {}, const pubCb& distCb = {}, const pubCb& failCb={}) :
        m_pb{rootCb, schemaCb, idChainCb, signIdCb, addrLoc, [this](const rData c, const certStore& cs){ m_chCb(this, c, cs); } },
        m_pubpre{m_pb.pubPrefix()},
        m_chCb{certHndlr},
        m_gkCb{distCb},
        m_failCb{failCb},
        m_relayChk{Cap::checker("RLY", m_pubpre, m_pb.cs_)} {}

    void run() { m_pb.run(); }
    const auto& pubPrefix() const noexcept { return m_pubpre; }
    const auto& face() { return m_pb.getFace(); }
    auto failCnt() { return m_fail; }
    auto label() { return m_pb.pubVal("#chainInfo", "_roleId"); }
    auto successCnt() { return m_success; }
    void clearFailures() { m_fail = 0; }
    auto isRelay(const thumbPrint& tp) { return m_relayChk(tp).first; }    // identity 'tp' has RLY capability?
    auto haveKeys() { return m_pb.m_pubDist; }
    auto relayTo()
    {
        // checks if RLY capability is present and, if so, returns its argument (where relaying to)
        // return empty span if RLY  capability wasn't found or has bad argument content
        const auto& tp = m_pb.cs_.Chains()[0];  // thumbprint of newest signing cert
        auto toNet = Cap::getval("RLY", m_pubpre, m_pb.cs_);
        return toNet(tp).toSv();
    }

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
     * If there is a Pub gkey distributor, now subscribe to all its Pubs
     * (pubPrefix() is used for distributor pubprefix when created in DCTmodel)
     * This will subscribe to ALL the pub group key distributor publications to pass to relay
     *
     * connect does not timeout; if there is a wait time limit meaningful to an
     * application it should set its own timeout.
     */

    void connect(connectCb&& scb)
    {
        m_connectCb = std::move(scb);
        //print ("ptps::connect process started for transport {}\n",  label(), relayTo());
        // call start() with lambda to confirm success/failure
        m_pb.start([this](bool success) {
                if (!success)  throw runtime_error("ptps failed to initialize connection");
                m_connected = true;
                if (m_pb.m_pubDist) {
                    m_pb.m_gkSync->subscribe(m_pb.pubPrefix(),  [this](const rData p){ m_gkCb(this, p);});
                }
                m_connectCb();
            });
    }

    void setup(const auto& sibs, bool skipVal) {
        //print ("ptps::setup process started for transport {}\n",  label(), relayTo());
        // pull certs from sibling transports by signing chains
        auto n = startCertBatch();
        for (auto sp : sibs) if (sp != this) sp->passValidChains(this);
        endCertBatch(n);
        //  if there is a keys/msgs collection, pull Publications in keys/msgs from sibling transports
        if (haveKeys()) {
            n = startKeysBatch();
            for (auto sp : sibs) if (sp != this) sp->passGroupKeys(this);
            endKeysBatch(n);
        }
        // pull Publications in msgs from sibling transports that are connected
        n = startMsgsBatch();
        for (auto sp : sibs) if (sp != this && sp->isConnected()) sp->passMsgs(this, skipVal);
        endMsgsBatch(n);
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
     * p is a complete schema compliant (structurally valid) Publication on the input Face and goes directly to the syncps
     */
    void publish(Publication&& p)
    {
        if (!msgsBatching()) {  // to reduce number of PDUs sent
            startMsgsBatch();
            oneTime(m_batchDly, [this]{ endMsgsBatch(0); });
        }
        if(m_failCb) {    //if a fail callback is set, request confirmation
            if (! m_pb.publish(std::move(p), [this](auto p, bool s){confirmPublication(Publication(p), s);}))
                confirmPublication(Publication(p), 0);   // failed to publish for structural reasons - didn't set callback
        } else {
            m_pb.publish(std::move(p));
        }
        return;
    }
    /*
     * p is a complete schema-compliant Publication for the input DeftT
     * A sub-schema can be used to limit Publications that are accepted from relay to DeftT
     * This allows checking of the Publication against this outgoing DeftT's trust schema
     * Thus "failed to validate" is a _desired_ behavior if using schema to limit some publications
     *
     * Returns true if p was passed to syncps, false otherwise
     */
    bool validPub(const Publication& p) {return m_pb.isValidPub(p);}

    bool publishValid(Publication&& p)
    {      
        if(validPub(p)) {
            publish(std::move(p));
            return true;
        } else {
            // print("publishValid failed to validate {}\n", p.name());     // this pub isn't in the schema for this DeftT or signing cert hasn't arrived
            return false;
        }
    }
      /*
     * p is a complete schema-compliant Publication on the *input* Face
     * This is used to pass keys/msgs collection Publications
     * This allows checking of the Publication against this (outgoing) Face's schema
     * Only called for DeftTs that are connected
     * Returns true if p was passed to gk syncps, false otherwise
     */
    bool publishGKey(Publication&& p)
    {
        if (!keysBatching()) {  // to reduce number of PDUs sent
            startKeysBatch();
            oneTime(m_batchDly, [this]{ endKeysBatch(0); });
        }
        // print ("ptps::publishGKey: called for {} with {}\n", relayTo(), p.name());
        return m_pb.publishKey(std::move(p));
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
     * In smart "trust-based" pass through, the cert gets checked against the
     * trust schema before it is published to this DefTT's cert collection
     * rather than simply moving any cryptographically valid cert to other attached transports.
     * The thumbprint of the signing cert is added to the DCT model's relayed chain list so it can both
     * be distinguished from chains that arrived via interface of this DefTT's cert distributor and tested to
     * see if this DefTT already was relayed this chain. (Local relayed chain list could hold tps of
     * all signing certs and have 0 or "false" if locally received, but currently that is tested in
     * relay by not calling this method for chains that arrive locally
     *
     * addRelayed() calls the dct model's checker m_pb.addCert(&c) just like is done on reception from a cAdd
     * which will check the cert for validity against this DefTT's trust schema.
     *
     * Although the passed in cert should be valid against the schema of the originating DeftT,
     * this is only useful for the case of identical trust schema for all DefTTs so is both
     * less general and not "belt and suspenders" security
     */
    bool addRelayedChain(const rData sc, const auto& cs) {
        auto tp = sc.computeTP();       
        if (m_pb.certs().contains(tp)) return true;   // have already seen this signing chain

        size_t n = 0;
        auto batch = certBatching();
        if (!batch) n = startCertBatch();   // not already batching (i.e., not called from passValidChains)
        cs.chain_for_each(tp, [this](const auto &c) {    // for each cert on this signing chain
            auto ctp = c.computeTP();
            if (! m_pb.certs().contains(ctp))   m_pb.addRelayed(ctp, c);    // add as a cert that was relayed to this DeftT
        });
        if (!batch) endCertBatch(n);

        if (m_pb.certs().contains(tp)) {     //check if the signing cert validated
            return true;
        }
        return false;
    }

    /*
     * Pass all all received validated signing chains that were not relayed to me on to sibling deftt r
     * (i.e., the signing chains of members on my face's subnet) nor are relay identities to r
     *
     * Intended for use when a DeftT connects
     */
    void passValidChains(const auto& r) {
        // print ("ptps:passValidChains: transport {} conn={} passing to {}\n", relayTo(), m_connected, r->relayTo());
        for (auto kv : m_pb.certs()) {
            auto c = kv.second;
            // add "&& !m_pb.wasRelayed(kv.first)" to test if want to prefer getting from originator
            if (m_pb.isSigningCert(c) && !isRelay(kv.first))
                    r->addRelayedChain(c, m_pb.certs());
        }
    }

    /*
     * Pass all the active Publications in my keys/msgs collection that I received from the network to r
     * Intended for use when a DeftT connects
     * Transport r will batch the publications it receives from me (could batch all other transports at relay
     * connect cb)
     */
    void passGroupKeys(const auto & r) {      
        m_pb.keysColl()->forFromNet([r](const auto& p) { r->publishGKey(Publication(p)); });
    }

    /*
     * Pass all the active Publications in my msgs collection that I received from the network to r
     * Intended for use when a DeftT connects
     */
    void passMsgs(const auto & r, bool skip) {
        if (skip) m_pb.m_sync.forFromNet([r](const auto& p) { r->publish(Publication(p)); });
       else m_pb.m_sync.forFromNet([r](const auto& p) {  if (r->validPub(p)) r->publish(Publication(p)); });
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
