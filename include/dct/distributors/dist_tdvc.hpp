#ifndef DIST_TDVC_HPP
#define DIST_TDVC_HPP
#pragma once
/*
 * dist_tdvc - coordinate local versions of the trust domain virtual clock
 * via a tdvc collection.
 * This version is a self-contained 'header-only' library.
 *
 * This distributor publishes its current virtual clock at start up
 * and during the rounds of a clock synchronization session.
 *
 * Since clock values should only be distributed through a single hop
 * to avoid indeterminate additional delays, adjustments are made to its syncps.
 * tdvc's syncps is set to NOT send the pubs of others since this is for "one-hop" neighbors only
 * and sets its hold time for the clock publications to be longer than the pub lifetime
 *
 * This initial release includes the round trip delay estimator for  neighborhood but the value is set to
 * a minimum and only changed if the value is large. This RTT is used for pub lifetimes, etc.
 * Uses 5 ms as quantization for clock differences and as an estimate of RTT/2 to remove from samples.
 * If the RTT/2 is greater than quantization, then set the excess delay to (RTT/2 - 5ms).
 *
 * This distributor uses topics:
 * <pubprefix/clk> - for clock values - lifetime is short and less than hold time to ensure only sent once
 * <pubprefix/sts> - for status messages that have lifetimes of the time between calibration cycles.
 *                              published at startup (and refreshed until starts) and after each calibration finishes
 * <pubprefix/png> - for a ping that a specific neighbor is to respond to but all neighbors overhear, contains last rtt
 * <pubprefix/eco> - response to a ping
 *
 * The PDU prefix the distributor's sync uses is <TDid>/tdvc>, the "tdvc" collection

 * As soon as the syncps is registered, pubs are received into its collection(s) but pubs don't invoke
 * a subscription callback until one is registered (in setup)
 * 
 * Copyright (C) 2020-5 Pollere LLC
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
 *  dist_tdvc.hpp is not intended as production code.
 */

#include <algorithm>
#include <cstring> // for memcmp
#include <functional>
#include <utility>

#include <dct/schema/capability.hpp>
#include <dct/schema/certstore.hpp>
#include <dct/schema/tlv_encoder.hpp>
#include <dct/schema/tlv_parser.hpp>
#include <dct/sigmgrs/sigmgr_by_type.hpp>
#include <dct/syncps/syncps.hpp>
#include <dct/utility.hpp>
#include "dct/rand.hpp"

using namespace std::literals::chrono_literals;

namespace dct {

// calSp should be (slightly) less than the amount of time it could take for a member's clock to drift beyond MaxTol

struct DistTDVC {
    int64_t calSp{300};  // number of seconds between status publications (also their lifetime) fractions of this used for probe clocks, pings
    uint8_t TolRnds{4};  // at end of calibration, number of rounds to publish my clock values without receiving an out of tolerance
                                      // sample from a neighbor - keeps from prematurely updating local clock
    size_t SetSz{3};       // number of clock values per round
    static constexpr std::chrono::milliseconds MaxTDdiff = 60s;  // delays outside of this will be ignored - not using for now
    static constexpr std::chrono::microseconds zeroUs = std::chrono::microseconds(0);
    int64_t MaxTol = 30000;    // amount of clock difference with neighbors that is tolerated - integer microsecs
    tdv_clock::duration MinNhdDly = 5ms;    // floor value and initial value for neighborhood transit delay
    tdv_clock::duration ClkXTm = 40*MinNhdDly;    // time span for exchanging clock samples during a calibrate round
                                                                    // needs to be at least > #sets * nhd dly
    tdv_clock::duration ClkLt = 4*MinNhdDly;
    pTimer m_probe{std::make_shared<Timer>(getDefaultIoContext())};
    tdv_clock::duration vcQuant{MinNhdDly}; // quantization for vc adjustments

    using connectedCb = std::function<void(bool)>;
    using relayValueCb = std::function<void(thumbPrint, int64_t, size_t, size_t)>;
    using logEvCb = std::function<void(crName&&, std::span<const uint8_t>)>;
    using spCb = std::function<void()>;
    using expireCb = std::function<void(const rCert&)>;

    /*
     * DistTDVC Publications contain the value of their local system clock in their timestamp
     * and are signed by their originator from which their tpID can be obtained
     * An integer indicates session/round number (can rollover)
     */
     struct cdiff {
         size_t nhSz{};       // size of neighborhood used in this vc estimate
         uint8_t st{};            // state of the sender: 0=not calibrating, 1=in tolerance but counting nbrs, 2+ calibrating
         int64_t v{};            // min of differences of my vc estimate and received value
         bool lives{true};    // indicates this neighbor has been heard from recently
     };

     struct vcVars {
             uint8_t state;    // my state: 0 for not calibrating, 1 for locally in tolerance and counting nbrs, 2+ for calibrating
             size_t nbrs = 1;  // number of neighbors (incl. me) that were used in previous round's computation (neighborhood size)
             size_t tolRnds;
             int zAdj;           // number of times in a row I've used a zero adjustment
             dct::tdv_clock::duration adjust = std::chrono::microseconds(0);  // calibration in-progress adjustment to vc
      };

     std::vector<uint32_t> m_rtts;
     // saves time of pings sent or heard by the expected responder's Id TP
     std::unordered_map<thumbPrint,uint64_t> m_pings{};

    const crName m_prefix;        // prefix for pubs in this distributor's collection
    SigMgrAny m_tdvcSM{sigMgrByType("EdDSA")};   // to sign/validate Publications and PDUs
    SyncPS m_sync;
    const certStore& cs_;
    connectedCb m_connCb{[](auto) {}};
    logEvCb logsCb_{[](crName&&, std::span<const uint8_t>){}};  // default logs callback
    relayValueCb m_relayCb{[](auto,auto,auto,auto){}};  //only for relays/ptps: called when a new clock value received from neighbor
    size_t sentClks_{};        // number of clock values sent this publishing round
    bool m_started{false};      // true once another member has been heard from in this collection and delay calculated
    tdv_clock::duration nhdRtt_{MinNhdDly}; // rough estimate of transit + process rtt between neighbors in my 'hood
    tdv_clock::duration txDly_{0ms}; // excess delay (greater than one way delay minus quant) should be removed

    std::map<thumbPrint,cdiff> m_clkDiffs{};
    vcVars vs_;
    thumbPrint m_tp{};

    tdv_clock::duration m_statusLifetime{std::chrono::seconds(calSp)};
    tdv_clock::duration m_clkLifetime{ClkLt}; // for clk pubs

    int64_t m_tolVal{MaxTol};        // largest clock difference tolerated in calibration integer microseconds
    tdv_clock::duration m_computeDly{ClkXTm};   //time to accumulate clock samples for each "round"
    tdv_clock::duration m_pingInt{10*MinNhdDly};  // interval between pings is initially short
    dct::rand rand{};
    bool m_init{true};
    bool m_pinging{false};
    bool waitSP_{false};
    spCb newSPcb_;
    expireCb expcb_;
    Cap::capChk m_relayChk;   // method to return true if the identity chain has the relay (RLY) capability
    Cap::capChk m_priClkChk;   // method to indicate if the identity chain has the priority clock (PCLK) capability
    IsExpiredCb m_defExpired;
    GetCreationCb m_defCreationTm;


    DistTDVC(DirectFace& face, const Name& pPre, const Name& dPre,  const certStore& cs, const spCb newSPcb, const expireCb expCb) :
             m_prefix{pPre},
             m_sync(face, dPre, m_tdvcSM.ref(), m_tdvcSM.ref()),
             cs_{cs},
             newSPcb_{newSPcb},
             expcb_{expCb},
             m_relayChk{Cap::checker("RLY", pPre, cs)}
     {
        m_sync.autoStart(false); // shouldn't start until cert distributor is done initializing
         m_sync.noOthers();       // won't send publications of others (clock sync is between neighbors)
        m_sync.signerHoldtime(0ms);  // don't hold publications for signing cert (can interfere with timing)
         // if the syncps set its cStateLifetime longer, means we are on a low rate network
         m_sync.cStateLifetime(6763ms);
        // the clock samples have short lifetimes as they are not ever forwarded but longer guard bands
         m_sync.pubHoldtime(6*nhdRtt_);  // setting post-publication holdtime to be longer than active time ensures "send once"
         m_sync.getLifetimeCb([this](const auto& p) ->tdv_clock::duration {
             auto n = p.name();
             if (crPrefix(m_prefix/"sts").isPrefix(n)) return m_statusLifetime;
             else return m_clkLifetime;   // clk lifetime
         });
         // have to manipulate this since clocks may be very different when not calibrated
         // but need to put some bound on this to prevent replay attacks, so set a MaxTDdiff
         // should help force new members that are outside of this to move toward domain's vc
         // because others will ignore its clk pubs and just send their own, but could also create
         // problems so commented out here for the initial work
         m_defCreationTm = m_sync.getCreation_;
         m_sync.getCreationCb([this](const auto& p) ->tdv_clock::time_point {
             if (crPrefix(m_prefix/"sts").isPrefix(p.name()))  return m_sync.tdvcNow(); // don't want to miss status messages
             // if (!m_init && m_sync.tdvcNow() - p.name().last().toTimestamp() > MaxTDdiff) return m_defCreationTm;
             return m_sync.tdvcNow();   // for very different clocks, just use arrival time
         });
         // note: don't need to alter isExpired as it is only used for arrivals in onCAdd but default
         // calculates the "age" of the pub based on now-creationTime using timestamp for latter.
         // no content field for a tdvc Publication - all info is in the name
         // get our identity thumbprint, set up our public and private signing keys.
         auto tp = cs_.Chains()[0];
         updateSigningKey(cs_.key(tp), cs_[tp]);
      }

    auto isRelay(const thumbPrint& tp) { return m_relayChk(tp).first; }    // identity 'tp' has RLY capability?
    void setRelayCb(relayValueCb& rvcb) { m_relayCb = std::move(rvcb); }
    auto isStarted() { return m_started; }
    auto getSetSize() { return SetSz; }
    auto getNhdDly() { return nhdRtt_; }   // these three might change due to measurements
    auto getComputeDly() { return m_computeDly; }

    /*
     * Called to process a new local signing key.
     *  use new key immediately to sign - update the signature managers
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        if (cs_.Chains().size() == 0) throw runtime_error("dist_tdvc::updateSigningKey: no signing chain");
        // check if passed in pubCert same as the thumbPrint of the new first signing chain
        if (cs_.Chains()[0] != pubCert.computeTP())
            throw runtime_error("dist_tdvc:updateSigningKey gets new key not at chains[0]");
        m_tp = cs_.Chains()[0];
        // sigmgr needs to get the new signing keys and public key lookup callbacks
        m_tdvcSM.updateSigningKey(sk, pubCert);
        m_tdvcSM.setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });
        if (waitSP_) {  // had to request a new SP due to TDVC change
                   dct::print("distTDVC:updateSigningKey: {} received new SP\n", cs_[m_tp].name().nthBlk(2).toSv());
            waitSP_ = false;
            if (!m_started && isRelay(m_tp)) calibrateClock();
            else endFin("cal");
        }
        else if (!m_init) probeClock();  //send one with new sc
    }

    void initDone() {
        if (vs_.state) return;    //started calibrating again
        if (m_init) {
            m_init = false;
            m_sync.cStateLifetime(6763ms);
            m_connCb(true);
        }
    }

    /*
     * want those in neighborhood to use same tolerances, but need to
     * check for places where the actual neighborhood delay is larger
     * than the default
     * compute m_nhdDy and tolerance from the measurement distributions
     * using a present minimum value and rounding everything to 1ms
     * have to reschedule self
     *
     * To use this value for face delays, remember that pubLifetimes in general
     * should survive transiting the entire Domain while hold times and other
     * sync-related delays might use neighborhood delay values
     */
    void calculateDlys() {
        if (m_rtts.empty()) {   // if no rtts, try again after a delay
            if (m_pinging) m_sync.oneTime(m_computeDly, [this](){ calculateDlys(); }); // (re)starting pinging will schedule
            return;
        }
        auto k = m_rtts.size();
        auto s = m_rtts;
        std::sort(s.begin(), s.end());
        // use min or near-min for RTT estimate.
        auto d = std::chrono::milliseconds( std::lround((double)(s[k/10])/5000.)*5);
        if (std::chrono::milliseconds (s[k/10]/1000) > nhdRtt_) {   //need to update default
           // dct::print("calculateDlys changing values\n\n");
            nhdRtt_ = d;
            if (d/2 > vcQuant)
                txDly_ = d/2 - vcQuant; //  Divide by 2 as estimate of excess one-way delay, remove quant
            else txDly_ = 0ms;
            m_tolVal = s[0.75*k];
            auto q = nhdRtt_.count();
            m_tolVal = std::ceil((double)(m_tolVal)/q) * q;
            m_clkLifetime = 4*nhdRtt_; // or near max rtt for clock pub lifetime?
            m_computeDly = 12*SetSz*nhdRtt_; // needs to be > SetSz * nhdRtt_
            m_sync.pubHoldtime(6*nhdRtt_);
        }
        if (m_init && vs_.state==0) calibrateClock(); // runs calibrateClock to start up
        //clean up and reschedule
        auto l = m_clkDiffs.size() > vs_.nbrs ? m_clkDiffs.size() : vs_.nbrs;
        if (k > SetSz*l) {  // remove older rtt samples
            l = k > 1000 ? 500 : k/2;   // can pick a much larger number, just keeping from growing without bounds
            m_rtts.erase(m_rtts.begin(), m_rtts.end() - l);
        }
        m_pingInt = std::chrono::seconds(calSp/2);    // after first delay calculation, go to a longer interval
        m_sync.oneTime(std::chrono::seconds(calSp), [this](){ calculateDlys(); });   //reschedule
   //     dct::print("calculateDlys: {} has nhdDly={}, computed d={}({}), clkLifetm={}, pubHold={}, clkDiffs={}\n",
   //                me, nhdRtt_, d, s[k/4], m_clkLifetime, 6*nhdRtt_, m_clkDiffs.size());
        std::erase_if(m_clkDiffs,  [](const auto& it) { return it.second.lives == false; }); // erase those I didn't hear from
        if (m_pings.empty()) return;
        // remove any unanswered pings that are deemed "too old"
        auto t = tp2d(std::chrono::system_clock::now()).count() - 2*s[k-1];
        std::erase_if(m_pings, [t](const auto& it) { return it.second < t; });
     }

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
static constexpr auto tp2d = [](auto t){ return std::chrono::duration_cast<ticks>(t.time_since_epoch()); };

     void publishPing() {
         if (m_clkDiffs.size() == 0) {
             m_pinging = false; // no members to ping, return to not pinging state
             return;
         }
        //dct::print("publishPing: {} has {} neighbors, {} rtt samples\n", cs_[m_tp].name().nthBlk(2).toSv(), m_clkDiffs.size(), m_rtts.size());
         auto r = rand( m_clkDiffs.size() );    // randomly select a member to ping
         //schedule my next ping - in init state, publish more pings to get more rtt samples
         m_sync.oneTime(m_pingInt + std::chrono::milliseconds(rand(1,9)), [this](){ publishPing(); });
         dct::thumbPrint trgt;
         for (const auto& [key, value] : m_clkDiffs)  if (r-- == 0) { trgt = key; break; }
         m_pings[trgt] = tp2d(std::chrono::system_clock::now()).count(); // save sending time
         auto myId = cs_[m_tp].name().nthBlk(2).toSv(); //XXXX add before vc field for debugging
         crData p(m_prefix/"png"/trgt/myId/m_sync.tdvcNow());
         p.content(std::vector<uint8_t>{});
         m_pinging = true;
         try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishPing: " << e.what() << std::endl; }
     }

     /*
      * Using this to process pings and echos.
      * If hear ping with my Id, respond, otherwise record time
      * Note that the thumbprint is of identity cert, not signing cert
      * If hear an echo and have a ping time for it, use as a neighborhood rtt measurement
      */
     void receivePngEco (const rPub& p) {
        static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
            return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };

        auto n = p.name();
        if (n.nextAt(m_prefix.size()).toSv() == "png") {   // subcollection
            auto myId = cs_[m_tp].signer();   // thumbprint of identity cert
            auto tps = n.nextBlk().toSpan();    // responder's Id as span
            dct::thumbPrint tpId{};     // have to convert from span so can use to acces cs_, m_pings below
            std::copy(tps.begin(), tps.end(), tpId.begin());
            if (! cs_.contains(tpId)) return;   // don't have the sender's chain so won't hear its eco
            if (equal(tps, std::span(myId))) {    // if the png is for me to echo, respond
                auto me = cs_[m_tp].name().nthBlk(2).toSv(); //XXX add before vc field for debugging
                crData p(m_prefix/"eco"/me/m_sync.tdvcNow());
                p.content(std::vector<uint8_t>{});
                try { m_sync.signThenPublish(std::move(p)); }
                catch (const std::exception& e) { std::cerr << "dist_tdvc::receivePngEco: " << e.what() << std::endl; }
            } else {
                m_pings[tpId] = tp2d(std::chrono::system_clock::now()).count(); // save time heard ping
            }
            return;
        }
        // got an eco since only subscribed to png and eco subcollections
        const auto& tpId = cs_[p.signer()].signer();
        if (!m_pings.contains(tpId)) return;
        if (tp2d(std::chrono::system_clock::now()).count() >= m_pings[tpId]) // check if time adjusted since ping was sent
            m_rtts.push_back(tp2d(std::chrono::system_clock::now()).count() - m_pings[tpId]);
        m_pings.erase(tpId);    // clear)
     }

    void publishStatus() {
        auto myId = cs_[m_tp].name()[2].toSv(); //XXX can add before vc field for debugging
        crData p(m_prefix/"sts"/vs_.nbrs/myId/m_sync.tdvcNow());
        p.content(std::vector<uint8_t>{});
        try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishStatus: " << e.what() << std::endl; }
        m_sync.oneTime(m_statusLifetime, [this](){ publishStatus(); }); // schedule next one
    }

    /*
     * publish my virtual clock value with: name <m_prefix><round><neighborhoodsize><myId><timestamp>
     * space the samples by small number of random ms but perhaps f(distDly) for long delay networks
     * clock values have a short lifetime on order of a distribution delay
     */
    void publishClock() {
        auto vc = m_sync.tdvcNow() - vs_.adjust;  //subtract since pass in negative of vs_.adjust when finished calibrating
        auto myId = cs_[m_tp].name().nthBlk(2).toSv(); //can add before vc field for debugging
        crData p(m_prefix/"clk"/uint64_t(vs_.state)/vs_.nbrs/myId/vc);
        p.content(std::vector<uint8_t>{});
        try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishClock: " << e.what() << std::endl; }
        // if not all in set have been published, reschedule
        // when all have been published, schedule the computeOffset for many distDlys later - must wait long enough
        if (++sentClks_ < SetSz) {
            if (vs_.state) m_sync.oneTime(m_computeDly/SetSz + std::chrono::milliseconds(rand(10)),  [this](){ publishClock(); });
            else m_sync.oneTime(2*m_computeDly/SetSz + std::chrono::milliseconds(rand(10)),  [this](){ publishClock(); });
        } else {
            sentClks_ = 0;
            if (vs_.state == 0 || isRelay(m_tp)) return; // sending probe clocks or I'm a relay, so don't do computeOffset
            //XXX delaying for longer on first compute(s) in case clocks are far apart, don't want to converge early
            if (m_init) m_sync.oneTime(std::chrono::milliseconds(2*600+rand(100)), [this](){ computeOffset(); });
            else m_sync.oneTime(m_computeDly, [this](){ computeOffset(); });
        }
    }

    // log distributor publishes to logs collection; use dctwatch and postprocess
    void publishLog(std::string s, std::span<const uint8_t> content = {}) {
        // name portion for tdvc calibrate log publication with role and role-id and # nbrs, no content
        // XXX role and role-id only works for examples - consider using more of cert name to be more general
        logsCb_( crName("tdvc")  / s / cs_[m_tp].name()[1] / cs_[m_tp].name()[2] / vs_.nbrs, content);
    }

    /*
     * Start a virtual clock calibration session (of one or more rounds)
     */
    void calibrateClock() {      
        if (vs_.state>0 || waitSP_) return;   // already calibrating or waiting for a new SP
        if (!m_started) {
            // check if the tdvc has already been adjusted due to other deftts of relay
            // need to check signing cert (skipping Identity cert since should have been caught
            // already but can add that test - see finishCalibration method below
            if (isRelay(m_tp) && m_sync.tdvcAdjust() != std::chrono::microseconds(0)) {
                auto sc = (rCert) (cs_.get(cs_.Chains()[0]));  // check if invalidates current signing cert
                  if ( !(sc.validNow(m_sync.tdvcAdjust())) ) {   // cert valid methods use system clock with passed in adjustment
                      waitSP_ = true;   // when waitSP_ is set and !m_started, calibrateClock() will be called from updateSigningKey()
                      newSPcb_();    // when new SP is created and validated, tdvc's updateSigningKey() will be called
                      return;
                  } else {
                      expcb_(sc);  // vc was adjusted so signing cert expire may happen sooner/later which can be a problem if other members expire my sc
                  }
            }
            m_started = true;
        }
        m_probe->cancel();      // cancel pending send of clock probe
        for (auto& m : m_clkDiffs) m.second.nhSz = 0;   //clear last round
        vs_.state = 2; //cleared when calibration finishes
        vs_.tolRnds = 0;
        publishLog("ccs");  //calibrateClock start
        if (sentClks_ > 0) sentClks_ = 0; // implies in process of sending probe clocks and a publish has been scheduled
        else publishClock();     //publish a set of clock values and  schedule a computeOffset upon completion
    }

    // used by relays only - need to set in-progress adjustment
    void publishRound(uint8_t r, std::chrono::microseconds a, auto n) {
        vs_.state = r;
        vs_.nbrs = n;
        vs_.adjust = a;
        sentClks_ = 0;
        publishClock();
    }

       /*
     * Called when a new status Publication is received in the tdvc collection
     * status pub names <m_prefix><sts><#nbrs><timestamp> (currently inserts myId before vc for testing)
     * Status pubs have a longish lifetime
     */
    void receiveStsValue(const rPub& p) {
        auto tpId = cs_[p.signer()].signer();   // thumbprint of identity cert
        if (!m_clkDiffs.contains(tpId)) m_clkDiffs[tpId].nhSz = 0;  // make an entry for ping to use
        m_clkDiffs[tpId].lives = true; // note that tpId has been heard from
        if (!m_pinging) {   // can start pinging since have neighbor(s)
            m_sync.oneTime(std::chrono::milliseconds(rand(5)), [this](){ publishPing(); });
            m_sync.oneTime(m_computeDly, [this](){ calculateDlys(); });
            m_pinging = true;
         }
     }

    /*
     * Called when a new clk Publication is received in the tdvc collection
     * clock pub names <m_prefix><clk><round><#nbrs><timestamp> (XXXcurrently inserts myId before vc for testing)
     */
    void receiveClkValue(const rPub& p) {
        if (!m_started) return; // will start from calibrateClock (called after receiveSts and calculateDlys)
       /* process the sample
         * compute difference between local virtual clock estimate and timestamp in us, signed value
         * add the current offset estimate (used for multiple rounds) which is estimate of how far ahead my vc is of domain vc
         * this is the amount of time my vc is ahead of sender plus the time to send
         * Compute minimum of clock differences because rts includes additive noise of tx + proc delay
        */
        const auto& tp = p.signer();    // thumbprint of p's signing cert
        auto n = p.name();
        n.nextAt(m_prefix.size()).toSv();   // skip over subcollection clk
        auto st = n.nextBlk().toNumber();
        auto nhd = n.nextBlk().toNumber();
        auto tpId = cs_[tp].signer();   // thumbprint of identity cert
        auto rts = n.lastBlk().toTimestamp(); // received pub timestamp as a timepoint
        auto cd = m_sync.tdvcNow() - vs_.adjust - rts - txDly_;
        /*
         * In state 0 clock, send nothing to another state 0 member
         * A member in state 1 will need my values to finish, so publish if not already doing so
        // A member not in state 0 or 1 will start me calibrating (if not change in vc, nothing happens to my vc)
        */
        if (vs_.state == 0) {
            if (st > 1 || std::abs(cd.count()) > m_tolVal) {
                if (isRelay(m_tp)) m_relayCb(tpId, cd.count(), nhd, st);    // causes relay to start calibrating again
                else calibrateClock();
            } else if (st == 1 && sentClks_ == 0) publishClock(); // not already sending
           return;
        }

        if (isRelay(m_tp)) {    // relay deftts share all values
            m_relayCb(tpId, cd.count(), nhd, st);
            return;
        }

        if (!m_clkDiffs.contains(tpId) || st != m_clkDiffs[tpId].st || m_clkDiffs[tpId].nhSz == 0 ) {
            // new or not the same as last state received from this tpId or entry was from status not clock pub
            m_clkDiffs[tpId].st = st;
            m_clkDiffs[tpId].v = cd.count();
        } else if ( cd.count() < m_clkDiffs[tpId].v) m_clkDiffs[tpId].v = cd.count();
        m_clkDiffs[tpId].nhSz = nhd;            // use received value
        m_clkDiffs[tpId].lives = true;
    }

    // in state 0, periodically announce my clock to neighborhood: out-of-tolerance restarts calibration
    void probeClock() {
        if (vs_.state > 0) return;    // not in calibrated state
        sentClks_ = SetSz - 1; // this will only send one probe clock instead of setSz
        publishClock();
        m_probe = m_sync.schedule(std::chrono::seconds(calSp/4+ rand(13)), [this](){ probeClock(); });
    }

     /*
      * Does all the clean up that happens when finish calibration and sets TDVC
      * For relays, this can be called from the relay when synchronizing the sibling DeftTs
      * If the adjustment means my signing cert is no longer valid, need to have a test and
      * callback to create a new signing key pair
      *
      * endFin separates out the shared ending code. Might be a good idea to schedule initDone
      * at a delay and check in initDone() to see if calibration restarted (vs_.state > 0)
      */
     void endFin(std::string s, std::span<const uint8_t> content = {}) {
          publishLog(s, content);  // log when finishCalibration, changed or not
          vs_.adjust = zeroUs;
          probeClock();
          if (s == "oob") return;   // not done if in m_init
          // delay calling initDone in case there are "ripple" effects from domains that aren't all on one mcast net
          if (m_init) m_sync.oneTime(4*m_computeDly, [this](){ initDone(); });
     }

     void finishCalibration(auto a, uint8_t n=1) {
          for (auto& m : m_clkDiffs) m.second.nhSz = 0;   //clear last round
          vs_.tolRnds = 0;
          vs_.state = 0;
          sentClks_ = 0;
          if (isRelay(m_tp)) vs_.nbrs = n;
          if (a == zeroUs) { endFin("cal"); return; }   // local vc didn't change

          try {
              auto sc = (rCert) (cs_.get(cs_.Chains()[0]));  // check for continued validity of signing cert
              auto ic = (rCert)  (cs_.get(sc.signer()));        //      and identity cert
              if ( ic.validNow(m_sync.tdvcAdjust()+a) ) {   // cert valid methods use system clock with passed in adjustment
                  m_sync.tdvcAdjust(a); // okay to apply adustment to the virtual clock
                  if ( !(sc.validNow(m_sync.tdvcAdjust())) ) {  // check if invalidates current signing cert
                      waitSP_ = true;   // when waitSP_ is set, endFin() will be called from updateSigningKey()
                      newSPcb_();    // when new SP is created and validated, tdvc's updateSigningKey() will be called
                  } else {
                      expcb_(sc);  // vc was adjusted so signing cert expire may happen sooner/later which can be a problem if other members expire my sc
                      endFin("cal");
                  }
               } else {
                  std::string s = dct::format("Ignoring out-of-bounds vc adjustment: adjustment {} to {} would invalidate identity cert", a, m_sync.tdvcNow() );
                  std::vector<uint8_t> c(s.begin(), s.end());
                  endFin("oob", c);  // ignoring out-of-bounds clock adjustment - can't invalidate identity cert
              }
          } catch (const std::exception& e) {
                  std::cerr << "dist_tdvc::finishCalibration: " << e.what() << std::endl;
                  std::runtime_error("can't continue");
          }
     }

    /*
     * computeOffset() is called several distDly after the last clock value for this round is sent.
     * doCompute() breaks out the computation so that same method can be used by relays
     * Uses the minimum difference value received from a peer (s)
     * The clock differences are noisy samples for the actual clock difference. The "noise" is the
     * transmission plus processing time and is always additive.
     * Quantizing the clock difference to use as the next offset to the vc.
     * The quantizating should be some high quantile of the tx+proc time for the neighborhood
     * Here, the tolerance value is set to a slightly larger value.
     * If the stopping criteria are met, the calibration session is done.
     * Otherwise, calls publishClock() to start another round
     *
     */

     bool doOffset(std::map<dct::thumbPrint,cdiff>& cvs, vcVars& sv) {
        // find my neighborhood size for the next round and nbrs who are in tolerance
        size_t z = 0;               // number of neighbors in state 0
        size_t un = 0;               // number of neighbors in state 1
        size_t h = 1;               // count number of sending neighbors
        size_t n = sv.nbrs;    // to find smallest neighborhood
        for (auto& m : cvs) {
            auto& cd = m.second;
            if (cd.nhSz != 0) { // have value from this neighbor?
                ++h;                                // I have clks from this neighbor, increase
                if (cd.nhSz < n) n = cd.nhSz;
                // count neighbors in state 0 and state 1 in this round but don't count neighbors that are just starting
                if (cd.nhSz > 1) {
                    if (cd.st == 0) ++z;
                    else if (cd.st == 1) ++ un;
                }
            } else cd.lives = false;    // this will get set back to true if hear from this id, else gets cleaned up later
        }
        if (h==1) {
            sv.nbrs = 1;    // no neighbors communicating - just keep publishing clk samples
            return false;
        }

        n -=1;                                      // replication factor
        std::vector<int64_t> ud{};  // for the microsecond differences from my virtual clock
        // put values from each tpId in a vector and sort
        // want to use those with largest neighborhoods preferentially so replicate them
        for (size_t i=0; i<sv.nbrs-n; ++i) ud.push_back(0);  // zero diffs for my clock
        for (auto& m : cvs) {    // replicate by nbrhd size - smallest nbrhd +1
            auto& cd = m.second;
            if (cd.nhSz != 0) for (size_t j=0; j<cd.nhSz-n; ++j)  ud.push_back(cd.v);
        }
        // sort differences (amount by which my clock is ahead of others in int us) from smallest to largest
        if (ud.size())   std::sort(ud.begin(), ud.end());

        /*
         * Approach is to move toward mode (don't need ud sorted for mode but used above)
         * 1. Find the (quantized) mode and number of times it occurs
         * 2. If more than one mode, move halfway toward closest mode (faster movement and works with small nbrhds)
         *     Else move (# at mode/total nbhd) * mode
         *  Only times I don't adjust my clock are: single mode with value quantized to zero,
         *  two values with mode frequency, one is zero, the other is q (because the "behind" one adjusts)
         */
        auto q = vcQuant.count();  // an estimate of tx+proc time in the neighborhood in int us
        int64_t adj = 0;
        std::map<int64_t, int> freq;
        int64_t v;
        int c = 0;
        int64_t md = 0;
        for (int64_t d : ud) {  // finding frequency of each quantized diff
            v = std::floor((double)(d)/q) * q;
            if (std::abs(v) > std::abs(md)) md = v; // largest abs value diff
            freq[v]++;
            if (freq[v] > c) c = freq[v];
        }

        std::erase_if(freq, [c](const auto& it) { return it.second != c; });
        int64_t md2 = md;   // set to largest abs value diff
        for (const auto& it : freq) {   // set md to the smallest abs diff, preferring neg
            if (std::abs(it.first) < std::abs(md) || (std::abs(it.first) == std::abs(md) && it.first < md)) {
                md2 = md;  // second smallest abs value difference
                md = it.first; // smallest abs value difference
            } else if (std::abs(it.first) < std::abs(md2) || (std::abs(it.first) == std::abs(md2) && it.first < md2))
                md2 = it.first;
        }
        // check for special cases:  more than one value has the max number of occurances?
        //  move toward smallest non-zero diff,  tie-breaker is move toward forward clock
        if (freq.size() > 1 && md == 0 && md2 < 0) adj = md2;
        else adj = md;
        if (adj == 0 && sv.zAdj > 10 && sv.state > 12) {   // detect if I haven't moved in many rounds
            size_t i = 0;
            for ( ; i < ud.size(); ++i) if (ud[i] == 0) break; // find first zero
            if (i != 0) adj = std::floor((double)(ud[i-1])/q) * q; // use smallest neg value, if any
        }
        // get vs_.nbrs, number of neighbors in agreement to the mode and test for state 0 or 1
        // a tolerance round is when differences are within q and all neighbors are either state 0 or 1
        // counting tolerance rounds could possibly be replaced by or augmented with a minimum time in state 1 (~domain delay)
        sv.nbrs = 1; // start by counting self as contributing to this vc used in  next samples (because will use adj)
        // count number of neighbors quantized within q of adj - this is the number in nbhd that agree on this vc
        for (const auto& m :cvs) if (m.second.nhSz != 0 && (m.second.v - adj) < 2*q && (m.second.v-adj ) > -q) ++(sv.nbrs);
        // if within q of all and adjustment did not change from last round, go to state 1
        if (sv.nbrs == h && adj == 0) {
            if (sv.state != 1) { sv.state = 1; sv.tolRnds = 0; } // if not in state 1, go there
            if (z+un != h-1) sv.tolRnds = 0; // only count rounds where all neighbors are in state 0 or 1
            else if (++sv.tolRnds > TolRnds) { // this is a tolerance round - does it exceed TolRnds?
                return true;    // indicates should finishCalibration
            }
        } else {
            sv.state =  (sv.state == 255) ? 2 : ++(sv.state); // if state was 1 for in agreement, will start back at 2
            // add to adjust which is the running total for this calibration
            sv.zAdj = adj == 0 ? ++sv.zAdj : 0;   // track number of zero adjustments when not in state 1
        }
        if (adj != 0) {  // if not finished, set up for another round
            sv.adjust += std::chrono::microseconds(adj);  // total amount being added to vc for next round
            for (auto& m : cvs) m.second.nhSz = 0;   // clear round
        }
        return false;
     }

     void computeOffset() {
         if (isRelay(m_tp))  return;    //  relay computes centrally
         if (doOffset(m_clkDiffs, vs_) == true) finishCalibration(-vs_.adjust);
         else if (vs_.nbrs > 1) publishClock();   // start next round
         else m_sync.oneTime(m_computeDly,  [this](){ publishClock(); }); //no neighbors communicating - delay for others to join
      }

    /*
     * setup() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when an updated trust domain virtual clock has been computed
     * so that there won't be problems with publication in key distributors and applications.
     * subscribes will process any publications waiting in collection
     *
     * Calls its syncps's start() before returning to start participating in collection
     */
    void setup(connectedCb&& ccb) {
        m_connCb = std::move(ccb);
        m_sync.start();     // distributors "before" me have initialized (cert distributor)
        publishLog("ivc"); // to get initial clock
        m_sync.subscribe(m_prefix/"clk", [this](const auto& p){ receiveClkValue(p); });
        m_sync.subscribe(m_prefix/"sts", [this](const auto& p){ receiveStsValue(p); });
        m_sync.subscribe(m_prefix/"png", [this](const auto& p){ receivePngEco(p); });
        m_sync.subscribe(m_prefix/"eco", [this](const auto& p){ receivePngEco(p); });
        publishStatus();    // lets others know I'm in the tdvc collection
    }    
};   // DistTDVC
} // namespace dct

#endif //DIST_TDVC_HPP
