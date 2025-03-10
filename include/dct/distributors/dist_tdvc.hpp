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
 * This initial release includes the round trip delay estimator for
 * neighbors but is not currently using it
 * Since clock values should only be distributed through a single hop
 * to avoid indeterminate additional delays, adjustments are made to its syncps.
 * tdvc's syncps is set to NOT send the pubs of others since this is for "one-hop" neighbors only
 * and sets its hold time for the clock publications to be longer than the pub lifetime
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

struct DistTDVC {
    static constexpr std::chrono::milliseconds MaxTDdiff = 60s;  // delays outside of this will be ignored
    int64_t calSp{300};  // number of seconds between status publications, fractions of this used for probe clocks, pings

    using connectedCb = std::function<void(bool)>;
    using relayValueCb = std::function<void(thumbPrint, int64_t, size_t, size_t, tdv_clock::duration)>;

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

     std::vector<uint32_t> m_rtts;
     // saves time of pings sent or heard by the expected responder's Id TP
     std::unordered_map<thumbPrint,uint64_t> m_pings{};

    const crName m_prefix;        // prefix for pubs in this distributor's collection
    SigMgrAny m_tdvcSM{sigMgrByType("EdDSA")};   // to sign/validate Publications and PDUs
    SyncPS m_sync;
    const certStore& m_certs;
    connectedCb m_connCb{[](auto) {}};
    relayValueCb m_relayCb{[](auto,auto,auto,auto,auto){}};  //only for relays/ptps: called when a new clock value received from neighbor
    size_t m_sentClks{};        // number of clock values sent this publishing round
    size_t m_nbrs{1};            // number of neighbors (incl. me) that were used in previous round's computation (neighborhood size)
    size_t m_set{3};              // number of clock values per round
    uint8_t m_tolRnds{};
    uint8_t m_state{};                   //my state: 0=not calibrating, 1=in tolerance but counting nbrs, 2+ calibrating
    bool m_started{false};      // true once another member has been heard from in this collection
    tdv_clock::duration m_adjust{0us};         // during calibration, keeps the in-progress local adjustment to vc
    std::map<thumbPrint,cdiff> m_clkDiffs{};
    thumbPrint m_tp{};

    tdv_clock::duration m_statusLifetime{std::chrono::seconds(calSp)};
    tdv_clock::duration m_clkLifetime{20ms}; // for clk pubs
    tdv_clock::duration m_nhdDly{5ms}; // rough estimate of transit + process time between neighbors in my 'hood
    int64_t m_tolVal{20000};        // largest clock difference tolerated in calibration integer microseconds
    tdv_clock::duration m_computeDly{500ms};   //delay for each "round"
    dct::rand rand{};
    bool m_init{true};
    bool m_pinging{false};
    Cap::capChk m_relayChk;   // method to return true if the identity chain has the relay (RLY) capability
    Cap::capChk m_priClkChk;   // method to indicate if the identity chain has the priority clock (PCLK) capability
    IsExpiredCb m_defExpired;
    GetCreationCb m_defCreationTm;

    DistTDVC(DirectFace& face, const Name& pPre, const Name& dPre,  const certStore& cs) :
             m_prefix{pPre},
             m_sync(face, dPre, m_tdvcSM.ref(), m_tdvcSM.ref()),
             m_certs{cs},
             m_relayChk{Cap::checker("RLY", pPre, cs)}
     {
        m_sync.autoStart(false); // shouldn't start until cert distributor is done initializing
         m_sync.noOthers();       // won't send publications of others (clock sync is between neighbors)
        m_sync.signerHoldtime(0ms);  // don't hold publications for signing cert (can interfere with timing)
         // if the syncps set its cStateLifetime longer, means we are on a low rate network
         m_sync.cStateLifetime(6763ms);
        // the clock samples have short lifetimes as they are not ever forwarded but longer guard bands
         m_sync.pubHoldtime(6*m_nhdDly);  // setting post-publication holdtime to be longer than active time ensures "send once"
         m_sync.getLifetimeCb([this](const auto& p) ->tdv_clock::duration {
            auto n = p.name();
            if (crPrefix(m_prefix/"sts").isPrefix(n)) return m_statusLifetime;
            else if (crPrefix(m_prefix/"cal").isPrefix(n)) return 2*m_nhdDly; // will become log pub
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
         auto tp = m_certs.Chains()[0];
         updateSigningKey(m_certs.key(tp), m_certs[tp]);
      }

    auto isRelay(const thumbPrint& tp) { return m_relayChk(tp).first; }    // identity 'tp' has RLY capability?
    void setRelayCb(relayValueCb& rvcb) { m_relayCb = std::move(rvcb); }
    auto isStarted() { return m_started; }

    /*
     * Called to process a new local signing key.
     *  use new key immediately to sign - update the signature managers
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        if (m_certs.Chains().size() == 0) throw runtime_error("dist_tdvc::updateSigningKey: no signing chain");
        // chexk if passed in pubCert same as the thumbPrint of the new first signing chain
        if (m_certs.Chains()[0] != pubCert.computeTP())
            throw runtime_error("dist_tdvc:updateSigningKey gets new key not at chains[0]");
        m_tp = m_certs.Chains()[0];
        // sigmgr needs to get the new signing keys and public key lookup callbacks
        m_tdvcSM.updateSigningKey(sk, pubCert);
        m_tdvcSM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
    }

    void initDone() {
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
     * using a minimum value of 5ms and rounding everything to 1ms
     * have to reschedule self
     *
     * To use this value for face delays, remember that pubLifetimes in general
     * should survive transiting the entire Domain while hold times and other
     * sync-related delays might use neighborhood delay values
     */
    void calculateDlys() {
        if (m_rtts.empty()) {   // if no rtts, try again after a delay
            m_sync.oneTime(m_computeDly/4, [this](){ calculateDlys(); });
            return;
        }
        auto k = m_rtts.size();
        auto s = m_rtts;
        std::sort(s.begin(), s.end());
        auto d = std::chrono::milliseconds( std::lround((double)(s[k/10])/5000.)*5); // should use min or close to min
        if (std::chrono::milliseconds (s[k/10]/1000) > 2*m_nhdDly) {   //need to update default
        dct::print("calculateDlys changing values\n\n");
            m_nhdDly = d;
            m_tolVal = s[0.75*k];
            auto q = m_nhdDly.count();
            m_tolVal = std::ceil((double)(m_tolVal)/q) * q;
            m_clkLifetime = 4*m_nhdDly; // or near max rtt for clock pub lifetime?
            m_sync.pubHoldtime(6*m_nhdDly);
        }

        //clean up and reschedule
        auto l = m_clkDiffs.size() > m_nbrs ? m_clkDiffs.size() : m_nbrs;
        if (k > m_set*l) {  // remove older rtt samples
            l = k > 1000 ? 500 : k/2;   // can pick a much larger number, just keeping from growing without bounds
            m_rtts.erase(m_rtts.begin(), m_rtts.end() - l);
        }
        m_sync.oneTime(std::chrono::seconds(calSp), [this](){ calculateDlys(); });   //reschedule
   //     dct::print("calculateDlys: {} has nhdDly={}, computed d={}({}), clkLifetm={}, pubHold={}, clkDiffs={}\n",
   //                me, m_nhdDly, d, s[k/4], m_clkLifetime, 6*m_nhdDly, m_clkDiffs.size());
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
        //dct::print("publishPing: {} has {} neighbors, {} rtt samples\n", m_certs[m_tp].name().nthBlk(2).toSv(), m_clkDiffs.size(), m_rtts.size());
         auto r = rand( m_clkDiffs.size() );    // randomly select a member to ping
         //schedule my next ping
         if (m_init)  // in init state, publish more pings to get more rtt samples
             m_sync.oneTime(m_computeDly + std::chrono::milliseconds(rand(1,9)), [this](){ publishPing(); });
         else
             m_sync.oneTime(std::chrono::seconds(calSp/10) + std::chrono::milliseconds(rand(1,9)), [this](){ publishPing(); });
         dct::thumbPrint trgt;
         for (const auto& [key, value] : m_clkDiffs)  if (r-- == 0) { trgt = key; break; }
        //dct::print ("publishPing: {} chose {}\n", m_certs[m_tp].name().nthBlk(2).toSv(), m_certs[trgt].name().nthBlk(2).toSv());
         m_pings[trgt] = tp2d(std::chrono::system_clock::now()).count(); // save sending time
         auto myId = m_certs[m_tp].name().nthBlk(2).toSv(); //XXXX add before vc field for debugging
         crData p(m_prefix/"png"/trgt/myId/m_sync.tdvcNow());
         p.content(std::vector<uint8_t>{});
         m_pinging = true;
         try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishPing: " << e.what() << std::endl; }
     }

     /*
      * Using this to process pings and echos.
      * Could use to detect extreme clock differences before starting calibration but seems more
      * complicated that it's worth.
      * If hear ping with my Id, respond, otherwise record time
      * Note that the thumbprint is of identity cert, not signing cert
      * If hear an echo and have a ping time for it, use as a neighborhood rtt measurement
      */
     void receivePngEco (const rPub& p) {
        static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
            return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };

        auto n = p.name();
        if (n.nextAt(m_prefix.size()).toSv() == "png") {   // subcollection
            auto myId = m_certs[m_tp].signer();   // thumbprint of identity cert
            auto tps = n.nextBlk().toSpan();    // responder's Id as span
            dct::thumbPrint tpId{};     // have to convert from span so can use to acces m_certs, m_pings below
            std::copy(tps.begin(), tps.end(), tpId.begin());
            if (! m_certs.contains(tpId)) return;   // don't have the sender's chain so won't hear its eco
            if (equal(tps, std::span(myId))) {    // if the png is for me to echo, respond
                auto me = m_certs[m_tp].name().nthBlk(2).toSv(); //XXX add before vc field for debugging
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
        const auto& tpId = m_certs[p.signer()].signer();
        if (!m_pings.contains(tpId)) return;
        m_rtts.push_back(tp2d(std::chrono::system_clock::now()).count() - m_pings[tpId]);
        m_pings.erase(tpId);    // clear
     }

    void publishStatus() {
        auto myId = m_certs[m_tp].name().nthBlk(2).toSv(); //XXX can add before vc field for debugging
        crData p(m_prefix/"sts"/m_nbrs/myId/m_sync.tdvcNow());
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
        auto vc = m_sync.tdvcNow() - m_adjust;  //subtract since pass in negative of m_adjust when finished calibrating
        auto myId = m_certs[m_tp].name().nthBlk(2).toSv(); //can add before vc field for debugging
        crData p(m_prefix/"clk"/m_state/m_nbrs/myId/vc);
        p.content(std::vector<uint8_t>{});
        try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishClock: " << e.what() << std::endl; }

        // when all have been published, schedule the computeOffset for many distDlys later - must wait long enough
        if (++m_sentClks < m_set) m_sync.oneTime(m_computeDly/m_set + std::chrono::milliseconds(rand(20)),  [this](){ publishClock(); });
        else {
            m_sentClks = 0;
            if (m_state == 0 || isRelay(m_tp)) return;
            m_sync.oneTime(m_computeDly/m_set, [this](){ computeOffset(); });
        }
    }

    // XXX for test/logging - no subscribers needed, use dctwatch and postprocess
    void publishCalibrate() {
        auto myRole = m_certs[m_tp].name().nthBlk(1).toSv();
        auto myId = m_certs[m_tp].name().nthBlk(2).toSv();
        crData p(m_prefix/"cal"/myRole/myId/m_nbrs/m_sync.tdvcNow());
        p.content(std::vector<uint8_t>{});
        try { m_sync.signThenPublish(std::move(p)); }
        catch (const std::exception& e) { std::cerr << "dist_tdvc::publishCalibrate: " << e.what() << std::endl; }
    }

    /*
     * Start a virtual clock calibration session (of one or more rounds)
     */
    void calibrateClock() {
        if (m_state>0) return;   // already calibrating
        m_state = 2; //cleared when computeOffset finishes
        m_sentClks = 0;
        if(m_init) publishCalibrate(); // testing only - gives my baseline clock for this session
        publishClock();     //publish a set of clock values and  schedule a computeOffset upon completion
    }

    // used by relays only - need to set in-progress adjustment
    void publishRound(uint8_t r, std::chrono::microseconds a, auto n) {
        m_state = r;
        m_nbrs = n;
        m_adjust = a;
        publishClock();
    }

       /*
     * Called when a new sts Publication is received in the tdvc collection
     * status pub names <m_prefix><sts><#nbrs><timestamp> (currently inserts myId before vc for testing)
     * Status pubs have a longish lifetime
     */
    void receiveStsValue(const rPub& p) {
        auto tpId = m_certs[p.signer()].signer();   // thumbprint of identity cert
        if (!m_clkDiffs.contains(tpId)) m_clkDiffs[tpId].nhSz = 0;  // make an entry for ping to use
        else m_clkDiffs[tpId].lives = true; // make sure note tpId has been heard from
        if (!m_started) {
            m_started = true;
            if (!m_pinging) {   // can start pinging since have neighbor(s)
                m_sync.oneTime(m_nhdDly + std::chrono::milliseconds(rand(20)), [this](){ publishPing(); });
                m_sync.oneTime(2*m_computeDly, [this](){ calculateDlys(); });
                m_pinging = true;
            }
            if (m_state==0) calibrateClock();
            return;
        }
      }

    /*
     * Called when a new clk Publication is received in the tdvc collection
     * clock pub names <m_prefix><clk><round><#nbrs><timestamp> (XXXcurrently inserts myId before vc for testing)
     */
    void receiveClkValue(const rPub& p) {
        if (!m_started) return; // will start from receiveStsValue

        const auto& tp = p.signer();    // thumbprint of p's signing cert
        auto n = p.name();
        n.nextAt(m_prefix.size()).toSv();   // skip over subcollection clk
        auto st = n.nextBlk().toNumber();
        auto nhd = n.nextBlk().toNumber();
        auto tpId = m_certs[tp].signer();   // thumbprint of identity cert
        auto rts = n.lastBlk().toTimestamp(); // received pub timestamp as a timepoint

        if (m_state == 0 && std::abs((m_sync.tdvcNow() - rts).count()) < m_tolVal) {
            if (st == 0) return; //sender is also not calibrating (responding to other)
            if (st == 1) {
                if (m_sentClks == 0) publishClock(); // sender is still calibrating and needs my values
                return; // in the middle of publishing clocks
            }
        } // all other cases start calibrating again

        /* process the sample
         * compute difference between local virtual clock estimate and timestamp in us, signed value
         * add the current offset estimate (used for multiple rounds) which is estimate of how far ahead my vc is of domain vc
         * this is the amount of time my vc is ahead of sender plus the time to send
         * Use minimum of clock differences because rts includes additive noise of tx + proc delay
        */
        auto cd = m_sync.tdvcNow() - m_adjust - rts;
        if (isRelay(m_tp)) {    // relay deftts share all values
            m_relayCb(tpId, cd.count(), nhd, st, m_nhdDly);
            return;
        }

        if (!m_clkDiffs.contains(tpId) || st != m_clkDiffs[tpId].st ) {   // new or not the same as last state received from this tpId
            m_clkDiffs[tpId].st = st;
            m_clkDiffs[tpId].v = cd.count();
         } else if (m_clkDiffs[tpId].nhSz == 0 || cd.count() < m_clkDiffs[tpId].v) m_clkDiffs[tpId].v = cd.count();
        m_clkDiffs[tpId].nhSz = nhd;            // use received value
        m_clkDiffs[tpId].lives = true;
        if (m_state == 0) calibrateClock();  // if not currently calibrating, launch a new calibrate
    }

    // in state 0, periodically announce my clock to neighborhood: out-of-tolerance restarts calibration
    void probeClock() {
        if (m_state > 0) return;
        publishClock();
        m_sync.oneTime(std::chrono::seconds(calSp/4 + rand(3,60)), [this](){ probeClock(); });
    }

     /*
      * Does all the clean up that happens when finish calibration and sets TDVC
      * For relays, this can be called from the relay when synchronizing the sibling DeftTs
      */
     void finishCalibration(auto a, uint8_t n=1) {
         for (auto& m : m_clkDiffs)  m.second.nhSz = 0;   //clear last round
          m_tolRnds = 0;
          m_state = 0;
          if (isRelay(m_tp)) m_nbrs = n;      
          if (a != 0us) m_sync.tdvcAdjust(a); // apply adustment to the virtual clock
          publishStatus();
          m_sync.oneTime(100ms, [this](){ publishCalibrate(); }); // (temporary) logging function - delay so goes in sep cAdd
          //dct::print("finishCalibration: {} with total virtual clock offset {}, {} nbrs ({} this session) sent={}\n", m_certs[m_tp].name().nthBlk(2).toSv(), m_sync.tdvcAdjust(), m_nbrs, m_adjust, m_sentClks);
          m_adjust = 0us;
          if (m_init) {
              m_sync.oneTime(std::chrono::seconds(calSp/4 + rand(3,60)), [this](){ probeClock(); });
              initDone();
          }
     }

    /*
     * computeOffset() is called several distDly after the last clock value for this round is sent.
     * Uses the minimum difference value received from a peer (s)
     * The clock differences are noisy samples for the actual clock difference. The "noise" is the
     * transmission plus processing time and is always additive.
     * Quantizing the clock difference to use as the next offset to the vc.
     * The quantizating should be some high quantile of the tx+proc time for the neighborhood
     * Here, the tolerance value is set to to twice that.
     * If the stopping criteria are met, the calibration session is done.
     * Otherwise, calls publishClock() to start another round
     *
     */
     int m_zAdj;    // number of times I've used a zero adjustment
     void computeOffset() {
         if (m_state==0 || isRelay(m_tp))  return;    // relay computes centrally

        // find my neighborhood size for the next round and nbrs who are in tolerance
        size_t z = 0;
        size_t h = 1;               // count number of sending neighbors
        size_t n = m_nbrs;    // to find smallest neighborhood
        for (auto& m : m_clkDiffs) {
            auto& cd = m.second;
            if (cd.nhSz != 0) { // have value from this neighbor?
                ++h;                                // I have clks from this neighbor, increase
                if (cd.nhSz < n) n = cd.nhSz;
                if (cd.st <= 1) ++z;       // count neighbors who were in tolerance this round
            } else cd.lives = false;    // this will get set back to true if hear from it, else gets cleaned up later
        }
        if (h==1) {
            if (m_tolRnds > 4) {
                finishCalibration(-m_adjust);  // no neighbors communicating
                return;
            }
           if (m_state > 1) {
               m_state = (m_state == 255) ? 2 : ++m_state;
            }
           publishClock(); // prompt others to send clock values when receive mine
           return;
        }

        // if receive some values from a later round, in particular from round2 when I'm finishing
        // round 1. Not sure if want to take round into account
        auto q = m_nhdDly.count();  // an estimate of tx+proc time in the neighborhood in int us
        n -=1;                                      // replication factor
        std::vector<int64_t> ud{};  // for the microsecond differences from my virtual clock
        // put values from each tpId in a vector and sort
        // want to use those in largest neighborhoods preferentially so replicate them
        for (size_t i=0; i<m_nbrs-n; ++i) ud.push_back(0);  // zero diffs for my clock
        for (auto& m : m_clkDiffs) {
            auto& cd = m.second;
            // replicate by nbrhd size - smallest nbrhd +1
            if (cd.nhSz != 0) for (size_t j=0; j<cd.nhSz-n; ++j)  ud.push_back(cd.v);
        }

        // sort differences from smallest to largest
        // (this is amount by which my clock is ahead of others in int us)
        /*
         * Approach is to move toward mode
         * 1. Find the (quantized) mode and number of times it occurs
         * 2. If more than one mode, move halfway toward closest mode (faster movement and works with small nbrhds)
         *     Else move (# at mode/total nbhd) * mode
         *  Only times I don't adjust my clock are: single mode with value quantized to zero,
         *  two values with mode frequency, one is zero, the other is q (because the "behind" one adjusts)
         */
        int64_t adj = 0;
        std::sort(ud.begin(), ud.end());    // don't really need to sort using mode but is useful to know order
        std::map<int64_t, int> freq;
        int64_t v;
        int c = 0;
        int64_t md = 0;
        for (int d : ud) {  // finding frequency of each quantized diff
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
        if (adj == 0 && m_zAdj > 10 && m_state > 12) {   // detect if I haven't moved in many rounds
            size_t i = 0;
            for ( ; i < ud.size(); ++i) if (ud[i] == 0) break; // find first zero
            if (i != 0) adj = std::floor((double)(ud[i-1])/q) * q; // use smallest neg value, if any
        }
        m_nbrs = 1; // start by counting self as contributing to this vc used in  next samples
        for (const auto& m : m_clkDiffs)   // count number of neighbors quantized within q of adj
            if (m.second.nhSz != 0 && (m.second.v - adj) < 2*q && (m.second.v-adj ) > -q) ++m_nbrs;
        if (m_nbrs == h) m_state = 1; // this adjustment makes me in tolerance with all
        else m_state =  (m_state == 255) ? 2 : ++m_state;    // if m_state was 1 for in tolerance, will start back at 2

        // add to m_adjust which is the running total for this calibration
        m_zAdj = adj == 0 ? ++m_zAdj : 0;   // track number of zero adjustments
        m_adjust += std::chrono::microseconds(adj);  // total amount being added to vc for next round
      //  dct::print("computeOffset: {} has nbhdSz={}, nbrs in tol of mode={}, state={}, mode= {}, tol nbrs={}, #tolRnds={}, tot off={}\n",
             //      me, h, m_nbrs, m_state, adj, z, m_tolRnds, m_sync.tdvcAdjust() - m_adjust);

        /*
         * stopping criteria: all neighbors must be within tolerance
         * compute this by my neighbors must all be sending rounds marked zero 
         * and have completed some minimal number of rounds
         */
        // Note: used the previous value of m_adjust (-adj) in computing the clkDiffs
        if (m_state == 1 && z == h-1) ++m_tolRnds;    // counting rounds in tolerance
        else m_tolRnds = 0;                                         // reset count (will need an "out" if some neighbor is weird)
        if (m_tolRnds > 4) {   // all in tolerance for more than 4 rounds?
            finishCalibration(-m_adjust); // calibrated: set the clock and related values
        } else { // try again
            for (auto& m : m_clkDiffs) m.second.nhSz = 0;   // clear round
            m_sync.oneTime(m_computeDly/m_set + std::chrono::milliseconds(rand(3,47)), [this](){ publishClock(); });
        }
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
        m_sync.subscribe(m_prefix/"clk", [this](const auto& p){ receiveClkValue(p); });
        m_sync.subscribe(m_prefix/"sts", [this](const auto& p){ receiveStsValue(p); });
        m_sync.subscribe(m_prefix/"png", [this](const auto& p){ receivePngEco(p); });
        m_sync.subscribe(m_prefix/"eco", [this](const auto& p){ receivePngEco(p); });
        publishStatus();    // lets others know I'm in the tdvc collection
    }    
};   // DistTDVC
} // namespace dct

#endif //DIST_TDVC_HPP
