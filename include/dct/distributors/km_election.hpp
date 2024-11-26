#ifndef KM_ELECTION_HPP
#define KM_ELECTION_HPP
#pragma once
/*
 * km_election - run a key-maker election for some distributor
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
 *  km_election is not intended as production code.
 *
 * This class runs a distributed election for some distributor to choose
 * an entity to perform some function (usually to be a 'key maker' for
 * the distributor). Entities are authorized to perform this function by
 * having a particular capability cert in their signing chain. The value of
 * the capability influences the probability of this entity being elected
 * with 0 (or no cert) meaning 'not authorized' and larger values giving
 * higher priority.
 *
 * The keyMaker election is conducted via publications to a "km" sub-topic
 * of the distributor's topic. The election is currently one-round &
 * priority-based but will eventually follow a 'simple paxos' re-election
 * model to handle loss of the current keymaker.
 *
 * Candidate KeyMakers send a 'proposal' consisting of an election
 * epoch number plus their keyMaker priority and thumbprint. Proposals are
 * normal, signed, publications with a fixed lifetime and replay protection.
 * The thumbprint used to rank the proposal is taken from the publication's
 * key locator so proposals cannot be forged.
 *
 * The election runs for a fixed time interval starting with the first
 * publication of the current epoch.  Publications prior to the current
 * epoch are ignored.  Current epoch publications are ordered by km value
 * then thumbprint and the highest value announced wins the election.
 * The election winner increments the epoch and sends a 'finalize' publication
 * to end the election.
 * The epoch semantics also allow for keyMaker failure detection
 * and Paxos-like re-election proposals but this has not been implemented yet.
 *
 * All candidates send their initial proposal with an epoch of 0.  If they receive
 * a proposal with a later epoch, the election has been finalized and they
 * are not the keyMaker.  To support (future) re-election on keyMaker failure,
 * the current epoch is remembered in m_kmEpoch.
 */

#include "invocable.h"

namespace dct {

struct kmElection {
    using doneCB = ofats::any_invocable<void(bool,int32_t)>;
    using kmpriCB = ofats::any_invocable<int32_t(thumbPrint)>;
    using millis = std::chrono::milliseconds;
    using sys_micros = std::chrono::sys_time<std::chrono::microseconds>;

    const crName prefix_;   // prefix of election publications
    const certStore& certs_;
    SyncPS& sync_;          // collection used to communicate with peers
    doneCB done_;           // election done callback
    kmpriCB kmpri_;         // get key maker priority value from a signing chain
    uint32_t epoch_{};      // current election epoch
    int32_t priority_;      // this instance's win priority
    const thumbPrint& ourTP_;   // this instance's signing cert thumbprint
    const millis elecDur_;  // election duration
    const uint16_t preSz_;  // leading prefix size of all election pubs
    const uint16_t nmBlks_; // number of components in election pub names
    bool elecDone_{false};

    // build and publish a key maker ('km') publication
    void publishKM(const char* topic) {
        crData p(prefix_ / topic / epoch_ / std::chrono::system_clock::now());
        p.content(std::vector<uint8_t>{});
        sync_.signThenPublish(std::move(p));
    }

    // This is called when the local election timer times out. If this instance didn't win
    // (signaled by priority_ <= 0) nothing more is done. Otherwise, the winning instance
    // increments epoch_ then sends an 'elected' pub to tell other candidate KMs that it
    // has won. It then sends an empty group key list with its own tp to everyone which
    // will cause them to send member requests.
    void electionDone() {
        if (elecDone_) return;
        elecDone_ = true;
        if (priority_ > 0) {
            ++epoch_;
            publishKM("elec");
            dct::log(L_TRACE)("kmElection::electionDone: election {} done", epoch_);
        }
        done_(priority_ > 0, epoch_);
    }

    // check that msg from peer is in same epoch as us. Return value of 'true'
    // means msg should be ignored because of epoch mis-match.  If peers are
    // in later epoch, cancel current election & update our epoch.
    bool wrongEpoch(const auto epoch) {
        if (epoch == epoch_) return false;
        if (epoch > epoch_) {
            if (priority_ > 0) priority_ = -priority_;
            epoch_ = epoch;
        }
        return true;
    }

    // Update our contending/lost state based on a new peer "candidate" publication.
    // "priority_" is our election 'priority' (a positive integer; higher wins).
    // If peer has a larger priority or thumbprint we can't win the election which
    // we note by negating the value of priority_.
    void handleKMcand(const rData& p) {
        if (priority_ <= 0) return; // already know election is lost
        try { 
            const auto& tp = p.signer();
            int pri = kmpri_(tp);
            auto n = p.name();
            if (pri <= 0 || wrongEpoch(n.nextAt(preSz_).toNumber())) return;

            if (std::cmp_greater(priority_, pri)) return; // candidate loses
            if (std::cmp_greater(pri, priority_) || tp > ourTP_) priority_ = -priority_; // we lose
            dct::log(L_TRACE)("kmElection::handleKMcand {:02x} pri {} us {:02x} {}\n",
                     fmt::join(std::span(tp).first(4), ""), pri, fmt::join(std::span(ourTP_).first(4), ""), priority_);
        } catch (std::runtime_error& ex) { return; }
    }

    // handle an "I won the election" publication from some peer
    void handleKMelec(const rData& p) {
        auto n = p.name();
        if (n.nBlks() != nmBlks_) return; // bad name format
        auto epoch = n.nextAt(preSz_).toNumber();
        if (epoch_ >= epoch) return; // ignore msg from earlier election

        // if this app has been restarted (epoch_ = 0) and it was the keymaker
        // for the previous election (the app probably has a new signing key
        // so this is checked by looking at the thumbprint of the identity
        // key in the signing key) make it the new keymaker.
        const auto& tp = p.signer();
        if (kmpri_(tp) <= 0) return;
        if (epoch_ == 0 && certs_[tp].signer() == certs_[ourTP_].signer()) {
            epoch_ = epoch;
            if (priority_ < 0) priority_ = -priority_;
            electionDone();
            return;
        }
        if (priority_ > 0) priority_ = -priority_;
        epoch_ = epoch;
    }

    kmElection(crName&& pre, const certStore& cs, SyncPS& sy, doneCB&& done, kmpriCB&& kmv, const thumbPrint& tp,
                millis dur = 100ms)
        : prefix_{std::move(pre)}, certs_{cs}, sync_{sy}, done_{std::move(done)}, kmpri_{std::move(kmv)}, ourTP_{tp},
          elecDur_{dur}, preSz_{static_cast<uint16_t>((prefix_/"elec").size())},
          nmBlks_{static_cast<uint16_t>(prefix_.nBlks()+3)} {

        // subscriptions are done first since we may have received pubs from an in-progress
        // or finished election. 'subscribe' will upcall for each of those pubs so we can
        // avoid wasting time if we've already lost the election.
        priority_ = kmpri_(ourTP_);
        sync_.subscribe(prefix_/"elec", [this](const auto& p){ handleKMelec(p); });
        sync_.subscribe(prefix_/"cand", [this](auto p){ handleKMcand(p); });
        if (priority_ <= 0) { electionDone(); return; } // we lost the election
        publishKM("cand");
        sync_.oneTime(elecDur_, [this]{ electionDone(); });
    }
};

} // namespace dct

#endif // KM_ELECTION_HPP
