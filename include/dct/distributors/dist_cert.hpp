#ifndef DIST_CERT_HPP
#define DIST_CERT_HPP
#pragma once
/*
 * sync a collection of certs among peers
 *
 * This  module distributes certs for a particular Collection
 * that derives from the application domain and appends "/certs".
 * It subscribes to the Collection at initialization and publishes
 * its signing chain as dctCert Publications.  On receiving a new
 * Publication, callback to addCertCb.
 *
 * Copyright (C) 2020-6 Pollere LLC
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
 *  dist_cert.hpp is not intended as production code.
 */

#include <unordered_set>
#include "dct/schema/dct_cert.hpp"
#include "dist.hpp"

namespace dct {

/*
 * Key distributor for certs.
 * Parent sets the pduPrefix used for its sync
 * and sets the pubprefix used for subscription in start().
 * Also passes in a call back for each new received signing cert.
 *
 * DistCert's sync_ uses the RFC7693 signature manager for cAdd PDUs.
 * Its pubs use a SigMgrNull since the Certificates are fully signed Publications
 * and signature validation happens in the parent certstore and cert exchange
 * happens in bootstrapping. This is unique among distributors
 */

 using addCertCb = std::function<void(const rData)>;

struct DistCert : Dist
{
    std::unordered_set<size_t> initialPubs_{};
    bool havePeer_{false};

    DistCert(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs, addCertCb&& addCb) :
        Dist(face, pPre, dPre, cs, "RFC7693", "NULL")
    {
        dtype_.assign("cert");
        sync_.autoStart(true);  // override base class default
        sync_.cStateLifetime(4789ms);
        sync_.getCreationCb([this](const auto& p) { return sync_.tdvcFromSys(rCert(p).validAfter()); });
        sync_.getLifetimeCb([](const auto& p) {
                auto c = rCert(p);
                return std::chrono::duration_cast<tdv_clock::duration>(c.validUntil() - c.validAfter());
            });
        // Unlike most pubs, certs can go into the collection before they're valid since the validity period is
        // checked when they're used but they expire at the end of their validity period. 
        sync_.isExpiredCb([](const auto& p) { return rCert(p).expired(); });
        sync_.subscribe(prefix_, std::move(addCb));
    }

    /*
     * The dct model calls when it is started.
     * Passed a callback to use when the publication of the signing chain is confirmed.
     * This approach just keeps trying to publish the certs but the application
     * can set a timeout to exit if connCb_ isn't called after a suitable delay
     * connCb is called when initial cert exchange done
     */
    void setup(connectedCb&& connCb) override final {
        connCb_ = std::move(connCb);
     }

    /*
     * Called when an initial cert exchange has completed (some peer(s) have our cert
     * chain and we have theirs).
     */
    void initDone() override final {
        if (init_) {
            init_ = false;
            connCb_(true);
            sync_.pubLifetime_ = 2s;
        }
    }

    /*
     * Certstore has validated and accepted a peer's cert.
     */
    void publishCert(const rData c) {
        havePeer_ = true;
        sync_.publish(c);
        if (init_ && initialPubs_.empty()) initDone();
    }

    // adding for ptps - relayed certs only so don't set havePeer_
    void publishRlyCert(const rData c) {
        sync_.publish(c);
    }
    // confirm publication of this cert - used after bootstrap so doesn't set havePeer
    void publishConfCert(const rData c, DelivCb cb) {
        sync_.publish(c, std::move(cb));
    }

    /*
     * publish bootstrap / local identity certs to the collection
     * 
     * The bootstrap (app identity) cert chain is published via calls to this
     * routine. These are the only certs this app publishes to the collection.
     *
     * Bootstrap publications are done with a confirmation callback and, when
     * all of them have been confirmed as received by peer(s), the outbound
     * half of initialization is done (indicated by 'initialPubs_.empty()').
     * The inbound half of initialization finishes when the certstore has
     * received and validated the entire signing chain of at least one peer
     * (indicated by 'havePeer_ = true'). When both halves are done, future
     * pubs are done without confirmation, cState timeout is much less
     * aggressive, and the 'connect' callback is called to move to the next
     * phase of operation.
     */
    void initialPub(const rData c) {
        if (init_) {
            auto h = std::hash<tlvParser>{}(c);
            initialPubs_.emplace(h);
            sync_.pubLifetime_ = sync_.getLifetime_(c);
            sync_.publish(c, [this, h](const auto& /*d*/, bool /*acked*/) {
                        // when all the initial pubs have been acked and we have
                        // at least one peer's signing chain, initialization is done.
                        initialPubs_.erase(h);
                        if (havePeer_ && initialPubs_.empty())
                            initDone();
                    });
            return;
        }
        sync_.publish(c);
    }
};

} // namespace dct

#endif //DIST_CERT_HPP
