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
 *  keydist_cert.hpp is not intended as production code.
 */

#include <functional>
#include <unordered_set>

#include "dct/schema/dct_cert.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"
#include "dct/syncps/syncps.hpp"

namespace dct {

using addCertCb = std::function<void(const rData)>;
using connectedCb = std::function<void(bool)>;

/*
 * Key distributor for certs.
 * Parent certstore sets the pduPrefix used for its SyncPubSub (would   with domain and
 * probably include "cert") and sets the pubprefix used for subscription in start().
 * Also passes in a call back for each new received signing cert.
 *
 * DistCert's m_sync uses the RFC7693 signature manager for cAdds.
 * Its pubs use a SigMgrNull since the Certificates are fully signed Publications
 * and signature validation happens in the parent certstore.
 */

struct DistCert
{    
    crName m_pubPrefix;  //prefix for subscribe()
    SigMgrAny m_syncSigMgr{sigMgrByType("RFC7693")}; // to sign/validate SyncData packets
    SigMgrAny m_certSigMgr{sigMgrByType("NULL")};   // to sign/validate Publications
    SyncPS m_sync;
    connectedCb m_connCb{[](bool){}};   // called when initial cert exchange done
    std::unordered_set<size_t> m_initialPubs{};
    bool m_havePeer{false};
    bool m_initDone{false};

    DistCert(DirectFace& face, const Name& pPre, const Name& wPre, addCertCb&& addCb, IsExpiredCb&& eCb) :
        m_pubPrefix{pPre},
        m_sync(face, wPre, m_syncSigMgr.ref(), m_certSigMgr.ref())
    {
        m_sync.cStateLifetime(4789ms);
        m_sync.getLifetimeCb([](auto p) {
                auto lt = rCert(p).validUntil() - std::chrono::system_clock::now();
                return std::chrono::duration_cast<std::chrono::milliseconds>(lt);
            });
        m_sync.isExpiredCb(std::move(eCb));
        m_sync.subscribe(m_pubPrefix, std::move(addCb));
    }

    /*
     * The dct model calls when it is started.
     * Passed a callback to use when the publication of the signing chain is confirmed.
     * This approach just keeps trying to publish all the keys in m_skv but the application
     * can set a timeout to exit if m_connCb isn't called after a suitable delay
     */
    void setup(connectedCb&& connCb) { m_connCb = std::move(connCb); }

    /*
     * Called when an initial cert exchange has completed (some peer(s) have our cert
     * chain and we have theirs).
     */
    void initDone() {
        m_sync.pubLifetime_ = 2s;
        m_initDone = true;
        m_connCb(true);
    }

    /*
     * Certstore has validated and accepted a peer's cert.
     */
    void publishCert(const rData c) {
        m_havePeer = true;
        m_sync.publish(c);
        if (! m_initDone && m_initialPubs.empty()) initDone();
    }

    // adding for ptps - relayed certs only so don't set m_havePeer
    void publishRlyCert(const rData c) {
        m_sync.publish(c);
    }
    // confirm publication of this cert - used after bootstrap so doesn't set havePeer
    void publishConfCert(const rData c, DelivCb cb) {
        m_sync.publish(c, std::move(cb));
    }

    /*
     * publish bootstrap / local identity certs to the collection
     * 
     * The bootstrap (app identity) cert chain is published via calls to this
     * routine. These are the only certs this app publishes to the collection.
     *
     * Bootstrap publications are done with a confirmation callback and, when
     * all of them have been confirmed as received by peer(s), the outbound
     * half of initialization is done (indicated by 'm_initialPubs.empty()').
     * The inbound half of initialization finishes when the certstore has
     * received and validated the entire signing chain of at least one peer
     * (indicated by 'm_havePeer = true'). When both halves are done, future
     * pubs are done without confirmation, cState timeout is much less
     * aggressive, and the 'connect' callback is called to move to the next
     * phase of operation.
     */
    void initialPub(const rData c) {
        if (! m_initDone) {
            auto h = std::hash<tlvParser>{}(c);
            m_initialPubs.emplace(h);
            m_sync.pubLifetime_ = m_sync.getLifetime_(c);
            m_sync.publish(c, [this, h](const auto& /*d*/, bool /*acked*/) {
                        // when all the initial pubs have been acked and we have
                        // at least one peer's signing chain, initialization is done.
                        m_initialPubs.erase(h);
                        if (m_havePeer && m_initialPubs.empty())
                            initDone();
                    });
            return;
        }
        m_sync.publish(c);
    }
};

} // namespace dct

#endif //DIST_CERT_HPP
