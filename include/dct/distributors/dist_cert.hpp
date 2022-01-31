#ifndef DIST_CERT_HPP
#define DIST_CERT_HPP
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
 *  keydist_cert.hpp is not intended as production code.
 */

#include <functional>
#include <unordered_set>

#include "dct/schema/dct_cert.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"
#include "dct/syncps/syncps.hpp"

using certPub = dctCert;
using addCertCb = std::function<void(const certPub&)>;
using connectedCb = std::function<void(bool)>;

/*
 * Key distributor for certs.
 * Parent certstore sets the wirePrefix used for its SyncPubSub (would start with domain and
 * probably include "cert") and sets the pubprefix used for subscription in start().
 * Also passes in a call back for each new received signing cert.
 *
 * DistCert's m_sync uses the RFC7693 signature manager for packets.
 * Its pubs use a SigMgrNull since the Certificates are fully signed Publications
 * and signature validation happens in the parent certstore.
 */

struct DistCert
{    
    ndn::Name m_pubPrefix;  //prefix for subscribeTo()
    SigMgrAny m_syncSigMgr{sigMgrByType("RFC7693")}; // to sign/validate SyncData packets
    SigMgrAny m_certSigMgr{sigMgrByType("NULL")};   // to sign/validate Publications
    syncps::SyncPubsub m_sync;
    addCertCb m_addCertCb{[](auto ){}}; // called when cert rcvd from peer
    connectedCb m_connCb{[](bool){}};   // called when initial cert exchange done
    bool m_havePeer{false};
    bool m_initDone{false};
    std::unordered_set<size_t> m_initialPubs{};
    log4cxx::LoggerPtr staticModuleLogger{log4cxx::Logger::getLogger("certDist")};

    DistCert(const std::string& pPre, const ndn::Name& wPre, addCertCb&& addCb, syncps::IsExpiredCb&& eCb) :
        m_pubPrefix{pPre},
        m_sync(wPre, m_syncSigMgr.ref(), m_certSigMgr.ref()),
        m_addCertCb{std::move(addCb)}
    {
        m_sync.syncInterestLifetime(std::chrono::milliseconds(4789));
        m_sync.syncDataLifetime(std::chrono::milliseconds(877));       // (data caching not useful)
        m_sync.pubLifetime(std::chrono::milliseconds(0)); // pubs don't auto expire
        m_sync.isExpiredCb(std::move(eCb));
        m_sync.filterPubsCb([](auto& pOurs, auto& pOthers) mutable {
                    // certs are small so send everything that will fit in a packet
                    pOurs.insert(pOurs.end(), pOthers.begin(), pOthers.end());
                    return pOurs;
                });
        m_sync.subscribeTo(m_pubPrefix, [this](auto p) {onReceiveCert(reinterpret_cast<const dctCert&>(p));});
    }

    /*
     * The dct model calls when it is started.
     * Passed a callback to use when the publication of the signing chain is confirmed.
     * This approach just keeps trying to publish all the keys in m_skv but the application
     * can set a timeout to exit if m_confCb isn't called after a suitable delay
     */
    void setup(connectedCb&& connCb) { m_connCb = std::move(connCb); }

    /*
     * Called when a new Publication is received in signingKey Collection.
     * At this point the packet containing the Cert has been validated by
     * m_syncSigMgr but the cert has not been validated.
     */
    void onReceiveCert(const certPub& p)
    {
        _LOG_INFO("onReceiveCert " << p.getName().toUri());
        m_addCertCb(p); //callback - expected to handle validation
    }

    /*
     * Called when an initial cert exchange has completed (some peer(s) have our cert
     * chain and we have theirs).
     */
    void initDone() {
        _LOG_INFO("initDone");
        m_initDone = true;
        m_connCb(true);
    }

    /*
     * Certstore has validated and accepted a peer's cert.
     */
    void publishCert(const certPub& c) {
        if (! m_initDone) {
            m_havePeer = true;
            if (m_initialPubs.empty()) initDone();
        }
        //will ensure publication for relayed (or new local) certs
        m_sync.publish(dctCert(c));
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
     * pubs are done without confirmation, interest timeout is much less
     * aggressive, and the 'connect' callback is called to move to the next
     * phase of operation.
     */
    void initialPub(certPub&& c) {
        _LOG_INFO("initialPub " << c.getName());
        if (! m_initDone) {
            m_initialPubs.emplace(std::hash<ndn::Data>{}(c));
            m_sync.publish(std::move(c),
                    [this](const ndn::Data& d, bool acked) {
                        // since cert pub lifetime is infinite 'acked' should always be true
                        // when this routine is called. If all the initial pubs have been acked
                        // and we have at least one peer's signing chain, initialization is done.
                        _LOG_INFO("wasDelivered: " << acked << " " << d.getName());
                        m_initialPubs.erase(std::hash<ndn::Data>{}(d));
                        if (m_havePeer && m_initialPubs.empty()) initDone();
                    });
            return;
        }
        m_sync.publish(std::move(c));
    }
};

#endif //DIST_CERT_HPP
