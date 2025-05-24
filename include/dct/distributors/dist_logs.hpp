#ifndef DIST_LOGS_HPP
#define DIST_LOGS_HPP
#pragma once
/*
 * dist_logs - make a publication from passed in event information and publish in logs collection
 * This version is a self-contained 'header-only' library.
 *
 *
 * This distributor uses a passed in value subt as a subtopic <pubprefix><subt>
 * where <pubprefix> is passed in at creation as the topic for all its publications
 * The PDU prefix the distributor's sync uses is <td_id>/logs/ in the "logs" collection
 * Loggers don't subscribe to the collection: log messages can be post-processed from
 * a dctwatch output or a member can subscribe and process, plot, check for alarms/alerts, etc
 *
 * This distributor is publish-only. Expects that a collector will be built on top of dctwatch
 * or as an entity within the TD
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
 *  dist_logs is not intended as production code.
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

using namespace std::literals::chrono_literals;

namespace dct {

struct DistLogs {
    using connectedCb = std::function<void(bool)>;

    /*
     * DistLogs Publications contain
     */

    const crName m_prefix;        // prefix for pubs in this distributor's collection
    SigMgrAny m_keySM{sigMgrByType("EdDSA")};   // to sign/validate Publications and PDUs
    SyncPS m_sync;
    size_t m_maxContent = m_sync.maxInfoSize();
    size_t m_maxName = m_maxContent/2;  //arbitrary
    const certStore& m_certs;
    connectedCb m_connCb{[](auto) {}};
    thumbPrint m_tp{};
    tdv_clock::duration m_logLifetime;

    std::uniform_int_distribution<unsigned short> randInt_{2u, 9u};
    bool m_init{true};                  // key maker status unknown while in initialization
    Cap::capChk m_relayChk;   // method to return true if the identity chain has the relay (RLY) capability

    DistLogs(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs, tdv_clock::duration logLifetime= 4s) :
             m_prefix{pPre},    // identifier being used on all pubs in domain - could be empty
             m_sync(face, dPre, m_keySM.ref(), m_keySM.ref()),
             m_certs{cs},
             m_logLifetime(logLifetime)
        {
       m_sync.autoStart(false); // shouldn't start until cert distributor is done initializing
       // if the syncps set its cStateLifetime longer, means we are on a low rate network
       if (m_sync.cStateLifetime_ < 6763ms) m_sync.cStateLifetime(6763ms);
       m_sync.pubLifetime(tdv_clock::duration(logLifetime));
       m_sync.getLifetimeCb([this](const auto&) ->tdv_clock::duration { return m_logLifetime; });

       // compute space for content for the log Publication.
        m_maxContent -= m_maxName;
        if (m_maxContent <= 0) throw ("DistLogs: no  space in Pub to carry content");

        // get our identity thumbprint,  set up our public and private signing keys.
        if (m_certs.Chains().size()==0)  throw runtime_error("dist_gkey::constructor finds empty identity chain\n");
        m_tp = m_certs.Chains()[0];
        updateSigningKey(m_certs.key(m_tp), m_certs[m_tp]);
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.  
     *      use new key immediately to sign - update the my signature managers
     *      if member, send a new membership request
     *     keymaker needs to assert its role under new cert
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        if (m_certs.Chains().size()==0)  throw runtime_error("dist_logs::updateSigningKey finds empty identity chain\n");
        m_tp = m_certs.Chains()[0];     // set to the thumbPrint of the new first signing chain
        if (m_tp != pubCert.computeTP())
            throw runtime_error("dist_logs:updateSigningKey gets new key not at chains[0]");

        // sigmgr needs to get the new signing keys and public key lookup callbacks
        m_keySM.updateSigningKey(sk, pubCert);
        m_keySM.setKeyCb([&cs=m_certs](rData d) -> keyRef { return cs.signingKey(d); });
    }

    void initDone() {
        if (m_init) {
            m_init = false;
            m_connCb(true);
        }
    }

    /*
     * setup() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers.
     * Calls its syncps's start() before returning to start participating in collection
     */
    void setup(connectedCb&& ccb) {
        m_connCb = std::move(ccb);
        m_sync.start();     // all distributors "before" me have initialized
        //   m_sync.subscribe(m_prefix, [](const auto& p){ dct::print("dist_logs got {}\n", p.name()); }); // testing
         initDone();
    }

    // publish the passed in log information: name <m_prefix><logMsg><timestamp>
    // the first component of logMsg should be  identify the type of log, e.g. could be "tdvc" for a log message from dist_tdvc
    // XXX batch until a PDU is full or timer goes off
    void publishLog(crName&& logNm, std::span<const uint8_t> c) {
        crData p(m_prefix/std::move(logNm)/m_sync.tdvcNow());
        p.content(c);
        try {
            if (m_sync.signThenPublish(std::move(p)) == 0)
                dct::print("dist_logs::publishLog failed to publish {}\n", p.name());
        } catch (const std::exception& e) {
            std::cerr << "dist_logs::publishLog: " << e.what() << std::endl;
        }
    }

};

} // namespace dct

#endif //DIST_LOGS_HPP
