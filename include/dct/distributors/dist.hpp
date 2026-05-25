#ifndef DIST_HPP
#define DIST_HPP
#pragma once
/*
 * Distributor abstraction
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
 *  dist.hpp is not intended as production code.
 */
/*
 * Base class for distributors.
 * Not useful in itself but contains methods and variables commonly used in distributors
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

struct Dist {
    using connectedCb = std::function<void(bool)>;
    using logEvCb = std::function<void(crName&&, std::span<const uint8_t>)>;

    const crName prefix_;        // prefix for pubs in this distributor's collection
    SigMgrAny pduSM_;   // to sign/validate PDUs
    SigMgrAny pubSM_;   // to sign/validate Publications
    SyncPS sync_;
    const certStore& cs_;
    connectedCb connCb_{[](auto) {}};
    thumbPrint tp_{};
    logEvCb logsCb_{[](crName&&, std::span<const uint8_t>){}};  // default logs callback
    ssize_t maxContent_;
    ssize_t maxName_;
    std::string dtype_{}; // should be set to an identifying string used in each distributor's collection name

    dct::rand rand_{};
    bool init_{true};                  // true until done initializing - some status unknown while in initialization
    Cap::capChk relayChk_;   // method to return true if the identity chain has the relay (RLY) capability

    Dist(std::string_view typ, DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs, std::string_view d="EdDSA", std::string_view p="EdDSA") :
             prefix_{pPre},    // identifier being used on all pubs in domain - could be empty
             pduSM_{sigMgrByType(d)},
             pubSM_{sigMgrByType(p)},
             sync_(face, dPre, pduSM_.ref(), pubSM_.ref()),
             cs_{cs},
             dtype_{typ},
             relayChk_{Cap::checker("RLY", pPre, cs)}
     {
          sync_.autoStart(false); // delay start until predecessor distributors done initializing (cert sets true)
         // get our identity thumbprint,  set up our public and private signing keys.
          if (cs_.Chains().size()==0)  throw runtime_error("dist::constructor finds empty identity chain\n");
          auto tp = cs_.Chains()[0];
          Dist::updateSigningKey(cs_.key(tp), cs_[tp]); // won't call the class override
          maxContent_ = sync_.maxInfoSize();
          maxName_ = maxContent_/2;  //arbitrary
         // if the syncps set its cStateLifetime longer, means we are on a low rate network
          if (sync_.cStateLifetime_ < 6763ms) sync_.cStateLifetime(6763ms);
          // compute space for content: use worst case, the Publication with longest name
          maxContent_ -= maxName_;
          // syncps's getLifetimeCb() returns this value by default:
          sync_.pubLifetime(100ms);  // needs to be reset for derived distributor if not its default
          // derived distributors should call their own setup method in their constructors
    }

    auto type() { return dtype_; }
    auto isRelay(const thumbPrint& tp) { return relayChk_(tp).first; }    // identity 'tp' has RLY capability?

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and update my SigMgrs. Uses new key immediately to sign
     * Specific distributors may do need to do more steps in their version
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        if (cs_.Chains().size()==0)  throw runtime_error("dist::updateSigningKey finds empty identity chain:" + dtype_);
        tp_ = cs_.Chains()[0];     // set to the thumbPrint of the new first signing chain
        if (tp_ != pubCert.computeTP())
            throw runtime_error("dist:updateSigningKey gets new key not at chains[0]");

        // sigmgrs need to get the new signing keys and public key lookup callbacks
        pduSM_.updateSigningKey(sk, pubCert);
        pduSM_.setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });
        pubSM_.updateSigningKey(sk, pubCert);
        pubSM_.setKeyCb([&cs=cs_](rData d) -> keyRef { return cs.signingKey(d); });
    }

    void initDone() {
        if (init_) {
            init_ = false;
            connCb_(true);
        }
    }

    /*
     * start() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peer members. When there are multiple distributors
     * in use, they are chained so that start isn't called until all the distributors
     * that need to start previously have finished necessary work (certs are always first).
     * Usually calls its syncps's start() and sets up subscriptions in order to start participating in collection.
     *
     * Specific distributor may have other set up tasks, including initiating
     * more processes before calling initDone() from some other method
     */
    void start(connectedCb&& ccb) {
        connCb_ = std::move(ccb);
        if (!sync_.autoStart_) sync_.start();     // all distributors "before" me have initialized
    }

    // publish the passed in log information: name <prefix_><logMsg><timestamp>
    // the first component of logMsg should be  identify the type of log, e.g. could be "tdvc" for a log message from dist_tdvc

    // If there is a log distributor, it publishes to logs collection; use dctwatch and postprocess
    // This default just uses the distributor type and the passed in event description string and content
    // as well as pulling fields from certs. Specific distributors may use different names so should override
    void logEvent(std::string s, std::span<const uint8_t> content = {}) {
        if (!logsCb_) return;   // no log distributor callback set, ignore
        // XXX role and role-id only works for examples - consider using more of cert name (or tp) to be more general
       logsCb_( crName(dtype_) / s, content); // more general
       // logsCb_( crName(dtype_) / s / cs_[tp_].name()[1] / cs_[tp_].name()[2], content);
    }
};

} // namespace dct

#endif //DIST_HPP
