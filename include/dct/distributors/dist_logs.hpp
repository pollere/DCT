#ifndef DIST_LOGS_HPP
#define DIST_LOGS_HPP
#pragma once
/*
 * dist_logs - make a publication from passed in event information and publish in "logs" collection
 * This version is a self-contained 'header-only' library.
 *
 *
 * This distributor uses a passed in value subt as a subtopic <pubprefix><subt>
 * where <pubprefix> is passed in at creation as the topic for all its publications
 * and may be empty, the TD ID, a string that identifies a TD or application.
 * The PDU prefix the distributor's sync uses is <td_id>/logs/ in the "logs" collection
 * Loggers don't normally subscribe to the collection: log messages can be post-processed from
 * a dctwatch output or a member can subscribe and process, plot, check for alarms/alerts, etc
 *
 * This distributor is publish-only. Expects that a collector will be built on top of dctwatch
 * or as an entity within the TD
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
 *  dist_logs is not intended as production code.
 */

#include "dist.hpp"

using namespace std::literals::chrono_literals;

namespace dct {

struct DistLogs : Dist {

    // setting logLifetime small can remove resends if just post-processing dctwatch. Needs to be longer for a subscriber
    DistLogs(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs) :
        Dist(face, pPre, dPre, cs)  { sync_.pubLifetime(tdv_clock::duration(300ms)); dtype_.assign("logs"); }

    /*
     * can add subscribe calls to setup for testing or for members that process logs
    */
    void setup(connectedCb&& ccb) override final {
        connCb_ = std::move(ccb);
        if (!sync_.autoStart_) sync_.start();     // all distributors "before" me have initialized
        // sync_.subscribe(prefix_, [](const auto& p){ dct::print("dist_logs got {}\n", p.name()); }); // testing
        initDone();
    }

    // publish the passed in log information: name <prefix_><logMsg><timestamp>
    // the first component of logMsg should be  identify the type of log, e.g. could be "tdvc" for a log message from dist_tdvc
    // XXX batch until a PDU is full or timer goes off ?
    void publishLog(crName&& logNm, std::span<const uint8_t> c) {
        crData p(prefix_/std::move(logNm)/sync_.tdvcNow());
        p.content(c);
        try {
            if (sync_.signThenPublish(std::move(p)) == 0)
                dct::print("dist_logs::publishLog failed to publish {}\n", p.name());
        } catch (const std::exception& e) {
            std::cerr << "dist_logs::publishLog: " << e.what() << std::endl;
        }
    }

    // caller subscribes to the logs publications that match topic
    auto& subscribeLogs(std::string_view topic, SubCb&& cb) {
        return sync_.subscribe(crPrefix{appendToName(prefix_, topic)}, std::move(cb) );
    }

     // caller subscribes to all logs publications
    auto& subscribeLogs(SubCb&& cb) {
        return sync_.subscribe(prefix_, std::move(cb) );
    }

    //caller unsubscribes to topic
    auto& unsubscribeLogs(std::string_view topic) {
        sync_.unsubscribe( crPrefix{appendToName(prefix_, topic)} );
        return *this;
    }

};

} // namespace dct

#endif //DIST_LOGS_HPP
