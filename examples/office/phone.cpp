/*
 * phone.cpp: phone app for the Office example used for ICN2021 tutorial
 *
 * This application uses mbps. Message body (if any) is packaged
 * in int8_t vectors to pass between application and mbps. Parameters
 * are passed to mpbs in an vector of pairs (msgParms) and passed from mbps
 * to the application in a mbpsMsg structure that contains an unordered_map
 * where values are indexed by the tags (components of Names) that are
 * defined in the trust schema for this particular application.
 *
 * phone models an app on a user phone
 * The identity bundle gives the app a role and the app can query through
 * mbps to get that role (employee, guard, manager) and predicate
 * actions on the role.
 * (Note that an app can try to publish messages that are not permitted by the
 * trust schema and it will not be permitted to create the publication)
 *
 * Copyright (C) 2021-2 Pollere LLC
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
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <getopt.h>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <random>

#include "../util/dct_example.hpp"

// command line start
static struct option opts[] = {
    {"debug", no_argument, nullptr, 'd'},
    {"wait", required_argument, nullptr, 'w'}
};

static void usage(const char* cname) { dct::print("- {} usage: id [-w ms] [loc] function args\n", cname); }

/* Globals */
static std::chrono::microseconds pubWait = std::chrono::seconds(5);

// instance attributes from signing chain
static std::string role{};
static std::string id{};
static std::string room{};

// command pub arguments from cmdline args
static std::string func{};
static std::string loc{};
static std::string args{};

/*
 * msgPubr passes messages to publish to the mbps.
 */
static void cmdPubr(mbps &cm) {
    // publish command to func at loc then wait a bit to collect replies
    cm.oneTime(pubWait, [](){ exit(0); });
    cm.publish(msgParms{ {"topic","command"s}, {"loc",  loc}, {"func", func}, {"args", args} });
}

/*
 * statusRecv handles a command received in a subscription (use as callback).
 * Does not use the message body (should be empty)
 */
static void statusRecv(mbps& cm, const mbpsMsg& msg, const std::span<const uint8_t>&)
{
    using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
    auto dt = ticks(cm.tdvcNow() - msg.time("_ts")).count() / 1000.;
    auto now = std::chrono::system_clock::now();
    const auto& f = msg["func"];
    const auto& a = msg["args"];
    const auto& l = msg["loc"];

    dct::print("{:%M:%S} {} {}: status of {} {} is {} ({:.3} mS transit)\n",
            ticks(now.time_since_epoch()), role, id, l, f, a, dt);
}

static int debug = 0;


int main(int argc, char* argv[])
{
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, ":dh:w:", opts, nullptr)) != -1;) {
        switch (c) {
                case 'w':
                    pubWait = std::chrono::milliseconds(std::stoi(optarg));
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    usage(argv[0]);
                    exit(0);
        }
    }
    auto n = argc - optind;
    if (n < 3 || n > 4) {
        usage(argv[0]);
        exit(1);
    }

    readBootstrap(argv[optind++]);
    // the DeftT shim needs callbacks to get the trust root, the trust schema, the identity
    // cert chain, and the current signing secret key plus public cert (see util/identity_access.hpp)
   //Create the mbps DeftT
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();}, []{return getSigningPair();});
    role = cm.attribute("_role");
    id = cm.attribute("_roleId");
    room = cm.attribute("_roomId");

    loc = n == 3? room : argv[optind++];
    func = argv[optind++];
    args = argv[optind++];

    // Connect and pass in the handler
    try {
        cm.connect([&cm]{
            // subscribe to status messages from all functions, any room
            for (const auto& f : std::array{"light"s, "door"s, "temp"s, "screen"s}) {
                cm.subscribe(f + "/status", statusRecv);
            }
            dct::print("{} {}'s phone sending to {}\n", role, id, loc);
            cmdPubr(cm);
        });
        cm.run();
    } catch (const std::exception& e) {
        std::cerr << "{} got exception: " << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps failed to connect with code " << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception";
        exit(1);
    }
}
