/*
 * app2.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using the mbps shim. Message body is packaged
 * in int8_t vectors are passed between application and mbps. Parameters
 * are passed to mpbs in an vector of pairs (msgParms) along with an optional
 * callback if message qos is desired (confirmation that the message has been published).
 * Parameters are passed from mbps to the application in a mbpsMsg structure that
 * contains an unordered_map where values are indexed by the tags (components of Names)
 * that are defined in the trust schema for this particular application.
 *
 * app2 models an asymmetric, request/response style protocol between controlling
 * agent(s) ("operator" role in the schema) and controlled agent(s) ("device" role
 * in the schema). If the identity bundle gives the app an 'operator' role, it
 * periodically publishes a message and prints all the responses it receives.
 * If the app is given a 'device' role, it waits for a message then sets its
 * simulated state based on the message an announces its current state.
 *
 * Copyright (C) 2020-22 Pollere LLC
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

static constexpr bool deliveryConfirmation = false; // get per-message delivery confirmation

// handles command line
static struct option opts[] = {
    {"addr", required_argument, nullptr, 'a'},
    {"capability", required_argument, nullptr, 'c'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
    {"location", required_argument, nullptr, 'l'},
    {"count", required_argument, nullptr, 'n'},
    {"quiet", no_argument, nullptr, 'q'},
    {"wait", required_argument, nullptr, 'w'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] id.bundle\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -a addr           transport addr, defaults to multicast\n"
           "  -c capability     defaults to 'lock'\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -l location       defaults to 'all'\n"
           "  -n |--count       number of messages to publish\n"
           "  -q |--quiet       don't print progress messages\n"
           "  -w |--wait        wait (in ms) between sends\n";
}

/* Globals */
static std::string myPID, myId, role;
static std::chrono::microseconds pubWait = std::chrono::seconds(4);
static decltype(std::chrono::system_clock::now().time_since_epoch()) lastSend;
static int Cnt = 0;
static int nMsgs = 10;
static int nRcv = 0;
static bool quiet = false;
static std::string addr{};
static std::string capability{"lock"};
static std::string location{"all"}; // target's location (for operators)
static std::string myState{"unlocked"};       // simulated state (for devices)

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
static constexpr auto tp2d = [](auto t){ return std::chrono::duration_cast<ticks>(t.time_since_epoch()); };

/*
 * msgPubr passes messages to publish to the mbps. A simple lambda
 * is used if "qos" is desired. A more complex callback (messageConfirmation)
 * is included in the app1.cpp file.
 */
static void msgPubr(mbps &cm) {
    // make a message to publish
    std::string s = format("Msg #{} from {}:{}-{}", ++Cnt, role, myId, myPID);
    std::vector<uint8_t> toSend(s.begin(), s.end());
    msgParms mp;

    if(role == "operator") {
        lastSend = std::chrono::system_clock::now().time_since_epoch();
        std::string a = (std::rand() & 2)? "unlock" : "lock"; // randomly toggle requested state
        mp = msgParms{{"target", capability},{"topic", "command"s},{"trgtLoc",location},{"topicArgs", a}};
    } else {
        mp = msgParms{{"target", capability},{"topic", "event"s},{"trgtLoc",myId},{"topicArgs", myState}};
    }
    if constexpr (deliveryConfirmation) {
        cm.publish(std::move(mp), toSend, [ts=std::chrono::system_clock::now()](bool delivered, uint32_t) {
                    if (! quiet) {
                        auto now = std::chrono::system_clock::now();
                        auto dt = ticks(now - ts).count() / 1000.;
                        dct::print("{:%M:%S} {}:{}-{} #{} published and {} after {:.3} mS\n",
                                tp2d(now), role, myId, myPID, Cnt - 1, delivered? "confirmed":"timed out", dt);
                    } });
    } else {
//         auto now = std::chrono::system_clock::now();
//        dct::print("{:%M:%S} {}:{}-{} #{} publishing to shim\n", tp2d(now), role, myId, myPID, Cnt - 1);
        cm.publish(std::move(mp), toSend);  //no callback to skip message confirmation
    }

    if (Cnt >= nMsgs && nMsgs) {
        cm.oneTime(2*pubWait, [](){
                dct::print("{}:{}-{} published {} messages, received {} and exits\n", role, myId, myPID, Cnt, nRcv);
                    exit(0);
                });
        return;
    }

    // operators send periodic messages, devices respond to incoming msgs
    if (role == "operator") {
        cm.oneTime(pubWait + std::chrono::milliseconds(rand() & 0x1ff), [&cm](){ msgPubr(cm); });
    }
}

/*
 * msgRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 * The message is opaque to mbps which uses
 * a msgMsg to pass tag data (tags from trust schema)
 *
 * Prints the message content
 * Could take action(s) based on message content
 */

void msgRecv(mbps &cm, const mbpsMsg& mt, std::vector<uint8_t>& msgPayload)
{
    auto now = tp2d(std::chrono::system_clock::now());
    auto dt = (now - tp2d(mt.time("mts"))).count() / 1000.;
    nRcv++;

    // actions can be conditional upon msgArgs and msgPayload

    if (role == "device") {
        // devices set their 'state' from the incoming 'arg' value then immediately reply
        if (! quiet) dct::print("{:%M:%S} {}:{}-{} rcvd ({:.3} mS transit): {} {}: {} {} | {}\n",
                now, role, myId, myPID, dt, mt["target"], mt["topic"], mt["trgtLoc"], mt["topicArgs"],
                std::string(msgPayload.begin(), msgPayload.end()));
        myState = mt["topicArgs"] == "lock"? "locked":"unlocked";
        msgPubr(cm);
    } else if (!quiet) {
        auto rtt = (now - std::chrono::duration_cast<ticks>(lastSend)).count() / 1000.;
        dct::print("{:%M:%S} {}:{}-{} rcvd ({:.3}ms transit, {:.3}ms rtt): {} {}: {} {} | {}\n",
                now, role, myId, myPID, dt, rtt, mt["target"], mt["topic"], mt["trgtLoc"], mt["topicArgs"],
                std::string(msgPayload.begin(), msgPayload.end()));
    }
}

/*
 * Main() for the application to use.
 * First complete set up: parse input line, set up message to publish,
 * set up entity identifier. Then make the mbps DeftT, connect, and run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    std::srand(std::time(0));
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, ":a:c:dhl:n:qw:", opts, nullptr)) != -1;) {
        switch (c) {
                case 'a':
                    addr = optarg;
                    break;
                case 'c':
                    capability = optarg;
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
                case 'l':
                    location = optarg;
                    break;
                case 'n':
                    nMsgs = std::stoi(optarg);    //number of times to publish
                    break;
                case 'q':
                    quiet = true;;
                    break;
                case 'w':
                    pubWait = std::chrono::milliseconds(std::stoi(optarg));
                    break;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        exit(1);
    }

    /*
     *  These are useful in developing DeftT-based applications and/or
     *  learning about Defined-trust Communications and DeftT.  The rootCert,
     *  schemaCert, identityChain and currentSigningPair callbacks are how
     *  DeftT's internals request the four kinds of information needed to
     *  bootstrap an app. In a real deployment these would be handled in
     *  a Trusted Execution Environment. For expository purposes,
     *  identity_access.hpp contains simple, unsecure, examples of these
     *  callbacks implemented by routine readBootstrap which reads an identity
     *  bundle file (whose name must be the final command line arg passed to the
     *  app), splits it into the pieces needed by the callbacks, and supplies a
     *  routine to locally generate the app identity cert and signing key.
     */
    myPID = std::to_string(getpid());   // useful for identifying trust domain members in dctwatch,
                                        // of doubtful usage in a deployment
    readBootstrap(argv[optind]);

    // the DeftT shim needs callbacks to get the trust root, the trust schema, the identity
    // cert chain, and the current signing secret key plus public cert (see util/identity_access.hpp)
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();}, []{return getSigningPair();}, addr);

    // this example application needs information about some of its identity attributes which can now be returned by
    // DeftT modules through the shim but this may not be needed in a deployed application
    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");

    // Connect and pass in the handler
    try {
        /* main task for this entity */
         cm.connect([&cm]{
            auto now = std::chrono::system_clock::now();
            print("{:%M:%S} {}:{}:{} is connected\n", ticks(now.time_since_epoch()), role, myId, myPID);
            if (role == "operator") {
                cm.subscribe(msgRecv);  // single callback for all messages
                msgPubr(cm);
            } else {    // devices just subscribe to command topic
                cm.subscribe(capability + "/command/" + myId, msgRecv); // msgs to this instance
                cm.subscribe(capability + "/command/all", msgRecv);     // msgs to all instances
            }
        });
    } catch (const std::exception& e) {
        std::cerr << "main encountered exception while trying to connect: " << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps failed to connect with code " << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception";
        exit(1);
    }
    cm.run();
}
