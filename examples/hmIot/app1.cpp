/*
 * app1.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using the mbps shim. Messages packaged
 * in int8_t vectors are passed between application and DeftT via mbps.
 * To publish a message, an optional list of arguments can also be
 * included along with an optional callback if message qos is
 * desired (here, confirmation that the message has been published).
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
 *  This DeftT proof-of-concept example is not intended as production code.
 *  More information on DeftT and DCT is available from info@pollere.net
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
    {"count", required_argument, nullptr, 'n'},
    {"capability", required_argument, nullptr, 'c'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
    {"location", required_argument, nullptr, 'l'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] id.bundle\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -n |--count       number of messages to publish\n"
           "  -c capability     defaults to 'lock'\n"
           "  -p |--persist     keep running after publish messages\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "-l location       defaults to 'all'\n";
}

/* Globals */
static std::string myPID, myId, role;
static std::chrono::microseconds pubWait = std::chrono::seconds(1);
static int Cnt = 0;
static int Done = 10;
static bool Persist = false;
static std::string capability{"lock"};
static std::string location{"all"};

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
static constexpr auto tp2d = [](auto t){ return std::chrono::duration_cast<ticks>(t.time_since_epoch()); };

/*
 * msgPubr passes messages to publish to mbps. A simple lambda
 * is used if "qos" is desired. A more complex callback (messageConfirmation)
 * is included in this file.
 */
static void msgPubr(mbps &cm) {
    // make a message to publish
    std::string s = dct::format("Msg #{} from {}:{}-{}", ++Cnt, role, myId, myPID);
    std::vector<uint8_t> toSend(s.begin(), s.end());
    msgParms mp;

    if(role == "operator") {
        mp = msgParms{{"target", capability},{"topic", "command"s},{"trgtLoc","all"s},{"topicArgs", "unlock"s}};
    } else {
        mp = msgParms{{"target", capability},{"topic", "event"s},{"trgtLoc",myId},{"topicArgs", "unlocked"s}};
    }
    if constexpr (deliveryConfirmation) {
        cm.publish(std::move(mp), toSend, [ts=std::chrono::system_clock::now()](bool delivered, uint32_t) {
                    auto now = std::chrono::system_clock::now();
                    auto dt = ticks(now - ts).count() / 1000.;
                    dct::print("{:%M:%S} {}:{}-{} #{} published and {} after {:.3} mS\n",
                            tp2d(now), role, myId, myPID, Cnt - 1, delivered? "confirmed":"timed out", dt);
                    });
    } else {
        cm.publish(std::move(mp), toSend);  //no callback to skip message confirmation
    }

     if(Cnt < Done) {  // wait then publish another message
        cm.oneTime(pubWait, [&cm](){ msgPubr(cm); });
    } else {
        if(!Persist) {
            cm.oneTime(2*pubWait, [](){
                    dct::print("{}:{}-{} published {} messages and exits\n", role, myId, myPID, Cnt);
                    exit(0);
            });
        }
    }
}

/*
 * msgRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 * mbps uses an argument list to pass any necssary data
 * not carried in the message body
 *
 * Prints the message content
 * May take action(s) based on message content
 */

void msgRecv(mbps&, const mbpsMsg& mt, std::vector<uint8_t>& msgPayload)
{
    auto now = tp2d(std::chrono::system_clock::now());
    auto dt = (now - tp2d(mt.time("mts"))).count() / 1000.;

    dct::print("{:%M:%S} {}:{}-{} rcvd ({:.3}ms transit): {} {}: {} {} | {}\n",
            now, role, myId, myPID, dt, mt["target"], mt["topic"], mt["trgtLoc"], mt["topicArgs"],
            std::string(msgPayload.begin(), msgPayload.end()));

    // further action can be conditional upon msgArgs and msgPayload
}

/*
 * Can be used as a QoS/confirm callback in msgPubr().
 */
std::unordered_map<uint32_t, int> mesgBoard;
static int outstandingMsgs = 0;

void messageConfirmation(bool s, uint32_t m)
{
    try {
            mesgBoard.at(m);
        } catch(const std::exception& e) {
            dct::print("exception {}\nNo message on mesgBoard with received ID", e.what());
        }
        if(!s) {
            //could put another attempt here or other logic
            dct::print("{}:{} msg {} failed to reach collection\n", myId, myPID, m);
        }
        outstandingMsgs--;
        mesgBoard.erase(m);
}

/*
 * Main() for the application to use.
 * First complete set up: parse input line, set up message to publish,
 * set up entity identifier. Then make the mbps DeftT, connect,
 * and run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    // parse input line
    if (argc <= 1) {
                help(argv[0]);
                exit(1);
    }
    for (int c;
        (c = getopt_long(argc, argv, "n:c:pdhl:", opts, nullptr)) != -1;) { 
        switch (c) {
                case 'n':
                    Done = std::stoi(std::string(optarg));    //number of times to publish
                    break;
                case 'c':
                    capability = optarg;
                    break;
                case 'p':
                    Persist = true;
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
    mbps cm(rootCert, []{ return schemaCert();}, []{ return identityChain();}, []{ return getSigningPair();});

    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");



    // Connect and pass in the handler
    try {
        // send initial msg when connected. msgPubr schedules next send each time its called
        cm.connect( [&cm]() {
            if (role == "operator") {
                cm.subscribe(msgRecv);   //single callback for all messages
            } else {
                //here devices just subscribe to command topic
                cm.subscribe(capability + "/command/" + myId, msgRecv); // msgs to this instance
                cm.subscribe(capability + "/command/all", msgRecv);     // msgs to all instances
            }
            msgPubr(cm);
         });
    } catch (const std::exception& e) {
        std::cerr << "main encountered exception while trying to connect: "
                 << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps failed to connect with code "
                 << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception";
        exit(1);
    }

    cm.run();
}
