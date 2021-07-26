/*
 * app2.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using mbps client. Messages packaged
 * in int8_t vectors are passed between application and client. To
 * publish a message, an optional list of arguments can also be
 * included along with an optional callback if message qos is
 * desired (here, confirmation that the message has been published).
 *
 * app2 models an asymmetric, request/response style protocol between controlling
 * agent(s) ("operator" role in the schema) and controlled agent(s) ("device" role
 * in the schema). If the identity bundle gives the app an 'operator' role, it
 * periodically publishes a message and prints all the responses it receives.
 * If the app is given a 'device' role, it waits for a message then sets its
 * simulated state based on the message an announces its current state.
 *
 * Copyright (C) 2020 Pollere, Inc
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

#include "mbps.hpp"

static constexpr bool deliveryConfirmation = true; // get per-message delivery confirmation

// handles command line
static struct option opts[] = {
    {"capability", required_argument, nullptr, 'c'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
    {"location", required_argument, nullptr, 'l'},
    {"count", required_argument, nullptr, 'n'},
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
           "  -c capability     defaults to 'lock'\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -l location       defaults to 'all'\n"
           "  -n |--count       number of messages to publish\n"
           "  -w |--wait        wait (in ms) between sends\n";
}

/* Globals */
static std::string myPID {};
static std::chrono::nanoseconds pubWait = std::chrono::seconds(1);
static int Cnt = 0;
static int nMsgs = 10;
static Timer timer;
static std::string capability{"lock"};
static std::string location{"all"}; // target's location (for operators)
static std::string role{};          // this instance's role
static std::string myId{};
static std::string myState{"unlocked"};       // simulated state (for devices)

/*
 * msgPubr passes messages to publish to the mbps client. A simple lambda
 * is used if "qos" is desired. A more complex callback (messageConfirmation)
 * is included in the app1.cpp file.
 */
static void msgPubr(mbps &cm) {
    // make a message to publish
    std::string s = format("Msg #{} from {}:{}-{}", ++Cnt, role, myId, myPID);
    std::vector<uint8_t> toSend(s.begin(), s.end());

    msgArgs a;
    a.cap = capability;
    if(role == "operator") {
        a.topic = "command";
        a.loc = location;
        a.args = (std::rand() & 2)? "unlock" : "lock"; // randomly toggle requested state
    } else {
        a.topic = "event";
        a.loc = myId;
        a.args = myState;
    }
    if constexpr (deliveryConfirmation) {
        cm.publish(toSend, a, [a,ts=std::chrono::system_clock::now()](bool delivered, uint32_t /*mId*/) {
                    using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
                    auto now = std::chrono::system_clock::now();
                    auto dt = ticks(now - ts).count() / 1000.;
                    print("{:%M:%S} {}:{}-{} #{} published and {} +{:.3} mS: {} {}: {} {}\n",
                            ticks(ts.time_since_epoch()), role, myId, myPID, Cnt,
                            delivered? "confirmed":"timed out", dt, a.cap, a.topic, a.loc, a.args); 
                    });
    } else {
        cm.publish(toSend, a);  //no callback to skip message confirmation
    }

    if(Cnt >= nMsgs && nMsgs) {
        timer = cm.schedule(2*pubWait, [](){
                    print("{}:{}-{} published {} messages and exits\n", role, myId, myPID, Cnt);
                    exit(0);
                });
        return;
    }

    // operators send periodic messages, devices respond to incoming msgs
    if (role == "operator") {
        timer = cm.schedule(pubWait + std::chrono::milliseconds(rand() & 0x1ff), [&cm](){ msgPubr(cm); });
    }
}

/*
 * msgRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 * The message is opaque to the mbps client which uses
 * an argument list to pass any necssary data that was
 * not carried in the message body
 *
 * Prints the message content
 * Could take action(s) based on message content
 */

static void msgRecv(mbps &cm, std::vector<uint8_t>& msgPayload, const msgArgs& a)
{
    using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
    auto now = std::chrono::system_clock::now();
    auto dt = ticks(now - a.ts).count() / 1000.;

    print("{:%M:%S} {}:{}-{} rcvd ({:.3} mS transit): {} {}: {} {} | {}\n",
            ticks(now.time_since_epoch()), role, myId, myPID, dt, a.cap, a.topic, a.loc, a.args, 
            std::string(msgPayload.begin(), msgPayload.end()));

    // further action can be conditional upon msgArgs and msgPayload

    // devices set their 'state' from the incoming 'arg' value then immediately reply
    if (role == "device") {
        myState = a.args == "lock"? "locked":"unlocked";
        msgPubr(cm);
    }
}

/*
 * Main() for the application to use.
 * First complete set up: parse input line, set up message to publish,
 * set up entity identifier. Then make the mbps client, connect,
 * and run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    std::srand(std::time(0));
    INIT_LOGGERS();
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, ":c:dhl:n:w:", opts, nullptr)) != -1;) {
        switch (c) {
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
                case 'w':
                    pubWait = std::chrono::milliseconds(std::stoi(optarg));
                    break;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        exit(1);
    }
    myPID = std::to_string(getpid());
    mbps cm(argv[optind]);     //Create the mbps client
    role = cm.myRole();
    myId = cm.myId();

    // Connect and pass in the handler
    try {
        cm.connect(    /* main task for this entity */
            [&cm]() {
                if (role == "operator") {
                    cm.subscribe(msgRecv);  // single callback for all messages
                    msgPubr(cm);            // send initial message to kick things off
                } else {
                    //here devices just subscribe to command topic
                    cm.subscribe(capability + "/command/" + myId, msgRecv); // msgs to this instance
                    cm.subscribe(capability + "/command/all", msgRecv);     // msgs to all instances
                }
            });
    } catch (const std::exception& e) {
        std::cerr << "main encountered exception while trying to connect: " << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps client failed to connect with code " << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception";
        exit(1);
    }

    cm.run();
}
