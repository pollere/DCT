/*
 * loc.cpp: location reporting application
 * part of example showing use of publisher privacy
 *
 * loc models a location sensing and reporting application that could be running
 * on a mobile device. It periodically publishes a message with its location.
 *
 * Copyright (C) 2022 Pollere LLC
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

// handles command line
static struct option opts[] = {
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
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
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -n |--count       number of messages to publish\n"
           "  -w |--wait        wait (in ms) between sends\n";
}

/* Globals */
static std::string myPID, myId, role, fullId;
static std::chrono::microseconds pubWait = std::chrono::seconds(1);
static int Cnt = 0;
static int nMsgs = 10;

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;

/*
 * locRprtr reports location periodically
 */
static void locRprtr(mbps &cm) {
    dct::print("{}:{}:{} publishing location report {}\n", role, myId, myPID, Cnt+1);
    // make a message to publish - hokey, but this is just for illustration
    std::string s = dct::format("Location sample #{} from {}:{}:{} at coords: {},{}", ++Cnt, role, myId, myPID,
        arc4random() % 91, arc4random() % 91);
    std::vector<uint8_t> toSend(s.begin(), s.end());
    msgParms mp;
    mp = msgParms{{"target", "loc"s},{"rptr",fullId}};
    cm.publish(std::move(mp), toSend);
    if (Cnt >= nMsgs && nMsgs) {
        cm.oneTime(2*pubWait, [](){
        dct::print("{}:{}:{} published {} location messages\n", role, myId, myPID, Cnt);
                    //dct::print("{}:{}:{} published {} location messages and exits\n", role, myId, myPID, Cnt);
                    //exit(0);
                });
        return;
    }
    // set up next report
    cm.oneTime(pubWait + std::chrono::milliseconds(rand() & 0x1ff), [&cm](){ locRprtr(cm); });
}

/*
 * First complete set up: parse input line, set up message to publish,
 * set up entity identifier. Then make the mbps DeftT, connect, and run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    std::srand(std::time(0));
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, ":dh:n:w:", opts, nullptr)) != -1;) {
        switch (c) {
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
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
    readBootstrap(argv[optind]);

    // the DeftT shim needs callbacks to get the trust root, the trust schema, the identity
    // cert chain, and the get signing secret key plus public cert (see util/identity_access.hpp)
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();},
        [](std::chrono::microseconds a){return getSigningPair(dct::idTag(), a);});

    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");
    fullId = dct::format("{}:{}:{}", role, myId, myPID);

    // Connect and pass in the handler
    try {
        /* main task for this entity */
        cm.connect([&cm] {
            auto now = std::chrono::system_clock::now();
            dct::print("{:%M:%S} {} is connected\n", ticks(now.time_since_epoch()), fullId);
            cm.oneTime(std::chrono::milliseconds(rand() & 0x1ff), [&cm](){ locRprtr(cm); });
        });
    } catch (const std::exception& e) {
        std::cerr << "main encountered exception while trying to connect: " << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps failed to connect with code " << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception\n";
        exit(1);
    }
    cm.run();
}
