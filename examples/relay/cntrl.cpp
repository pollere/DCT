/*
 * cntrl.cpp: Controller app for sensor example with mesh of relays
 *
 * cntrl receives reports from sensors and publishes commands (infrequently)
 * for the sensors
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
static std::string myId, role;
static int Cnt = 0;
static int Cmd = 0;
static std::chrono::microseconds pubWait = std::chrono::seconds(30);

/*
 * rprtRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 *
 * Prints the message content
 */

void rprtRecv(mbps&, const mbpsMsg& mt, std::vector<uint8_t>& msgPayload)
{
    using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
    auto now = std::chrono::system_clock::now();
    auto dt = ticks(now - mt.time("mts")).count() / 1000.;
    dct::print("{:%M:%S} {}:{} rcvd ({:.3} mS transit): {} {} \n\t{}\n",
            ticks(now.time_since_epoch()), role, myId, dt, mt["topic"],
                mt["args"], std::string(msgPayload.begin(), msgPayload.end()));
    Cnt++;
}

/*
 * sends commands periodically
 */
static void cmdPubr(mbps &cm) {
    // dct::print("{}:{} publishing command {}\n", role, myId, Cmd+1);
    // make a message to publish
    std::string s = dct::format("Command #{} from {}:{}", ++Cmd, role, myId);
    std::vector<uint8_t> toSend(s.begin(), s.end());
    msgParms mp = msgParms{{"target", "sens"s},{"topic","cmd"s},{"args","read"s}};
    cm.publish(std::move(mp), toSend);
    // set up next command
    cm.oneTime(pubWait + std::chrono::milliseconds(std::rand() & 0x1ff), [&cm](){ cmdPubr(cm); });
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
        (c = getopt_long(argc, argv, ":dh:", opts, nullptr)) != -1;) {
        switch (c) {
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        exit(1);
    }
    readBootstrap(argv[optind]);

    // the DeftT shim needs callbacks to get the trust root, the schema, the identity
    // cert chain, and the current signing secret key plus public cert (see util/identity_access.hpp)
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();}, []{return getSigningPair();});

    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");

    // Connect and pass in the handler
    try {
        /* main task for this entity is to wait for location reports */
        cm.connect([&cm]{
            dct::print("{}:{} connected and waiting for location reports\n", role, myId);
            cm.subscribe("sens/rpt", rprtRecv);     // if collection command acks, need to subscribe to that
            cmdPubr(cm);
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
