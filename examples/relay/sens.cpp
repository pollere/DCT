/*
 * sens.cpp: sensor reporting application
 * would receive environmental readings from sensors and periodically publishes
 * them. May receive commands.
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
static std::string myId, role, fullId;
static std::chrono::microseconds pubWait = std::chrono::seconds(45);
static int Cnt = 0;
static int nMsgs = 5;

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
static constexpr auto tp2d = [](auto t){ return std::chrono::duration_cast<ticks>(t.time_since_epoch()); };

/*
 * reports environmental information periodically
 */
static void sensRprtr(mbps &cm) {
    dct::print("{} publishing sensor report {}\n", fullId, Cnt+1);
    // make a message to publish
    std::string s = dct::format("Sensor sample #{} from {}", ++Cnt, fullId);
    std::vector<uint8_t> toSend(s.begin(), s.end());
    msgParms mp;
    mp = msgParms{{"target", "sens"s},{"topic","rpt"s},{"args", myId}};
    cm.publish(std::move(mp), toSend);
    if (Cnt >= nMsgs && nMsgs) {
        cm.oneTime(2*pubWait, [](){
                    dct::print("{} published {} location messages and exits\n", fullId, Cnt);
                    exit(0);
                });
        return;
    }
    // set up next report
    cm.oneTime(pubWait + std::chrono::milliseconds(std::rand() & 0x1ff), [&cm](){ sensRprtr(cm); });
}

/*
 * cmdRecv handles a command received in subscription.
 * Used as callback passed to subscribe()
 *
 * Prints the message content
 * Could take action(s) based on message content
 */

void cmdRecv(mbps& cm, const mbpsMsg& mt, const std::span<const uint8_t>& msgPayload)
{    
    auto mtm = mt.time("_ts"); // gets timestamp of message origination
    auto dt = (tp2d(cm.tdvcNow()) - tp2d(mtm)).count() / 1000.;
    auto now = tp2d(std::chrono::system_clock::now());

    dct::print("{:%M:%S} {} rcvd ({:.3} mS transit): {} {}: {} | {}\n",
           now, fullId, dt, mt["target"], mt["topic"], mt["args"],
                std::string(msgPayload.begin(), msgPayload.end()));

    // further action can be conditional upon msgArgs and msgPayload

    // if acknowledgement is required, then immediately reply
    // std::vector<uint8_t> toSend(fullId.begin(), fullId.end());
    //  msgParms mp;
    //  mp = msgParms{{"target", "sens"s},{"topic", "ack"s},{"args",mt[msgID]}};
    //  cm.publish(std::move(mp), toSend);
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
    readBootstrap(argv[optind]);

    // the DeftT shim needs callbacks to get the trust root, the schema, the identity
    // cert chain, and the current signing secret key plus public cert (see util/identity_access.hpp)
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();}, []{return getSigningPair();});

    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");
    fullId = dct::format("{}:{}", role, myId);

    // Connect and pass in the handler
    try {
        /* main task for this entity */
        cm.connect([&cm]{
            cm.subscribe("sens/cmd", cmdRecv);
            sensRprtr(cm); });
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
