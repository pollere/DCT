/*
 * logApp.cpp: example app to subscribe to logs
 *
 * This application uses the mbps shim.
 *
 * Copyright (C) 2020-26 Pollere LLC
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
    {"addr", required_argument, nullptr, 'a'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
    {"quiet", no_argument, nullptr, 'q'}
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
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -q |--quiet       don't print progress messages\n";
}

/* Globals */
static std::string myPID,myId, role;
static int nRcv = 0;
static std::string addr{};
static bool quiet = false;

using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
static constexpr auto tp2d = [](auto t){ return std::chrono::duration_cast<ticks>(t.time_since_epoch()); };

/*
 * logRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 *
 * Prints the message content
 */
void logRecv(const dct::logMsg& lm, const std::span<const uint8_t>& logInfo)
{
    auto now = tp2d(std::chrono::system_clock::now());
    nRcv++;
    if (!quiet) {
        dct::print("{:%M:%S} {}:{} rcvd log #{}: {}\n\t {}\n",
                now, role, myId, nRcv, lm, std::string(logInfo.begin(), logInfo.end()));
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
        (c = getopt_long(argc, argv, ":a:dh:q:", opts, nullptr)) != -1;) {
        switch (c) {
                case 'a':
                    addr = optarg;
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
                case 'q':
                    quiet = true;;
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
     *  schemaCert, identityChain and getSigningPair callbacks are how
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
    // cert chain, and the signing secret key plus public cert (see util/identity_access.hpp)
    mbps cm(rootCert, []{return schemaCert();}, []{return identityChain();},
            [](std::chrono::microseconds a){return getSigningPair(dct::idTag(), a);}, addr);
    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");
    cm.setLogging(); // if logging, set here - must be before connect()

    // Connect and pass in the handler
    try {
        /* main task for this entity */
         cm.connect([&cm]{
            auto now = std::chrono::system_clock::now();
            dct::print("{:%M:%S} {}:{} is connected\n", ticks(now.time_since_epoch()), role, myId);
            cm.subscribeLogs(logRecv);  // this logger just subscribes to all logs
            // cm.subscribeLogs("exApp", logRecv); // this subscribes only to logs with exApp topic
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
