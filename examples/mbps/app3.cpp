/*
 * app3.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using mbps client. Messages packaged
 * in int8_t vectors are passed between application and client. To
 * publish a message, an optional list of arguments can also be
 * included.
 *
 * This version publishes messages to the domain of the client
 * and subscribes to all the messsages in that domain's collection
 * (i.e., targets are not used to particularize subscriptions).
 *
 * app3 publishes a message and waits for a message from
 * another member of the enclave. When a message is received, a new
 * message is scheduled for publication.
 *
 * app3 is not intended as production code.
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
#include <functional>
#include <iostream>
#include <chrono>

#include "mbps0.hpp"

// handles command line
static struct option opts[] = {
    {"count", required_argument, nullptr, 'c'},
    {"role", required_argument, nullptr, 'r'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] -f file_name\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -r |--role        role of this process\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n";
}

/* Globals */
static std::string role("device");     //default
static std::string myId {};
static std::chrono::nanoseconds pubWait = std::chrono::seconds(1);
static int Cnt = 0;
static bool Pending = false;
static Timer timer;

//options for the argument list that can be randomly selected
std::string loc[] = {"all", "frontdoor", "gate", "backdoor"};
std::string topic[] = {"status", "event"};
std::string args[] = {"lock", "unlock", "report"};

/*
 * msgPubr passes messages to publish to the mbps client.
 */

void msgPubr(mbps &cm, std::vector<uint8_t>& toSend) {
    msgArgs a;
    a.cap = "lock";
    if(role == "operator") {
        a.topic = "command";
        //randomly select loc
        auto k = randombytes_uniform((uint32_t)4);
        a.loc = loc[k];
        //randomly select topic args
        k = randombytes_uniform((uint32_t)3);
        a.args = args[k];
    } else {
        //randomly select topic
        auto k = randombytes_uniform((uint32_t)(2));
        a.topic = topic[k];
        a.loc = "me";
        //randomly select topic args
        k = randombytes_uniform((uint32_t)2);
        a.args = args[k] + "ed";
    }
    try {
        cm.publish(toSend, a);
        Pending = false;
    } catch (const std::exception& e) {
        _LOG_INFO("msgPubr got exception trying to publish message: " << e.what());
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

void msgRecv(mbps &cm, std::vector<uint8_t>& msgPayload, const msgArgs& a)
{
    try {
    std::cout << "Application entity " << myId << " received message:" << std::endl;
    std::cout << "\tcapability = " << a.cap << std::endl;
    std::cout << "\tspecifier = " << a.loc << std::endl;
    std::cout << "\tdirective = " << a.topic << std::endl;
    std::cout << "\tmodifiers = " << a.args << std::endl;
    std::cout << "\tmessage creation time = " << a.ts << std::endl;
    //auto content = reinterpret_cast<appMsg*>(msgPayload.data());
    auto content = std::string(msgPayload.begin(), msgPayload.end());
    std::cout << "\tmessage body: " << content << std::endl;
    } catch (const std::exception& e) {
        _LOG_INFO("msgRecv got exception while parsing message and args: " << e.what());
    }
    /* further action can be conditional upon msgArgs and msgPayload
     * e.g., for command, change state if differs and publish event
     * or, if already in that state, publish a status with state
     *
     * publish another message after a delay
     */
    if(!Pending) {
        Pending = true;
        timer = cm.schedule(pubWait, [&cm](){
            std::string s = "Message number " + std::to_string(++Cnt)
                            + " from " + myId;
            std::vector<uint8_t> m(s.begin(), s.end());
            msgPubr(cm, m);
        });
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
    INIT_LOGGERS();
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, "r:dh", opts, nullptr)) != -1;) {
        switch (c) {
                case 'r':
                    role = optarg;
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
        }
    }

    myId = std::to_string(getpid());
    mbps cm(role);     //Create the mbps client

    // Connect and pass in the handler
    try {
        cm.connect(    /* main task for this entity */
            [&cm]() {
                cm.subscribe(msgRecv);   //single callback for all messages
                // make a message to publish
                std::string s("Message number 0 from " + myId);
                std::vector<uint8_t> toSend(s.begin(), s.end());
                msgPubr(cm, toSend);    //send initial message
            });
    } catch (const std::exception& e) {
        std::cerr << "main encountered exception while trying to connect: "
                 << e.what() << std::endl;
        exit(1);
    } catch (int conn_code) {
        std::cerr << "main mbps client failed to connect with code "
                 << conn_code << std::endl;
        exit(1);
    } catch (...) {
        std::cerr << "default exception";
        exit(1);
    }

    cm.run();
}
