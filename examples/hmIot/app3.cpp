/*
 * app3.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using mbps client. Messages packaged
 * in int8_t vectors are passed between application and client. To
 * publish a message, an optional list of arguments can also be
 * included.
 *
 * app3 publishes a message and waits for a message from
 * another member of the enclave. When a message is received, a new
 * message is scheduled for publication.
 *
 * app3 is not intended as production code.
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

#include "../shims/mbps.hpp"

// handles command line
static struct option opts[] = {
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
           "  -c capability     defaults to 'lock'\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -l location       defaults to 'all'\n";
}


/* Globals */
static std::string myPID, myId, role;
static std::chrono::microseconds pubWait = std::chrono::seconds(1);
static int Cnt = 0;
static bool Pending = false;
static std::string capability{"lock"};
static std::string location{"all"};

//options for the argument list that can be randomly selected
std::string loc[] = {"all", "frontdoor", "gate", "backdoor", "all"};
std::string topic[] = {"status", "event"};
std::string args[] = {"lock", "unlock", "report"};

void repCmd(mbps &cm) {
    if(role != "operator") return;
    msgParms mp;
    mp = msgParms{{"target", capability},{"topic", "command"s},{"trgtLoc","all"s},{"topicArgs", "report"s}};
    std::string s("Status command to all from operator: " + myId + "-" + myPID);
    std::vector<uint8_t> opNote(s.begin(), s.end());
    try {
        cm.publish(std::move(mp), opNote);
        std::cout << "Operator: " << myId << "-" << myPID << " published status command to all." << std::endl;
    } catch (const std::exception& e) {
        _LOG_INFO("msgPubr got exception trying to publish message: " << e.what());
   }
}

/*
 * msgPubr passes messages to publish to the mbps client.
 */

void msgPubr(mbps &cm, std::vector<uint8_t>& toSend) {
    msgParms mp;
    if(role == "operator") {
        mp = msgParms{{"target", capability},{"topic", "command"s},{"trgtLoc",loc[randombytes_uniform((uint32_t)5)]},
            {"topicArgs", args[randombytes_uniform((uint32_t)3)]}};
    } else {
        mp = msgParms{{"target", capability},{"topic", topic[randombytes_uniform((uint32_t)(2))]},{"trgtLoc",myId},
            {"topicArgs", args[randombytes_uniform((uint32_t)2)] + "ed"}};
    }

    try {
        cm.publish(std::move(mp), toSend);
        Pending = false;
        std::cout << "Entity " << role << ":" << myId << "-" << myPID << " published." << std::endl;
    } catch (const std::exception& e) {
        _LOG_INFO("msgPubr got exception trying to publish message: " << e.what());
    }
    if(role == "operator")
        repCmd(cm);
}


/*
 * msgRecv handles a message received in subscription (callback passed to subscribe)
 * The message is opaque to the mbps client which uses an argument list to pass
 * any necssary data that was not carried in the message body
 *
 * Prints the message content
 * Could take action(s) based on message content
 */

void msgRecv(mbps &cm, const mbpsMsg& mt, std::vector<uint8_t>& msgPayload)
{
    try {
        std::cout << "Entity " << role << ":" << myId << "-" << myPID << " received message:" << std::endl
                  << "\tcapability = " << mt["target"] << std::endl << "\ttopic = " << mt["topic"] << std::endl
                      << "\tlocation = " << mt["trgtLoc"] << std::endl << "\targuments = " << mt["topicArgs"] << std::endl
                      << "\tmessage creation time = " << mt.time("mts").time_since_epoch().count() << std::endl;
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
        cm.oneTime(pubWait, [&cm](){
            std::string s = "Message number " + std::to_string(++Cnt) + " from " + role + ":" + myId + "-" + myPID;
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
        (c = getopt_long(argc, argv, "c:dhl", opts, nullptr)) != -1;) {
        switch (c) {
                case 'c':
                    capability = optarg;
                    break;
                case 'l':
                    location = optarg;
                    break;
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

    myPID = std::to_string(getpid());
    mbps cm(argv[optind]);     //Create the mbps client
    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");

    // Connect and pass in the handler
    try {
        cm.connect(    /* main task for this entity */
            [&cm]() {
                std::cout << "Entity " << role << ":" << myId << "-" << myPID << " connected to TZ" << std::endl;
                 //going to publish in this function
                if (role == "operator")  {
                    cm.subscribe(msgRecv);   //single callback for all messages
                } else {
                    //here devices just subscribe to command topic
                    cm.subscribe(capability + "/command/" + myId, msgRecv); // msgs to this instance
                    cm.subscribe(capability + "/command/all", msgRecv);     // msgs to all instances
                }
                std::string s("Message number 0 from " + role + ":" + myId + "-" + myPID);
                std::vector<uint8_t> toSend(s.begin(), s.end());
                Pending = true;
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
