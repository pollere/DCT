/*
 * app1.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using mbps client. Messages packaged
 * in int8_t vectors are passed between application and client. To
 * publish a message, an optional list of arguments can also be
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
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  This DCT proof-of-concept example is not intended as production code.
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

/*
 * msgPubr passes messages to publish to the mbps client. A simple lambda
 * is used if "qos" is desired. A more complex callback (messageConfirmation)
 * is included in this file.
 */

void msgPubr(mbps &cm, std::vector<uint8_t>& toSend) {
    msgParms mp;

    if(role == "operator") {
        mp = msgParms{{"target", capability},{"topic", "command"s},{"trgtLoc",location},{"topicArgs", "unlock"s}};
    } else {
        mp = msgParms{{"target", capability},{"topic", "status"s},{"trgtLoc",myId},{"topicArgs", "unlocked"s}};
    }
    /*
    cm.publish(std::move(mp), toSend);  //no callback to skip message confirmation
    */
    cm.publish(std::move(mp), toSend, [](bool s, uint32_t mId) {
        if(s){
            std::cout << role << ":" << myId << "-" << myPID << " published message number " << Cnt-1 << " identifier " << mId
                  << " to Collection." << std::endl;
        } else {
            std::cout << role << ":" << myId << "-" << myPID << " message number " << Cnt-1
                   << " timed out without reaching Collection." << std::endl;
        }
        });

    if(++Cnt < Done) {  // wait then publish another message
        cm.oneTime(pubWait, [&cm](){
            std::string s = "Message number " + std::to_string(Cnt)
                            + " from " + role + ":" + myId + "-" + myPID;
            std::vector<uint8_t> m(s.begin(), s.end());
            msgPubr(cm, m);
        });
    } else {
        if(!Persist) {
            cm.oneTime(2*pubWait, [](){
                    std::cout << myPID << " is done publishing messages." << std::endl;
                    exit(0);
            });
        }
    }
}

/*
 * msgRecv handles a message received in subscription.
 * Used as callback passed to subscribe()
 * The mbps client  uses an argument list to pass any necssary data
 * not carried in the message body
 *
 * Prints the message content
 * May take action(s) based on message content
 */

void msgRecv(mbps&, const mbpsMsg& mt, std::vector<uint8_t>& msgPayload)
{

    std::cout << "Entity " << myPID << " received message:"
        << "\tcapability = " << mt["target"] << std::endl << "\ttopic = " << mt["target"] << std::endl
        << "\tlocation = " << mt["trgtLoc"] << std::endl << "\targuments = " << mt["topicArgs"] << std::endl
        << "\tmessage creation time = " << mt.time("mts").time_since_epoch().count() << std::endl;
    auto content = std::string(msgPayload.begin(), msgPayload.end());
    std::cout << "\tmessage body: " << content << std::endl;

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
            _LOG_ERROR("exception " << e.what() <<
                        "\nNo message on mesgBoard with received ID");
        }
        _LOG_INFO(role << ":" << myId << "-" << myPID << ": " << " called back for message " << m);
        if(s) {
            _LOG_INFO(" published to collection");
        } else {
            //could put another attempt here or other logic
            _LOG_INFO(" failed to reach collection");
        }
        outstandingMsgs--;
        mesgBoard.erase(m);
        _LOG_INFO(role << ":" << myId << "-" << myPID << ": has " << outstandingMsgs << " unconfirmed messages");
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
    if (argc <= 1) {
                help(argv[0]);
                exit(1);
    }
    for (int c;
        (c = getopt_long(argc, argv, "nc:pdhl", opts, nullptr)) != -1;) {
        switch (c) {
                case 'n':
                    Done = std::stoi(optarg);    //number of times to publish
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
    myPID = std::to_string(getpid());        //process id useful for debugging
    mbps cm(argv[optind]);     //Create the mbps client
    role = cm.attribute("_role");
    myId = cm.attribute("_roleId");

    // Connect and pass in the handler
    try {
        cm.connect(    /* main task for this entity */
            [&cm]() {
                if (role == "operator") {
                    cm.subscribe(msgRecv);   //single callback for all messages
                } else {
                    //here devices just subscribe to command topic
                    cm.subscribe(capability + "/command/" + myId, msgRecv); // msgs to this instance
                    cm.subscribe(capability + "/command/all", msgRecv);     // msgs to all instances
                }
                // construct message to send
                std::string s("Message number 0 from " + role + ":" + myId + "-" + myPID);
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
