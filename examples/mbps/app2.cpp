/*
 * app2.cpp: command-line application to exercise mbps.hpp
 *
 * This is an application using mbps client. Messages packaged
 * in int8_t vectors are passed between application and client. To
 * publish a message, an optional list of arguments can also be
 * included along with an optional callback if message qos is
 * desired (here, confirmation that the message has been published).
 *
 * This version publishes messages to the domain of the client
 * and subscribes to all the messsages in that domain's collection
 * (i.e., targets are not used to particularize subscriptions).
 *
 * app2 publishes a message and waits for a message from
 * another member of the enclave. When a message is received, a new
 * message is scheduled for publication.
 *
 * app2 is not intended as production code.
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

/*
 * msgPubr passes messages to publish to the mbps client.
 * This uses a simple lambda callback that can be used
 * if "qos" is desired. A more complex callback (messageConfirmation)
 * is included in this file.
 */

void msgPubr(mbps &cm, std::vector<uint8_t>& toSend) {
    msgArgs a;
    a.cap = "lock";
    if(role == "operator") {
        a.loc = "frontdoor";
        a.topic = "command";
        a.args = "unlock";
    } else {
        a.loc = "me";
        a.topic = "event";
        a.args = "unlocked";
    }
    /*
    cm.publish(toSend, a);  //no callback to skip message confirmation
    */
    cm.publish(toSend, a, [&cm](bool s, uint32_t mId) {
        if(s){
            std::cout << myId << " published message number " << Cnt
                  << " to Collection." << std::endl;
        } else {
            std::cout << myId << " message number " << Cnt
                   << " timed out without reaching Collection." << std::endl;
            //schedule another Publication since this app ping-pongs
            Pending = true;
            timer = cm.schedule(pubWait, [&cm](){
                std::string s = "Message number " + std::to_string(++Cnt)
                                + " from " + myId;
                std::vector<uint8_t> m(s.begin(), s.end());
                msgPubr(cm, m);
            });
        }
        });
    Pending = false;
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

    std::cout << "Application entity " << myId << " received message:" << std::endl;
    std::cout << "\tcapability = " << a.cap << std::endl;
    std::cout << "\tspecifier = " << a.loc << std::endl;
    std::cout << "\tdirective = " << a.topic << std::endl;
    std::cout << "\tmodifiers = " << a.args << std::endl;
    std::cout << "\tmessage creation time = " << a.ts << std::endl;
    //auto content = reinterpret_cast<appMsg*>(msgPayload.data());
    auto content = std::string(msgPayload.begin(), msgPayload.end());
    std::cout << "\tmessage body: " << content << std::endl;

    // further action can be conditional upon msgArgs and msgPayload
    // publish another message after a delay
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
        _LOG_INFO(myId << ": " << " called back for message " << m);
        if(s) {
            _LOG_INFO(" published to collection");
        } else {
            //could put another attempt here or other logic
            _LOG_INFO(" failed to reach collection");
        }
        outstandingMsgs--;
        mesgBoard.erase(m);
        _LOG_INFO(myId << ": has " << outstandingMsgs << " unconfirmed messages");
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
