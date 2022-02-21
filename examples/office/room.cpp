/*
 * room.cpp: room controller application for Office example for ICN2021 tutorial
 *
 * This application using mbps client. Message body (if any) is packaged
 * in int8_t vectors to pass between application and client. Parameters
 * are passed to mpbs in an vector of pairs (msgParms) and passed from mbps
 * to the application in a mbpsMsg structure that contains an unordered_map
 * where values are indexed by the tags (components of Names) that are
 * defined in the trust schema for this particular application.
 *
 * room models a raspPi-like computer that controls settings of attached
 * devices for its assigned room (temperature, light, lock, screen)
 * For the Office example, application settable parameters are:
 *
 * func - the particular accessory device: light, door, screen, temp
 * topic - the type of message: command or status
 * args - the action to perform for command or the state for status
 *
 * A room controller waits for a command, prints it (simulated action),
 * then publishes this new status
 *
 * Copyright (C) 2021-2 Pollere LLC
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

#include "../shims/mbps.hpp"

using namespace std::literals;

/* Globals */

static std::string role{};          // this instance's role
static std::string id{};            // this instance's roleId
static std::string room{};          // this instance's roomId (same as id for a room)

/*
 * cmdRecv handles a command received in a subscription so is used as a callback
 * when subscribing through the mbps client, hence must be a
 * Does not use the message body
 */
void cmdRecv(mbps &cm, const mbpsMsg& msg, std::vector<uint8_t>&)
{
    using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
    auto now = std::chrono::system_clock::now();
    auto dt = ticks(now - msg.time("mts")).count() / 1000.;
    const auto& f = msg["func"];
    const auto& a = msg["args"];

    print("{:%M:%S} {} in {} setting {} to {} ({:.3} mS transit)\n",
            ticks(now.time_since_epoch()), role, id, f, a, dt);
    //passes message to mbps client to publish (message body is empty)
    cm.publish(msgParms{{"func", f},{"topic", "status"s},{"loc",room},{"args", a}});
}

/*
 * Main() for room controller application
 * Make the mbps client, connect, and run the context.
 */

int main(int argc, char* argv[])
{
    INIT_LOGGERS();
    mbps cm(argv[argc-1]);     //Create the mbps client
    cm.m_pb.pubLifetime(500ms); // want fresh status information
    role = cm.attribute("_role");
    id = cm.attribute("_roleId");
    room = cm.attribute("_roomId");

    // Connect and pass in the handler
    try {
        cm.connect(    /* main task for this entity */
            [&cm]() {
                std::vector<std::string> acc;
                if(id == "hall") {
                    acc = {"light", "door"};
                } else {
                    acc = {"light", "door", "screen", "temp"};
                }
                //subscribe to command topic for all my accessory functions
                for(auto i=0u; i < acc.size(); i++) {
                    cm.subscribe(acc[i] + "/command/" + id, cmdRecv); // msgs to this instance
                    cm.subscribe(acc[i] + "/command/all", cmdRecv); // msgs to all instances
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
