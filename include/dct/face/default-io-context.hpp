#ifndef GET_DEFAULT_IO_CONTEXT_HPP
#define GET_DEFAULT_IO_CONTEXT_HPP
#pragma once
/*
 * getDefaultIoContext - get current DCT application's default io_context
 *
 * DCT is not multi-threaded and expects all I/O and timer events to use the
 * same boost::asio:io_context (aka "io_service" in older boost implementations).
 * It's expected that any routine that needs an io_context call this routine
 * to get it..
 *
 * Copyright (C) 2021-2 Pollere LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <boost/asio.hpp>

namespace dct {

static inline auto& getDefaultIoContext()
{
    static boost::asio::io_context* ioc{};
    if (ioc == nullptr) {
        ioc = new boost::asio::io_context;
        static auto work = boost::asio::require(ioc->get_executor(), boost::asio::execution::outstanding_work.tracked);
    }
    return *ioc;
}

} // namespace dct

#endif // GET_DEFAULT_IO_CONTEXT_HPP
