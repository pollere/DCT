#ifndef DCT_FACE_API_HPP
#define DCT_FACE_API_HPP
#pragma once
/*
 * Types related to the DCT Direct Face API
 *
 * Copyright (C) 2021-4 Pollere LLC
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
 *  This is not intended as production code.
 */

#include <functional>
#include <memory>

#if 1
// As of Dec 2022, get spurious warnings when include boost asio
// because sprintf is deprecated (on mac os xcode 12+).
// Theses pragmas are to prevent the warning from this.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// XXX boost bug workaround: this should be defined for any c++17 or beyond compiler and is
// *required* for c++20 or beyond since std::result_of is gone.
// Broken in boost 1.77 and earlier
#if BOOST_ASIO_VERSION<102200
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#endif
#include <boost/asio.hpp>
#pragma GCC diagnostic pop
#else
#include <boost/asio.hpp>
#endif

#include <dct/schema/rpacket.hpp>

namespace dct {

using Timer = boost::asio::system_timer;
using pTimer = std::shared_ptr<Timer>;
using TimerCb = std::function<void()>;
using csID_t = uint32_t; // aka csID - 32-bit murmurhash of cState name

using DataCb = std::function<void(rData d)>;
using StateCb = std::function<void(const rName& n, const rState& i)>;
using StateTO = std::function<void(csID_t)>;
using RegisterCb = std::function<void(const rName& prefix)>;

} // namespace dct

#endif  // DCT_FACE_API_HPP
