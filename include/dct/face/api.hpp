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

#include <boost/asio.hpp>

#include <dct/schema/rpacket.hpp>

namespace dct {

using Timer = boost::asio::system_timer;
using pTimer = std::shared_ptr<Timer>;
using TimerCb = std::function<void()>;
using csID_t = uint32_t; // aka csID - 32-bit murmurhash of cState name

using DataCb = std::function<void(const rState& i, rData d)>;
using StateCb = std::function<void(const rName& n, const rState& i)>;
using StateTO = std::function<void(csID_t)>;
using RegisterCb = std::function<void(const rName& prefix)>;

} // namespace dct

#endif  // DCT_FACE_API_HPP
