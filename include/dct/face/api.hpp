#ifndef DCT_FACE_API_HPP
#define DCT_FACE_API_HPP
#pragma once
/*
 * Types related to the DCT Direct Face API
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

using DataCb = std::function<void(const rInterest& i, rData d)>;
using InterestCb = std::function<void(const rName& n, const rInterest& i)>;
using InterestTO = std::function<void(const rInterest& i)>;
using RegisterCb = std::function<void(const rName& prefix)>;

} // namespace dct

#endif  // DCT_FACE_API_HPP
