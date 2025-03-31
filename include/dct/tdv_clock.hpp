#ifndef TDV_CLOCK_HPP
#define TDV_CLOCK_HPP
#pragma once
/*
 * Trust Domain Virtual Clock
 *
 * Copyright (C) 2024 Pollere LLC
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
#include <chrono>

namespace dct {

// TDV clock has a 1uS tick duration to match timestamp TLV format.
// It starts with the same time_since_epoch as the system clock but
// but 'adjust(..)' calls can change this. Its 'now()' method
// uses the system clock 'now()' offset by the adjustment kept in the
// '_offset_' field. 'adjust(dur)' adds 'dur' to the current value of
// _offset_. 'reset()' sets _offset_ to zero (so tdv_clock now() will
// again be the same as sys_clock now()).
struct tdv_clock {
    typedef std::chrono::microseconds duration;
    typedef duration::rep rep;
    typedef duration::period period;
    typedef std::chrono::time_point<tdv_clock> time_point;
    using sysclk_dur = decltype(std::chrono::system_clock::now().time_since_epoch());
    static constexpr const bool is_steady = false;

    time_point now() const noexcept { return time_point{
        std::chrono::duration_cast<duration>(std::chrono::system_clock::now().time_since_epoch()) + _offset_}; }
    duration adjust(duration delta) noexcept { return (_offset_ += delta); }
    duration adjust() const noexcept { return _offset_; }
    void reset() noexcept { _offset_ = duration::zero(); }
    auto to_sys(time_point tdvctp) const noexcept { return std::chrono::sys_time<sysclk_dur>{
        std::chrono::duration_cast<duration>(tdvctp.time_since_epoch() - _offset_)}; }
    auto from_sys(std::chrono::sys_time<sysclk_dur> systp) const noexcept { return time_point{
        std::chrono::duration_cast<duration>(systp.time_since_epoch()) + _offset_}; }
  private:
    duration _offset_{duration::zero()};
};

template<class Duration>
    using tdv_time = std::chrono::time_point<tdv_clock, Duration>;

auto format_as(tdv_clock::time_point t) { return std::chrono::sys_time<tdv_clock::duration>{t.time_since_epoch()}; }

} // namespace dct

#endif // TDV_CLOCK_HPP
