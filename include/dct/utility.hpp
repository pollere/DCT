#ifndef DCT_UTILITY_HPP
#define DCT_UTILITY_HPP
#pragma once
/*
 * misc utility routines used by DCT modules
 *
 * Copyright (C) 2020-2 Pollere LLC
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

extern "C" {
    //int gethostname(const char*, size_t); //Posix
    int gethostname(char*, size_t); //MacOS
    pid_t getpid(void);
}

namespace dct {

#ifndef HOST_NAME_MAX
static constexpr size_t HOST_NAME_MAX = 64;  //Linux limit
#endif

inline static const std::string& sysID() noexcept {
    static std::string sysid{};
    if (sysid.size() == 0) {
        char h[HOST_NAME_MAX+1];
        if (gethostname(&h[0], sizeof(h)-1) != 0) {
            h[0] = h[1] = '?'; h[2] = 0;
        }
        sysid = format("p{}@{}", getpid(), h);
    }
    return sysid;
}

} // namespace dct

#endif // DCT_UTILITY_HPP
