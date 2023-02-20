#ifndef SIGMGR_DEFS_HPP
#define SIGMGR_DEFS_HPP
#pragma once
/*
 * Signature Manager type and size definitions
 *
 * Copyright (C) 2019-2 Pollere LLC
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

/*
 * Type and size definitions related to sigmgrs. These have
 * been extracted from the sigmgr class to avoid circular
 * dependencies between classes that deal with certs and
 * their signatures.
 */

#include <functional>
#include <span>
#include <vector>

// this file is included by syncps.hpp so libsodium calls can be available
extern "C" {
    #include <sodium.h>
};

namespace dct {
    constexpr size_t thumbPrint_s{crypto_hash_sha256_BYTES};
    using thumbPrint = std::array<uint8_t,thumbPrint_s>;

    using keyVal = std::vector<uint8_t>;
    using keyRef = std::span<const uint8_t>;
    using SigInfo = std::vector<uint8_t>;
    using SigType = uint8_t;

    // Signature types (must match equivalent NDN TLV if any) and be less than 64
    static constexpr SigType stSHA256 = 0;
    static constexpr SigType stAEAD = 7;
    static constexpr SigType stEdDSA = 8;
    static constexpr SigType stRFC7693 = 9;
    static constexpr SigType stNULL = 10;
    static constexpr SigType stPPAEAD = 11;
    static constexpr SigType stPPSIGN = 12;
    static constexpr SigType stAEADSGN = 13;

} // namespace dct

#endif //SIGMGR_DEFS_HPP
