#ifndef SIGMGRNULL_HPP
#define SIGMGRNULL_HPP
#pragma once
/*
 * Null Signature Manager
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

/*
 * SigMgr Null provides a signing and validation methods that do nothing.
 * This is specifically provided for cert distribution and should not be
 * used otherwise (i.e., if you don't know why you are using this, don't!).
 *
 */

#include <array>
#include "sigmgr.hpp"

namespace dct {

struct SigMgrNULL final : SigMgr {

    SigMgrNULL() : SigMgr(stNULL, 0) {}

    bool sign(crData& , const SigInfo& , const keyVal& ) override final { return true; }

    /*
     * Here just return true
     */
    bool validate(rData ) override final { return true; }
    bool validate(rData , const rData&) override final { return true; }
};

} // namespace dct

#endif // SIGMGRNULL_HPP
