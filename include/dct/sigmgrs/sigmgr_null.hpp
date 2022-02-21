#ifndef SIGMGRNULL_HPP
#define SIGMGRNULL_HPP
/*
 * Null Signature Manager
 *
 * Copyright (C) 2020-2 Pollere LLC
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

/*
 * SigMgr Null provides a signing and validation methods that do nothing.
 * This is specifically provided for cert distribution and should not be
 * used otherwise (i.e., if you don't know why you are using this, don't!).
 *
 */

#include <array>
#include "sigmgr.hpp"

struct SigMgrNULL final : SigMgr {

    SigMgrNULL() : SigMgr(stNULL) {}

    bool sign(ndn::Data& data, const SigInfo&, const keyVal&) override final {
        data.wireEncode();
        return true;
    }
    /*
     * Here just return true
     */
    bool validate(rData ) override final { return true; }
    bool validate(rData , const dct_Cert&) override final { return true; }

    bool validate(const ndn::Data&) override final { return true; }
    bool validate(const ndn::Data&, const dct_Cert&) override final { return true; }

    bool needsKey() const noexcept override final { return 0; };
};

#endif // SIGMGRNULL_HPP
