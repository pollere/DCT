#ifndef CERT_BUNDLE_HPP
#define CERT_BUNDLE_HPP
/*
 * unpack a bundle of wire-format certs into a vector of cert objects
 *
 * Copyright (C) 2021 Pollere, Inc.
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
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */
#include <string_view>
#include <tuple>
#include <vector>

#include "dct/format.hpp"
#include "dct/schema/dct_cert.hpp"
#include "dct/schema/tlv_parser.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"

using certItem = std::pair<dctCert,keyVal>;
using certBundle = std::vector<certItem>;

static inline certBundle rdCertBundle(const std::vector<uint8_t>& buf) {

    // unpack all the objects in the bundle
    certBundle cb{};
    auto bundle = tlvParser(tlvParser::Blk(buf), 0U); 
    for (auto obj : bundle) {
        // Bundles contain only certs (tlv 6 = ndn::Data) and keys (tlv 23 = Signature).
        // Keys immediately follow their cert so each iteration must start with cert.
        // It may be immediately followed by a key that will be attached to the cert.
        // After that must be eof or another cert.
        if (obj[0] != 6) throw std::runtime_error(format("invalid bundle format (type {})", obj[0]));
    
        // have a cert (type tlv::Data)
        auto data = ndn::Data();
        data.wireDecode(obj.data(), obj.size());
        auto cert = dctCert(data);
        // if the next item is a key, stick it in the bundle with the cert
        // otherwise give the cert an empty key
        keyVal key{};
        if (!bundle.eof() && bundle.cur() == 23) {
            auto b = bundle.nextBlk().rest();
            key.assign(b.begin(), b.end());
        }
        cb.emplace_back(cert, key);
    }
    return cb;
}

#endif // CERT_BUNDLE_HPP
