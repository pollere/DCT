#ifndef GETSCHEMA_HPP
#define GETSCHEMA_HPP
/*
 * Get a certificate containing a schema from the PIB
 *
 * Copyright (C) 2020 Pollere, Inc.
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

#include <sstream>
#include <ndn-ind/security/pib/pib-sqlite3.hpp>
#include <ndn-ind/generic-signature.hpp>
#include "dct/format.hpp"
#include "rdschema.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"

// return the binary schema associated with certificate 'cert'
bSchema getSchema(const ndn::Name& certname) {
    ndn::PibSqlite3 pib;

    auto cert = *pib.getCertificate(certname);
    if (cert.getIssuerId() != "schema") {
        throw schema_error(format("cert {} isn't a schema\n", cert.getName().toUri()));
    }
    // (next 3 lines of ugly setup just to get the signature type byte from the cert so we can validate it)
    std::vector<ndn_NameComponent> n(32);
    ndn::SignatureLite sig(n.data(), n.size());
    cert.getSignature()->get(sig);

    // validate the cert's signature then read and validate its schema
    if (! sigMgrByType(sig.getType()).validate(cert)) {
        throw schema_error(format("cert {} didn't validate\n", cert.getName().toUri()));
    }
    auto pk = *cert.getPublicKey();
    std::istringstream is(std::string((char*)pk.data(), pk.size()), std::ios::binary);
    return rdSchema(is).read();
}

#endif // GETSCHEMA_HPP
