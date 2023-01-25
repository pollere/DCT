#ifndef CERT_TO_SCHEMA_HPP
#define CERT_TO_SCHEMA_HPP
/*
 * Convert the schema from a DCTcert to its bSchema representation
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

#include <sstream>
#include "dct_cert.hpp"
#include "dct/format.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"
#include "rdschema.hpp"

// return the binary schema associated with certificate 'cert'
// It's assumed that the cert signature has been validated and
// the cert name checked for conformance to schema conventions.
static inline bSchema certToSchema(const dctCert& cert, thumbPrint& tp) {
    std::istringstream is(std::string(cert.content().toSv()), std::ios::binary);
    auto bs = rdSchema(is).read();
    bs.schemaTP_.insert(bs.schemaTP_.begin(), tp.begin(), tp.end());
    return bs;
}

#endif // CERT_TO_SCHEMA_HPP
