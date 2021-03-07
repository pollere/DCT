#ifndef SCHEMAINSTALL_HPP
#define SCHEMAINSTALL_HPP
/*
 * Install a compiled schema in the NDN PIB
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

#include <ndn-ind/security/pib/pib-sqlite3.hpp>
#include "dct/format.hpp"
#include "dct/schema/mkcert.hpp"
#include "dct/sigmgrs/sigmgr_by_type.hpp"

auto schemaInstall(const bSchema& bs, const auto& pk) {
    auto certName = format("{}/schema/{}", bs.pubVal("#pubPrefix"), bs.pubName(0));
    auto valtype = bs.pubVal("#pubValidator").substr(1);;
    auto sm{sigMgrByType(valtype)};
    auto cert = mkCert(certName, pk, sm.ref());

    ndn::PibSqlite3 pib;
    pib.addCertificate(cert);
    pib.setDefaultCertificateOfKey(cert.getKeyName(), cert.getName());
    print("installed cert {} with validator {}\n", certName, valtype);
}

#endif // SCHEMAINSTALL_HPP
