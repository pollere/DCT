#ifndef PIBCERTS_HPP
#define PIBCERTS_HPP
/*
 * Certstore-abstraction implemented for an NDN PIB
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


#include <ndn-ind/security/key-chain.hpp>
#include <ndn-ind/security/pib/pib-sqlite3.hpp>
#include "certstore.hpp"

struct pibCerts : certStore {
    ndn::PibSqlite3 pib_{};

    pibCerts() {
        for (const auto& i: pib_.getIdentities()) {
            auto pk = pib_.getDefaultKeyOfIdentity(i);
            emplace(pib_.getDefaultCertificateOfKey(pk)->getName());
        }
    }
    pibCerts(certVec&& certs) { insert(certs.begin(), certs.end()); }

    auto getCert(const certName& nm) const { return pib_.getCertificate(nm); }

    // Given a certname, return the portion NDN calls the 'key name' (all but the last 2 components)
    // (this is the TPM locator for the signing key).
    auto getKeyName(const certName& nm) const { return nm.getPrefix(-2); }

    bool canSign(const certName& nm) const { return ndn::KeyChain().getTpm().hasKey(getKeyName(nm)); }
};

#endif // PIBCERTS_HPP
