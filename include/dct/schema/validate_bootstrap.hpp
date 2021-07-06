#ifndef VALIDATE_BOOTSTRAP_HPP
#define VALIDATE_BOOTSTRAP_HPP
/*
 * validate and load the DCT bootstrap identity information
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

#include <string_view>
#include "cert_bundle.hpp"
#include "cert_to_schema.hpp"
#include "certstore.hpp"
#include "validate_certs.hpp"
#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"


// return the binary schema described by 'scert'. If the schema has already
// been loaded and parsed, just return it. Otherwise load, parse and save
// the copy in scert's content block.
static inline const bSchema& loadSchema(const dctCert& scert) {
    // map containing schemas loaded so far
    static std::unordered_map<std::string,bSchema> schemas{};

    // schema name is 5th from end of cert name
    auto v = scert.getName()[-5].getValue();
    std::string schema((const char*)v.buf(), v.size());

    // if the schema has been loaded just return it
    if (auto s = schemas.find(schema); s != schemas.end()) return s->second;

    schemas.emplace(schema, certToSchema(scert));
    return schemas[schema];
}


// 'bootstrap' is a cert bundle file containing the information needed to start a DCT app:
//      0: the trust anchor
//      1: the schema
//      2..n-2: signing cert's signing chain
//      n-1: signing cert and its key
// This routine loads the bundle and distributes the contents to the cert & schema
// stores. Nothing in the bundle is trusted implicitly so all of the contents are
// validated.
static inline const auto& validateBootstrap(std::string_view bootstrap, certStore& cs) {

    auto cb = rdCertBundle(fileToVec(bootstrap));
    // first item must be a trust anchor and validly signed
    // all items in the bundle must use the same signature type so use root's
    // type to get a sigMgr then validate the root.
    const auto& root = cb[0].first;
    auto sigType = root.getSigType();
    auto sm = sigMgrByType(sigType);
    if (! sm.needsKey()) throw schema_error("bootstrap certs can't use a keyless validator");
    if (! root.selfSigned()) throw schema_error("bootstrap first item not a trust anchor");
    if (! sm.validate(root, root)) throw schema_error("trust anchor doesn't validate");
    cs.add(root);

    // validate then load the schema
    const auto& scert = cb[1].first;
    if (! sm.validate(scert, root)) throw schema_error("schema cert doesn't validate");
    const auto& scname = scert.getName();
    if (to_sv(scname[-6]) != "schema" || to_sv(scname[-4]) != "KEY")
        throw schema_error("schema cert name malformed");

    const auto& bs = loadSchema(scert);
    if (getSigMgr(bs).ref().type() != sigType)
        throw schema_error("schema signature type doesn't match its pubValidator");

    // check that schema and root cert match (root cert is always last in schema cert table)
    if (! matches(bs, root.getName(), bs.cert_.size() - 1))
        throw schema_error("root cert name doesn't match schema's root cert");

    // check that schema cert name starts with schema's pub prefix, has the correct
    // length and is for the right pub name.
    auto pubPre = bs.pubTmpl0(bs.findPub("#pubPrefix"));
    if (pubPre.size() == 0 || scname.size() - pubPre.size() != 6 || to_sv(scname[-5]) != bs.pubName(0))
        throw schema_error("schema cert name malformed");

    cs.add(scert);

    // check that all certs have the right sigType, each locator refers to the previous
    // and is validated by the previous.
    for (size_t c = 2, l = 0; c < cb.size(); l = c++) {
        const auto& [cert, key] = cb[c];
        const auto& prev = cb[l].first;
        if (cert.getSigType() != sigType) throw schema_error("bundle certs don't all have same signing type");
        if (cert.getKeyLoc() != prev.computeThumbPrint()) throw schema_error("signing chain invalid");
        if (! sm.validate(cert, prev)) throw schema_error(format("cert {} doesn't validate", c));
        if (matchesAny(bs, cert.getName()) < 0) throw schema_error(format("cert {} doesn't match a schema cert", cert.getName().toUri()));
        cs.add(cert, key);
    }
    // final cert is the signing cert - make it the signing chain head
    auto sc = cb.back().first;
    if (validateChain(bs, cs, sc) < 0) throw schema_error(format("cert {} signing chain invalid", sc.getName().toUri()));
    cs.addChain(sc);

    return bs;
}

#endif // VALIDATE_BOOTSTRAP_HPP
