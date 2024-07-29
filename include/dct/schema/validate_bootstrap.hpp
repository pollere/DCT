#ifndef VALIDATE_BOOTSTRAP_HPP
#define VALIDATE_BOOTSTRAP_HPP
#pragma once
/*
 * validate and load the DCT bootstrap identity information
 *
 * Copyright (C) 2020-3 Pollere LLC
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

#include <string_view>
#include "cert_bundle.hpp"
#include "cert_to_schema.hpp"
#include "certstore.hpp"
#include "validate_certs.hpp"
#include "dct/file_to_vec.hpp"
#include "dct/format.hpp"

namespace dct {

using certCb = std::function< dctCert ()>;
using chainCb = std::function<std::vector<dctCert> ()>;
using pairCb = std::function<certItem()>;

// return the binary schema described by 'scert'. If the schema has already
// been loaded and parsed, just return it. Otherwise load, parse and save
// the copy in scert's content block.
static inline const bSchema& loadSchema(const dctCert& scert) {
    // map containing schemas loaded so far
    static std::unordered_map<thumbPrint,const bSchema> schemas{};

    // if the schema has been loaded just return it
    auto tp = scert.computeThumbPrint();
    if (auto s = schemas.find(tp); s != schemas.end()) return s->second;

    return schemas.try_emplace(tp, certToSchema(scert, tp)).first->second;
}

// 'bootstrap' of a Defined-trust transport instance requires the following certs and one secret key
//      0: the trust anchor
//      1: the schema
//      2..n-2: signing cert's signing chain
//      n-1: signing cert and its key
// This routine retrieves the required certs, performs validation, and distributes the contents to the cert & schema
// stores. Nothing is trusted implicitly so all of the certs are validated.
static inline const auto& validateBootstrap(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, certStore& cs) {
    // first cert needed is a validly signed trust anchor
    // all certs must use the same signature type so use root's
    // type to get a sigMgr then validate the root.
    auto root = rootCb();
    auto sigType = root.getSigType();
    auto sm = sigMgrByType(sigType);
    if (! sm.needsKey()) throw schema_error("bootstrap certs can't use a keyless validator");
    if (! root.selfSigned()) throw schema_error("bootstrap first item not a trust anchor");
    if (! sm.validate(root, root)) throw schema_error("trust anchor doesn't validate");
    cs.add(root);

    // validate then load the schema
    auto scert = schemaCb();
    if (! sm.validate(scert, root)) throw schema_error("schema cert doesn't validate");
    auto scname = tlvVec{scert.name()};
    if (scname[-6].toSv() != "schema" || scname[-4].toSv() != "KEY")
        throw schema_error("schema cert name malformed");

    const auto& bs = loadSchema(scert);
    // check if it matches the certValidator from schema
    if (getCertSigMgr(bs).ref().type() != sigType)
        throw schema_error("schema signature type doesn't match its certValidator");

    // check that schema and root cert match (root cert is always last in schema cert table)
    if (! matches(bs, root.name(), bs.cert_.size() - 1))
        throw schema_error("root cert name doesn't match schema's root cert");

    // check that schema cert name starts with schema's pub prefix, has the correct
    // length and is for the right pub name.
    auto pubPre = bs.pubTmpl0(bs.findPub("#pubPrefix"));
    if (pubPre.size() == 0 || scname.size() - pubPre.size() != 6 || scname[-5].toSv() != bs.pubName(0))
        throw schema_error("schema cert name malformed");

    cs.add(scert);

    // check that all identity chain certs have the right sigType, each locator refers to the previous
    // and is validated by the previous.
    auto ch = idChainCb();
    auto prevTP = root.computeThumbPrint();
    for (size_t c = 0; c < ch.size(); c++) {
        const auto& cert = ch[c];
        if (cert.getSigType() != sigType) throw schema_error("identity chain certs don't all have same signing type");
        if (cert.getKeyLoc() != prevTP) throw schema_error(format("cert {} signing chain invalid",cert.name()));
        if (! sm.validate(cert, cs[prevTP])) throw schema_error(format("cert {} doesn't validate", c));
        if (matchesAny(bs, cert.name()) < 0) throw schema_error(format("cert {} doesn't match a schema cert", cert.name()));
        cs.add(cert);
        prevTP = cert.computeThumbPrint();
    }

    // all the bootstrap identity certs are valid, ask for a signing pair of <cert, secretKey> to complete the chain
    auto sp = signIdCb();
    auto sc = sp.first;

    // belt and suspenders? This code would be repeated when a new signing pair is created
    if (sc.getSigType() != sigType) throw schema_error("signing pair cert has incorrect signing type");
    if (sc.getKeyLoc() != ch.back().computeThumbPrint())
        throw schema_error(format("signing pair cert  invalid"));
    if (! sm.validate(sc, ch.back())) throw schema_error(format("signing cert doesn't validate"));
    if (matchesAny(bs, sc.name()) < 0) throw schema_error(format("signing cert doesn't match a schema cert"));

    //add this signing cert
    cs.add(sp.first, sp.second);
    // make it the signing chain head
    if (validateChain(bs, cs, sc) < 0) throw schema_error(format("cert {} signing chain invalid", sc.name()));
    cs.addChain(sc);    //this could be cs.insertChain(sc) to match rekey actions

    return bs;
}

// This routine is only for tools that validate or display 'bootstrap' bundle files.
// The callback-based version above should be used by applications.
//
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
    auto scname = tlvVec{scert.name()};
    if (scname[-6].toSv() != "schema" || scname[-4].toSv() != "KEY")
        throw schema_error("schema cert name malformed");

    const auto& bs = loadSchema(scert);
    if (getCertSigMgr(bs).ref().type() != sigType)
        throw schema_error("schema signature type doesn't match its certValidator");

    // check that schema and root cert match (root cert is always last in schema cert table)
    if (! matches(bs, root.name(), bs.cert_.size() - 1))
        throw schema_error("root cert name doesn't match schema's root cert");

    // check that schema cert name starts with schema's pub prefix, has the correct
    // length and is for the right pub name.
    auto pubPre = bs.pubTmpl0(bs.findPub("#pubPrefix"));
    if (pubPre.size() == 0 || scname.size() - pubPre.size() != 6 || scname[-5].toSv() != bs.pubName(0))
        throw schema_error("schema cert name malformed");

    cs.add(scert);

    // check that all certs have the right sigType, each locator refers to the previous
    // and is validated by the previous.
    for (size_t c = 2, l = 0; c < cb.size(); l = c++) {
        const auto& [cert, key] = cb[c];
        const auto& prev = cb[l].first;
        if (cert.getSigType() != sigType) throw schema_error("bundle certs don't all have same signing type");
        if (cert.getKeyLoc() != prev.computeThumbPrint())
            throw schema_error(format("cert {} signing chain invalid",cert.name()));
        if (! sm.validate(cert, prev)) throw schema_error(format("cert {} doesn't validate", c));
        if (matchesAny(bs, cert.name()) < 0) throw schema_error(format("cert {} doesn't match a schema cert", cert.name()));
        cs.add(cert, key);
    }
    // final cert is the signing cert - make it the signing chain head
    auto sc = cb.back().first;
    //if (validateChain(bs, cs, sc) < 0) throw schema_error(format("cert {} signing chain invalid", sc.name()));
    cs.addChain(sc);

    return bs;
}

} // namespace dct

#endif // VALIDATE_BOOTSTRAP_HPP
