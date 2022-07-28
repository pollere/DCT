#ifndef SCHEMA_CAPABILITY_HPP
#define SCHEMA_CAPABILITY_HPP
/*
 * Cap - method(s) to handle DCT schema "capability" certs
 *
 * Capability certs have the format:
 *    <prefix>/CAP/<capName>/<capArg>
 * where <prefix> is the pub prefix for the schema, "CAP" is a
 * reserved name used to indicate that a cert grants a capability,
 * <capName> is the name of the capability granted and <capArg>
 * contains any arguments associated with the capability.
 *
 * Capabilities for some identity cert must be in that cert's signing
 * chain (otherwise the identity could grant itself capabilities)
 * so they're found by walking the chain looking for the a cert
 * starting with <prefix>/CAP/<capName>. 
 *
 * Something that needs to know if some identity has a capability
 * should:
 *  - Add a method variable to hold the capability checker, e.g.,
 *      Cap::capchk m_fooChk;
 *  - Initialize that variable in the constructor's member inits:
 *      ..., m_fooChk{Cap::checker("foo", pubPrefix, cs)}, ...
 *    where 'pubPrefix' is the schema's pub prefix string and
 *    'cs' is a "const CertStore&" reference to the DCT model's
 *    cert store.
 *  - where some identity's thumbPrint needs to be checked to
 *    see if it has been granted the capability do:
 *      if (m_fooChk(tp).first) {
 *          // identity 'tp' has the capability
 *
 * See distributors/dist_gkey.hpp for an example of using this for
 * the KM (Key Maker) capability.
 *
 * Copyright (C) 2022 Pollere LLC
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
 *  capability is not intended as production code.
 */

#include <functional>

#include <dct/schema/certstore.hpp>
#include <dct/schema/rpacket.hpp>

struct Cap {
    using capChk = std::function<std::pair<bool,rData>(const thumbPrint&)>;
    static inline auto checker(const char* cap, const std::string& prefix, const certStore& cs) {
        return [&cs = cs, p = crPrefix{syncps::Name{prefix + "/CAP/" + cap}}]
                (const thumbPrint& tp) -> std::pair<bool,rData> {
                    return cs.chainMatch(tp, [&p](rData c){ return p.isPrefix(c.name()); }); };
    }
};

#endif // SCHEMA_CAPABILITY_HPP
