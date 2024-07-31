#ifndef SIGMGR_HPP
#define SIGMGR_HPP
#pragma once
/*
 * Signature Manager abstraction
 *
 * Copyright (C) 2019-2 Pollere LLC
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
 * Base class for signature managers. Provides a 'null' signer (no signing,
 * provided for certs, and an accept-all validator). Both of
 * these methods should be overridden in derived classes.
 */

#include <functional>
#include <span>

// this file is included by syncps.hpp so libsodium calls can be available
extern "C" {
    #include <sodium.h>
};

#include "sigmgr_defs.hpp"
#include "../schema/crpacket.hpp"

namespace dct {

using KeyCb = std::function<keyRef(rData)>;

struct SigMgr {
    const SigType m_type;
    const SigSize m_sigSize;
    SigInfo m_sigInfo;
    keyVal m_signingKey{};
    KeyCb m_keyCb{};

    // types that require a key locator in their sigInfo   
    static constexpr uint64_t needsKey_{ (1 << stEdDSA) | (1 << stPPAEAD) | (1 << stPPSIGN) | (1 << stAEADSGN) };
    static constexpr bool needsKey(SigType typ) noexcept { return (needsKey_ & (1 << typ)) != 0; };

    // types that encrypt content
    static constexpr uint64_t encryptsContent_{(1 << stAEAD) | (1 << stAEGIS) | (1 << stPPAEAD) |
                                               (1 << stPPSIGN) | (1 << stAEADSGN)};
    static constexpr bool encryptsContent(SigType typ) noexcept  { return (encryptsContent_ & (1 << typ)) != 0; };

    // types that with restricted subscriber group
    static constexpr uint64_t subscriberGroup_{(1 << stPPAEAD) | (1 << stPPSIGN)};
    static constexpr bool subscriberGroup(SigType typ) noexcept  { return (subscriberGroup_ & (1 << typ)) != 0; };

    // build a siginfo for signing key type 'typ'
    auto  mkSigInfo(SigType typ) {
        if (! needsKey(typ)) {
            auto a = TLV<tlv::SignatureInfo>(TLV<tlv::SignatureType>(typ));
            return SigInfo{a.begin(), a.end()};
        } else {
            auto a = TLV<tlv::SignatureInfo>(tlvFlatten(
                        TLV<tlv::SignatureType>(typ),
                        TLV<tlv::KeyLocator>(TLV<tlv::KeyDigest>(std::array<uint8_t,thumbPrint_s>{}))));
            return SigInfo{a.begin(), a.end()};
        }
    }

    SigMgr(SigType typ, SigSize sz) : m_type{typ}, m_sigSize{sz}, m_sigInfo{mkSigInfo(typ)} {
        if (sodium_init() == -1) exit(EXIT_FAILURE);
    }
    bool sign(crData& d) { return sign(d, m_sigInfo, m_signingKey); };
    bool sign(crData& d, const SigInfo& si) { return sign(d, si, m_signingKey); }
    virtual bool sign(crData&, const SigInfo&, const keyVal&) { abort(); };
    virtual bool validate(rData ) { return false; };
    virtual bool validate(rData, const rData&) { return false; };
    virtual bool validateDecrypt(rData d) { return validate(d); };
    virtual bool validateDecrypt(rData d, const rData&) { return validate(d); };
    virtual bool decrypt(rData) { return true; };

    virtual void addKey(keyRef, uint64_t = 0) {};
    virtual void addKey(keyRef pk, keyRef, uint64_t = 0) { addKey(pk, 0); };
    virtual void updateSigningKey(keyRef, const rData&) {};

    constexpr bool needsKey() const noexcept { return needsKey(m_type); };
    constexpr bool encryptsContent() const noexcept { return encryptsContent(m_type); };
    constexpr bool subscriberGroup() const noexcept { return subscriberGroup(m_type); };

    // if validate requires public keys of publishers, m_keyCb returns by keylocator
    void setKeyCb(KeyCb&& kcb) { m_keyCb = std::move(kcb);}

    constexpr SigType type() const noexcept { return m_type; };
    constexpr SigSize sigSize() const noexcept { return m_sigSize; };
    constexpr SigInfo getSigInfo() const noexcept { return m_sigInfo; }
    // when constructing packets, need to know the total space occupied
    // by sigInfo & signature including their outer TLV headers
    constexpr SigSize sigSpace() const noexcept { return m_sigInfo.size() + m_sigSize + 4; };
};

} // namespace dct

#endif //SIGMGR_HPP
