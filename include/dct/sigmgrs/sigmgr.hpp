#ifndef SIGMGR_HPP
#define SIGMGR_HPP
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

/*
 * List of available signature-managers and SIGNER_TYPE:
 *  0x00 SHA256
 *  0x07 AEAD
 *  0x08 EdDSA
 *  0x09 RFC7693
 *  0x0a NULL
 *  0x0b PPAEAD
 *  0x0c PPSIGN
 * Note that NULL is used to bypass signing for dctCerts which are already
 * signed, does not appear in "wire" packets and should not be otherwise used.
 */

#include <span>


// this file is included by syncps.hpp so libsodium calls can be available
extern "C" {
    #include <sodium.h>
};

using keyVal = std::vector<uint8_t>;
using keyRef = std::span<const uint8_t>;
using SigInfo = std::vector<uint8_t>;
using SigType = uint8_t;

#include <dct/schema/dct_cert.hpp>

using KeyCb = std::function<keyRef(rData)>;

struct SigMgr {
    // Signature types (must match equivalent NDN TLV when there is one)
    static constexpr SigType stSHA256 = 0;
    static constexpr SigType stAEAD = 7;
    static constexpr SigType stEdDSA = 8;
    static constexpr SigType stRFC7693 = 9;
    static constexpr SigType stNULL = 10;
    static constexpr SigType stPPAEAD = 11;
    static constexpr SigType stPPSIGN = 12;

    const SigType m_type;
    SigInfo m_sigInfo;
    keyVal m_signingKey{};
    KeyCb m_keyCb{};

    // types that require a key locator in their sigInfo 
    static constexpr uint16_t m_needsKeyLoc{(1 << stEdDSA) | (1 << stPPAEAD) | (1 << stPPSIGN)};
 
    static constexpr bool needsKey(SigType typ) noexcept { return (m_needsKeyLoc & (1 << typ)) != 0; };

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

    SigMgr(SigType typ) : m_type{typ}, m_sigInfo{mkSigInfo(typ)} { if (sodium_init() == -1) exit(EXIT_FAILURE); }

    bool sign(crData& d) { return sign(d, m_sigInfo, m_signingKey); };
    bool sign(crData& d, const SigInfo& si) { return sign(d, si, m_signingKey); }
    virtual bool sign(crData&, const SigInfo&, const keyVal&) { abort();return false; };
    virtual bool validate(rData ) { return false; };
    virtual bool validate(rData, const rData&) { return false; };
    virtual bool validateDecrypt(rData d) { return validate(d); };
    virtual bool validateDecrypt(rData d, const rData&) { return validate(d); };
    //sigmgrs make own copies
    virtual void addKey(keyRef, uint64_t = 0) {};
    virtual void addKey(keyRef pk, keyRef, uint64_t = 0) { addKey(pk, 0); };
    virtual void updateSigningKey(keyRef, const rData&) {};

    constexpr bool needsKey() const noexcept { return needsKey(m_type); };

    // if validate requires public keys of publishers, m_keyCb returns by keylocator
    void setKeyCb(KeyCb&& kcb) { m_keyCb = std::move(kcb);}

    SigType type() const noexcept { return m_type; };
    SigInfo getSigInfo() const noexcept { return m_sigInfo; }
};

#endif //SIGMGR_HPP
