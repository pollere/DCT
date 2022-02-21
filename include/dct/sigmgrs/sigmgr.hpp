#ifndef SIGMGR_HPP
#define SIGMGR_HPP
/*
 * Signature Manager abstraction
 *
 * Copyright (C) 2019-2 Pollere LLC
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
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

/*
 * Base class for signature managers. Provides a 'null' signer (no
 * signature added to data) and an accept-all validator). Both of
 * these methods should be overridden in derived classes.
 */

/*
 * Five signature-managers and using SIGNER_TYPE:
 *  0x00 SHA256
 *  0x07 AEAD
 *  0x08 EdDSA
 *  0x09 RFC7693
 *  0x0a NULL
 * Note that NULL is used to bypass signing for dctCerts which are already
 * signed and should not be used otherwise.
 */

#include <ndn-ind/data.hpp>
#include <ndn-ind/generic-signature.hpp>
#include <dct/schema/rpacket.hpp>

// this file is included by syncps.hpp so libsodium calls can be available
extern "C" {
    #include <sodium.h>
};

// type signatures for validate() callbacks 
using ValidDataCb = std::function<void(ndn::Data&)>;
using FailedDataCb = std::function<void(ndn::Data&, const std::string&)>;

using keyVal = std::vector<uint8_t>;
using keyRef = std::span<const uint8_t>;
using SigInfo = std::vector<uint8_t>;
using SigType = uint8_t;
using dct_Cert = ndn::Data;

//using KeyCb = std::function<const std::vector<uint8_t>&(const ndn::Data&)>;
using KeyCb = std::function<keyRef(rData)>;

struct SigMgr {
    SigType m_type;
    SigInfo m_sigInfo;
    keyVal m_signingKey{};
    KeyCb m_keyCb{};
 
    // Signature types (must match equivalent NDN TLV when there is one)
    static constexpr SigType stSHA256 = 0;
    static constexpr SigType stAEAD = 7;
    static constexpr SigType stEdDSA = 8;
    static constexpr SigType stRFC7693 = 9;
    static constexpr SigType stNULL = 10;

    SigMgr(SigType typ, SigInfo&& si = {}) : m_type{typ}, m_sigInfo{std::move(si)} {}
    SigMgr(SigType typ, const SigInfo& si) : m_type{typ}, m_sigInfo{si} {}

    bool sign(rData d) { return sign(d, m_sigInfo, m_signingKey); };
    bool sign(rData d, const SigInfo& si) { return sign(d, si, m_signingKey); }
    virtual bool sign(rData, const SigInfo&, const keyVal&) { return false; };
    virtual bool validate(rData ) { return false; };
    virtual bool validate(rData, const dct_Cert&) { return false; };
    virtual bool validateDecrypt(rData d) { return validate(d); };

    bool sign(ndn::Data& d) { return sign(d, m_sigInfo, m_signingKey); };
    bool sign(ndn::Data& d, const SigInfo& si) { return sign(d, si, m_signingKey); }
    virtual bool sign(ndn::Data&, const SigInfo&, const keyVal&) { return false; };
    virtual bool validate(const ndn::Data&) { return false; };
    virtual bool validate(const ndn::Data&, const dct_Cert&) { return false; };

    virtual void addKey(const keyVal&, uint64_t = 0) {};
    virtual void updateSigningKey(const keyVal&, const dct_Cert&) {};
    virtual bool needsKey() const noexcept { return 1; };

    // if validate requires public keys of publishers, m_keyCb returns by keylocator
    void setKeyCb(KeyCb&& kcb) { m_keyCb = std::move(kcb);}

    void validate(ndn::Data& d, const ValidDataCb& vCB, const FailedDataCb& fCB) {
        validate(d) ? vCB(d) : fCB(d, "signature error");
    }

    SigType type() const noexcept { return m_type; };
    SigInfo getSigInfo() const noexcept { return m_sigInfo; }

    // sign() helper method
    auto setupSignature(ndn::Data& data, const SigInfo& si) const {
        auto sigInfo = ndn::GenericSignature();
        sigInfo.setSignatureInfoEncoding(si);
        data.setSignature(sigInfo);
        return data.wireEncode();
    }
};

#endif //SIGMGR_HPP
