#ifndef SIGMGR_HPP
#define SIGMGR_HPP
/*
 * Signature Manager abstraction
 *
 * Copyright (C) 2019 Pollere, Inc.
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

/*
 * Base class for signature managers. Provides a 'null' signer (no
 * signature added to data) and an accept-all validator). Both of
 * these methods should be overridden in derived classes.
 */

/*
 * Five signature-managers and using SIGNER_TYPE:
 *  0x00 SHA256
 *  0x03 ECDSA
 *  0x07 AEAD
 *  0x08 EdDSA
 *  0x09 RFC7693
 */

#include <ndn-ind/generic-signature.hpp>

// this file is included by syncps.hpp so libsodium calls can be available
extern "C" {
    #include <sodium.h>
};

// type signatures for validate() callbacks 
using ValidDataCb = std::function<void(const ndn::Data&)>;
using FailedDataCb = std::function<void(const ndn::Data&, const std::string&)>;
using keyVal = std::vector<uint8_t>;
using SigInfo = std::vector<uint8_t>;
using SigType = uint8_t;

struct SigMgr {
    SigMgr(SigType typ, SigInfo&& si = {}) : m_type{typ}, m_sigInfo{si} {}
    virtual bool sign(ndn::Data& d) { return sign(d, m_sigInfo); };
    virtual bool sign(ndn::Data&, const SigInfo&) { return false; };
    virtual bool validate(ndn::Data&) { return true; };
    virtual void addKey(const std::vector<uint8_t>, uint64_t) {};
    virtual void updateSigningKey(const std::vector<uint8_t>, const ndn::CertificateV2) {};
    virtual bool needsKey() const noexcept { return 1; };

    void validate(ndn::Data& d, const ValidDataCb& vCB, const FailedDataCb& fCB) {
        validate(d) ? vCB(d) : fCB(d, "signature error");
    }

    SigType type() const noexcept { return m_type; };
    SigInfo getSignatureInfo() const noexcept { return m_sigInfo; }

    // sign() helper method
    auto setupSignature(ndn::Data& data, const SigInfo& si) const {
        auto signatureInfo = ndn::GenericSignature();
        signatureInfo.setSignatureInfoEncoding(ndn::Blob(si.data(), si.size()));
        data.setSignature(signatureInfo);
        return data.wireEncode();
    }

    const SigType m_type;
    SigInfo m_sigInfo;
};

#endif //SIGMGR_HPP
