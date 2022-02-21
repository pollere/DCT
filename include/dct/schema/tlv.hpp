#ifndef TLV_HPP
#define TLV_HPP
/*
 * Data Centric Transport NDN c++ TLV defines
 * (from NDN Packet Format Specification 0.3
 *  https://named-data.net/doc/NDN-packet-spec/current/types.html)
 *
 * Copyright (C) 2022 Pollere LLC.
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

enum class tlv : uint16_t {
    Name = 7,
        // name component types
        GenericNameComponent = 8,
        ImplicitSha256DigestComponent = 1,
        ParametersSha256DigestComponent = 2,
        KeywordNameComponent = 32,
        SegmentNameComponent = 33,
        ByteOffsetNameComponent = 34,
        VersionNameComponent = 35,
        TimestampNameComponent = 36,
        SequenceNumNameComponent = 37,

    // an NDN Interest packet contains exactly 5 TLV blocks in the following order:
    //   7 (Name), 10 (Nonce), 12 (InterestLifetime), 33 (CanBePrefix) 18 (MustBeFresh),
    Interest = 5,
        Nonce = 10,
        InterestLifetime = 12,
        CanBePrefix = 33,
        MustBeFresh = 18,
        // TLVs that can't be in a DCT Interest
        //ForwardingHint = 30,
        //HopLimit = 34,
        //ApplicationParameters = 36,

    // an NDN Data packet contains exactly 5 TLV blocks in the following order:
    //   7 (Name), 20 (Metainfo), 21 (Content), 22 (SignatureInfo), 23 (SignatureValue)
    Data = 6,
        MetaInfo = 20,
            ContentType = 24,
                // Content types
                ContentType_Blob = 0,
                ContentType_Link = 1,
                ContentType_Key = 2,
                ContentType_Nack = 3,
                ContentType_Manifest = 4,
            FreshnessPeriod = 25,
            //FinalBlockId = 26,
        Content = 21,
        SignatureInfo = 22,
            SignatureType = 27,
                DigestSha256 = 0,
                SignatureSha256WithRsa = 1,
                SignatureSha256WithEcdsa = 3,
                SignatureHmacWithSha256 = 4,
            KeyLocator = 28,
            KeyDigest = 29,
            ValidityPeriod = 253,
                NotBefore = 254,
                NotAfter = 255,
        SignatureValue = 23
};

#endif // TLV_HPP
