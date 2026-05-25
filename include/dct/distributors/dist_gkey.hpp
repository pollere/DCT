#ifndef DIST_GKEY_HPP
#define DIST_GKEY_HPP
#pragma once
/*
 * dist_gkey - distribute a symmetric encryption key to a group of peers.
 * This version is a self-contained 'header-only' library.
 *
 * DistGKey manages all the group key operations including the decision on
 * which (eligible) entity will create the group key. Only one entity should
 * be making group keys and will rekey at periodic intervals to distribute
 * a new key, encrypting each key with the public key of each peer (see
 * https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519). If a new
 * member joins between rekeying, it is added to the list of encrypted keys and
 * a key list publication is issued with just the new encrypted key.
 *
 * This distributor puts three separate subtopics into use: <pubprefix>/{km,mr,gk}
 * where <pubprefix> is passed in as the topic for all publications and
 * subtopic km is used by the key maker election,
 * subtopic mr is used by members of the group to request a copy of the encryption key, and
 * subtopic gk is used by the key maker to publish key records where the symmetric key is encrypted
 *      for each valid member of the group.
 * The PDU prefix the distributor's sync uses is <tp_id>/keys/<msgs || pdus>, in the "keys" collection
 *
 * As soon as its syncps is registered, it will receive pubs into its collection(s) but the pubs don't invoke
 * a subscription callback until one is registered (in start)
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
 *  dist_gkey is not intended as production code.
 */

#include "dist_key.hpp"

namespace dct {

struct DistGKey :
    DistKey<crypto_aead_xchacha20poly1305_IETF_KEYBYTES,
            crypto_aead_xchacha20poly1305_IETF_KEYBYTES + crypto_box_SEALBYTES> {
    /*
     * DistGKey Publications contain the creation time of the symmetric key and a list of
     * pairs containing that symmetric key individually encrypted for each peer. Each
     * pair has the thumbprint of a signing key and the symmetric key encrypted using that
     * (public) signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators)
     */

    DistGKey(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs,  addKeyCb&& keyCb,
             tdv_clock::duration reKeyInterval = 3600s, tdv_clock::duration reKeyRandomize = 10s,
             tdv_clock::duration expirationGB = 60s) :
             DistKey("kygrp", face, pPre, dPre, cs, std::move(keyCb), reKeyInterval, reKeyRandomize, expirationGB) {
        // compute space for content for the key list Publication. Other Pubs are smaller, so use worst-case
        maxContent_ = sync_.maxInfoSize() - (prefix_.size() + 2 +3 + 9 + 2 + 2 + 2*(4+2));    // all the components of Name
        if (maxContent_ < ssize_t(sizeof(thumbPrint) + DistKey::encSKSz_))
            throw ("DistGKey: not enough space in Pub Content to carry group key list");
        maxKR_ = (maxContent_) / (sizeof(thumbPrint) + DistKey::encSKSz_);
        // print ("DistGKey: maxContent is {} max num key records is {}\n", maxContent_, maxKR_);

        convertSK(cs_.key(tp_), cs_[tp_]);    // updateSigningKey was called from dist base class
     }

 };
} // namespace dct

#endif //DIST_GKEY_HPP
