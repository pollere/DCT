#ifndef DIST_SGKEY_HPP
#define DIST_SGKEY_HPP
#pragma once
/*
 * dist_sgkey - distribute a pub/priv X keypair to the members in a bespoke
 * transport using publisher privacy with authorized subscription. Only authorized
 * members (via capability in identity chain) receive the secret key
 * This version is a self-contained 'header-only' library.
 *
 * DistSGKey manages all the group key operations including the decision on
 * which (eligible) entity will create the subscriber group key pair. Only one entity should
 * be making group key pairs and will rekey at periodic intervals to distribute
 * a new key, encrypting each private key with the public key of each peer with
 * subscriber capability (see https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519),
 * denoted by "SG" capability. The corresponding public key is not encrypted.
 * If a new subscribing member joins between rekeying, it is added to the member
 * list and a Publication with a secret key encrypted for it is published.
 * The group key pair is used by sigmgr_ppaead.hpp and sigmgr_ppsigned.hp
 *
 * Any entity with a valid certificate for this trust schema (i.e., any entity that belongs to
 * this trust domain) can publish but must have the appropriate SG (denoted by the
 * SG cert's capability argument) in order to subscribe.
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
 *  dist_sgkey is not intended as production code.
 */

#include <algorithm>
#include <cstring> // for memcmp
#include <functional>
#include <utility>

#ifndef KEM
#define KEM 0
#endif
#if KEM>0
#include "dist_kem.hpp" // for KEM style key distributor with xwing option
#else
#include "dist_key.hpp" // for original key distributor that keeps a member list
#endif

namespace dct {

struct DistSGKey :
    DistKey<crypto_kx_SECRETKEYBYTES, crypto_kx_SECRETKEYBYTES + crypto_box_SEALBYTES, crypto_kx_PUBLICKEYBYTES> {
 //   DistKey<crypto_kx_SECRETKEYBYTES, crypto_kx_SECRETKEYBYTES + crypto_box_SEALBYTES, crypto_kx_PUBLICKEYBYTES> {
    /*
     * DistSGKey Publications contain the creation time of the group key pair (an 8 byte
     * uint64_t), the pair public key (kxpkKeySz) and a list containing the pair secret key
     * individually encrypted for each authorized subscriber peer. The list holds the
     * thumbprint of a signing key and the group secret key encrypted using that (public)
     * signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators and sigInfo)
     */

    std::string sgColl_{}; // the subscriber group handled by this distributor (for now just use last part of collection name)
    capValCB sgMbr_;    //to check signing chain for SG capability for the sgColl_ subscriber group
    // sDecKey_ from base class holds sk converted to X is used by subr to open sealed box with
    //  subscriber group secret key
    // grpPK_ from base class is current subscribergroup public key: made and kept by keymaker

    DistSGKey(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs, addKeyCb&& keyCb,
              tdv_clock::duration reKeyInterval = 3600s) :
          //    DistKey("kysbr", face, pPre, dPre, cs, std::move(keyCb), reKeyInterval, expirationGB) {
              DistKey("kysbr", face, pPre, dPre, cs, std::move(keyCb), reKeyInterval) {
        sgColl_ = sync_.collName_.last().toSv(); // should be either msgs or pdus
        pubOnlyPossible_ = true;    // SG may have subscribe only members
        // compute space for content for the key list Publication. Other Pubs are smaller, so use worst-case
        maxContent_ = sync_.maxInfoSize() - (prefix_.size() + 2 +3 + 9 + 2 + 2 + 2*(4+2));
        if (maxContent_ < ssize_t(6 + pkSize_  + sizeof(thumbPrint) + encSKSz_))
            throw ("DistSGKey: not enough space in Pub Content to carry key record list");
        // maximum number of encrypted SKs per publication
        maxKR_ = (maxContent_ - pkSize_ - 6) / (sizeof(thumbPrint) + encSKSz_);

        // updateSigningKey was called from dist base class so have identity
        /* build function to get the subscriber group id (if any) from a signing chain
         * checks if SG cap is present and, if so, returns its argument
         * return 0 if cap wasn't found or has wrong content
         * XXX eventually might use a specific subcollection */
        auto sgId = Cap::getval("SG", prefix_, cs_);
        sgMbr_ = [this,sgId](const thumbPrint& tp) { return sgId(tp).toSv() == sgColl_; };
        subscriber_ = sgMbr_(tp_);
        if (subscriber_)  convertSK(cs_.key(tp_), cs_[tp_]);  // member has subscriber group capability, convert the new key to form needed for group key encrypt/decrypt
    }

    // methods for  _kem

    // called on (new) signing cert after update to see if this is a subscriber and thus will need to decrypt group secret key
    bool setSubscriber() override {
        if( subscriber_ != sgMbr_(tp_) )
            std::runtime_error("DistSGKey::isSubscriber subscriber group capability change indicates bad signing chain");
        if (!(subscriber_ = sgMbr_(tp_))) return false;  // this identity is publish only
        return true;
    }
    // specific to this distributor: tp identity is disqualified from getting group secret key if not in subscriber group
     bool isSubscriber(thumbPrint& tp) override  {return sgMbr_(tp);}

    // make a new key pair for subscriber group distributor
    void getNewKey() override {
        grpPK_.resize(pkSize_);
        grpSK_.resize(skSize_);
        crypto_kx_keypair(grpPK_.data(), grpSK_.data());    // set key pair: X25519
    }

    // only needed for _key
    #if KEM < 1
    // called on (new) signing cert after update to see if this is a subscriber and thus will need to decrypt group secret key

    bool pkOnly(keyVal& pk, uint64_t ct) override {
        if (subscriber_) return false;
        // not a subscriber, set public key to received value, secret key to size 0 and finish
        grpKeyVT_ = ct;
        grpPK_ = pk;
        grpSK_.resize(0);
        newKeyCb_(grpSK_, grpPK_, grpKeyVT_); //use addKeyCb to set new sg public key in pub privacy sigmgr
        if (init_) initDone();
        return true;
    }

    bool mReqNeeded() override { return (!mrPending_ && subscriber_); }

     void publishKeyList(const thumbPrint& tpl, const thumbPrint& tph, std::span<const keyRec> esk) override {
        tlvEncoder krEnc{};    //tlv encoded content
        krEnc.addNumber(36, grpKeyVT_);
        krEnc.addArray(150, grpPK_);
       krEnc.addArray(130, esk.begin(), esk.size());
       publishKeyRange(tpl, tph, krEnc.vec());
    }
#endif
};
}   // namespace dct

#endif //DIST_SGKEY_HPP

