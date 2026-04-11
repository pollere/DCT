#ifndef DIST_SGKEY_HPP
#define DIST_SGKEY_HPP
#pragma once
/*
 * dist_sgkey - distribute a pub/priv X keypair to the peers in a bespoke
 * transport using publisher privacy with authorized subscription.
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
 * a subscription callback until one is registered (in setup)
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

#include <dct/schema/capability.hpp>
#include <dct/schema/certstore.hpp>
#include <dct/schema/tlv_encoder.hpp>
#include <dct/schema/tlv_parser.hpp>
#include <dct/sigmgrs/sigmgr_by_type.hpp>
#include <dct/syncps/syncps.hpp>
#include <dct/utility.hpp>
#include "dist_gkey.hpp"

namespace dct {

struct DistSGKey : DistGKey {
    static constexpr uint32_t kxpkKeySz = crypto_kx_PUBLICKEYBYTES;
    static constexpr uint32_t kxskKeySz = crypto_kx_SECRETKEYBYTES;
    static constexpr size_t encSGKeySz = crypto_box_SEALBYTES + kxskKeySz;
    using encSGK = std::array<uint8_t, crypto_box_SEALBYTES + kxskKeySz>;

    /*
     * DistSGKey Publications contain the creation time of the group key pair (an 8 byte
     * uint64_t), the pair public key (kxpkKeySz) and a list containing the pair secret key
     * individually encrypted for each authorized subscriber peer. The list holds the
     * thumbprint of a signing key and the group secret key encrypted using that (public)
     * signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators and sigInfo)
     */
    using encKy = std::pair<const thumbPrint, encSGK>;

    std::string sgColl_;    // the subscriber group handled by this distributor (for now just use last part of collection name)
    capValCB sgMbr_;    //to check signing chain for SG capability for the sgColl_ subscriber group
    // sDecKey_ from base holds sk converted to X is used by subr to open sealed box with subscriber group secret key
    // curPK_ from base class is current subscribergroup public key: made and kept by keymaker
    bool subr_{false};         // set if this identity has the subscriber capability

    DistSGKey(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs,  addKeyCb&& keyCb,
             tdv_clock::duration reKeyInterval = 3600s,
             tdv_clock::duration reKeyRandomize = 10s,
             tdv_clock::duration expirationGB = 60s) :
              DistGKey(face, pPre, dPre, cs, std::move(keyCb), reKeyInterval, reKeyRandomize, expirationGB)
              {
        dtype_.assign("kysbr"); // XXX change to append when use dist_key
        initOnAssert_ = true;   // sort-of hack for publisher only groups, may revisit
        if ( sync_.collName_.last().toSv() == "msgs") {
            msgsDist_ = true; dtype_.append("/msgs");
            sgColl_.assign("msgs");  // here should be msgs or pdus
        } else {
            dtype_.append("/pdus");
            sgColl_.assign("pdus");  // here should be msgs or pdus
         }

        if (maxContent_ < (6 + kxpkKeySz  + sizeof(thumbPrint) + encSGKeySz))
            throw ("DistSGKey: not enough space in Pub Content to carry group key list");
        maxKR_ = (maxContent_ - kxpkKeySz - 6) / (sizeof(thumbPrint) + encSGKeySz);
        // if the syncps set its cStateLifetime longer, means we are on a low rate network
        if (sync_.cStateLifetime_ < 5233ms) sync_.cStateLifetime(5233ms);

        // build function to get the subscriber group id (if any) from a signing chain
        //checks if SG cap is present and, if so, returns its argument
        // return 0 if cap wasn't found or has wrong content
        // XXX eventually might use a specific subcollection
        auto sgId = Cap::getval("SG", prefix_, cs_);
        sgMbr_ = [this,sgId](const thumbPrint& tp) { return sgId(tp).toSv() == sgColl_; };
        if ((subr_ = sgMbr_(tp_))) {
            // member has subscriber group capability, convert the new key to form needed for group key encrypt/decrypt
            auto sk = cs_.key(tp_);
            keyVal ssk(sk.begin(), sk.begin()+32);  // only need first 32 bytes of sk (rest is appended pk)
            convertSK(ssk, cs_[tp_]);
        }

        sync_.getLifetimeCb([this,cand=crPrefix(prefix_/"km"/"cand"),elec=crPrefix(prefix_/"km"/"elec"),mreq=crPrefix(mrPrefix_)](const auto& p) ->tdv_clock::duration {
              if (mreq.isPrefix(p.name())) return mrLifetime_;
              if (cand.isPrefix(p.name()) || elec.isPrefix(p.name())) return 3s;
              // if the Publication's signer is the keymaker, its assertion kr and km/elec should persist until there's a new epoch
              // expire normal kr lists with same lifetime as membership requests
              const auto& tp = p.signer();    // get thumbprint of this Pub's signer
              auto n = p.name();
              if (! crPrefix(klPrefix_).isPrefix(p.name())) return 1ms; // shouldn't happen - expect a kr
              auto epoch = n.nextAt(klPrefix_.size()).toNumber();
              if (tp == kmtp_ && epoch < KMepoch_) return 0ms;  // from earlier epoch
              // Check if this is an assertion kr list Pub which should persist
              static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
                         return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };
             auto tpl = n.nextBlk().toSpan();
             auto tpId = std::span(tp).first(tpl.size());    // get corresponding portion of signer's tp
             auto tph = n.nextBlk().toSpan();                // shouldn't actually have to check that tpl=tph
             // keymaker assertion kr should persist for keylifetime
             if(equal(tpId, tpl) && equal(tpl, tph)) return keyLifetime_;
             return mrLifetime_;
        });
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.
     *      use new key immediately to sign - update the my signature managers
     *      if member, send a new membership request
     *      need to keep immediately prior decrypt key
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) override {
        dct::Dist::updateSigningKey(sk, pubCert);

        if( subr_ && !sgMbr_(tp_) )
            std::runtime_error("DistSGKey::updateSigningKey subscriber group capability change indicates bad signing chain");
        if (!(subr_ = sgMbr_(tp_))) return;  // this identity is publish only, done updating signing pair
        // member has subscriber group capability, convert the new key to form needed for group key encrypt/decrypt
        // only need first 32 bytes of sk (rest is appended pk)
        keyVal ssk(sk.begin(), sk.begin()+32);
        convertSK(ssk, cs_[tp_]);

        if (init_) return;
        if (! keyMaker_) {
             publishMembershipReq();
             return;
        }                               
        // if keymaker is rekeyed it needs to change epoch
        if (kmPri_(tp_) <= 0) std::runtime_error("DistSGKey::updateSigningKey keymaker capability change indicates bad signing chain");
        kmtp_ = tp_;
        ++KMepoch_;
        makeGKey(); // redo this so gklists are under the new signing cert
    }

    /*
     * Called when a new Publication is received in the Key Record topic
     * If have subr capability, look for the group key record with *my* key thumbprint
     * Using first 4 bytes of thumbPrints as identifiers. In the unlikely event that the first and last
     * thumbPrint identifiers are the same, doesn't really matter since we look through for our full
     * thumbPrint and just return if don't find it
     * kr names <klPrefix_><epoch><low tpId><high tpId><timestamp>
     */
    void receiveKeyList(const rPub& p) override
    {
        if (msgsDist_ && isRelay(tp_)) return;   // relays don't get keys to decrypt msgs publications

        // test validity of sender and  the key list
        const auto& tp = p.signer();    // thumbprint of this SGKeyRec's signer
        if (!cs_.contains(tp) || kmPri_(tp) <= 0) {
            print("DistSGKey:receiveKeyList ignoring keylist {} signed by expired or unauthorized identity\n", p.name());
            return;
        }

        auto n = p.name();
        auto epoch = n.nextAt(klPrefix_.size()).toNumber();
        // if keylist is from earlier signing key of my identity
        if (cs_[tp].signer() == cs_[tp_].signer()) {
            // keylist is from earlier signing key of my signing identity
            if (init_) {
                // implies I am a restarted keymaker, grab keymaker status and return
                keyMaker_ = true;
                KMepoch_ = ++epoch;    // epoch is incremented when KM gets new signing pair
                sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                gkeyTimeout();  //create a group key and schedule group key creation with this  epoch and current signing cert
             }
             return;
         }
        if (keyMaker_) {
             // another member claims to be a keyMaker - largest thumbPrint and most recent epoch wins
            if ((tp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_)) {
                keyMaker_ = false; // relinquish keymaker status
                sync_.unsubscribe(mrPrefix_);
                kmtp_ = tp;            // set my keymaker to this one
                curKeyCT_ = 0;
                KMepoch_ = epoch;
                if (subr_) publishMembershipReq();
            }
            else return;
        }
        // not a keymaker if get here
        if (init_ && kmtp_ != tp) { // In init state, set or reset my keymaker.
            // test for first keymaker or if this keymaker supersedes previous
            if (KMepoch_ == 0 || ((kmtp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_) || !cs_.contains(kmtp_))) {
                kmtp_ = tp; //  set this klist sender as my keymaker
                KMepoch_ = epoch;
                if (subr_ && !mrPending_) { // if needed, publish a membership request
                    publishMembershipReq();
                    return;                 // haven't sent a mr yet so can't be a secret key for me
                }
            }
        }
        // decode the content to extract key pair creation time and public key
        auto content = p.content();
        decltype(curKeyCT_) newCT{};
        try {
            newCT = content.nextBlk(36).toNumber(); // first tlv should be type 36 and should decode to a uint64_t
            curPK_ = content.nextBlk(150).toVector(); // second tlv should be type 150 that decodes to a vector of uint8_t (for public SG key)
            if(!subr_) {   //I'm not a subscriber, just get public key and finish
                curKeyCT_ = newCT;
                newKeyCb_(curKey_, curPK_, curKeyCT_); //use addKeyCb to set new sg public key in pub privacy sigmgr
                if (init_) initDone();
                return;
            }
        } catch (std::runtime_error& ex) { return; } //ignore this publication - content type error e.what()

        /*
         * I am a subscriber member that has issued at least one membership request in the past
         * (set kmtp_ but may or may not have received a copy of the group key)
         * and may or may not be in init state
         * This key list may service that request or may be an updated gk or updated keymaker
         * Parse the name and make checks to determine if this key record publication should be used.
         * if this msg was from an earlier Key Maker epoch, test for restarted keymaker, otherwise ignore it.
         */
        if (tp == kmtp_) {  //signed by my keymaker's signing key
            if (epoch != KMepoch_) KMepoch_ = epoch; // keymakers bump epoch when they update signing pairs, so shouldn't happen
        } else if (cs_.contains(kmtp_)  && cs_[tp].signer() == cs_[kmtp_].signer()) {
            // same keymaker identity, different signing key could be updated key or restart of same keymaker
            uint64_t pt = std::chrono::duration_cast<std::chrono::microseconds>(n.lastBlk().toTimestamp().time_since_epoch()).count();
            if (epoch > KMepoch_ || (isAssertKL(p) && curKeyCT_ < pt)) {
                // new epoch and and signing cert for my KM or my curKeyCT is older than this packet  or not set yet
                KMepoch_ = epoch;   // update KM and epoch
                curKeyCT_ = 0;
                kmtp_ = tp;
                // a new MR is sent (below) if none for me in this key list
            } else return;  // this seems to be a key list from keymaker's past so ignore it
        } else { // from different identity from my KM  and/or my KM may be expired
            // if this keymaker has a larger tp than my previous keymaker
            // (can resolve conflict after elections though can happen in relayed domains in particular)
            // (re)set my km and curkey ct records so I get a new key and publish MR (below)
            if (!cs_.contains(kmtp_) || (kmtp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_)) {
                KMepoch_ = epoch;   // changing KM
                kmtp_ = tp;
                curKeyCT_ = 0;
                // a new MR is sent (below) if none for me in this sgklist
            } else return;   // from a KM that is displaced by my KM
        }

        static constexpr auto less = [](const auto& a, const auto& b) -> bool {
            auto asz = a.size();
            auto bsz = b.size();
            auto r = std::memcmp(a.data(), b.data(), asz <= bsz? asz : bsz);
            if (r == 0) return asz < bsz;
            return r < 0;
        };

        // get range of ids for which this publication contains secret keys
        auto tpl = n.nextBlk().toSpan();
        auto tph = n.nextBlk().toSpan();
        auto tpId = std::span(tp_).first(tpl.size());
        if((less(tpId, tpl) || less(tph, tpId))) { // check if I'm included in this pub
            if (curKeyCT_ == 0 && !mrPending_) publishMembershipReq(); // make sure new KM has my MR
            return; // no secret key for me in this pub
        }
        std::span<const encKy> skVec{};
        try {
            // a new key will have a creation time larger than curKeyCT_
            if (newCT == curKeyCT_) receivedGK(); //duplicate so ensure not sending MRs
            if(newCT <= curKeyCT_) return; // received key not newer than ours
            // content third tlv should be type 130 and contain a vector of gkr pairs
            skVec = content.nextBlk(130).toSpan<encKy>();
            // (future: ensure it's from the same creator as last time?)
        } catch (std::runtime_error& ex) {
            return; //ignore this groupKey message - content type error e.what()
        }

        // look for my encrypted secret key
        auto it = std::find_if(skVec.begin(), skVec.end(), [this](auto p){ return p.first == tp_; });
        if (it == skVec.end()) {
            // didn't find our encrypted key in pub - make sure current KM has our request
            if (curKeyCT_ == 0 && !mrPending_) publishMembershipReq();
            return;
        }
        //decrypt and save the secret key of pair [might not need to save since gets passed to sigmgr to use]
        const auto& nk = it->second;
        uint8_t m[kxskKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), pDecKey_.data(), sDecKey_.data()) != 0) {
            return; //can't open encrypted key
        }
        //Received a good key pair, now can set it
        curKey_ = std::vector<uint8_t>(m, m + kxskKeySz);
        curKeyCT_ = newCT;
        newKeyCb_(curKey_, curPK_, curKeyCT_);   //call back parent to pass the new sg key pair to pub privacy sigmgr
        receivedGK();   // got new sg key, cancel pending member request
        // am in init state now have key, can exit init. Send a confirming cState in case KM starting, too
        if (init_)  { sync_.sendCState(); initDone();}
    }

    /*
     * setup() is called from a start function in dct_model,
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when this entity has completed initialization. For a keymaker, that means
     * winning the election, making the first group key and having some entity receive
     * its key record (it does not need to have sg members since it may be the only subscriber
     * but does need to know a potential publisher got the public key).
     * For a non-keymaker sg member, it must have received the group key pair.
     * For a pure publisher, it must have received the public key. The value of the keyMaker
     * capability influences the probability of this entity being elected
     * with larger values giving higher priority.
     * A schema using subscription groups should ensure key maker
     * capability is only given with subscription group capability.
     *
     * subscribe() calls will process any publications waiting in collection
     */
    void setup(connectedCb&& ccb) override {
        if ( sync_.collName_.last().toSv() == "msgs") msgsDist_ = true;    // this will need to be changed if put in names for subscriber groups
        connCb_ = std::move(ccb);
        sync_.start();     // all distributors "before" me have initialized

        // relay: doesn't participate in pub group as it doesn't do encryption or decryption
        // but needs to pass through the sgklists so has a sgk distributor active with its own subscription cb
        // which is set by the ptps shim and the ptps shim when the interface is "connected"
        if (msgsDist_ && isRelay(tp_) ) { initDone(); return; }

        // build function to get the key maker priority from a signing chain then
        // use it to see if we should join the key maker election
        auto kmval = Cap::getval(msgsDist_ ? "KMP" : "KM", prefix_, cs_);
        auto kmpri = [kmval](const thumbPrint& tp) {
                          // return 0 if cap wasn't found or has wrong content
                          // XXX value currently has to be a single digit
                          auto kmv = kmval(tp);
                          if (kmv.size() != 3) return 0;
                          auto c = kmv.cur();
                          if (c < '0' || c > '9') return 0;
                          return c - '0';
                      };
        kmPri_ = kmpri;

        // all members  subscribe to group key subcollection; keymakers subscribe in case of conflicts
        // subscribe could result in finding a KRList in local collection from an elected keymaker
        sync_.subscribe(klPrefix_, [this](const auto& p){ receiveKeyList(p); });
        if (!subr_ || kmPri_(tp_) <= 0 || KMepoch_ > 0) {
            // we're not a non-keymaker or got a keylist that tells us the election is done
            return;
        }
        auto eDone = [this](auto elected, auto epoch) {
                        if (keyMaker_) return;    // this can happen when restarted and  just take over previous role
                         if (mrPending_ || curKeyCT_ > 0) return;  // got assertion gk and/or gk from existing KM
                        keyMaker_ = elected;
                        KMepoch_ = epoch;
                        if (! elected) return;
                        // keymaker must get requests
                        sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); });
                        gkeyTimeout();  //create a group key, publish it, callback parent with key
                      };
        kme_ = new kmElection(prefix_/"km", cs_, sync_, std::move(eDone), std::move(kmpri), tp_, 500ms);
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key records ***/

    // Make a new subscriber key pair and publish it
    // publishKeyRange uses a confirmation callback to locally switch to using the new key and call initDone if needed

    void makeGKey() override {
        // remove expired (not valid) certs (thumbprints) from memberList
        // may need to address time differences in wildly unsynced domains
        auto now = std::chrono::system_clock::now();
        std::erase_if(mbrList_, [this,now](auto& kv) { return cs_.contains(kv.first)? rCert(cs_[kv.first]).validUntil() < now : true; });

        //make a new key pair and set the creation time
        curPK_.resize(kxpkKeySz);
        curKey_.resize(kxskKeySz);
        crypto_kx_keypair(curPK_.data(), curKey_.data());    // set key pair: X25519
        auto vNow = sync_.tdvcNow();
        curKeyCT_ = std::chrono::duration_cast<std::chrono::microseconds>(
                        vNow.time_since_epoch()).count();

        // once every time the keymaker makes a new key
        // publish empty list to continue to assert keymaker role ("assertion kr")
        // This also delivers the new public key to publish-only members
        tlvEncoder sgkp{};    //tlv encoded content
        sgkp.addNumber(36, curKeyCT_);
        sgkp.addArray(150, curPK_);
        sgkp.addArray(130, std::vector<encKy>{});
        publishKeyRange(tp_, tp_, vNow, sgkp.vec());   // use own tp in range
        //newKeyCb_(curKey_, curPK_, curKeyCT_);  // call back to parent with new key, parent calls the application publication sigmgr's addKey()

        auto s = mbrList_.size();
        if (s == 0) return;     // no subscriber members

        mrResp_.clear();
        //encrypt the new secret key for all the subscriber group members
        std::vector<encKy> skVec;
        for (auto& [k,v]: mbrList_) {
            encSGK egKey;
            crypto_box_seal(egKey.data(), curKey_.data(), curKey_.size(), v.data());
            skVec.emplace_back(k,egKey);
        }

        auto p = s <= maxKR_ ? 1 : (s + maxKR_ - 1) / maxKR_; // determine number of Publications needed
        auto it = skVec.begin();
        auto pcnt = sync_.batchPubs();
        for(auto i=0u; i<p; ++i) {
            auto r = i < (p-1) ? maxKR_ : s;
            tlvEncoder sgkp{};    //tlv encoded content for this PDU
            sgkp.addNumber(36, curKeyCT_);
            sgkp.addArray(150, curPK_);
            it = sgkp.addArray(130, it, r);
            auto l = i*maxKR_;
            publishKeyRange(skVec[l].first, skVec[l+r-1].first, vNow, sgkp.vec());
            s -= r;
        }
        sync_.batchDone(pcnt);
    }

    /*
     * This called when there is a new valid peer member request to join the distribution group.
     * This indicates to the keyMaker there is a new peer that needs the private group key.
     * Only subscribe to this after win election to be keyMaker, ignore if not a keyMaker as a safeguard
     * If received while in initialization state, haven't made a key yet so don't try to publish.
     *
     * This called when there is a new valid peer member request to join the subscriber group.
     * This indicates to the keyMaker there is a new peer that needs the group secret key
     * Only subscribe to this after win election to be keyMaker, ignore if not a keyMaker as a safeguard
     * If received while in initialization state, haven't made a key yet so don't try to publish.
     *
     * Shouldn't have to republish the entire list of key records, so publishes a new encrypted secret key separately.
     * Might also want to check if this peer is de-listed (e.g., blacklisted) but for now assuming
     * this is handled in validation of cAdd PDU and of Publications
     * A publish-only member can get the public key from any kr Publication
     */
    void addGroupMem(const rData& p) override {
        if (!keyMaker_) return;
        // number of Publications should be fewer than 'complete peeling' iblt threshold (currently 80).      
        if (mbrList_.size() == 80*maxKR_)   return; // XXXX return some indication of this

        auto tp = p.signer();   // thumbprint of the signer of the member request
        if(! sgMbr_(tp)) return;  //this signing cert doesn't have SG capability

        // Test here for request  in /keys/msgs/mr  from a RLY identity
        if(msgsDist_ && isRelay(tp))  return;

        if (!mbrList_.contains(tp))  //if not already a member, add to list
        {
            // uncomment to remove members with new signing certs, otherwise, just removed when expires
            // auto itp = cs_[tp].signer();  // check for earlier signing key from the same identity and erase
            // auto sameId = std::erase_if(mbrList_, [this,tp,itp](auto& kv) { return kv.first != tp? rCert(cs_[kv.first]).signer() == itp : false; });
           // if (sameId) print ("DistSGKey::addGroupMem: found and erased {} earlier signing cert(s) from this identity\n", sameId);
            auto pk = cs_[tp].content().toVector();   //access the public key for this signer's thumbPrint
            // convert pk to form that can be used to encrypt and add to member list
            if(crypto_sign_ed25519_pk_to_curve25519(mbrList_[tp].data(), pk.data()) != 0) {
                print ("distSGkey::addGroupMem: unable to encrypt sgk for {}\n", cs_[tp].name());
                mbrList_.erase(tp);    //unable to convert member's pk to sealed box pk
                return;
            }
            // check for older member signing cert with same identity
            if(mbrIds_.contains(cs_[tp].signer())) removeGroupMem(mbrIds_[cs_[tp].signer()]);
            mbrIds_[cs_[tp].signer()] = tp;
        }

        if(!curKeyCT_)    return;  // haven't made first group key
        // hold for 2 distribution delays before resending a response to an MR
        if (mrResp_.contains(tp)) {
            if (mrResp_[tp] >  std::chrono::system_clock::now()) return;
            mrResp_.erase(tp);
        } else mrResp_[tp] = std::chrono::system_clock::now() + 2*sync_.distDelay_;

        //publish the subscriber group key for this new peer (republishing if already on list)
        encSGK egKey;
        crypto_box_seal(egKey.data(), curKey_.data(), curKey_.size(), mbrList_[tp].data());
        std::vector<encKy> ekp {{tp,egKey}};
        tlvEncoder sgkp{};    //tlv encoded content
        sgkp.addNumber(36, curKeyCT_);
        sgkp.addArray(150, curPK_);
        sgkp.addArray(130, ekp);
        publishKeyRange(tp, tp, sync_.tdvcNow(), sgkp.vec());
    }
};
}   // namespace dct

#endif //DIST_SGKEY_HPP

