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
 *  dist_gkey is not intended as production code.
 */

#include "dist.hpp"
#include "km_election.hpp"

namespace dct {

struct DistGKey : Dist {
    static constexpr uint32_t aeadKeySz = crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
    static constexpr size_t encGKeySz = crypto_box_SEALBYTES + aeadKeySz;
    using encGK = std::array<uint8_t, crypto_box_SEALBYTES + aeadKeySz>;
    using xmpk = std::array<uint8_t, crypto_scalarmult_curve25519_BYTES>;
    using addKeyCb = std::function<void(keyRef, keyRef, uint64_t)>;
    using capValCB = ofats::any_invocable<int32_t(thumbPrint)>;

    /*
     * DistGKey Publications contain the creation time of the symmetric key and a list of
     * pairs containing that symmetric key individually encrypted for each peer. Each
     * pair has the thumbprint of a signing key and the symmetric key encrypted using that
     * (public) signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators)
     */
    using gkr = std::pair<const thumbPrint, encGK>;
    const crName klPrefix_;     // prefix for key list publications
    const crName mrPrefix_;    // prefix for member request publications
    size_t maxKR_;
    addKeyCb newKeyCb_;   // called when group key rcvd
    capValCB kmPri_;             // for function to extract keymaker priority from identity chain
    thumbPrint kmtp_{};        // thumbprint of the keymaker
    keyVal pDecKey_{};         // transformed pk used to encrypt group key; use with
    keyVal sDecKey_{};         // transformed sk used to decrypt group key
    keyVal curKey_{};           // current secret key
    keyVal curPK_{};            // current public key (not set for symmetric group key sigmgrs)
    uint64_t curKeyCT_{};      // current key creation time in microsecs
    std::map<thumbPrint,xmpk> mbrList_{};
    std::unordered_map<thumbPrint,thumbPrint> mbrIds_{};
    std::unordered_map<thumbPrint,std::chrono::system_clock::time_point> mrResp_;

    tdv_clock::duration reKeyInt_{3600s};
    tdv_clock::duration keyRand_{10s};
    tdv_clock::duration keyLifetime_{3600s+10s};
    tdv_clock::duration mrLifetime_{10s}; // set to ~ few dispersion delays, this is also the lifetime of non-empty gklists
    kmElection* kme_{};
    uint32_t KMepoch_{};        // current election epoch
    bool keyMaker_{false};      // true if this entity is a key maker
    bool msgsDist_ = false;     // true indicates this is a group key distributor for msgs  (not pdus)
    bool mrPending_{false};    //member request pending
    bool initOnAssert_{false}; // keymaker goes to initDone with a confirmed publication of its assert (useful for publish only groups)
    pTimer mrRefresh_{std::make_shared<Timer>(getDefaultIoContext())};

    bool isAssertKL(const rData& p) {
        static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
            return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };
        auto n = p.name();
        n.nextAt(klPrefix_.size());    // skip to epoch
        const auto& tp = p.signer();
        auto tpl = n.nextBlk().toSpan();
        auto tpId = std::span(tp).first(tpl.size());    // get corresponding portion of signer's tp
        auto tph = n.nextBlk().toSpan();                // shouldn't actually have to check that tpl=tph
        if (equal(tpId, tpl) && equal(tpl, tph)) return true;
        return false;
    }

    DistGKey(DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs,  addKeyCb&& gkeyCb,
             tdv_clock::duration reKeyInterval = 3600s, tdv_clock::duration reKeyRandomize = 10s, tdv_clock::duration expirationGB = 60s) :
             Dist(face, pPre, dPre, cs),
        klPrefix_{pPre/"kl"}, mrPrefix_{pPre/"mr"},
        newKeyCb_{std::move(gkeyCb)},  //called when a (new) group key arrives or is created
        reKeyInt_{reKeyInterval}, keyRand_(reKeyRandomize), keyLifetime_(reKeyInt_ + keyRand_)
    {
        dtype_.assign("kygrp"); // XXX change to append when use dist_key
        if ( sync_.collName_.last().toSv() == "msgs") { msgsDist_ = true; dtype_.append("/msgs"); }
        else dtype_.append("/pdus");
        // compute space for content for the gkr Publication. Other Pubs are smaller, so gkr is worst-case
        maxContent_ = sync_.maxInfoSize() - (prefix_.size() + 2 +3 + 9 + 2 + 2 + 2*(4+2));    // all the components of Name
        if (maxContent_ < (sizeof(thumbPrint) + encGKeySz))
            throw ("DistGKey: not enough space in Pub Content to carry group key list");
        maxKR_ = (maxContent_) / (sizeof(thumbPrint) + encGKeySz);
        // print ("DistGKey: maxContent is {} max num key records is {}\n", maxContent_, maxKR_);
        convertSK(cs_.key(tp_), cs_[tp_]);    // updateSigningKey has been called from dist base class

        sync_.pubLifetime(tdv_clock::duration(reKeyInterval + reKeyRandomize + expirationGB));
        sync_.getLifetimeCb([this,cand=crPrefix(prefix_/"km"/"cand"),elec=crPrefix(prefix_/"km"/"elec"),mreq=crPrefix(mrPrefix_)](const auto& p) ->tdv_clock::duration {
            auto n = p.name();
            if (mreq.isPrefix(n)) return mrLifetime_;
            if (cand.isPrefix(n) || elec.isPrefix(n)) return 3s;
            const auto& tp = p.signer();    // get thumbprint of this Pub's signer
            if (! crPrefix(klPrefix_).isPrefix(n)) return 0ms; // shouldn't happen - expect a gk list
            auto epoch = n.nextAt(klPrefix_.size()).toNumber();
             if (tp == kmtp_ && epoch < KMepoch_) return 0ms;  // from earlier epoch of my current km
            // Check if this is an assertion gk list Pub which should persist for gk rekey time
            if (isAssertKL(p)) return keyLifetime_;
            return mrLifetime_;                                // other gk lists only need to last as long as member requests
                                                                             // if members might sleep after request could be keyLifetime_
        }); // end of getLifetimeCb
    }

    // log distributor publishes to logs collection
    void logEvent(std::string s, std::span<const uint8_t> content = {}) override final {
        // name portion for tdvc calibrate log publication with role and role-id and # nbrs, no content
        // XXX role and role-id only works for examples - consider using more of cert name to be more general
        if (msgsDist_)
            logsCb_( crName("gkp")  / s / cs_[tp_].name()[1] / cs_[tp_].name()[2] , content);
        else
            logsCb_( crName("gkd")  / s / cs_[tp_].name()[1] / cs_[tp_].name()[2] , content);
    }

    // publish my membership request with updated key: name <mrPrefix_><timestamp>
    // requests don't have epoch since the keymaker sets the epoch, member learns from key list
    // Member requests have a lifetime on order of a few distribution delays and are reissued until
    // a key is received
    void publishMembershipReq() {
        if (msgsDist_ && isRelay(tp_))  return;   // relays don't publish msgs (shouldn't get here)
        /*using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
        auto now = std::chrono::system_clock::now();
        print("{:%M:%S} {} publishes a {} membership request\n",  ticks(now.time_since_epoch()), cs_[tp_].name(), sync_.collName_.last().toSv());*/
        mrRefresh_->cancel();  // if a membership request refresh is scheduled, cancel it
        crData p(mrPrefix_/sync_.tdvcNow());
        p.content(std::vector<uint8_t>{});
        mrPending_ = true;
        try {
            sync_.signThenPublish(std::move(p));
        } catch (const std::exception& e) {
            std::cerr << "dist_" << dtype_ << "::publishMembershipReq: " << e.what() << std::endl;
        }
        mrRefresh_ = sync_.schedule(mrLifetime_, [this](){ publishMembershipReq(); });
    }

    // Called when a group key has been received and decrypted. Cancel any pending refresh
    // of the membership request. It will be reissued only if a new group key record is received
    // and I'm not in the list
    void receivedGK() {
        mrRefresh_->cancel();  // if a membership request refresh is scheduled, cancel it
        mrPending_ = false;
    }

     // convert the new key to form needed for group encrypt/decrypt
    void convertSK(const keyVal sk, const rData& pc) {
        sDecKey_.resize(crypto_scalarmult_curve25519_BYTES);
        if(crypto_sign_ed25519_sk_to_curve25519(sDecKey_.data(), sk.data()) != 0) {
            std::runtime_error("DistGKey::updateSKforGK could not convert secret key");
        }
        pDecKey_.resize(crypto_scalarmult_curve25519_BYTES);
        const auto& pk = pc.content().toSpan();
        if(crypto_sign_ed25519_pk_to_curve25519(pDecKey_.data(), pk.data()) != 0) {
            std::runtime_error("DistGKey::updateSKforGK unable to convert signing pk to sealed box pk");
        }
    }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.  
     *      use new key immediately to sign - update the my signature managers
     *      if member, send a new membership request
     *     keymaker needs to assert its role under new cert
     */
    virtual void updateSigningKey(const keyVal sk, const rData& pubCert) override {
        Dist::updateSigningKey(sk, pubCert);    // common distributor code handles update, sets tp_
        convertSK(cs_.key(tp_), cs_[tp_]);    // convert signing key pair for group key distributor use
        if (init_) return;
        if (! keyMaker_) {
            // print("DistGKey::updateSigningKey new SP for member {}\n", pubCert.name() );
             publishMembershipReq();
             return;
        }

        // if keymaker is rekeyed it needs to change epoch
        if (kmPri_(tp_) <= 0) std::runtime_error("DistGKey::updateSigningKey keymaker capability change indicates bad signing chain");
        kmtp_ = tp_;
        ++KMepoch_;
        // print("DistGKey::updateSigningKey new SP for keymaker {} epoch = {}\n", pubCert.name(), KMepoch_);
        makeGKey(); // redo this so gklists are under the new signing cert
    }

    /*
     * Called when a new Publication is received in the key collection
     * Look for the group key record with *my* key thumbprint
     * Using first 4 bytes of thumbPrints as identifiers. In the event that the first and last
     * thumbPrint identifiers are the same, doesn't really matter since we look through for our full
     * thumbPrint and just return if don't find it
     * Since keymaker publishes an empty gk when it wins election, the receipt causes
     * non-keymakers to publish first membership request
     * gk names <klPrefix_><epoch><low tpId><high tpId><timestamp>
     */
    virtual void receiveKeyList(const rPub& p) {
        if (msgsDist_ && isRelay(tp_))  return;   // relays don't get pub keys for msgs collection

        const auto& tp = p.signer();    // thumbprint of this GKeyList's signer
        if (!cs_.contains(tp) || kmPri_(tp) <= 0) {
            print("DistGKey:receiveKeyList ignoring keylist {} signed by expired or unauthorized identity\n", p.name());
            return;
        }
        auto n = p.name();
        auto epoch = n.nextAt(klPrefix_.size()).toNumber();

        decltype(curKeyCT_) newCT{};   //decode the new key's creation time
        std::span<const gkr> gkrVec{};  // decode the content of the gk list (empty for assertion gk)
        try {
            auto content = p.content();
            // the first tlv should be type 36 and it should decode to a uint64_t
            // a new key will have a creation time larger than curKeyCT_
            newCT = content.nextBlk(36).toNumber();
            // the second tlv should be type 130, a vector of gkr pairs
            gkrVec = content.nextBlk(130).toSpan<gkr>();
        } catch (std::runtime_error& ex) {
            return; //ignore this publication
        }

        if (cs_[tp].signer() == cs_[tp_].signer()) {
            // keylist is from earlier signing key of my signing identity
            if (init_) {
                // seem to be restarted keymaker, grab keymaker status and return
                keyMaker_ = true;
                KMepoch_ = ++epoch;    // epoch is incremented when KM gets new signing pair
                // print("DistGKey:receiveKeyList: received key list from my Id in init set epoch to {}\n", KMepoch_);
                sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                gkeyTimeout();  //create a group key and schedule group key creation with this  epoch and current signing cert
            }
            return;
        }
        if (keyMaker_) {
            // another member claims to be a keyMaker - largest thumbPrint and most recent epoch wins
            if ((tp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_)) {
                keyMaker_ = false; // relinquish keymaker status
                kmtp_ = tp;            // set my keymaker to this one
                curKeyCT_ = 0;
                KMepoch_ = epoch;
                sync_.unsubscribe(mrPrefix_);
                publishMembershipReq();
            }
            return;
        }

        // tests for non-keymakers
        if (init_) {
            if (!mrPending_) publishMembershipReq();
            if (isAssertKL(p)) return; // can't be a gk for me
            if (KMepoch_ == 0) {
                kmtp_ = tp;        //  first time to set a keymaker
                KMepoch_ = epoch;
            }
        } else if (isAssertKL(p)) {
            // publish an MR in response to an assert
            // at the cost of a short delay to send a MR that is needed, reduce/eliminate MR explosion
            if (tp != kmtp_ || curKeyCT_ < newCT)
                sync_.oneTime(sync_.distDelay_+std::chrono::milliseconds(rand_(2,9)),
                               [this, nt=newCT](){ if (curKeyCT_ < nt) publishMembershipReq();});
            return;
        }

        /*
         * I am a member that has issued at least one membership request in the past
         * (set kmtp_ but may or may not have received a copy of the group key)
         * and may or may not be in init state
         * This gklist may service that request or may be an updated gk or updated keymaker
         * Parse the name and make checks to determine if this key record publication should be used.
         * if this msg was from an earlier Key Maker epoch, test for restarted keymaker, otherwise ignore it.
         */
        if (tp == kmtp_) {  //signed by my keymaker's signing key
            if (epoch > KMepoch_) {
                KMepoch_ = epoch;
                curKeyCT_ = 0;         // will need a new gk for this epoch
            }
        } else if (cs_.contains(kmtp_)  && cs_[tp].signer() == cs_[kmtp_].signer()) {
            // same keymaker identity, different signing key could be updated key or restart of same keymaker
            if (curKeyCT_ < newCT) {
                // new epoch and and signing cert for my KM or my curKeyCT is older than when this packet was sent  or not set yet
                KMepoch_ = epoch;   // update KM and epoch
                curKeyCT_ = 0;         // will need a new gk this epoch and sc
                kmtp_ = tp;
            } else return;  // this seems to be a gklist from keymaker's past so ignore it
        } else { // from different identity from my KM and/or my KM may be expired
            // if this keymaker has a larger tp than my previous keymaker
            // (can resolve conflict after elections though can happen in relayed domains in particular)
            // (re)set my km and curkey ct records so I get a new key and publish MR (below)
            if (!cs_.contains(kmtp_) || (kmtp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_)) {
                KMepoch_ = epoch;   // changing KM
                kmtp_ = tp;
                curKeyCT_ = 0; // a new MR is sent (below) if no key for me in this gklist
            } else return;   // from a KM that is displaced by my KM
       }

        static constexpr auto less = [](const auto& a, const auto& b) -> bool {
            auto asz = a.size();
            auto bsz = b.size();
            auto r = std::memcmp(a.data(), b.data(), asz <= bsz? asz : bsz);
            if (r == 0) return asz < bsz;
            return r < 0;
        };

        try {
            if (newCT == curKeyCT_) receivedGK();  // duplicate so make sure not sending MRs
            if(newCT <= curKeyCT_) return; // group key not newer than ours

            // check if I'm in this gk publication's range
            auto tpl = n.nextBlk().toSpan();    // continues from epoch, above
            auto tph = n.nextBlk().toSpan();
            auto tpId = std::span(tp_).first(tpl.size());
            if(less(tpId, tpl) || less(tph, tpId)) {
                if (curKeyCT_ == 0 && !mrPending_) publishMembershipReq();    // make sure new KM has my MR
                else    // likely that my km has made a new key - delay in case one on the way
                    sync_.oneTime(sync_.distDelay_+std::chrono::milliseconds(rand_(2,9)),
                               [this, nt=newCT](){ if (curKeyCT_ < nt) publishMembershipReq();});
                return; // no key for me in this gk list
            }
        } catch (std::runtime_error& ex) {
            return; //ignore this publication
        }

        // find my gk
        auto it = std::find_if(gkrVec.begin(), gkrVec.end(), [this](auto p){ return p.first == tp_; });
        if (it == gkrVec.end()) {
            // didn't find our encrypted key in pub (error in gklist name) - make sure new KM it has our request
            if (curKeyCT_ == 0 && !mrPending_) publishMembershipReq();
            return;
        }

        // decrypt and save the key
        const auto& nk = it->second;
        uint8_t m[aeadKeySz];
        if(crypto_box_seal_open(m, nk.data(), nk.size(), pDecKey_.data(), sDecKey_.data()) != 0) {
            if(!mrPending_) publishMembershipReq(); // make sure there is a published request
            return;
        }

        // print ("DistGKey::receiveGKey {} got a new key made at {}\n", (cs_[tp_]).name(), newCT);
        curKeyCT_ = newCT;
        curKey_ = std::vector<uint8_t>(m, m + aeadKeySz);
        receivedGK();   //got a new group key, cancel pending member request
        newKeyCb_(curKey_, curPK_, curKeyCT_);   // call back parent with new key
        // am in init state now have key, can exit init. Send a confirming cState in case KM starting, too
        if (init_)  { sync_.sendCState(); initDone();}
    }

    /*
     * setup() is called from a connect() function in dct_model, typically
     * after some initial signing certs have been exchanged so it's known
     * there are active peers. It is passed a callback, 'ccb', to be
     * invoked when a group key has been received (i.e., when this entity is
     * able to encrypt/decrypt pdu content). There may also be a
     * km capability cert in this entity's signing chain which allows
     * it to participate in keyMaker elections.  The value of the
     * capability influences the probability of this entity being elected
     * with larger values giving higher priority.
     * subscribes will process any publications waiting in collection
     *
     * Calls its syncps's start() before returning to start participating in collection
     */
    void setup(connectedCb&& ccb) override {

        connCb_ = std::move(ccb);
        sync_.start();     // all distributors "before" me have initialized

        // relay doesn't participate in pub group as it doesn't do encryption or decryption
        // but needs to pass through the gklists so has a gk distributor active with its own subscription cb
        // which is set by the ptps shim when the interface is "connected"
        if (msgsDist_ && isRelay(tp_)) { initDone(); return; }

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

        // subscribe could result in finding a GKList in local collection that could be from the elected keymaker
        sync_.subscribe(klPrefix_, [this](const auto& p){ receiveKeyList(p); });

        // check if keymaker candidate and whether election is over
        auto eDone = [this](auto elected, auto epoch) {
                if (keyMaker_) return;    // this can happen when restarted and  just take over previous role
                if (mrPending_ || curKeyCT_ > 0) return;  // got assertion gk and/or gk from existing KM
                keyMaker_ = elected;
                KMepoch_ = epoch;
                if (! elected) return;
                //print("{} wins election to make {} GKs\n", cs_[tp_].name(), sync_.collName_.last().toSv());
                sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                gkeyTimeout();  //create a group key and reschedule group key creation                
        };
        // start election. election durations should be ~10 distDelays
        kme_ = new kmElection(prefix_/"km", cs_, sync_, std::move(eDone), std::move(kmpri), tp_, 500ms);
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key list ***/

   // Publish the group key list from thumbprint tpl to thumbprint tph
   // gk names <klPrefix_><epoch><low tpId><high tpId><timestamp>
    void publishKeyRange(const auto& tpl, const auto& tph, auto ts, auto& c) {
        //constant 4 may be determined dynamically later
        const auto TP = [](const auto& tp){ return std::span(tp).first(4); };
        crData p(klPrefix_/KMepoch_/TP(tpl)/TP(tph)/ts);
        p.content(c);
        try {
            // in init state and either initializing on confirmed assert publication or this is a non-empty key list
            if (init_ && tpl != tp_){
                sync_.signThenPublish(std::move(p), [this](const rData&, bool s){ if(s) initDone();});
            } else if (tpl == tp_ && tph == tp_) {
                // is an assertion gk, use conf cb before starting to use new gkey locally
                // if s =false, means an entire gkey lifetime has passed and a new key will be made
                 sync_.signThenPublish(std::move(p), [this](const rData&, bool s){ if(s) {
                        newKeyCb_(curKey_, curPK_, curKeyCT_);
                        if (init_ && initOnAssert_) initDone(); }
                        });
            } else
                sync_.signThenPublish(std::move(p));
       } catch (const std::exception& e) {
            std::cerr << "dist_" << dtype_ << "::publishKeyRange: " << e.what() << std::endl;
        }
    }

    /*
     * Make a new group key, publish it, and locally switch to using the new key.
     * A keymaker that has just won an election will publish an empty gk list to assert its win
     * to later joiners. Since subscribers get this gklist, using reception of any gklist (when in init
     * state with no pending member requests) to publish a membership request.
     *
     * If in init state and there are group members, call initDone to exit init
    */
    virtual void makeGKey() {
        curKey_.resize(aeadKeySz); // crypto_aead_xchacha20poly1305_IETF_KEYBYTES
        crypto_aead_xchacha20poly1305_ietf_keygen(curKey_.data());
        //print("{} makes a new {} GK\n", cs_[tp_].name(), sync_.collName_.last().toSv());
        //set the key's creation time using the domain virtual clock
        auto vNow = sync_.tdvcNow();
        curKeyCT_ = std::chrono::duration_cast<std::chrono::microseconds>(
                        vNow.time_since_epoch()).count();

        // remove expired certs (thumbprints) from memberList
        // could give some "grace time" if there is a non-zero tdvc but signing certs should have sufficient overlap
        auto now = std::chrono::system_clock::now();
        std::erase_if(mbrList_, [this,now](auto& kv) { return cs_.contains(kv.first)? rCert(cs_[kv.first]).validUntil() < now : true; });

        auto pcnt = sync_.batchPubs();
        // once every time the keymaker makes a new key
        // publish empty list to continue to assert keymaker role ("assertion gk")
        tlvEncoder gkrEnc{};    //tlv encoded content
        gkrEnc.addNumber(36, curKeyCT_);
        gkrEnc.addArray(130, std::vector<gkr>{});
        publishKeyRange(tp_, tp_, vNow, gkrEnc.vec());   // use own tp in range

        auto s = mbrList_.size();  // publish new gkey to all members
        if (s==0) {
            sync_.batchDone(pcnt);
            return;   // no members
         }
        //encrypt the new group key for all the group members in a sealed box
        // that can only opened by the secret key associated with converted public key in mbrList
        std::vector<gkr> pubPairs{};
        for (const auto& [k,v]: mbrList_) {
            encGK egKey;
            crypto_box_seal(egKey.data(), curKey_.data(), curKey_.size(), v.data());
            pubPairs.emplace_back(k, egKey);
        }
        mrResp_.clear();
        auto p = s <= maxKR_ ? 1 : (s + maxKR_ - 1) / maxKR_; // determine number of Publications needed
        auto it = pubPairs.begin();

        for(auto i=0u; i<p; ++i) {
            auto r = s < maxKR_ ? s : maxKR_;
            tlvEncoder gkrEnc{};    //tlv encoded content
            gkrEnc.addNumber(36, curKeyCT_);
            it = gkrEnc.addArray(130, it, r);
            auto l = i*maxKR_;
            publishKeyRange(pubPairs[l].first, pubPairs[l+r-1].first, vNow, gkrEnc.vec());
            s -= r;
        }
        sync_.batchDone(pcnt);
        // call back to parent with new key, parent calls the application publication sigmgr's addKey()
        // short delay before using so non-keymakers can receive new key
        // or may be better to use a conf callback on the assertion gk - see publishKeyRange and comment out this
        // sync_.oneTime(sync_.distDelay_, [this](){newKeyCb_(curKey_, curPK_, curKeyCT_);});
    }

    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void gkeyTimeout() {
        if (!keyMaker_) return;    // since not a cancelable timer, need to stop if I lose a future election or another keymaker took priority
        makeGKey();
        sync_.oneTime(reKeyInt_, [this](){ gkeyTimeout();});  //next re-keying event
    }

    /*
     * This called when there is a new valid peer member sends a member request message
     * For a new member or new signing cert, it is a request to join the distribution group.
     * This indicates to the keyMaker there is a peer that needs the group key.
     * Only subscribe to this after win election to be keyMaker, ignore if not a keyMaker as a safeguard
     * If received while in initialization state, haven't made a key yet so don't try to publish.
     *
     * If conversion of public key works, that adds this member to list (by thumbprint).
     * Shouldn't have to republish the entire keylist, so  publishes the
     * new encrypted group key separately for members joining after initialization
     * .
     * Might also want to check if this peer is de-listed (e.g., blacklisted) but for now assuming this
     * would be handled in validation of cAdd PDU and of Publication.
     */

    virtual void addGroupMem(const rData& p) {
        if (!keyMaker_) return;

        auto tp = p.signer();   // thumbprint of the signer of the member request (signing cert)
        if (msgsDist_ && isRelay(tp)) return;  // identities with RLY don't get pub keys

        std::string s = "mreq/"; // this is hinky but it works to make this example
        s.append(cs_[tp].name()[1].toSv()).append("/").append(cs_[tp].name()[2].toSv());
        logEvent(s );  // log when receive a member request

        if (!mbrList_.contains(tp)) {     // not already a member, add to list (signer already checked on receipt)
            auto pk = cs_[tp].content().toVector();   //access the public key for this signer's thumbPrint
            // convert pk to form that can be used to encrypt and add to member list
            if(crypto_sign_ed25519_pk_to_curve25519(mbrList_[tp].data(), pk.data()) != 0) {
                print ("distGkey::addGroupMem: unable to encrypt gk for {}\n", cs_[tp].name());
                mbrList_.erase(tp);    //unable to convert member's pk to sealed box pk - erase what the call put in
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

        //publish the group key for this member: if new, first time, if already a member, republish in response to this mr
        encGK egKey;
        crypto_box_seal(egKey.data(), curKey_.data(), curKey_.size(), mbrList_[tp].data());
        std::vector<gkr> ek{ {tp, egKey} };
        tlvEncoder gkrEnc{};    //tlv encoded content
        gkrEnc.addNumber(36, curKeyCT_);
        gkrEnc.addArray(130, ek);
        publishKeyRange(tp, tp, sync_.tdvcNow(), gkrEnc.vec());
    }

    /*
     *  won't encrypt a group key for this thumbPrint in future
     * if this becomes a subscription callback for delisted publications, should
     * probably mark mbrList entries rather than delete
     * if reKey is set, change the group key now to exclude the removed member
     */
    void removeGroupMem(thumbPrint& tp, bool reKey = false) {
        if (mbrList_.contains(tp)) {
            mbrIds_.erase(tp);
            mbrList_.erase(tp);
        }
        if (reKey) makeGKey();
    }
};

} // namespace dct

#endif //DIST_GKEY_HPP
