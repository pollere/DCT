#ifndef DIST_KEY_HPP
#define DIST_KEY_HPP
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
 * a subscription callback until one is registered (in start())
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

template <std::size_t skSize, std::size_t encSKSz, std::size_t pkSize = 0>
struct DistKey : Dist {
    constexpr static auto skSize_ = skSize;
    constexpr static auto encSKSz_ = encSKSz;
    constexpr static auto pkSize_ = pkSize;
    constexpr static std::size_t  xpkSz_{crypto_scalarmult_curve25519_BYTES};  // size of (converted) member PKs used to encrypt SK
    using keyRec = std::pair<const thumbPrint, std::array<uint8_t, encSKSz_>>;
    using xmpk = std::array<uint8_t, crypto_scalarmult_curve25519_BYTES>; //member PKs used to encrypt group SK
    using addKeyCb = std::function<void(keyRef, keyRef, uint64_t)>;
    using capValCB = ofats::any_invocable<int32_t(thumbPrint)>;

    /*
     * DistKey Publications contain the creation time of the symmetric key and a list of
     * pairs containing the symmetric key individually encrypted for the paired member. Each
     * pair has the thumbprint of a signing key and the symmetric key encrypted using that
     * (public) signing key. Publication names contain the range of thumbprints contained in the
     * enclosed list. (96 bytes also accounts for tlv indicators)
     *
     * Assumes using crypto box seal methods from libsodium (e.g.,use of xmpk) but may be
     * possible to generalize here. If not other methods can be derived
     */

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
    tdv_clock::duration keyExpireGB_{60s};
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

    DistKey(std::string_view dtype, DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs,
            addKeyCb&& keyCb, tdv_clock::duration reKeyInterval = 3600s, tdv_clock::duration reKeyRandomize = 10s,
            tdv_clock::duration expirationGB = 60s)
        : Dist(dtype, face, pPre, dPre, cs),
          klPrefix_{pPre/"kl"},
          mrPrefix_{pPre/"mr"},
          newKeyCb_{std::move(keyCb)},  //called when a (new) group key arrives or is created
          reKeyInt_{reKeyInterval},
          keyRand_(reKeyRandomize),
          keyLifetime_(reKeyInt_ + keyRand_),
          keyExpireGB_{expirationGB} {
        if ( sync_.collName_.last().toSv() == "msgs") { msgsDist_ = true; dtype_.append("/msgs"); }
        else dtype_.append("/pdus");
        sync_.pubLifetime(tdv_clock::duration(reKeyInt_+ keyRand_ + keyExpireGB_));
        sync_.getLifetimeCb(
            [this,cand=crPrefix(prefix_/"km"/"cand"),elec=crPrefix(prefix_/"km"/"elec"),mreq=crPrefix(mrPrefix_)]
            (const auto& p) ->tdv_clock::duration {
                auto n = p.name();
                if (mreq.isPrefix(n)) return mrLifetime_;
                if (cand.isPrefix(n) || elec.isPrefix(n)) return 3s;
                const auto& tp = p.signer();    // get thumbprint of this Pub's signer
                if (! crPrefix(klPrefix_).isPrefix(n)) return 0ms; // shouldn't happen - expect a key list
                auto epoch = n.nextAt(klPrefix_.size()).toNumber();
                 if (tp == kmtp_ && epoch < KMepoch_) return 0ms;  // from earlier epoch of my current km
                // Check if this is an assertion gk list Pub which should persist for gk rekey time
                if (isAssertKL(p)) return keyLifetime_;
                // other key lists only need to last as long as member requests
                // (if members might sleep after request could be keyLifetime_)
                return mrLifetime_;
            }
        ); // end of getLifetimeCb

        /*
         * Derived implementations should set these to its specifications in their constructors
         *
         * compute space for content for the kr list Publication. Use worst-case (longest) name size
          * maxContent_ = sync_.maxInfoSize() - (prefix_.size() +  <all the components of name>
          * skSize_ =  the size of SK for this distributor, e.g. crypto_aead_xchacha20poly1305_IETF_KEYBYTES
          * pkSize_ = the size of PK (if any) for this distributor
          * encSKSz_ = size needed for encrypted secret key, e.g., skSize_ + crypto_box_SEALBYTES
        */
    }

    // log distributor publishes to logs collection
    void logEvent(std::string s, std::span<const uint8_t> content = {}) {
        // name portion for tdvc calibrate log publication with role and role-id and # nbrs, no content
        // XXX role and role-id only works for examples - consider using more of cert name to be more general
        logsCb_( crName(msgsDist_? "gkp" : "gkd")  / s / cs_[tp_].name()[1] / cs_[tp_].name()[2] , content);
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

    // Called when a secret key has been received and decrypted. Cancel any pending refresh
    // of the membership request. It will be reissued only if a new secret key is detected
    // and I'm not in the list
    void receivedSK() {
        mrRefresh_->cancel();  // if a membership request refresh is scheduled, cancel it
        mrPending_ = false;
    }

     // convert a key pair to form needed (25519) for group encrypt/decrypt using sealed box
     // (override for a different approach)
     void convertSK(const keyVal sk, const rData& pc) {
        keyVal ssk(sk.begin(), sk.begin()+32);  // only need first 32 bytes of sk (rest is appended pk)
        sDecKey_.resize(xpkSz_);
        if(crypto_sign_ed25519_sk_to_curve25519(sDecKey_.data(), ssk.data()) != 0) {
            std::runtime_error("DistKey::convertSK could not convert secret key");
        }
        pDecKey_.resize(xpkSz_);
        const auto& pk = pc.content().toSpan();
        if(crypto_sign_ed25519_pk_to_curve25519(pDecKey_.data(), pk.data()) != 0) {
            std::runtime_error("DistKey::convertSK unable to convert signing pk to sealed box pk");
        }
    }

    // called on (new) signing cert after update for distributor-specific checks if needs to decrypt SK
    virtual bool getsSK() { return true; }

    /*
     * Called to process a new local signing key. Passes to the SigMgrs.
     * Stores the thumbprint and makes decrypt versions of the public
     * key and the secret key to use to decrypt the group key.  
     *      use new key immediately to sign - update the my signature managers
     *      if member, send a new membership request
     *     keymaker needs to assert its role under new cert
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        Dist::updateSigningKey(sk, pubCert);    // common distributor code handles update, sets tp_
        if (!getsSK()) return;

        convertSK(cs_.key(tp_), cs_[tp_]);    // convert signing key pair for group key distributor use
        // this code is common in current key distributors
        if (init_) return;
        if (! keyMaker_) {
            // print("DistKey::updateSigningKey new SP for member {}\n", pubCert.name() );
             publishMembershipReq();
             return;
        }
        // if keymaker is rekeyed it needs to change epoch
        if (kmPri_(tp_) <= 0) std::runtime_error("DistKey::updateSigningKey keymaker capability change indicates bad signing chain");
        kmtp_ = tp_;
        ++KMepoch_;
        // print("DistKey::updateSigningKey new SP for keymaker {} epoch = {}\n", pubCert.name(), KMepoch_);
        makeNewKey(); // redo this so kr lists are under the new signing cert
    }

    /*
     * Called when a new Publication is received in the key list collection
     * Look for the secret key record with *my* key thumbprint
     * Using first 4 bytes of thumbPrints as identifiers. In the event that the first and last
     * thumbPrint identifiers are the same, doesn't really matter since we look through for our full
     * thumbPrint and just return if don't find it
     * Since keymaker publishes an empty key list when it wins election, the receipt causes
     * non-keymakers to publish first membership request
     * publication names: <klPrefix_><epoch><low tpId><high tpId><timestamp>
     */

    virtual bool mReqNeeded() { return !mrPending_; }
    virtual bool pkOnly(keyVal&, uint64_t) { return false; }    // true if member only gets public key

    void receiveKeyList(const rPub& p) {
        if (msgsDist_ && isRelay(tp_))  return;   // relays don't get pub keys for msgs collection

        // test validity of sender
        const auto& tp = p.signer();    // thumbprint of this KeyList's signer
        if (!cs_.contains(tp) || kmPri_(tp) <= 0) {
          //  print("DistKey:receiveKeyList ignoring keylist {} signed by expired or unauthorized identity\n", p.name());
            return;
        }
        auto n = p.name();
        auto epoch = n.nextAt(klPrefix_.size()).toNumber();

        if (cs_[tp].signer() == cs_[tp_].signer()) { // From earlier signing key of my signing identity?
            if (init_) {
                // appears I am a restarted keymaker, grab keymaker status and return
                keyMaker_ = true;
                KMepoch_ = ++epoch;    // epoch is incremented when KM gets new signing pair
                // print("DistKey:receiveKeyList: received key list from my Id in init set epoch to {}\n", KMepoch_);
                sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                makeKeyTimeout();  //create a group key and schedule group key creation with this  epoch and current signing cert
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

        /* get here if not the keymaker */

        // extract key list and related items from the content
        decltype(curKeyCT_) newCT{};   //decode the new key's creation time
        keyVal newPK;
        std::span<const keyRec> krVec{};  // decode the content of the key record list (empty for assertion key list)
        try {
            auto content = p.content();
            // the first tlv should be type 36 and it should decode to a uint64_t
            // a new key will have a creation time larger than curKeyCT_
            newCT = content.nextBlk(36).toNumber();
            if constexpr (pkSize_) {
                // next tlv should be type 150 that decodes to a vector of uint8_t
                newPK = content.nextBlk(150).toVector();
            }
            // next tlv should be type 130, a vector of keyRecords
            krVec = content.nextBlk(130).toSpan<keyRec>();
        } catch (std::runtime_error& ex) { return; } //ignore this publication

        // various tests
        if (kmtp_ == tp) {   // from my keymaker
           if (epoch < KMepoch_ || curKeyCT_ > newCT) return;    // older
           if (curKeyCT_ == newCT) return; // already have this key from this keymaker
           curKeyCT_ = 0;   // indicates need the current key from my keymaker
           KMepoch_ = epoch;
        } else if (KMepoch_ == 0 || ((kmtp_ < tp && epoch == KMepoch_) || (epoch > KMepoch_) || !cs_.contains(kmtp_))) {
            // from first keymaker or if this keymaker supersedes previous => change keymaker
             kmtp_ = tp; //  set this klist sender as my keymaker
             KMepoch_ = epoch;
             curKeyCT_ = 0; // indicates need to get the current key
        } else return;  // ignore this KL

        // PK and CT are in any KL including assert, so done if this member only needs PK
        if (pkOnly(newPK, newCT)) return;

        // I am looking for new key(s) - in init, just send MR if not sending, else something might be on the way so delay
         if (mReqNeeded()) {
             if (init_) {
                 publishMembershipReq(); // haven't sent MR yet
                 return;
             } else sync_.oneTime(sync_.distDelay_+std::chrono::milliseconds(rand_(2,9)),
                               [this, nt=newCT](){ if (curKeyCT_ < nt) publishMembershipReq();});
         }
        // assert has no SKs
        if (isAssertKL(p)) return;

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
                curKeyCT_ = 0;         // will need a new group sk for this epoch
            }
        } else if (cs_.contains(kmtp_)  && cs_[tp].signer() == cs_[kmtp_].signer()) {
            // same keymaker identity, different signing key could be updated key or restart of same keymaker
            if (curKeyCT_ < newCT){
                // new epoch and and signing cert for my KM or my curKeyCT is older than when this packet was sent  or not set yet
                KMepoch_ = epoch;   // update KM and epoch
                curKeyCT_ = 0;         // will need a new group key this epoch
                kmtp_ = tp;
            } else return;  // this seems to be a kr list from keymaker's past so ignore it
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
            if (newCT == curKeyCT_) receivedSK();  // duplicate so make sure not sending MRs
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
        } catch (std::runtime_error&) { return; } //ignore this publication

        // find key record with my thumbprint
        // print ("DistKey::receiveKeyList: klist includes my tp, krVec has {} elements\n", krVec.size());
        auto it = std::find_if(krVec.begin(), krVec.end(), [this](auto p){ return p.first == tp_; });
        if (it == krVec.end()) {
            // didn't find our encrypted key in pub (error in kr list name) - make sure current KM has our request
            if (curKeyCT_ == 0 && !mrPending_) publishMembershipReq();
            return;
        }

        // print ("DistKey::receiveKeyList: {} found a SK\n", cs_[tp_].name());

        // decrypt and save the key - assumes crypto sealed box
        const auto& nk = it->second;
        uint8_t m[crypto_aead_xchacha20poly1305_IETF_KEYBYTES]; // this is what crypto_box_seal will return - should = skSize_
        if(crypto_box_seal_open(m, nk.data(), nk.size(), pDecKey_.data(), sDecKey_.data()) != 0) {
            if(!mrPending_) publishMembershipReq(); // make sure there is a published request
            return;
        }

        curKeyCT_ = newCT;
        curKey_.assign(m, m + skSize_);
        curPK_ = newPK;
        receivedSK();   //got a new group key, cancel pending member request
        newKeyCb_(curKey_, curPK_, curKeyCT_);   // call back parent with new key
        // am in init state now have key, can exit init. Send a confirming cState in case KM starting, too
        if (init_)  { sync_.sendCState(); initDone();}
    }

    /*
     * start() is called from a connect() function in dct_model, typically
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
     // test if not a non-keymaker or have received a keylist that tells us the election is done
     bool noElection() {
          if (kmPri_(tp_) <= 0 || KMepoch_ > 0) return true;
          return false;
     }
    void start(connectedCb&& ccb) {
        connCb_ = std::move(ccb);
        if (!sync_.autoStart_) sync_.start();  // all distributors "before" me have initialized

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

        // all members  subscribe to key list subcollection; keymakers subscribe in case of conflicts
        // subscribe could result in finding a KR list in local collection from an elected keymaker
        sync_.subscribe(klPrefix_, [this](const auto& p){ receiveKeyList(p); });
        if (noElection()) return;
        // check if keymaker candidate and whether election is over
        auto eDone = [this](auto elected, auto epoch) {
                if (keyMaker_) return;    // this can happen when restarted and  just take over previous role
                if (mrPending_ || curKeyCT_ > 0) return;  // got assertion kl and/or kl from existing KM
                keyMaker_ = elected;
                KMepoch_ = epoch;
                if (! elected) return;
                //print("{} wins election to make {} GKs\n", cs_[tp_].name(), sync_.collName_.last().toSv());
                sync_.subscribe(mrPrefix_, [this](const auto& p){ addGroupMem(p); }); // keymakers need the member requests
                makeKeyTimeout();  //create a group key and reschedule group key creation
        };
        // start election. election durations should be ~10 distDelays
        kme_ = new kmElection(prefix_/"km", cs_, sync_, std::move(eDone), std::move(kmpri), tp_,
                              std::chrono::duration_cast<std::chrono::milliseconds> (10*sync_.distDelay_));
    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key list ***/

   // Publish the list of key records from <klPrefix_><epoch><low tpId><high tpId><timestamp>
     void publishKeyRange(const auto& tpl, const auto& tph,  auto& c) {
        //constant 4 may be determined dynamically later
        const auto TP = [](const auto& tp){ return std::span(tp).first(4); };
        crData p(klPrefix_/KMepoch_/TP(tpl)/TP(tph)/sync_.tdvcNow()); //set timestamp using the domain virtual clock
        p.content(c);
        try {
            // in init state and either initializing on confirmed assert publication or this is a non-empty key list
            if (init_ && tpl != tp_){
                sync_.signThenPublish(std::move(p), [this](const rData&, bool s){ if(s) initDone();});
            } else if (tpl == tp_ && tph == tp_) {
                // is an assertion kl, use conf cb before starting to use new key locally
                // if s =false, means an entire key lifetime has passed and a new key will be made
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
     * makeNewKey makes a new group key, publishes it, and locally switches to using the new key.
     * getNewKey calls the specific keymaking library function needed to make a single key or a key pair,
     * depending on the particular type of key being distributed.
     * A keymaker that has just won an election will publish an empty gk list to assert its win
     * to later joiners. Since subscribers get this kr list, can use reception of any kr list (when in init
     * state with no pending member requests) to publish a membership request.
     * If in init state and there are group members, call initDone to exit init
     *
     * helper methods can be overriden in derived classes
    */
    // get and set a new group key for specific key distributor type
    virtual void getNewKey() {
        curKey_.resize(skSize_); // crypto_aead_xchacha20poly1305_IETF_KEYBYTES
        crypto_aead_xchacha20poly1305_ietf_keygen(curKey_.data());
    }

    // key list publication content specific to this key distributor
    virtual void publishKeyList(const thumbPrint& tpl, const thumbPrint& tph, std::span<const keyRec> esk) {
        tlvEncoder krEnc{};    //tlv encoded content
        krEnc.addNumber(36, curKeyCT_);
        krEnc.addArray(130, esk.begin(), esk.size());
        publishKeyRange(tpl, tph, krEnc.vec());
    }

    // for an assert or a single key record publication
    void publishKeyList(const thumbPrint& tp, std::span<const keyRec> esk) {
        publishKeyList(tp, tp, esk);
    }

    void makeNewKey() {
        // remove expired certs (thumbprints) from memberList
        std::erase_if(mbrList_, [this](auto& kv) { return cs_.contains(kv.first)? rCert(cs_[kv.first]).expired(sync_.tdvcAdjust()) : true; });

        //set the key's creation time
        auto vNow = sync_.tdvcNow(); //set the time using the domain virtual clock
        curKeyCT_ = std::chrono::duration_cast<std::chrono::microseconds>(vNow.time_since_epoch()).count();
        getNewKey();    // sets new curKey_ (and public if any) for specific type of distributor

        std::vector<keyRec> keyRecs{}; //empty vector of empty key records
        publishKeyList(tp_, keyRecs);   // assert uses own tp in range

        auto s = mbrList_.size();
        if (s == 0) { return; }  // no members
        mrResp_.clear();    // clear old response holds if any
        // encrypt the new secret key for each group member in a sealed box
        // that can only opened by the secret key associated with converted public key in mbrList
        for (const auto& [k,v]: mbrList_) {
            std::array<uint8_t, encSKSz_> esk;
            crypto_box_seal(esk.data(), curKey_.data(), curKey_.size(), v.data());
            keyRecs.emplace_back(k, esk);
        }

       // publish new key to all members
        auto pcnt = sync_.batchPubs();
        auto p = s <= maxKR_ ? 1 : (s + maxKR_ - 1) / maxKR_; // determine number of Publications needed
        auto it = keyRecs.begin();
        for(auto i=0u; i<p; ++i) {
            auto r = s < maxKR_ ? s : maxKR_;          
            it += r;
            auto l = i*maxKR_;
            publishKeyList(keyRecs[l].first, keyRecs[l+r-1].first, {it, r});
            s -= r;
        }
        sync_.batchDone(pcnt);
        // publishKeyRange for assertion kr list uses a conf callback that, in turn, calls the newKeyCb
        // that ensures the new key gets to sigmgr user(s). Conf callback means at least one member
        // received the new key
    }

    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void makeKeyTimeout() {
        if (!keyMaker_) return;    // since not a cancelable timer, need to stop if I lose a future election or another keymaker took priority
        makeNewKey();
        sync_.oneTime(reKeyInt_, [this](){ makeKeyTimeout();});  //next re-keying event
    }

    /*
     * This called when a member sends a member request message
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

     // check if this tp is not qualified to receive a copy of the group secret key - can be distributor-specific
     virtual bool noSKey(thumbPrint&) {
         // if (mbrList_.size() > MaxMembers)   return true;
         return false;
     }

    void addGroupMem(const rData& p) {
        if (!keyMaker_) return;
        auto tp = p.signer();   // thumbprint of the signer of the member request (signing cert)
        // check disqualifiers
        if (noSKey(tp) || (msgsDist_ && isRelay(tp))) return;  // identities with RLY don't get pub keys

        // these three lines are to illustrate simple logging
        std::string s = "mreq/";
        s.append(cs_[tp].name()[1].toSv()).append("/").append(cs_[tp].name()[2].toSv());
        logEvent(s);  // log when receive a member request

        if (!mbrList_.contains(tp)) {     // not already a member, add to list (signer already checked on receipt)
            auto pk = cs_[tp].content().toVector();   //access the public key for this signer's thumbPrint
            // convert pk to form that can be used to encrypt and add to member list
            if(crypto_sign_ed25519_pk_to_curve25519(mbrList_[tp].data(), pk.data()) != 0) {
                print ("distKey::addGroupMem: unusable/uncovertable pk for {}\n", cs_[tp].name());
                mbrList_.erase(tp);    //unable to convert member's pk to sealed box pk - erase what the call put in
                return;
            }
            // check for older member signing cert with same identity
            if(mbrIds_.contains(cs_[tp].signer())) removeGroupMem(mbrIds_[cs_[tp].signer()]);
            mbrIds_[cs_[tp].signer()] = tp;
        }
        if(!curKeyCT_)    return;  // haven't made a group key yet

        // hold for 2 distribution delays before resending a response to an MR from this member
        if (mrResp_.contains(tp)) {
            if (mrResp_[tp] >  std::chrono::system_clock::now()) return;
            mrResp_.erase(tp);
        } else mrResp_[tp] = std::chrono::system_clock::now() + 2*sync_.distDelay_;

        //publish the group key for this member: if new, first time. If already a member, republish in response to this mr
        std::array<uint8_t, encSKSz_> esk{};
        crypto_box_seal(esk.data(), curKey_.data(), curKey_.size(), mbrList_[tp].data());
        std::vector<keyRec> keyRecs{ {tp, esk} }; // vector with one key record
        // print ("DistKey::addGroupMem: sending key to {}\nNumber of records={} Size of record {},{}\n", cs_[tp].name(), keyRecs.size(), keyRecs[0].first.size(), keyRecs[0].second.size());
        publishKeyList(tp,  keyRecs);   // assert uses own tp in range
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
        if (reKey) makeNewKey();
    }
};

} // namespace dct

#endif //DIST_KEY_HPP
