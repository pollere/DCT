#ifndef DIST_KEM_HPP
#define DIST_KEM_HPP
#pragma once
/*
 * dist_kem - distribute an encryption key or key pair to a group of defined trust domain members
 * using Key Encapsulation Mechanism (KEM)
 * This version is a self-contained 'header-only' library.
 *
 * DistKem manages the key distribution operations including the decision on
 * which (eligible) entity will create the group key. Only one entity should
 * be making group keys and will rekey at periodic intervals to distribute
 * a new key. The entity that wins the election is a "keymaker" or "maker" and
 * publishes an announcement of the current key that has a lifetime equal to that of the
 * group keys it makes. Upon receiving the announcement, members publish a request-for-key.
 * Each member makes an ephemeral key pair and sends the ephemeral public key in
 * the key request. This key pair can either be made with the X25519 crypto_box_keypair()
 * or the hybrid PQ  crypto_kem_keypair
 *
 * Functions from libsodium are used to make keys and do encryption/decryption
 * The keymaker uses libsodium's crypto_kem_enc() to encrypt
 * the key which is publishes in a key record; the receiving member uses the ephemeral
 * sk to decrypt, after which it discards the ephemeral pair.
 *
 * This distributor puts four separate subtopics into use: <pubprefix>/{km,ck,rk,kr}
 * where <pubprefix> is passed in as the topic for all publications and
 * subtopic km is used by the key maker election,
 * subtopic ak is used by the (winning) key maker to announce the current key,
 * subtopic rk is used by members of the group to request a copy of the encryption key, and
 * subtopic sk is used by the key maker to publish the encrypted secret key in response to the rk.
 * The PDU prefix the distributor's sync uses is <tp_id>/keys/<msgs || pdus>, in the "keys" collection
 *
 * As soon as its syncps is registered, it will receive pubs into its collection(s) but the pubs don't invoke
 * a subscription callback until one is registered (in start())
 * 
 * Copyright (C) 2020-6 Pollere LLC
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
 *  dist_kem is not intended as production code.
 */

#include "dist.hpp"
#include "km_election.hpp"

namespace dct {

// for symmetric group key, skSize = crypto_aead_xchacha20poly1305_IETF_KEYBYTES, pkSize=0
// skSize should be the same as the xwing shared secret size (32 bytes)
// for xwing encrypted ephemeral shared secret: encSSSz = crypto_kem_CIPHERTEXTBYTES and
// for PQC=1 the group SK is encrypted using crypto_secretbox_easy encSKSz = crypto_aead_xchacha20poly1305_IETF_KEYBYTES + crypto_secretbox_MACBYTES
// sealed box encrypted ephemeral secret key: encSKSz = crypto_aead_xchacha20poly1305_IETF_KEYBYTES + crypto_box_SEALBYTES
// for subscriber group, pkSize = crypto_kx_PUBLICKEYBYTES

// Following allows use of different options via compile flags.
// Eventually, need to use schema to select, this is just in-progress
// Default gets the orignal DIstKey with a member list
// Use KEM=1 to get KEM DistKey and then PQC=0 for X25519 only and PQC=1 for xwing

// PQC of 0 uses X25519 ephemeral keys, PQC of 1 uses X-wing PQ ephemeral keys
#ifndef PQC
#define PQC 0
#endif

#if PQC>1
#include "kem_xwing_grpkey.c"
#endif

 static constexpr uint8_t reqLimit = 5;

template <std::size_t skSize, std::size_t encSKSz, std::size_t pkSize = 0>
struct DistKey : Dist {
    constexpr static auto skSize_ = skSize;
    constexpr static auto encSKSz_ = encSKSz;
    constexpr static auto pkSize_ = pkSize;
#if PQC>0 // xwing ephemeral KP
    constexpr static auto encSSSz_ = crypto_kem_CIPHERTEXTBYTES; // crypto_kem_mlkem768_CIPHERTEXTBYTES;
    constexpr static auto pkeSize_ = crypto_kem_PUBLICKEYBYTES;
    constexpr static auto skeSize_ = crypto_kem_SECRETKEYBYTES;
#else // PQC == 0 X25510 ephemeral KP
    constexpr static auto pkeSize_ = crypto_box_PUBLICKEYBYTES;
    constexpr static auto skeSize_ = crypto_box_SECRETKEYBYTES;
#endif

    constexpr static auto TPbytes_ = 4;  //leading portiong of thumbprint used as id in name - may be determined dynamically later
    constexpr static auto KeyReqLim = 10;   // number of times to request secret key before publishing nk
    using addKeyCb = std::function<void(keyRef, keyRef, uint64_t)>;
    using capValCB = ofats::any_invocable<int32_t(thumbPrint)>;

    const crName skPrefix_;     // prefix for secret key publications from keymaker
    const crName rkPrefix_;    // prefix for member request key publications
    const crName akPrefix_;     // prefix for key announcements
    size_t maxKR_;
    addKeyCb newKeyCb_;   // called when group key rcvd
    capValCB kmPri_;             // for function to extract keymaker priority from identity chain
    thumbPrint kmtp_{};         // thumbprint of the keymaker
    keyVal ePK_{};                  // a ephemeral pk sent in a kr; use with
    keyVal eSK_{};                   // ephemeral sk to decrypt group key
    keyVal grpSK_{};              // current secret key
    keyVal grpPK_{};               // current public key (not set for symmetric group key sigmgrs)
    uint64_t grpKT_{};          // current key (pair) "valid after" time in microsecs
    uint64_t preKT_{};          // saves current gk time when enter election (for later testing)
    keyVal grpSeed_{};           // the current seed so the group symmetric key is repeatable for xwing

    tdv_clock::duration reKeyInt_{};
    tdv_clock::duration announceLifetime_{};
    tdv_clock::duration newKeyDly_{20*sync_.distDelay_}; // KM sets new several dispersion delays in future
    tdv_clock::duration rkLifetime_{10*sync_.distDelay_}; // request for key and key records pubs, set to ~ several dispersion delays
    tdv_clock::duration elecDuration_{10*sync_.distDelay_};
    kmElection* kme_{};
    uint32_t KMepoch_{};        // current election epoch
    uint32_t sentSKs_{};         // KeyMaker counter for number of secret keys sent this epoch and keyId
    uint8_t keyId_{};                 // identifier keyMaker puts on each announced key
    uint8_t keyReqCtr_{};      // count number of times the request for secret key was unanswered in a row
    bool keyMaker_{false};      // true if this entity is a key maker
    bool keyElection_{false};   // true if this entity is in an on-going election
    bool msgsDist_ = false;     // true indicates this is a group key distributor for msgs  (not pdus)
    bool rkPending_{false};    //member request pending
    bool skRecv_{false};        // true if valid sk has been received that matches received ak
    bool subscriber_ {true};    // distributor-specific: set if I am in the subscriber group
    bool pubOnlyPossible_{false}; // set for groups that may have publish only members

    pTimer rkRefresh_{std::make_shared<Timer>(getDefaultIoContext())};
    pTimer installKP_{std::make_shared<Timer>(getDefaultIoContext())};

    DistKey(std::string_view dtype, DirectFace& face, const Name& pPre, const Name& dPre, const certStore& cs,
            addKeyCb&& keyCb, tdv_clock::duration reKeyInterval)
        : Dist(dtype, face, pPre, dPre, cs),
          skPrefix_{pPre/"sk"}, // encapsulated secret key pubs
          rkPrefix_{pPre/"rk"},  // request for secret key pubs
          akPrefix_{pPre/"ak"}, // announce key pubs
          newKeyCb_{std::move(keyCb)},  //called when a (new) group key arrives or is created
          reKeyInt_{reKeyInterval} {
        announceLifetime_ = reKeyInt_ + newKeyDly_;
        if ( sync_.collName_.last().toSv() == "msgs") { msgsDist_ = true; dtype_.append("/msgs"); }
        else dtype_.append("/pdus");
        sync_.pubLifetime(tdv_clock::duration(rkLifetime_));
        sync_.getLifetimeCb(
            [this,cand=crPrefix(prefix_/"km"/"cand"),elec=crPrefix(prefix_/"km"/"elec")]
            (const auto& p) ->tdv_clock::duration {
                auto n = p.name();
                if (crPrefix(skPrefix_).isPrefix(n) || crPrefix(rkPrefix_).isPrefix(n)) return rkLifetime_;   //key request or secret key response
                if (cand.isPrefix(n) || elec.isPrefix(n)) return 3s;    // election pubs
                if (crPrefix(akPrefix_).isPrefix(n)) return announceLifetime_;
                return sync_.pubLifetime_; // maybe change to 0ms since shouldn't get here
            }
        ); // end of getLifetimeCb

        /*
         * Derived implementations should compute space for content in their constructors
         * Use worst-case (longest) name size
          * maxContent_ = sync_.maxInfoSize() - (prefix_.size() +  <all the components of name>
        */
    }

     void convertSK(const keyVal, const rData&) {}    // XXXX DistKey approach needs this

    virtual bool setSubscriber() { return true; } // distributor-specific set if  this member needs group secret key for updated SKP
    // distributor-specific check if particular tp is not qualified to receive a copy of the group secret key
    virtual bool isSubscriber(thumbPrint&) { return true; }
    virtual void setPK(keyVal&) { }

    /*
     * Called when my identity has a new signing key pair
     *      use new key immediately to sign - update my signature managers
     *     keymaker needs to assert its role under new cert
     */
    void updateSigningKey(const keyVal sk, const rData& pubCert) {
        Dist::updateSigningKey(sk, pubCert);    // common distributor code handles update, sets tp_
        if (!setSubscriber() || init_ || !keyMaker_) return;

        // if keymaker is rekeyed it needs to change epoch
        if (kmPri_(tp_) <= 0) std::runtime_error("DistKey::updateSigningKey keymaker capability change indicates bad signing chain");
        kmtp_ = tp_;
        ++KMepoch_;
        keyId_ = 0;
        // print("DistKey::updateSigningKey new SP for keymaker {} epoch = {}\n", pubCert.name(), KMepoch_);
        makeKeyTimeout(KMepoch_); // new group key for new epoch and new signing cert
    }

    // members with KM capability call this when a keymaker election is needed
    void enterElection() {
        if (kmPri_(tp_)==0 || keyElection_) return;
        print("enterElection called by {}, epoch {} at {}\n", cs_[tp_].name().first(3), KMepoch_, sync_.tdvcNow());
        preKT_ = grpKT_;
        keyElection_ = true;    // in an election
        kme_->startElection(KMepoch_);
    }

    // monitoring for loss of access to keyMaker - subscribed to by all members with KM capability
    void receiveReqLimit(const rPub& p) {
        if (kmPri_(tp_)==0 || keyElection_) return;   // don't have KM capability (shouldn't happen) or in an election
        // check which key is being reported - if older than what I have, member is requesting from an older key announcement
        // ignore reports on older key announcement that has been superseded
        auto n = p.name();
        auto r =  n.nextAt(skPrefix_.size()).toByte();
        auto e = n.nextBlk().toNumber();
          print("rcvNoKm: {} e={}({}) i={} gets r={} {}\n", cs_[tp_].name()[2].toSv(), KMepoch_, e, keyId_, r, p.name());
        if (r == reqLimit && e == KMepoch_ && n.nextBlk().toByte() == keyId_)
              sync_.oneTime(std::chrono::milliseconds(rand_(1,19)), [this](){ enterElection(); });
    }

    // call newKeyCb_ to pass the new group key info. If key time sufficiently in future, use a timer to delay
    // after the first key in an epoch, keymaker sets KT to newKeyDly_ in future so members have time to
    // acquire the new key.
    // Note: if a member starts up during the time after the new key is made and before its
    // KT is reached, it won't be able to init until KT so delay should be kept relatively short
    // Non-keymakers with the KM capability monitor if the elected keymaker becomes incapacitated or unreachable
    // The KM should make a new key reKeyInt_ - newKeyDly_ after the grpKT_
    // adding reKeyInt_ to the grpKT_ gives an extra newKeyDly_ to receive news of the new key but
    // multiples of newKeyDly_ can be added for more conservative re-election but longer delays in electing a
    // new KM - only a problem for newly joining members.
    void installNewKey() {
        auto install = [this](){    // does key installation
            newKeyCb_(grpSK_, grpPK_, grpKT_); //use addKeyCb to set new group key in sigmgr - starts using to sign immediately
            if (kmPri_(tp_)) {    // >0 if I have KM capability
                uint64_t now =  std::chrono::duration_cast<std::chrono::microseconds>(sync_.tdvcNow().time_since_epoch()).count();
                tdv_clock::duration d{grpKT_ < now ? now-grpKT_ : 0};
                // here adds two  extra newKeyDly_ for check if a new grpKT_ has been set
                sync_.oneTime(reKeyInt_ - d + 2*newKeyDly_ + std::chrono::milliseconds(rand_(1,19)), [this,kt=grpKT_](){
                print("installCB:: grpKT_={}, kt={}\n", grpKT_, kt); if (grpKT_== kt) enterElection(); });
            }
            if (init_)  { initDone(); if(!keyMaker_) sync_.sendCState();} // can exit init; send a confirming cState in case KM starting, too
        };

        uint64_t now =  std::chrono::duration_cast<std::chrono::microseconds>(sync_.tdvcNow().time_since_epoch()).count();
        if (grpKT_ > now) { // times may be off by distDelay_ but shouldn't be an issue
            installKP_ = sync_.schedule(std::chrono::microseconds(grpKT_ - now), std::move(install));
        } else {
            installKP_->cancel();   // cancel any pending KP install
            install();
        }
     }

    /*
     * publish my request for key and include my ephemeral public key
     *      name: <rkPrefix_><req#><epoch><keyId><timestamp>
     * requests are specific to a particular key announcement, epoch+keyId
     * requests have a lifetime on order of a few distribution delays and are reissued until  a key is received
     * called when a key announcement is received, reschedules self until canceled
     * uses the same ephemeral key pair until a valid key is received which cancels requests
     * If request is unsuccessful reqLimit times in a row, need a new keymaker
     */

    void publishRequestForKey() {
        if (msgsDist_ && isRelay(tp_))  return;   // relays don't publish msgs (shouldn't get here)
        /*using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;
        auto now = std::chrono::system_clock::now();
        print("{:%M:%S} {} publishes a {} request for key\n",  ticks(now.time_since_epoch()), cs_[tp_].name(), sync_.collName_.last().toSv());*/
        rkRefresh_->cancel();  // if a request key refresh is scheduled, cancel it
        auto rdly = rkLifetime_ + std::chrono::milliseconds(rand_(1,13));
        if (++keyReqCtr_ > reqLimit) {
            keyReqCtr_ = reqLimit;
            if (!keyElection_ && kmPri_(tp_)) { // If I have KM capability, enter election. Potentially just elect self - fastest resolution
                rkPending_ = false;
                enterElection();
                return;
            }
            rdly = elecDuration_;   // wait longer before request key again
        }

        crData p(rkPrefix_/keyReqCtr_/KMepoch_/keyId_/sync_.tdvcNow());
        p.content(ePK_);
        rkPending_ = true;
        try {
           // print("DistKey::publishRequestForKey: name size={} content size={} available={}\n", p.name().size(), ePK_.size(), sync_.maxInfoSize_);
            sync_.signThenPublish(std::move(p));
        } catch (const std::exception& e) {
            std::cerr << "dist_" << dtype_ << "::publishRequestForKey: " << e.what() << std::endl;
        }
        rkRefresh_ = sync_.schedule(rdly, [this](){ publishRequestForKey(); });
    }

    /*
     * Receipt of  new key announcement causes non-keymakers to publish request for key
     * (key makers resolve if multiples)
     *      name: <akPrefix_><epoch><keyId><timestamp> content holds key valid time and public key, if any
     */
#if PQC>0
    void getEphemeralKP() {    // hybrid PQ X-wing
        ePK_.resize(pkeSize_);
        eSK_.resize(skeSize_);
        crypto_kem_keypair(ePK_.data(), eSK_.data());
     }
#else
     void getEphemeralKP() { // X25519
         ePK_.resize(pkeSize_);
         eSK_.resize(skeSize_);
         crypto_box_keypair(ePK_.data(), eSK_.data());
    }
#endif

    void receiveKeyAnnounce(const rPub& p) {
        if (msgsDist_ && isRelay(tp_))  return;   // relays don't get pub keys for msgs collection
        const auto& tp = p.signer();    // get thumbprint of this Pub's signer; must have KM capability
        if (!cs_.contains(tp) || kmPri_(tp) <= 0) return;  // ignore if signed by expired or unauthorized identity
        auto n = p.name();
        auto epoch = n.nextAt(skPrefix_.size()).toNumber();
        auto reqNo = n.nextAt(skPrefix_.size()).toNumber();
        uint8_t keyId = n.nextBlk().toByte();
        //illustrate simple logging
        std::string s = std::format("akRec/{}/{}/{}/{}", cs_[tp].name()[2].toSv(), reqNo, epoch, keyId);
        logEvent(s);  // log

        if (cs_[tp].signer() == cs_[tp_].signer()) { // From earlier signing key of my own identity?
            if (init_) {
                keyMaker_ = true; // appears I am a restarted keymaker, grab keymaker status and return
                KMepoch_ = ++epoch;    // epoch is incremented for new KM signing pair
                keyId_ = 0;     // restart keyId count for new epoch
                sync_.subscribe(rkPrefix_, [this](const auto& p){ receiveKeyRequest(p); }); // keymakers need the key requests
                makeKeyTimeout(KMepoch_);  //schedule group key creation with this epoch and current signing cert
            }
            return;
        }      
        if (keyMaker_) { // another key maker is announcing a key - largest thumbPrint and most recent epoch wins
                                    // test keyId_ because don't relinquish keymaker status if have made multiple keys in this epoch (late joiner)
            if ((tp_ < tp && epoch == KMepoch_ && keyId_ == 1) || (epoch > KMepoch_)) {
                keyMaker_ = false; // relinquish keymaker status
                sync_.unsubscribe(rkPrefix_);
                sync_.subscribe(skPrefix_, [this](const auto& p){ receiveSecretKey(p); });  //XXX put tp test in lambda
            }
            else return;    // remaining as keyMaker
        }

        // get here => not a key maker
        // ignore announcements from earlier epoch or keyId or smaller tp than my KM or (if larger) not if it's a late joiner
        if (epoch < KMepoch_ || (epoch == KMepoch_ && (keyId < keyId_ || (keyId ==keyId_ && tp <= kmtp_)))) {
        return; // older key that has been superseded
        }

        // extract key time and PK (if any) from content
        decltype(grpKT_) newKT{};
        keyVal newPK;
        try {
            auto content = p.content();
            newKT = content.nextBlk(36).toNumber(); // first tlv should be type 36 and should decode to a uint64_t
            // if group uses key pair, there should be a public key and next tlv should be type 150 that decodes to a vector of uint8_t
            if constexpr (pkSize_) newPK = content.nextBlk(150).toVector();
        } catch (std::runtime_error& ex) { return; } //ignore this publication

        // set/change to this sending keyMaker, epoch, keyId, KT to values of the group key
        kmtp_ = tp;
        KMepoch_ = epoch;
        keyId_ = keyId;
        grpKT_ = newKT; // might want to test for grpKT_ older than rekey interval
        grpPK_ = newPK;

        if (! subscriber_) { // publish-only: set public key to received value, secret key to size 0 and finish
            grpSK_.resize(0);
            installNewKey();
            return;
        }

        // subscribers need the group secret key
        skRecv_ = false;    // don't have sk for this ak
        keyReqCtr_ = 0;
        getEphemeralKP(); // make a new ephemeral key pair for each new key announcement
        publishRequestForKey();
    }

    /*
     * Receipt of secret key publication
     * Look for the pub name using first 4 bytes of my thumbPrint as identifier
     * Tests for valid and current keyMaker are done in receiveKeyAnnounce so a member
     * expects to get a response from a particular keyMaker, epoch and keyId (in order to decrypt and match pk, ct)
     * If the keyMaker changes, there's an announcement and new request will be issued
     *
     * publication names: <skPrefix_><epoch><keyId><tpId><timestamp> content: encrypted SK
     */
     #if PQC==1
     auto decryptSK(const std::span<const uint8_t>& kd) { // assumes x-wing and content contains ss, nonce, grpSK
         // retrieve the encrypted ephemeral ss and decrypt
         std::vector<uint8_t> e{};
         e.assign(kd.begin(), kd.begin()+encSSSz_);
         uint8_t ss[crypto_kem_SHAREDSECRETBYTES]; // for decrypted shared secret -should be skSize_
         if(crypto_kem_dec(ss, e.data(), eSK_.data()) != 0) return -1; // not a good key

         // retrieve the nonce and encrypted grpSK and decrypt with ss
         std::vector<uint8_t> n;
         n.assign(kd.begin()+encSSSz_, kd.begin()+encSSSz_+crypto_secretbox_NONCEBYTES);
         e.assign(kd.begin()+encSSSz_+crypto_secretbox_NONCEBYTES, kd.end());
         uint8_t m[skSize_];    // libsodium seems fiddly about using the vector data()
         if(crypto_secretbox_open_easy(m, e.data(), encSKSz_, n.data(), ss) != 0) return -1; // not a good key
         grpSK_.assign(m, m + skSize_);
         return 0;
     }
     #elif PQC==2
     auto decryptSK(const std::span<const uint8_t>& nk) { // assumes x-wing
        uint8_t ss[crypto_kem_SHAREDSECRETBYTES]; // for decrypted shared secret -should be skSize_
        if(crypto_kem_dec(ss, nk.data(), eSK_.data()) != 0) {
        print ("DistKey::decryptSK: {} \n\tcouldn't decrypt SK {}\n", cs_[tp_].name()[2].toSv(), nk);
         return -1; // not a good key
         }
     //   if(crypto_kem_xwing_dec_gk(ss, nk.data(), eSK_.data()) != 0) return -1; // not a good key - might want to count failures and take action
        grpSK_.assign(ss, ss + skSize_);
        return 0;
     }
    #else
     auto decryptSK(const std::span<const uint8_t>& nk) { // assumes crypto sealed box
         uint8_t m[skSize_]; // this is what crypto_box_seal will return - should = skSize_
         if(crypto_box_seal_open(m, nk.data(), nk.size(), ePK_.data(), eSK_.data()) != 0) {
         print ("DistKey::decryptSK: {} \n\tcouldn't decrypt SK {}\n", cs_[tp_].name(), nk);
            return -1; // not a good key - might want to count failures and take action
        }
        grpSK_.assign(m, m + skSize_);
        return 0;
     }
     #endif

    void receiveSecretKey(const rPub& p) {   
        if (!rkPending_ || (msgsDist_ && isRelay(tp_)))  return;  // ignore if no request pending; relays don't get pub keys for msgs collection

        static constexpr auto equal = [](const auto& a, const auto& b) -> bool {
            return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0; };

        // check that it matches my request
        const auto& tp = p.signer();    // thumbprint of this KeyRecord's signer
        if (!equal(tp, kmtp_)) return;  // not signed by my keyMaker
        auto n = p.name();
        auto epoch = n.nextAt(skPrefix_.size()).toNumber();
        if (epoch != KMepoch_)  return;
        if (n.nextBlk().toByte() != keyId_) return;
        if (!equal(n.nextBlk().toSpan(), std::span(tp_).first(TPbytes_))) return;   // not for me
 #if PQC==1
        if (p.content().len() != encSSSz_ + crypto_secretbox_NONCEBYTES + encSKSz_) return; //not the right size
 #else
        if (p.content().len() != encSKSz_) return; // not the right size
 #endif

        // for non PQC the content should decode to a vector of uint8_t, the encrypted secret key
        // for PQC=1, hold encrypted shared secret, nonce, and encrypted (with ss) secret key
        if (decryptSK(p.content().toSpan()) != 0) return;  // decrypt and save the key; non-zero return indicates decrypt failed

        //got a new group secret key, cancel pending member request
        rkRefresh_->cancel();  // if a request-for-key refresh is scheduled, cancel it
        rkPending_ = false;     // reissued if a new key announcement is received
        skRecv_ = true;     // received valid sk matching ak
        //print("receiveSecretKey at {} time {}\n", cs_[tp_].name().first(3), sync_.tdvcNow());
        installNewKey();          // since receiveAnnounce won't request an older key, don't have to test for older key here
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
    void start(connectedCb&& ccb) override {
        connCb_ = std::move(ccb);
        if (!sync_.autoStart_) sync_.start();  // all distributors "before" me have initialized

        // relay doesn't participate in pub group as it doesn't do encryption or decryption
        // relays need to pass-through the group key pubs so they have a distributor with
        // its own subscription cb set by the ptps shim when the interface is "connected"
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

        /*
         * All members subscribe to key announcement subcollection:
         * keymakers subscribe in case of conflicts with other keymakers
         * and may find a publication in the subcollection from an elected keymaker.
         * KM-capable members subscribe to nk pubs to monitor for a non-responsive keymaker
         */
        sync_.subscribe(akPrefix_, [this](const auto& p){ receiveKeyAnnounce(p); });
        if (kmPri_(tp_) == 0) { // if not keymaker candidate
            sync_.subscribe(skPrefix_, [this](const auto& p){ receiveSecretKey(p); });
            return;
        }

        auto eDone = [this](auto elected, uint8_t epoch) {
            keyElection_ = false;   // election over
            if (!elected || KMepoch_ >= epoch || grpKT_ > preKT_) {  // not elected or received ak/sk from more qualified KM
                    if (keyMaker_) sync_.unsubscribe(rkPrefix_);    // no longer keyMaker
                    keyMaker_ = false;
                    sync_.subscribe(skPrefix_, [this](const auto& p){ receiveSecretKey(p); });
                    sync_.subscribe(rkPrefix_/reqLimit, [this](const auto& p){ receiveReqLimit(p);});
                    return;
            }
            KMepoch_ = epoch;
            keyId_ = 0; // make sure cleared for this epoch
            if (rkPending_) {
                rkRefresh_->cancel();  // if a request-for-key refresh is scheduled, cancel it
                rkPending_ = false;
            }
            if (!keyMaker_) { // not previously keyMaker: subscribe to rk pubs and may need to unsubscribe sk pubs
                    sync_.unsubscribe(skPrefix_);
                    sync_.subscribe(rkPrefix_, [this](const auto& p){ receiveKeyRequest(p); }); // keymakers need the member requests
            }
            keyMaker_ = elected;
            //print("{} wins election to make {} group keys\n", cs_[tp_].name(), sync_.collName_.last().toSv());
            makeKeyTimeout(KMepoch_);  //create a group key and reschedule group key creation
        };

        // start my initial election - durations should be ~10 distDelays
        // KMepoch>0 indicates I received ak pub from established keymaker
        keyElection_ = true;    // in an election
        preKT_ = grpKT_;
        kme_ = new kmElection(prefix_/"km", cs_, sync_, std::move(eDone), std::move(kmPri_), tp_,
                      //        std::chrono::duration_cast<std::chrono::milliseconds> (elecDuration_),
                              std::chrono::duration_cast<std::chrono::milliseconds> (10*sync_.distDelay_),
                              KMepoch_);    // indicates I received ak pub from established keymaker

    }

    /*** Following methods are used by the keymaker to distribute and maintain the group key(s)***/

    // encrypt the current group secret key for public key pk

    /*
     * This PQC is a work-in-progress to get sizes, etc correct. More work is needed to encrypt a single
     * group key since libsodium does not expose methods to do so. The work around (hack) here is to
     * overwrite grpSK_ with the two-way shared secret (or "server key") and only test with two members,
     * one KM and one non-KM. This version works when used that way ONLY. Set PQC and KEM compile
     * flags to use this. Must use loopback at runtime for longer packets.
     *
     * PQC set to 1 gives version that uses the shared secret from crypto_kem_enc to encrypt the grpSK
     * This version puts the encrypted ss, the encrypted grpSK and the nonce used in that encryption into
     * the content of one pub. This will be large so future versions could split this up
     */
#if PQC==1
    auto encKey(const auto& pk, auto& ek) {     // X-wing - encSKSz_ is set when created for dist versions
         uint8_t ess[encSSSz_];    // encrypted ephemeral (two-way) shared secret
         uint8_t ss[skSize_];          // ephemeral shared secret
         if (crypto_kem_enc(ess, ss, pk.data()) != 0) return -1;
         ek.assign(ess, ess+encSSSz_);    // build the content to send to recipient member in ek vector

         // use ss to encrypt the group secret key
         uint8_t n[crypto_secretbox_NONCEBYTES];   // set nonce
         randombytes_buf(n, sizeof(n));
         ek.insert(ek.end(), n, n+sizeof(n));    // add nonce to ek
         uint8_t egk[encSKSz_]; // encrypted group key
         if (crypto_secretbox_easy(egk, grpSK_.data(), skSize_, n, ss) != 0) return -1;
         ek.insert(ek.end(), egk, egk+encSKSz_);   // add encrypted grpSK to ek
         return 0;
     }
#elif PQC==2
     auto encKey(const auto& pk, auto& ek) {     // X-wing - encSKSz_ is set when created for dist versions
         uint8_t ct[encSSSz_];    // should be size crypto_kem_CIPHERTEXTBYTES
         uint8_t ss[skSize_];
         if (crypto_kem_enc(ct, ss, pk.data()) != 0) return -1;
         for (std::size_t i=0; i<skSize_; ++i) grpSK_[i] = ss[i];
         /* alternative
         if (crypto_kem_xwing_enc_gk(ct, ss, pk.data(), grpSeed_.data()) != 0) return -1;
         for (size_t i=0; i<skSize_; i++) if (ss[i] != grpSK_[i]) { print("encKey: ss!=grpSK_ at {}: {} != {}\n", i, ss[i], grpSK_[i]); return -1; }
         */
         ek.assign(ct, ct+encSSSz_);
         return 0;
     }
#else
   auto encKey(const auto& pk, auto& ek) {     // X25519 - encSKSz_ is set when created for dist_key versions
       uint8_t m[encSKSz_];
       if (crypto_box_seal(m, grpSK_.data(), skSize_, pk.data()) != 0) return -1;
       ek.assign(m, m + encSKSz_);
       return 0;
   }
   #endif

   // Publish a secret key encrypted for member with tp <skPrefix_><epoch><keyId><tpId><timestamp>
   // this member has sent a request - KM can start using new key and be initialized
     void publishSecretKey(const auto& tp,  const auto& pk) {
        std::vector<uint8_t> ek;
        if (encKey(pk, ek) != 0) return;    // XXXX might want to print the error for testing
        const auto TP = [](const auto& tp){ return std::span(tp).first(TPbytes_); };
        crData p(skPrefix_/KMepoch_/keyId_/TP(tp)/sync_.tdvcNow()); //set timestamp using the domain virtual clock
        p.content(ek);
    //    print("publishSecretKey: {} publishes sk for {}\n", cs_[tp_].name(), cs_[tp].name());
        try {
            sync_.signThenPublish(std::move(p));
            sentSKs_++;
        } catch (const std::exception& e) {
            std::cerr << "dist_" << dtype_ << "::publishSecretKey: " << e.what() << std::endl;
        }
     }

     // When keymaker creates a new group key, it announces it. ck publication has a lifetime until next key's valid time
     // If there may be publish only members, use confirmation cb to start to use new key locally and move out of init
     // <akPrefix_><epoch><keyId><timestamp> content holds key creation time and public key, if any
     void announceKey() {
        tlvEncoder ckEnc{};    // build tlv encoded content
        ckEnc.addNumber(36, grpKT_);
        if constexpr (pkSize_) ckEnc.addArray(150, grpPK_); // decodes to a vector of uint8_t
        crData p(akPrefix_/KMepoch_/keyId_/sync_.tdvcNow()); //set timestamp using the domain virtual clock
        p.content(ckEnc.vec());
        try {
            // start using key locally when the announcement is in a member's collection (could wait for key request unless pubOnlyPossible_)
            //print("announceKey: {} announces(msgs={}) sk {}\n", cs_[tp_].name().first(3),  msgsDist_, p.name());
            sync_.signThenPublish(std::move(p), [this](const rData&, bool s){ if(s) installNewKey(); });
       } catch (const std::exception& e) {
            std::cerr << "dist_" << dtype_ << "::announceKey: " << e.what() << std::endl;
        }
    }

    /*
     * makeNewKey makes a new group key, publishes it
     * getNewKey calls the specific keymaking library function needed to make a single key or a key pair,
     * depending on the particular type of key being distributed.
     *
     * helper methods can be overriden in derived classes
    */
    // set a new group key for specific key distributor type

    #if PQC==2
    // this is for kem_gk alternative in progress
    virtual void getNewKey() {
         uint8_t seed[64];   //set up new group seed corresponding to the new group symmetric key
         randombytes_buf(seed, 64);
         for (int i=0; i<64; ++i) grpSeed_.push_back(seed[i]);
         uint8_t u[32], l[32];  // split for combiner
         for (int i=0; i<32; ++i) { l[i] = grpSeed_[i]; u[i] = grpSeed_[i+32]; }
         uint8_t ct[encSKSz_];  // doesn't get used
         uint8_t ss[crypto_kem_xwing_SHAREDSECRETBYTES];  //should be same as skSize_
         gk_combiner(ss, l, u, ct, grpPK_.data()); // shared secret is the group symmetric key
         grpSK_.assign(ss, ss+skSize_);
    }
   #else
    virtual void getNewKey() {
        grpSK_.resize(skSize_); // crypto_aead_xchacha20poly1305_IETF_KEYBYTES
        crypto_aead_xchacha20poly1305_ietf_keygen(grpSK_.data());
    }
  #endif

    void makeNewKey() {
        getNewKey();    // sets new grpSK_ (and public if any) for specific type of distributor
        keyId_++;
        if (keyId_ == 1)  grpKT_ = std::chrono::duration_cast<std::chrono::microseconds>(sync_.tdvcNow().time_since_epoch()).count();
        else grpKT_ = std::chrono::duration_cast<std::chrono::microseconds>(sync_.tdvcNow().time_since_epoch() + newKeyDly_).count();
        sentSKs_ = 0;
        announceKey();    // start using locally after publication feedback
    }

    // Periodically refresh the group key. This routine should only be called *once*
    // since each call will result in an additional refresh cycle running.
    void makeKeyTimeout(auto e) {
        if (!keyMaker_ || e != KMepoch_) return;    // need to stop if I lose a future election, another keymaker took priority, or I got a new signing key
        makeNewKey();
 //     dct::print("makeKeyTimeout: {} makes new sk (msgs={}) grpKT_={}\n", cs_[tp_].name().first(3), msgsDist_, grpKT_);
        sync_.oneTime(reKeyInt_, [this, e=KMepoch_](){ makeKeyTimeout(e);});  //next re-keying event
    }

    /*
     * receiveKeyRequest is call back for a key request publication a member sends
     * in response to receiving a particular key announcement
     * If received before a key has been made, don't try to publish.
     * .
     * Might also want to check if this peer is de-listed (e.g., blacklisted) but for now assuming this
     * would be handled in validation of cAdd PDU and of Publication.
     */
    void receiveKeyRequest(const rData& p) {
        if (!keyMaker_ || !grpKT_) return;   // haven't made key yet or election in progress (shouldn't happen)
        auto tp = p.signer();   // thumbprint of the signer of the member request (signing cert)
        if (!cs_.contains(tp) || !isSubscriber(tp) || (msgsDist_ && isRelay(tp))) return; // check disqualifiers

        auto n = p.name();  // check if request is for the current key
        n.nextAt(skPrefix_.size()).toByte();  // skip over request number
        if (n.nextBlk().toNumber() != KMepoch_) return;
        if (n.nextBlk().toByte() != keyId_) return;

        // extract ephemeral public key to encrypt response - check size/len
        if (p.content().len() != pkeSize_) { print("receiveKeyRequest: content size is not correct for PK\n"); return; }
        const keyVal& pk = p.content().toVector(); // XXX should this be toSpan keyVal?
        publishSecretKey(tp,  pk);    // publish SK encrypted for member tp using appropriate encryption method
    }

    /*
     * if reKey is set, change the group key now to exclude the removed member
     * needs an way to not encrypt a group key for this thumbPrint in future
     */
    void removeGroupMem(thumbPrint&, bool reKey = false) {
        // XXX could keep black list here or add decommissioning
        if (reKey) makeKeyTimeout(KMepoch_);
    }

    // log distributor publishes to logs collection
    void logEvent(std::string s, std::span<const uint8_t> content = {}) {
        // name portion for tdvc calibrate log publication with role and role-id and # nbrs, no content
        // XXX role and role-id only works for examples - consider using more of cert name to be more general
        logsCb_( crName(msgsDist_? "gkp" : "gkd")  / s / cs_[tp_].name()[1] / cs_[tp_].name()[2] , content);
    }
};

} // namespace dct

#endif //DIST_KEM_HPP
