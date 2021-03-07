#ifndef MBPS_HPP
#define MBPS_HPP
/*
 * mbps.hpp: message-based pub/sub API for DCT (NDN network layer)
 *
 * Copyright (C) 2020 Pollere, Inc
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

#include <algorithm>
#include <bitset>
#include <functional>
#include <getopt.h>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include "dct/syncps/syncps.hpp"
#include "dct/schema/dct_model.hpp"

using namespace syncps;


/* 
 * MBPS (message-based publish/subscribe) provides a pub/sub
 * data-centric transport inspired by the MQTT API.
 * MBPS uses Pollere's SignatureManager approach to signing
 * and validation,Operant's ndn-ind library, and Pollere's
 * patches to NFD.
 *
 * Messages passed from the application may exceed the size of
 * the Publications passed between the shim and syncps. Larger messages
 * are segmented and sent in multiple Publications and reassembled into
 * messages that are passed to the application's callback.
 *
 * This version (0) only integrity checks and signs the Publications
 * and syncData packets and is the simplest possible instantiation
 * of MBPS.
 */

using error = std::runtime_error;
static constexpr size_t MAX_CONTENT=768; //max content size in bytes, <= maxPubSize in syncps.hpp
static constexpr size_t MAX_SEGS = 64;  //max segments of a msg, <= maxDifferences in syncps.hpp

using confHndlr = std::function<void(const bool, const uint32_t)>;
using connectCb = std::function<void()>;
using MsgID = uint32_t;
using SegCnt = uint16_t;
using Timer = ndn::scheduler::ScopedEventId;
using TimerCb = std::function<void()>;
using MsgInfo = std::unordered_map<MsgID,std::bitset<64>>;
using MsgSegs = std::vector<uint8_t>;
using MsgCache = std::unordered_map<MsgID,MsgSegs>;
using mbpsPub = DCTmodel::sPub;

/*
 * Passes information about messages not in message body
 * These arguments are intended for an iot application
 * Might add payload to this struct in future
 */
struct msgArgs {
    msgArgs() {}
    bool dup{0};
    std::string cap{};      //capability
    std::string loc{};      //location
    std::string topic{};    //message type
    std::string args{};     //specifiers
    std::string ts{};       //message creation time
};

struct mbps;
using msgHndlr = std::function<void(mbps&, std::vector<uint8_t>&, const msgArgs&)>;

/* For subscription to multiple subCollections with different callbacks */
struct subscriptionInfo {
    subscriptionInfo(const msgHndlr&& mh) : sbcoll{}
    { cb = std::move(mh); }
    std::string sbcoll;
    msgHndlr cb;
};
using subscriptionList = std::vector<subscriptionInfo>;

struct mbps
{   
    std::string m_role {};  //temporary way to get role
    bool m_connected = false;
    connectCb m_connectCb;
    DCTmodel m_pb;
    syncps::SyncPubsub m_sync;
    Name m_pubpre{};     // full prefix for Publications
    std::unordered_map<MsgID, confHndlr> m_msgConfCb;
    MsgInfo m_pending{};  // unconfirmed published messages
    MsgInfo m_received{};  //received publications of a message
    MsgCache m_reassemble{}; //reassembly of received message segments
    Timer m_timer;

    mbps(std::string& role) : m_role{role},
        m_pb("mbps0", role),
        m_sync(m_pb.wirePrefix(), m_pb.wireSigMgr(), m_pb.pubSigMgr()),    //handles Sync Data/Interests
        m_pubpre{m_pb.pubPrefix()}  { }

    void run() { m_sync.run(); }
    const auto& pubPrefix() const noexcept { return m_pubpre; } //calling can convert to Name
    const std::string& myRole() const noexcept { return m_role; }

    /*
     * Kicks off the set up necessary for an application
     * to publish or receive publications.
     * This mbps0 client is not using signing keys so a client is considered "connected"
     * once everything is initialized and there's no need to wait for events like the
     * acquisition of keys.
     *
     * This is loosely analogous to MQTT's connect() which connects to a server,
     * but MBPS is serverless; this just makes things ready to communicate.
     */
    void connect(connectCb&& rf)
    {
        //libsodium set up
        if (sodium_init() == -1)
           throw error("Connect unable to set up libsodium");
        m_connectCb = std::move(rf);
        m_connected = true;
        m_connectCb(); //could schedule this with a small delay
    }

    /*
     * Subscribe to all topics in the m_sync Collection with a single callback.
     * An incoming Publication will cause cause the lambda callback to invoke
     * receivePub with the Publication and the application's msgHndlr callback
    */
    mbps& subscribe(const msgHndlr& mh)    {
        _LOG_INFO("mbps:subscribe: single callback for client topic " << m_pubpre);
        m_sync.subscribeTo(pubPrefix(),
                [this,mh](auto p) {receivePub((mbpsPub&)(p),mh);});
        return *this;
    }
    /*
     * Subscribes to the subCollections on the list
     * For an mbps client that is not target-specific, the subCollection
     * passed on the subscription list is used as a target
     */

    mbps& subscribe(const subscriptionList& subList) {
        // Derive subscriptions from the list
        for(auto s : subList) {
            //replace "/" in subcollection with "|" since currently a single component
            std::size_t f = (s.sbcoll).find_first_of("/");
            while(f != std::string::npos)   {
                (s.sbcoll)[f] = '|';
                f = (s.sbcoll).find_first_of("/", f+1);
            }
            _LOG_INFO("mbps:subscribe set up subscription to target: " << m_pubpre << "/" + s.sbcoll);
            m_sync.subscribeTo((pubPrefix().toUri() + "/" + s.sbcoll),
                [this,s](auto p) { receivePub((mbpsPub&)(p),s.cb); });
        }
        return *this;
    }

    /*
     * receivePub() is passed as a callback to m_sync.subscribe and is
     * called when a new Publication (carrying a message segment) is received
     * in a subscribed topic.
     *
     * A message is uniquely identified by its msgID and its timestamp.
     * and each name is identical except for the k in the k out of n sCnt.
     * When all n pieces received,reassemble into a message and callback
     * the message handler associated with subscription.
     *
     * This receivePub guarantees in-order delivery within a message.
     * If in-order delivery is required across messages for a particular
     * application, messages can be held by their origin and timestamp until ordering can be determined
     * or an additional sequence number can be introduced.
     */
     void receivePub(mbpsPub& p, const msgHndlr& mh)
     {      
        SegCnt k = p.number("sCnt"), n = 1u;
        std::vector<uint8_t> msg;
        if (k == 0) { //single publication in this message
            if(auto sz = p.getContent().size())
                msg.assign(p.getContent().buf(), p.getContent().buf() + sz);
        } else {
            MsgID mId = p.number("msgID");
            n = 255 & k;    //bottom byte
            k >>= 8;
            if (k > n || k == 0 || n > MAX_SEGS) {
                _LOG_WARN("receivePub: msgID " << p.number("msgID") << " piece " << k << " > " << n << " pieces");
                return;
            }
            //reassemble message            
            const auto& m = *p.getContent();
            auto& dst = m_reassemble[mId];
            if (k == n)
                dst.resize((n-1)*MAX_CONTENT+m.size());
            else if (dst.size() == 0)
                dst.resize(n*MAX_CONTENT);
            std::copy(m.begin(), m.end(), dst.begin()+(--k)*MAX_CONTENT);
            m_received[mId].set(k);
            if (m_received[mId].count() != n) return; // all segments haven't arrived
            msg = m_reassemble[mId];
            m_received.erase(mId);  //delete msg state
            m_reassemble.erase(mId);
        }                
        /*
         * Complete message received, prepare msgHndlr callback
         */
        _LOG_INFO("receivePiece: msgID " << p.number("msgID") << "(" << n << " pieces) delivered in " << p.timeDelta("mts") << " sec.");
        msgArgs ma;
        ma.ts =  ndn::toIsoString(p.time("mts"), true);
        ma.cap = p["target"];
        ma.loc = p["trgtLoc"];
        ma.topic = p["topic"];
        ma.args = p["topicArgs"];
        mh(*this, msg, ma);
    }

    /*
     * Confirms whether Publication made it to the Collection.
     * If "at least once" semantics are desired, the confirmPublication
     * method is passed to syncps as the onPublished callback to indicate
     * if Publication was externally published or timed out.
     *
     * success = true means appeared in some other node's IBLT
     * false = Publication timed out without appearing in another node's IBLT.
     *
     * When all k of n segments are confirmed published, may invoke a
     * confirmMessage callback to the application that is set when message is
     * passed to shim. (a confHndlr callback)
     *
     */
    void confirmPublication(const mbpsPub& p, bool success)
    {
        MsgID mId = p.number("msgID");
        SegCnt k = p.number("sCnt"), n = 1u;
        if (k != 0) {
            // Don't need to keep state for single piece msgs but multi-piece succeed
            // only if all their pieces arrive and fail otherwise. Keep per-msg arrival
            // state in a bitmap that's created on-demand and erased on completion or timeout.
            n = k & 255;
            if (success) {
                m_pending[mId].set(k >> 8);
                if (m_pending[mId].count() != n) return; // all pieces haven't arrived
            }
            // either msg complete or piece timed out so delivery has failed - delete msg state
            k = m_pending[mId].count();
            if (m_pending.contains(mId)) m_pending.erase(mId);
        }
        if (success) {  //TTP = "time to publish"
            _LOG_INFO("confirmPublication: msgID " << mId << "(" << n << " pieces) arrived, TTP " << p.timeDelta("mts"));
            //if a confirmation cb set by app, would go here
        } else {
            _LOG_INFO("confirmPublication: msgID " << mId << " " << n - k << " pieces (of " << n << ") timed out");
        }
        try {
            m_msgConfCb.at(mId)(success,mId);
        } catch (...) {
                //no confCb for this message, do nothing
        }
        m_msgConfCb.erase(mId); //used the callback so erase
    }

    /*
     * Publish the passed in message by building mbpsPubs to carry the message
     * content and passing to m_sync to publish
     *
     * An application calls this method and passes a message, and an argument
     * list that should contain target (if the client isn't target-specific),
     * topic, and topicArgs. (The argument list could be made optional for a
     * simple example like version 0 or where the shim knows how to extract needed
     * component parameters directly from the message.)
     *
     * The message may need to be broken into content-sized segments.
     * Publications for all segments have the same message ID and timestamp.
     * mId uniquely identifies using uint32_t hash of (origin, timestamp, message)
     *
     * For messages with a confirmation callback (roughly mqtt QoS 1) set, a cb
     * is set in m_sync.publish to confirm each publication of msg and the app
     * callback function (a confHndlr) gets called
     * either when all segments of a message were published or if any segments
     * timed out without showing up in the off-node collection. An application
     * can take action based on this.
     *
     * Return message id if successful, 0 otherwise.
     */

    MsgID publish(std::span<uint8_t> msg, const msgArgs& a,
                     const confHndlr&& ch = nullptr)
    {
        //if any msgArgs are required, check here
        /*
         * Set up and publish Publication(s)
         * msgID is an uint32_t hash of the message
         * incorporating process ID and timestamp to make unique
         */
        auto size = msg.size();
        auto mts = std::chrono::system_clock::now();
        uint64_t tms = duration_cast<ndn::microseconds>(mts.time_since_epoch()).count();
        auto mId = ndn::CryptoLite::murmurHash3((uint32_t)tms, tms >> 32);
        mId = ndn::CryptoLite::murmurHash3(mId, getpid());
        mId = ndn::CryptoLite::murmurHash3(mId, msg.data(), size);

        // determine number of message segments: sCnt forces n < 256,
        // iblt is sized for 80 but 64 fits in an int bitset
        size_t n = (size + (MAX_CONTENT - 1)) / MAX_CONTENT;
        if(n > MAX_SEGS) throw error("publishMsg: message too large");
        auto sCnt = n > 1? n + 256 : 0;
        for (auto off = 0u; off < size; off += MAX_CONTENT) {
            auto len = std::min(size - off, MAX_CONTENT);
            if(ch) {
                m_sync.publish(m_pb.pub(msg.subspan(off, len), "target",
                        a.cap, "trgtLoc", a.loc, "topic", a.topic,
                        "topicArgs", a.args, "msgID", mId, "sCnt", sCnt,
                        "mts", mts), [this](auto p, bool s) {
                            confirmPublication((const mbpsPub&)(p),s); });
            } else {
                m_sync.publish(m_pb.pub(msg.subspan(off, len), "target", a.cap,
                            "trgtLoc", a.loc, "topic", a.topic, "topicArgs", a.args,
                            "msgID", mId, "sCnt", sCnt, "mts", mts));
            }
            sCnt += 256;    //segment names differ only in sCnt
        }
        if(ch) {
            _LOG_INFO("mbps publish with call back for mId: " << mId);
            m_msgConfCb[mId] = std::move(ch);    //set mesg confirmation callback
        }
        return mId;
    }

    // Can be used by application to schedule
    Timer schedule(std::chrono::nanoseconds d, const TimerCb& cb) {
        return m_sync.schedule(d, cb);
    }

};

#endif
