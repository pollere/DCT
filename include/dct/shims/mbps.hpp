#ifndef MBPS_HPP
#define MBPS_HPP
#pragma once
/*
 * mbps.hpp: message-based pub/sub API for a DeftT
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
 *  This proof-of-concept is not intended as production code.
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

#include <dct/syncps/syncps.hpp>
#include <dct/schema/dct_model.hpp>

namespace dct {

// defaults
static constexpr size_t MAX_NAME=80; //max Name size in bytes is determined by a particular schema
                                                                // If not large enough or overly large, change here and recompile
static constexpr size_t MAX_SEGS = 64;  //max segments of a msg, <= maxDifferences in syncps.hpp

/* 
 * MBPS (message-based publish/subscribe) provides a pub/sub shim
 * (inspired by the MQTT API) for DefTT
 *
 * Messages passed from the application may exceed the size of
 * the Publications passed between the shim and syncps. Larger messages
 * are segmented and sent in multiple Publications and reassembled into
 * messages that are passed to the application's callback.
 *
 */

struct mbps;

using mbpsPub = DCTmodel::sPub;
// Used to pass message information to app that is not in message body
struct mbpsMsg : mbpsPub {
    using mbpsPub::mbpsPub;
    mbpsMsg(const mbpsPub& p) { *this = reinterpret_cast<const mbpsMsg&>(p); }
    mbpsMsg(mbpsPub&& p) { *this = std::move(reinterpret_cast<mbpsMsg&&>(p)); }
//    bool dup{0};
};
//publication parameter tags and values are passed to mbps in a vector of parItem pairs
// (defined in library as a string and a value that is a legal parmeter type)
using msgParms = std::vector<parItem>;
using msgHndlr = std::function<void(mbps&, const mbpsMsg&, std::vector<uint8_t>&)>;
using connectCb = std::function<void()>;
using confHndlr = std::function<void(const bool, const uint32_t)>;

using error = std::runtime_error;
using MsgID = uint32_t;
using SegCnt = uint16_t;
using MsgInfo = std::unordered_map<MsgID,std::bitset<64>>;
using MsgSegs = std::vector<uint8_t>;
using MsgCache = std::unordered_map<MsgID,MsgSegs>;

struct mbps
{   
    connectCb m_connectCb;
    DCTmodel m_pb;
    crName m_pubpre{};        // full prefix for Publications
    std::string m_uniqId{};   //create this from #chainInfo to use in creating message Ids
    size_t maxContent_;      // max number of bytes of application message per Publication
    std::unordered_map<MsgID, confHndlr> m_msgConfCb;
    MsgInfo m_pending{};    // unconfirmed published messages
    MsgInfo m_received{};   //received publications of a message
    MsgCache m_reassemble{}; //reassembly of received message segments
    Timer* m_timer;

    mbps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, std::string_view addr)
        : m_pb{rootCb, schemaCb, idChainCb, signIdCb, addr}, m_pubpre{m_pb.pubPrefix()}
        {
            // Pub maxContent is bytes left after space for Pub name and the TL bytes for both Name and Content
            if ((maxContent_ = m_pb.maxInfoSize() - (MAX_NAME + 4)) <= 0)
                throw runtime_error("mbps: no room for Pub Content");
        }

    mbps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb)
        : mbps(rootCb, schemaCb, idChainCb, signIdCb, "")  { }

    void run() { m_pb.run(); }
    void stop() { m_pb.stop(); }
    auto maxContent() { return maxContent_; }
    const auto& pubPrefix() const noexcept { return m_pubpre; }

    auto startMsgsBatch() { return m_pb.m_sync.batchPubs(); }
    void endMsgsBatch() { m_pb.m_sync.batchDone(0); }   // zero forces sendCAdd attempt
    auto msgsBatching() { return m_pb.m_sync.batching_; }

    /* relies on communication schema using mbps conventions of collecting all the signing chain
     * identity information (_role, _roleId, _room, etc.) in pseudo-pub "#chainInfo" so
     * the app can extract what it needs to operate.
     */
    auto attribute(std::string_view v) const { return m_pb.pubVal("#chainInfo", v); }

    /*
     * Kicks off the set up necessary for an application to publish or receive
     * publications. DefTT is considered "connected" once communications are
     * initialized which may include key distribution and/or acquisition. The callback
     * should be how the application starts its work that involves communication.
     * If m_pb.start results in a callback indicating success, m_connectCb is
     * invoked. If failure, throws error to catch
     *
     * This is loosely analogous to MQTT's connect() which connects to a server,
     * but MBPS is serverless; this simply makes DefTT "ready" to communicate.
     *
     * connect does not timeout; if there is a wait time limit meaningful to an
     * application it should set its own timeout.
     */

    void connect(connectCb&& scb)
    {
        m_connectCb = std::move(scb);
        m_uniqId = dct::format("{}", rName(m_pb.pubVal("#chainInfo")));

        // call start() with lambda to confirm success/failure
        m_pb.start([this](bool success) {
                if (!success) throw runtime_error("mbps failed to initialize connection");
                m_connectCb();
            });
    }

    /*
     * Subscribe to all Publications in the sync Collection with a single callback.
     *
     * An incoming Publication will cause cause the lambda to invoke
     * receivePub() with the Publication and the application's msgHndlr callback
    */
    mbps& subscribe(const msgHndlr& mh)    {
        m_pb.subscribe(pubPrefix(), [this,mh](auto p) {receivePub(p, mh);});
        return *this;
    }

    // distinguish subscriptions further by topic or topic/location
    // Slashes ("/") in suffix are component separators; there is no way to embed a slash in a component
    mbps& subscribe(std::string_view suffix, const msgHndlr& mh)    {
        //XXX 'format' is a hack - need to split suffix on slashes but want c++ ranges for that
//        m_pb.subscribe(crName{format("{}/{}", rName{pubPrefix()}, suffix)}, [this,mh](auto p) {receivePub(p, mh);});
        m_pb.subscribe(appendToName(pubPrefix(), suffix), [this,mh](auto p) {receivePub(p, mh);});
        return *this;
    }

    /*
     * receivePub() is called when a new Publication (carrying a message segment) is
     * received in a subscribed topic.
     *
     * A message is uniquely identified by its msgID and its timestamp.
     * and each name is identical except for the k in the k out of n sCnt.
     * When all n pieces received,reassemble into a message and callback
     * the message handler associated with subscription.
     * paramNames() gets the paramater tags of a publication while tagNames()
     * returns all the tags of a publication
     *
     * This receivePub guarantees in-order delivery of Publications within a message.
     *
     * If in-order delivery is required across messages from an origin for a particular
     * application, messages can be held by their origin and timestamp until ordering can
     * be determined or an additional sequence number can be introduced.
     */
     void receivePub(const Publication& pub, const msgHndlr& mh)
     {      
        const auto& p = mbpsPub(pub);
        //all the publication name ftags (in order) set by app or mbps
        SegCnt k = p.number("sCnt"), n = 1u;
        std::vector<uint8_t> msg{}; //for message body
        if (p.name().size() > MAX_NAME)
            print ("mbps::receivePub: pub name size {} ({}) exceeds preset max {}\n", p.name().size(), sizeof(p.name()), MAX_NAME);

        auto content = p.content().rest();
        if (k == 0) { //single publication in this message
            if(auto sz = content.size()) msg.assign(content.data(), content.data() + sz);
        } else {
            MsgID mId = p.number("msgID");
            n = 255 & k;    //bottom byte
            k >>= 8;
            if (k > n || k == 0 || n > MAX_SEGS) {
                print("receivePub: msgID {} piece {} > n pieces\n", p.number("msgID"), k, n);
                return;
            }
            //reassemble message            
            const auto& m = content;
            auto& dst = m_reassemble[mId];
            if (k == n)
                dst.resize((n-1)*maxContent_+m.size());
            else if (dst.size() == 0)
                dst.resize(n*maxContent_);
            std::copy(m.begin(), m.end(), dst.begin()+(--k)*maxContent_);
            m_received[mId].set(k);
            if (m_received[mId].count() != n) return; // all segments haven't arrived
            msg = m_reassemble[mId];
            m_received.erase(mId);  //delete msg state
            m_reassemble.erase(mId);
        }                
        // Complete message received, prepare arguments for msgHndlr callback
        mh(*this, mbpsMsg(p), msg);
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
    void confirmPublication(const Publication& pub, bool success)
    {
        const mbpsPub& p = mbpsPub(pub);
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
            if (m_pending.contains(mId)) m_pending.erase(mId);
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
     * content and passing to m_pb to publish
     *
     * An application calls this method and passes a vector of pairs (msgParms) that
     * is used to fill in any needed tag values and an optional message body.
     * (May use m_pb.paramNames() to make sure all the parameter tags have been set.)
     *
     * The message may need to be broken into content-sized segments.
     * Publications for all segments have the same message ID and timestamp.
     * mId uniquely identifies using uint32_t hash of (origin, timestamp, message)
     * where <origin> is a tag value or combination of tag values the application
     * uses as unique identifiers (e.g., role/roleId)
     *
     * For messages with a confirmation callback (roughly mqtt QoS 1) set, a cb
     * is set in m_pb.publish to confirm each publication of msg and the app
     * callback function (a confHndlr) gets called either when all segments of a
     * message were published or if any segments timed out without showing up in
     * the off-node collection. An application may take action based on this.
     *
     * Adds the mbps-specific parameters to pass to publication builder
     *
     * Return message id if successful, 0 otherwise.
     */

    constexpr void doPublish(auto&& p, bool hasCH) {
        if (p.name().size() > MAX_NAME) {
            dct::print ("mbps::publish: pub name size {} exceeds  MAX_NAME value {} (update MAX_NAME)\n", p.name().size(), MAX_NAME);
        }
        if (hasCH) {
            m_pb.publish(std::move(p), [this](auto p, bool s){ confirmPublication(mbpsPub(p),s); });
            return;
        }
        m_pb.publish(std::move(p));
    }

    MsgID publish(msgParms&& mp, std::span<const uint8_t> msg = {}, const confHndlr&& ch = nullptr)
    {
        /*
         * Set up and publish Publication(s)
         * can check here for required arguments
         * msgID is an uint32_t hash of the message, incorporating ID and timestamp to make unique
         */
        const bool hasCH = (bool)ch;
        auto size = msg.size();
        auto mts = std::chrono::system_clock::now();
        mp.emplace_back("mts", mts);

        uint64_t tms = duration_cast<std::chrono::microseconds>(mts.time_since_epoch()).count();
        std::vector<uint8_t> emsg;
        for(size_t i=0; i<sizeof(tms); i++)
            emsg.push_back( tms >> i*8 );
        emsg.insert(emsg.end(), m_uniqId.begin(), m_uniqId.end());
        emsg.insert(emsg.end(), msg.begin(),msg.end());
        std::array<uint8_t, 4> h;        //so fits in uint32_t
        crypto_generichash(h.data(), h.size(), emsg.data(), emsg.size(), NULL, 0);
        uint32_t mId = h[0] | h[1] << 8 | h[2] << 16 | h[3] << 24;
        mp.emplace_back("msgID", mId);
        if (ch) m_msgConfCb[mId] = std::move(ch);    //set mesg confirmation callback

        // determine number of message segments: sCnt forces n < 256,
        // iblt is sized for 80 but 64 fits in an int bitset
        size_t n = (size + (maxContent_ - 1)) / maxContent_;
        if(n > MAX_SEGS) throw error("publishMsg: message too large");
        auto sCnt = n > 1? n + 256 : 0;
        mp.emplace_back("sCnt", sCnt);

        // try...catch for errors in building the pub
        try {
            if (size == 0) { //empty message body
                doPublish(m_pb.pub({}, mp), hasCH);
                return mId;
            }

            if (n > 1)  // batch publications of same message
                startMsgsBatch();
            // publish as many segments as needed
            for (auto off = 0u; off < size; off += maxContent_) {
                auto len = std::min(size - off, maxContent_);
                doPublish(m_pb.pub(msg.subspan(off, len), mp), hasCH);
                sCnt += 256;    //segment names differ only in sCnt
                mp.pop_back();   //sCnt is last argument on the list
                mp.emplace_back("sCnt", sCnt);
            }
        } catch (const std::exception& e) {
            std::cerr << "mbps::publish: " << e.what() << std::endl;
            for (auto e : mp) print ("{}/", e.second);
            print ("\n");
            endMsgsBatch();
            return 0;
        }
        endMsgsBatch();
        return mId;
    }

    // Can be used by application to schedule a cancelable timer. Note that
    // this is expensive compared to a oneTime timer and should be used
    // only for timers that need to be canceled before they fire.
    pTimer schedule(std::chrono::microseconds d, TimerCb&& cb) { return m_pb.schedule(d, std::move(cb)); }

    // schedule a call to 'cb' in 'd' microseconds (cannot be canceled)
    void oneTime(std::chrono::microseconds d, TimerCb&& cb) { m_pb.oneTime(d, std::move(cb)); }
};

} // namespace dct

#endif
