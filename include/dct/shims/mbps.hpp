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
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <dct/syncps/syncps.hpp>
#include <dct/schema/dct_model.hpp>

namespace dct {

// defaults
static constexpr size_t MaxSegs = 64;  //max segments of a msg, <= maxDifferences in syncps.hpp
// adjust these to suit local use case
static constexpr size_t MaxMsgCache = 5;    // maximum number of incomplete messages to cache before clean up
static std::chrono::microseconds MaxMsgHold = std::chrono::seconds(1);  // max time to wait for publications of incomplete message

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

using  mbpsPub = DCTmodel::sPub;
// Used to pass message information to app that is not in message body
struct mbpsMsg : mbpsPub {
    using mbpsPub::mbpsPub;
    mbpsMsg(const mbpsPub& p) { *this = reinterpret_cast<const mbpsMsg&>(p); }
    mbpsMsg(mbpsPub&& p) { *this = std::move(reinterpret_cast<mbpsMsg&&>(p)); }
};
//publication parameter tags and values are passed to mbps in a vector of parItem pairs
// (defined in library as a string and a value that is a legal parmeter type)
using msgParms = std::vector<parItem>;
using msgHndlr = std::function<void(mbps&, const mbpsMsg&, const std::span<const uint8_t>&)>;
using connectCb = std::function<void()>;
using confHndlr = std::function<void(const bool, const uint32_t)>;
using paceHndlr = std::function<void(mbps&, const bool, const uint32_t)>;

using error = std::runtime_error;
using MsgID = uint32_t;
using SegCnt = uint16_t;
using MsgInfo = std::unordered_map<MsgID,std::bitset<64>>;  // track sent segments for confirm Pub
using MsgSegs = std::vector<uint8_t>;

struct msgState {
    std::bitset<64> trackSegs{};  // tracks which segments of the message have been received
    dct::timeVal tm{};          // used to check for elderly incomplete messages at clean up
    MsgSegs mesg{};         // reassembly buffer for content from Pubs of this message
    size_t contentSz{0};    // space for application message bytes in Publications of this message
    mbpsPub pubInfo{};
};

struct mbps
{   
    connectCb m_connectCb;
    DCTmodel m_pb;
    crName m_pubpre{};        // full prefix for Publications
    std::string m_uniqId{};   //create this from #chainInfo to use in creating message Ids 
    size_t pubSpace_;       // max number of bytes in Publication for mbps name + content
    std::unordered_map<MsgID, confHndlr> m_msgConfCb;
    paceHndlr m_msgPaceCb;  //assuming pace one message at time
    MsgInfo m_pending{};    // unconfirmed published messages
    std::unordered_map<MsgID, msgState> m_msgs{};
    Timer* m_timer;
    bool m_pacing{false};   //set when pacing out a multi-segment message

    mbps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb, std::string_view addr)
        : m_pb{rootCb, schemaCb, idChainCb, signIdCb, addr}, m_pubpre{m_pb.pubPrefix()}
        {
            // bytes left in Pub for mbps to use for both name and content (removes the required TL bytes)
            if ((pubSpace_ = m_pb.maxInfoSize() - 4)  <= 0)
                throw runtime_error("mbps: no room for Pub Name and Content fields");
        }

    mbps(const certCb& rootCb, const certCb& schemaCb, const chainCb& idChainCb, const pairCb& signIdCb)
        : mbps(rootCb, schemaCb, idChainCb, signIdCb, "")  { }

    void run() { m_pb.run(); }
    void stop() { m_pb.stop(); }
    auto maxContent() { return pubSpace_ - m_pubpre.size(); }   // an upper bound on max content bytes per pub - names are larger
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
        // m_pb.pubLifetime(5000ms);    // for setting lifetimes to other than default

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
     void receivePub(const mbpsPub& p, const msgHndlr& mh)
     {
        try {
            //all the publication name ftags (in order) set by app or mbps
            SegCnt k = p.number("sCnt"), n = 1u;
            if (k == 0) {   //single publication in this message
                mh(*this, p, p.content().toSpan());   // timestamp is message origination time
            } else {
                MsgID mId = p.number("msgID");
                n = 255 & k;    //bottom byte
                k >>= 8;
                if (k > n || k == 0 || n > MaxSegs) {
                    print("receivePub: msgID {} piece {} > n pieces\n", p.number("msgID"), k, n);
                    return;
                }
                // create or retrieve a message state entry
                auto& mS = m_msgs[mId];
                mS.tm = std::chrono::system_clock::now();    // time field to use for clean up
                if (mS.contentSz == 0) {
                    mS.contentSz = pubSpace_ - p.name().size();    // max content size for pubs of message mId
                } else if (pubSpace_ - p.name().size() != mS.contentSz) {
                    dct::print("mbps::receivePub: publication for message {} with name {}\n", mId, p.name());
                    throw error("mbps::receivePub: can't reassemble message as has name size mismatch");
                }

                if (k == 1) mS.pubInfo = p; // make a copy of the first segment of the message so app can extract info
                //reassemble message
                const auto& c =  p.content().rest();
                auto& dst = mS.mesg;
                if (k == n)
                    dst.resize((n-1)*mS.contentSz+c.size());
                else if (dst.size() == 0)   // first segment of message, unallocated mesg buffer
                    dst.resize(n*pubSpace_);
                std::copy(c.begin(), c.end(), dst.begin()+(--k)*mS.contentSz);
                (mS.trackSegs).set(k);
                if (mS.trackSegs.count() == n) { // all segments have been receive, message is complete
                    mh(*this, mS.pubInfo, mS.mesg); // msgHndlr callback
                    m_msgs.erase(mId);  //delete msg state
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "mbps::receivePub: " << e.what() << std::endl;
            exit(1);
        }

        // clean up state of incomplete messages when m_msgs cache exceeds threshold (for test on every pass, set threshold=0)
        if (m_msgs.size() >= MaxMsgCache) {
            auto expireTm = std::chrono::system_clock::now() - MaxMsgHold;
            std::erase_if(m_msgs, [expireTm](auto& kv) { return kv.second.tm < expireTm; });
        }
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
        if (hasCH) {
            m_pb.publish(std::move(p), [this](auto p, bool s){ confirmPublication(mbpsPub(p),s); });
            return;
        }
        if(m_pb.publish(std::move(p)) == 0)
            dct::print("doPublish: was unable to publish {}\n", p.name());
    }

    MsgID publish(msgParms&& mp, std::span<const uint8_t> msg = {}, const confHndlr&& ch = nullptr)
    {
        if (m_pacing) return 0;   // can't publish a message while pacing a previous one
        /*
         * Set up and publish Publication(s)
         * can check here for required arguments
         * msgID is an uint32_t hash of the message, incorporating ID and current time to make unique
         */
        const bool hasCH = (bool)ch;
        auto size = msg.size();
        uint64_t tms = duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
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

       // add sCnt value initialized for a single segment (Publication) message
        size_t n = 0;
        mp.emplace_back("sCnt", n); // just to get name size

        if (size == 0) {    //handle empty message body - no Pub content
            try {   // try...catch for errors in building the pub
                doPublish(m_pb.pub({}, mp), hasCH);
                return mId;
            } catch (const std::exception& e) {
                std::cerr << "mbps::publish: " << e.what() << std::endl;
                for (auto e : mp) print ("{}/", e.second);
                print ("\n");
                return 0;
            }
        }

        // determine name size in order to determine the space left for content
        auto contentSp = pubSpace_ - (m_pb.name(mp).size() + 2);   // add 2 bytes in case multiple segments
        if (contentSp < 10) {
            dct::print("mbps::publish Publication name only leaves {} bytes for content\n", contentSp);
            return 0;
        }

        // determine number of message segments to carry msg: sCnt forces n < 256,
        n = (size + (contentSp - 1)) / contentSp;
        if(n > MaxSegs) throw error("publishMsg: message too large");
        auto sCnt = n > 1? n + 256 : 0;
        mp.back().second = sCnt;    //sCnt is last argument on the list

        try {   // try...catch for errors in building the pub
            if (n >1) startMsgsBatch(); // will hold all the segments until finished before goes to network
            // publish as many segments as needed
            for (auto off = 0u; off < size; off += contentSp) {
                auto len = std::min(size - off, contentSp);
                doPublish(m_pb.pub(msg.subspan(off, len), mp), hasCH);
                sCnt += 256;    //segment names differ only in sCnt
                mp.back().second = sCnt;    //sCnt is last argument on the list
            }
        } catch (const std::exception& e) {
            std::cerr << "mbps::publish: " << e.what() << std::endl;
            for (auto e : mp) print ("{}/", e.second);
            print ("\n");
            if (n>1) endMsgsBatch();
            return 0;
        }
        if (n>1) endMsgsBatch();
        return mId;
    }

    /*
     * In-progress work to pace publications of a multi-segment message.
     * This is not likely to stay as is and is lightly tested, so use at your own risk.
     *
     * The approach is that publishPaced() sets all the parameters that don't change
     * segment-to-segment (the caller's parameters plus msgID) as pub builder 'defaults' 
     * which copies their values so it won't matter if either the caller's values or
     * tags go out of sccope when publishPaced returns. This means 'doSegment' only
     * has to supply sCnt in its doPublish call.
     */
    bool pacing() { return m_pacing; }

    void doSegment(uint32_t sC, uint32_t mId, std::chrono::milliseconds paceTm,
            std::vector< uint8_t>&& msg, const bool hasCH )
    {
        size_t k = sC >> 8; 
        auto off = k>0? (k-1)*m_msgs[mId].contentSz : 0;
        auto size = msg.size();
        auto len = std::min(size - off, m_msgs[mId].contentSz);
        // try...catch for errors in building the pub
        try {
            doPublish(m_pb.pub(std::span(msg).subspan(off, len), "sCnt", sC), hasCH);
        } catch (const std::exception& e) {
            std::cerr << "mbps::doSegment: " << e.what() << std::endl;
            return;
        }

        if(off + m_msgs[mId].contentSz >= size) {
            // no more content to send - but wait pace time for this final segment
            oneTime(paceTm, [this,mId] { m_pacing = false; m_msgPaceCb(*this, true, mId); });
            return;
        }
        sC += 256;
        oneTime(paceTm, [this,sC,mId,paceTm,msg=std::move(msg),hasCH]() mutable {
                doSegment(sC, mId, paceTm, std::move(msg), hasCH); });
    }

    MsgID publishPaced(std::chrono::milliseconds paceTm, const paceHndlr&& paceCb, msgParms&& mp,
            std::span<const uint8_t> msg = {}, const confHndlr&& ch = nullptr)
    {
        if (m_pacing) return 0;   // can't publish another message while still pacing one
        m_msgPaceCb = std::move(paceCb);
        /*
         * Set up and publish Publication(s)
         * msgID is an uint32_t hash of the message, hashing ID and current time to make it unique
         */
        const bool hasCH = (bool)ch;
        auto size = msg.size();
        uint64_t tms = duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::vector<uint8_t> emsg;
        for(size_t i=0; i<sizeof(tms); i++) emsg.push_back( tms >> i*8 );
        emsg.insert(emsg.end(), m_uniqId.begin(), m_uniqId.end());
        emsg.insert(emsg.end(), msg.begin(),msg.end());
        std::array<uint8_t, 4> h;        //so fits in uint32_t
        crypto_generichash(h.data(), h.size(), emsg.data(), emsg.size(), NULL, 0);
        uint32_t mId = h[0] | h[1] << 8 | h[2] << 16 | h[3] << 24;
        mp.emplace_back("msgID", mId);
        if (m_msgs.contains(mId)) throw error("mbps::publishPaced: duplicate message id");

        // mp now contains all the parameters that don't change per-segment so make them defaults
        m_pb.defaults(mp);

        if (ch) m_msgConfCb[mId] = std::move(ch);    //set mesg confirmation callback

        // determine max content for publications of this message
        mp.emplace_back("sCnt", 0u); // just to get a name size for this message
       m_msgs[mId].contentSz = pubSpace_ - (m_pb.name(mp).size() + 2);   // add 2 bytes in case multiple segments
        if (m_msgs[mId].contentSz < 10) {
            dct::print("mbps::publish Publication name only leaves {} bytes for content\n", m_msgs[mId].contentSz);
            return 0;
        }

        // determine number of message segments to carry msg: sCnt forces n < 256,
        size_t n = (size + (m_msgs[mId].contentSz - 1)) / m_msgs[mId].contentSz;
        if(n > MaxSegs) throw error("publishMsg: message too large");
        auto sCnt = n > 1? n + 256 : 0;

        // try...catch for errors in building the pub
        try {
            m_pacing = true;
            doSegment(sCnt, mId, paceTm, std::vector<uint8_t>(msg.begin(),msg.end()), hasCH);
        } catch (const std::exception& e) {
            std::cerr << "mbps::publish: " << e.what() << std::endl;
            for (auto e : mp) print ("{}/", e.second);
            print ("\n");
            return 0;
        }
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
