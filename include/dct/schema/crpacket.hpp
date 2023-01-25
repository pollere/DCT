#ifndef CRPACKET_HPP
#define CRPACKET_HPP
/*
 * DCT tlv builders
 *
 * Copyright (C) 2022 Pollere LLC
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
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <array>
#include <bit>
#include <cassert>
#include <cstring>
//#include <ranges> ...waiting for clang to catch up

#include "rand32.hpp"
#include "rpacket.hpp"

using namespace std::literals::chrono_literals;

// build a 'complete' raw TLV - vector containing TLV's data together with an rPacket view of it.

template <typename rView, tlv thisTLV>
struct crTLV : rView {
    std::vector<uint8_t> v_;    // backing store for TLV

    static constexpr uint8_t extra = tlvParser::extra_bytes_code;

    constexpr auto tlvType() const noexcept { return thisTLV; }
    constexpr auto tlvNum() const noexcept { return (uint8_t)thisTLV; }
    constexpr rView& asView() const noexcept { return *this; }

    // tlvBytes() is the #bytes of tlv header needed, tlvSize() is the total size of the tlv block
    static constexpr size_t tlvBytes(size_t len) noexcept { return len < extra? 2 : 4; }
    static constexpr size_t tlvSize(size_t len) noexcept { return len + tlvBytes(len); }

    constexpr auto blkOffset() noexcept {
        // check how much tlv space was left at the front
        size_t off{0};
        while (off < v_.size() && v_[off] == 0) ++off;
        return off;
    }

    constexpr auto initBlk() noexcept {
        // check how much tlv space was left at the front
        auto off = blkOffset();;
        auto len = v_.size() - off;
        rView::m_off = tlvBytes(len);
        if constexpr (std::is_same_v<rView,rPrefix>) {
            // an rPrefix view covers just the TLV value, hiding the initial type & len
            // but during construction the initial TL may not have been added yet
            if (rView::m_off > 0 && v_[off] == tlvNum()) {
                off += rView::m_off;
                len -= rView::m_off;
            }
            rView::m_off = 0;
        }
        rView::m_blk = decltype(rView::m_blk){v_.data()+off, len};
    }

    // C++ default constructors can't be used because they'll copy the source's view
    // and this object needs a view that points to its backing store v_. All constructors
    // have to initialize the object's view from the data in the vector.
    //
    // Default constructor assumes tlv will be built incrementally and leaves room to
    // add the tlv header. The max size for a tlv is 64K which means the max hdr size
    // is 4 bytes. The header will be filled in when .done() is called.
    //
    // Since names are always the first TLVs of their containing TLV,
    // they're initialized with an extra 4 bytes of space to hold the
    // containing TLVs hdr..

    constexpr crTLV() : v_(thisTLV != tlv::Name? 4:8) { }

    // constructor debugging
    crTLV(const crTLV& c) : v_{c.v_} {
        //print("{}cp {}\n", tlvNum(), v_.size());
        initBlk();
    }
    crTLV(crTLV&& c) : v_{std::move(c.v_)} {
        //print("{}mv {}\n", tlvNum(), v_.size());
        initBlk();
    }
    crTLV& operator=(const crTLV& c) {
        //print("{}cp= {}\n", tlvNum(), v_.size());
        if (this != &c) { v_ = c.v_; initBlk(); }
        return *this;
    }
    crTLV& operator=(crTLV&& c) {
        //print("{}mv= {}\n", tlvNum(), v_.size());
        if (this != &c) { std::swap(v_, c.v_); initBlk(); }
        return *this;
    }

    //template<typename V = rView> requires requires {thisTLV != tlv::Name;}
    template<typename V = rView> requires requires {!std::is_same_v<rView,rName>;}
    crTLV(crTLV<rName,tlv::Name>&& n) : rView{}, v_{std::move(n.v_)} {
        //print("{}mvN {} {}\n", tlvNum(), n.v_.size(), v_.size());
        initBlk();
    }
    // these constructors are used for pre-built TLVs and don't leave space for a header.
    // done() will check the tlv length against the vector length and fix it if something was appended.
    crTLV(rView r) : rView{}, v_{r.asSpan().begin(), r.asSpan().end()} { initBlk(); }

    crTLV(const std::vector<uint8_t>& v) : rView{}, v_{v} {
        //print("{}cp2 {}\n", tlvNum(), v_.size());
        initBlk();
    }
    crTLV(std::vector<uint8_t>&& v) : rView{}, v_{std::move(v)} {
        //print("{}mv2 {}\n", tlvNum(), v_.size());
        initBlk();
    }

    // always use the ordering operators of the view
    auto operator<=>(const rView& rhs) const noexcept { return rView(*this) <=> rView(rhs); }
    auto operator==(const rView& rhs) const noexcept { return rView(*this) == rView(rhs); }

    // the following routines are used to incrementally add bytes or TLVs to this tlv.
    // done() is called at the end of each addition to fix up the outer tlv length and
    // update the view to match the vector. The routines can be method-chained.

    // fill in the outer tlv header. 'len' is the *payload* length (doesn't include
    // the TLV header). The last byte of the header will at v_[off-1] (i.e., 'off'
    // is the first payload byte). View is updated to reflect the new hdr and
    // maintain the invarient that m_off indexes the payload start.
    constexpr auto fillOuterHdr(size_t len, size_t off) {
        // fill in the outer tlv header
        auto hsz = tlvBytes(len);
        auto hoff = off - hsz;
        addTlvHdr(tlvType(), len, hoff);
        rView::m_blk = decltype(rView::m_blk){v_.data() + hoff, len + hsz};
        rView::m_off = hsz;
    }

    constexpr auto& done() noexcept {
        auto off = blkOffset();
        auto len = v_.size() - off;
        if (off >= 4 && v_[off] != tlvNum()) {
            // there's no outer hdr yet so len is payload size
            fillOuterHdr(len, off);
            return *this;
        }
        assert(v_[off] == tlvNum());
        if (len > tlvSize(rView::size())) {
            // fix outer tlv length by overwriting previous header. new hdr may be larger
            // so make enough space for it first.
            auto hsz = v_[off+1] >= extra? 4u : 2u;
            off += hsz;
            len -= hsz;
            hsz = tlvBytes(len);
            if (off < hsz) { v_.insert(v_.begin()+off, hsz - off, 0); off = hsz; }
            fillOuterHdr(len, off);
        }
        return *this;
    }

    constexpr auto addTlvHdr(tlv typ, size_t len = 0) noexcept {
        v_.emplace_back((uint8_t)typ);
        if (len >= extra) {
            v_.emplace_back(extra);
            v_.emplace_back(len >> 8);
        }
        v_.emplace_back(len);
    }

    template <typename C> requires requires(C&& c) { c.begin(); }
    constexpr auto& append(C&& dat) noexcept {
        v_.insert(v_.end(), dat.begin(), dat.end());
        return *this;
    }
    template <typename C> requires requires(C&& c) { c.begin(); }
    constexpr auto& append(tlv typ, C&& dat) noexcept {
        addTlvHdr(typ, dat.size());
        return append(std::forward<C>(dat));
    }
    constexpr auto& append(tlv typ, uint64_t num) noexcept {
        // find the most significan non-zero byte then output it and the bytes below it
        int cnt = (std::bit_width(num) >> 3) + 1;
        addTlvHdr(typ, cnt);
        while (--cnt >= 0) v_.emplace_back(num >> (cnt << 3));
        return *this;
    }
    template <typename C> requires requires(C&& c) { c.begin(); }
    constexpr auto& operator+(C&& dat) noexcept { return append(std::forward<C>(dat)); }

    template <typename C> requires requires(C&& c) { c.asSpan(); }
    constexpr auto& appendC(tlv typ, const std::vector<C>& chunks) noexcept {
        size_t siz{};
        for(const auto& c : chunks) siz += c.size();
        addTlvHdr(typ, siz);
        for(const auto& c : chunks) append(c.asSpan());
        return *this;
    }
    constexpr auto& appendC(tlv typ, const std::vector<std::span<const uint8_t>>& chunks) noexcept {
        size_t siz{};
        for(const auto& c : chunks) siz += c.size();
        addTlvHdr(typ, siz);
        for(const auto& c : chunks) append(c);
        return *this;
    }

    // the following routines figure out in advance how big the tlv
    // is going to be and pre-allocate the space.

    constexpr auto addTlvHdr(tlv typ, size_t len, size_t pos) noexcept {
        v_[pos++] = (uint8_t)typ;
        if (len >= extra) {
            v_[pos++] = extra;
            v_[pos++] = len >> 8;
        }
        v_[pos++] = len;
        return pos;
    }

    // uses 'str' to construct a 'name' tlv at the current end of the vector.
    // Since name tlv's are the first item of Interest and Data tlv's and names
    // can be large, names aren't built incrementally and they leave empty
    // space at the front of the container for the outer TLV.
    constexpr auto& strToName(std::string_view str) noexcept {
        // ignore a leading '/'
        if (str.size() && str[0] == '/') str = str.substr(1);
        if (str.size() == 0) return *this;

        // get total size of the name and its component TLVs
        size_t len{0}, l{0}, p;
        for ( ; l < str.size(); l = p + 1) {
            if ((p = str.find('/', l)) == str.npos) p = str.size();
            len += tlvSize(p - l);
        }
        size_t pos = v_.size();
        v_.resize(pos + len);
        //pos = addTlvHdr(tlv::Name, len, pos);

        // copy the components
        for (l = 0; l < str.size(); l = p + 1) {
            if ((p = str.find('/', l)) == str.npos) p = str.size();
            len = p - l;
            pos = addTlvHdr(tlv::Generic, len, pos);
            if (len) std::memcpy(v_.data() + pos, str.data() + l, len);
            pos += len;
        }
        return *this;
    }

    // return the payload length and offset for the TLV length starting at 'off'
    constexpr std::pair<size_t,size_t> tlvLen(size_t off) const {
        auto c = rView::m_blk[off];
        if (c < rView::extra_bytes_code) return std::pair{c, off+1};
        if (c > rView::extra_bytes_code) throw runtime_error("tlv length >64k");
        return std::pair{(size_t(rView::m_blk[off+1]) << 8) | rView::m_blk[off+2], off+3};
    }
};

struct crName : crTLV<rName,tlv::Name> {
    constexpr crName() = default;

    crName(rName n) { append(n.asSpan()); initBlk(); }
    crName(rPrefix n) { append(n.asSpan()); done(); }
    crName(std::string_view s) { strToName(s).done(); }

    // return a tlvParser for name component 'comp'
    auto operator[](int comp) const { return rName(*this)[comp]; }

    // return a crname consisting of the first 'ncomp' components of this name
    auto first(int ncomp) const { return crName{rPrefix(*this).first(ncomp)}; }
};

template <typename C> requires requires(C&& c) { c.begin(); }
static inline crName operator/(crName p, C&& c) { p.append(tlv::Generic, std::forward<C>(c)).done(); return p; }

static inline crName operator/(crName p, std::string_view s) { p.append(tlv::Generic, s).done(); return p; }

static inline crName operator/(crName p, uint64_t n) { p.append(tlv::SequenceNum, n).done(); return p; }

static inline crName operator/(crName p, std::chrono::microseconds t) {
       p.append(tlv::Timestamp, t.count()).done(); return p;
}
static inline crName operator/(crName p, std::chrono::system_clock::time_point t) {
       return p / std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch());
}

// this routine appends a multi-component name (e.g., "foo/bar/baz"). '/' is always a
// component separator. Leading and trailing slashes and empty components are ignored.
static inline crName appendToName(crName p, std::string_view nm) {
    //for (const auto comp: std::ranges::lazy_split_view(nm, "/")) if (comp) p /= comp;
    // without ranges we do it the hard way...
    size_t pos{};
    size_t l;
    while ((l = nm.find('/', pos)) != std::string_view::npos) {
        if (l - pos > 0) p = p / nm.substr(pos, l - pos);
        pos = ++l;
    }
    if (pos < nm.size() - 1) p = p / nm.substr(pos);
    return p;
}

struct crPrefix : crTLV<rPrefix,tlv::Name> {
    constexpr crPrefix() = default;
    crPrefix(crPrefix&& ) = default;
    crPrefix(const crPrefix& ) = default;
    crPrefix& operator=(const crPrefix&) = default;
    crPrefix& operator=(crPrefix&&) = default;

    crPrefix(crName&& n) : crTLV{std::move(n)} { }
    crPrefix(const crName& n) : crTLV{n} { }
};

template<> struct fmt::formatter<crName>: formatter<rPrefix> {
    template <typename FormatContext>
    auto format(const crName& n, FormatContext& ctx) const -> decltype(ctx.out()) {
        return format_to(ctx.out(), "{}", rPrefix(n));
    }
};
template<> struct fmt::formatter<crPrefix>: formatter<rPrefix> {
    template <typename FormatContext>
    auto format(const crPrefix& n, FormatContext& ctx) const -> decltype(ctx.out()) {
        return format_to(ctx.out(), "{}", rPrefix(n));
    }
};

struct crInterest : crTLV<rInterest,tlv::Interest> {
    crInterest(crName&& n, std::chrono::milliseconds lt, uint32_t non = rand32()) : crTLV{std::move(n)} {
        append(tlv::Nonce, std::array{uint8_t(non), uint8_t(non >> 8), uint8_t(non >> 16), uint8_t(non >> 24)});
        append(tlv::InterestLifetime, lt.count());
        done();
    }
};

struct crData : crTLV<rData,tlv::Data> {
    constexpr crData() = default;

    void init(tlv typ) { append(TLV<tlv::MetaInfo>(TLV<tlv::ContentType>(uint8_t(typ)))); done(); }

    crData(rData d) : crTLV(d) { }
    crData(crName&& n, tlv typ=tlv::ContentType_CAdd) : crTLV{std::move(n)} { init(typ); }
    crData(rName n, tlv typ=tlv::ContentType_CAdd) { append(n.asSpan()); init(typ); }

    auto content() const { return rData::content(); }

    auto&& content(std::span<const uint8_t>& v) {
        append(tlv::Content, v);
        done();
        return std::move(*this);
    }
    auto&& content(const std::vector<uint8_t>& v) {
        append(tlv::Content, v);
        done();
        return std::move(*this);
    }
    template <typename C> requires requires(C&& c) { c.asSpan(); }
    auto&& content(const std::vector<C>& chunks) {
        appendC(tlv::Content, chunks);
        done();
        return std::move(*this);
    }
    auto&& content(const std::vector<std::span<const uint8_t>>& chunks) {
        appendC(tlv::Content, chunks);
        done();
        return std::move(*this);
    }

    template <typename C> requires requires(C&& c) { c.begin(); }
    auto&& siginfo(C&& si) {
        append(std::forward<C>(si));
        done();
        return std::move(*this);
    }
    template <typename C> requires requires(C&& c) { c.begin(); }
    auto&& signature(C&& sig) {
        append(tlv::SignatureValue, std::forward<C>(sig));
        done();
        return std::move(*this);
    }
    // create an empty 'siz' byte signature and return a writeable span covering its payload
    auto signature(size_t siz) noexcept {
        addTlvHdr(tlv::SignatureValue, siz);
        auto off = v_.size();
        v_.resize(off + siz);
        done();
        return std::span(v_.data() + off, siz);
    }
};

struct crCert : crData {
    constexpr crCert() = default;

    crCert(rCert d) : crData{d} { }
    crCert(crName&& n) : crData{std::move(n), tlv::ContentType_Key} { }
    crCert(rName n)  : crData{n, tlv::ContentType_Key} { }
};

#endif  // CRPACKET_HPP
