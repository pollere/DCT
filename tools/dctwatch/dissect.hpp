#ifndef DISSECT_HPP
#define DISSECT_HPP
/*
 * dissect - NDN packet dissector / printer
 *
 * Copyright (C) 2021 Pollere LLC.
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
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  This is not intended as production code.
 */
#include <unordered_map>
#include <string_view>
#include <tuple>
#include <vector>

#include "dct/format.hpp"
#include "dct/schema/tlv.hpp"
#include "dct/schema/tlv_parser.hpp"

struct Dissect {
    enum class cFmt { unknown, str, num, tstamp, bin };
    using Dict = const std::unordered_map<tlv, std::tuple<const char*,bool,cFmt>>;

    inline static Dict blockTLV = {
        {tlv::Content, {"Content", false, cFmt::unknown}},
        {tlv::Data, {"Data", false, cFmt::unknown}},
        {tlv::Interest, {"Interest", false, cFmt::unknown}},
        {tlv::KeyDigest, {"KeyDigest", true, cFmt::unknown}},
        {tlv::KeyLocator, {"KeyLocator", false, cFmt::unknown}},
        {tlv::MetaInfo, {"MetaInfo", false, cFmt::unknown}},
        {tlv::Name, {"Name", false, cFmt::unknown}},
        {tlv::SignatureInfo, {"SigInfo", false, cFmt::unknown}},
        {tlv::SignatureType, {"SigType", true, cFmt::unknown}},
        {tlv::SignatureValue, {"SigValue", true, cFmt::unknown}},
    };
    inline static Dict nameTLV = {
        {tlv::GenericNameComponent, {"Generic", true, cFmt::unknown}},
        {tlv::KeywordNameComponent, {"Keyword", false, cFmt::unknown}},
        {tlv::SegmentNameComponent, {"Segment", true, cFmt::unknown}},
        {tlv::ByteOffsetNameComponent, {"ByteOffset", true, cFmt::unknown}},
        {tlv::VersionNameComponent, {"Version", true, cFmt::unknown}},
        {tlv::TimestampNameComponent, {"Timestamp", true, cFmt::tstamp}},
        {tlv::SequenceNumNameComponent, {"SequenceNum", true, cFmt::unknown}},
        {tlv::ImplicitSha256DigestComponent, {"ImplicitSha256Digest", true, cFmt::bin}},
        {tlv::ParametersSha256DigestComponent, {"Sha256Digest", true, cFmt::bin}},
    };
    inline static Dict interestTLV = {
        {tlv::Nonce, {"Nonce", true, cFmt::bin}},
        {tlv::InterestLifetime, {"Lifetime", true, cFmt::num}},
        {tlv::MustBeFresh, {"MustBeFresh", true, cFmt::unknown}},
        {tlv::CanBePrefix, {"CanBePrefix", true, cFmt::unknown}},
        {tlv(30), {"ForwardingHint", false, cFmt::unknown}},
        {tlv(34), {"HopLimit", false, cFmt::unknown}},
        {tlv(36), {"ApplicationParameters", false, cFmt::unknown}},
        // obsolete stuff
        {tlv(9), {"Selectors", false, cFmt::unknown}},
        {tlv(13), {"MinSuffixComponents", true, cFmt::unknown}},
        {tlv(14), {"MaxSuffixComponents", true, cFmt::unknown}},
        {tlv(15), {"PublisherPublicKeyLocator", false, cFmt::unknown}},
        {tlv(16), {"Exclude", false, cFmt::unknown}},
        {tlv(17), {"ChildSelector", false, cFmt::unknown}},
        {tlv(19), {"Any", false, cFmt::unknown}},
    };
    inline static Dict metainfoTLV = {
        {tlv::ContentType, {"ContentType", true, cFmt::num}},
        {tlv::FreshnessPeriod, {"Freshness", true, cFmt::num}},
        {tlv(26), {"FinalBlockId", false, cFmt::unknown}},
    };
    inline static Dict contentTypeTLV = {
        // content types
        {tlv::ContentType_Blob, {"Blob", true, cFmt::num}},
        {tlv::ContentType_Link, {"Link", true, cFmt::num}},
        {tlv::ContentType_Key, {"Key", true, cFmt::num}},
        {tlv::ContentType_Nack, {"Nack", true, cFmt::num}},
        {tlv::ContentType_Manifest, {"Manifest", true, cFmt::num}},
        {tlv(129), {"SyncpsPubs", true, cFmt::num}},
        {tlv(131), {"TrustSchema", true, cFmt::num}},
        {tlv(5), {"PrefixAnn", true, cFmt::num}},
    };
    inline static Dict sigInfoTLV = {
        // SignatureInfo features
        {tlv::ValidityPeriod, {"Validity", false, cFmt::unknown}},
        {tlv::NotBefore, {"NotBefore", true, cFmt::str}},
        {tlv::NotAfter, {"NotAfter", true, cFmt::str}},
        {tlv(258), {"AdditionalDescription", false, cFmt::unknown}},
        {tlv(512), {"DescriptionEntry", false, cFmt::unknown}},
        {tlv(513), {"DescriptionKey", false, cFmt::unknown}},
        {tlv(514), {"DescriptionValue", false, cFmt::unknown}},
    };
    inline static Dict sigTypeTLV = {
        // SignatureType types
        {tlv::DigestSha256, {"DigestSha256", true, cFmt::unknown}},
        {tlv::SignatureSha256WithRsa, {"Sha256WithRsa", true, cFmt::unknown}},
        {tlv::SignatureSha256WithEcdsa, {"Sha256WithEcdsa", true, cFmt::unknown}},
        {tlv::SignatureHmacWithSha256, {"HmacWithSha256", true, cFmt::unknown}},
        { tlv(7), {"AEAD", true, cFmt::unknown} },
        { tlv(8), {"EdDSA", true, cFmt::unknown} },
        { tlv(9), {"RFC7693", true, cFmt::unknown} },
    };
    inline static Dict schemaTLV = {
        // trust schema types
        {tlv(131), {"TrustSchema", false, cFmt::unknown}},
        {tlv(132), {"strTab", true, cFmt::str}},
        {tlv(133), {"tokTab", true, cFmt::bin}},
        {tlv(134), {"certs", true, cFmt::bin}},
        {tlv(135), {"chains", true, cFmt::bin}},
        {tlv(136), {"cors", true, cFmt::bin}},
        {tlv(137), {"tags", true, cFmt::bin}},
        {tlv(138), {"templates", true, cFmt::bin}},
        {tlv(139), {"varLists", true, cFmt::bin}},
        {tlv(140), {"discrim", true, cFmt::bin}},
        {tlv(141), {"pubs", true, cFmt::bin}},
    };
    inline static Dict gkeyTLV = {
        // group key distributor types
        {tlv(130), {"gkeyList", true, cFmt::bin}},
        {tlv(150), {"ppGrpPK", true, cFmt::bin}},
        {tlv(36), {"pubTS", true, cFmt::tstamp}},
    };
    inline static const std::unordered_map<tlv, Dict*> dicts = {
        {tlv::Name, &nameTLV},
        {tlv::Interest, &interestTLV},
        {tlv::MetaInfo, &metainfoTLV},
        {tlv::ContentType, &contentTypeTLV},
        {tlv::SignatureInfo, &sigInfoTLV},
        {tlv::SignatureType, &sigTypeTLV},
        {tlv(131), &schemaTLV},
        {tlv::Content, &gkeyTLV},
    };

    struct DictStack {
        std::vector<const Dict*> ds_{};

        bool empty() const { return ds_.empty(); }

        void push(Dict* d) { ds_.emplace_back(d); }

        bool enter(tlv t) {
            if (!dicts.contains(t)) return false;
            ds_.emplace_back(dicts.at(t));
            return true;
        }
        bool enter(tlv t, tlv t1) {
            auto d = dicts.find(t);
            if (d == dicts.end() || !d->second->contains(t1)) return false;
            ds_.emplace_back(d->second);
            return true;
        }
        void exit(tlv t) { if (dicts.contains(t)) ds_.pop_back(); }

        auto operator[](tlv t) const noexcept {
            for (int i = ds_.size(); --i >= 0; ) {
                if (ds_[i]->contains(t)) return get<const char*>(ds_[i]->at(t));
            }
            return "?";
        }

        bool isLeaf(tlv t) const noexcept {
            for (int i = ds_.size(); --i >= 0; ) {
                if (ds_[i]->contains(t)) return get<bool>(ds_[i]->at(t));
            }
            return false;
        }
        cFmt fmt(tlv t) const noexcept {
            for (int i = ds_.size(); --i >= 0; ) {
                if (ds_[i]->contains(t)) return get<cFmt>(ds_[i]->at(t));
            }
            return cFmt::unknown;
        }
    };

    DictStack bdict;    // block tag dictionary stack
    DictStack vdict;    // leaf block values dictionary stack
    std::ostringstream ss;  // each TLV's description is built here
    int indent_{};      // current indent level

    constexpr void indentMore() noexcept { ++indent_; };
    constexpr void indentLess() noexcept { --indent_; };
    constexpr void indent(std::ostream& os) const noexcept { for (auto i = indent_; --i >= 0; ) os << "| "; }

    void printType(tlv type, const DictStack& ds) { print(ss, "{} ({})", (int)type, ds[type]); }

    void printTL(tlv type, size_t len) { print(ss, "{} ({}) size {}:", (int)type, bdict[type], len); }

    constexpr bool notPrintable(char c) const noexcept { return c < 0x20 || c >= 0x7f; }

    constexpr bool mostlyStr(tlvParser b) const noexcept {
        const auto dat = b.data() + b.off();
        int len = b.len();
        int thresh = len < 8? 0 : len < 16? 2 : len >> 3;
        for (int i = 0; i < len; i++) if (notPrintable(dat[i]) && --thresh < 0)  return false;
        return true;
    }

    // dump a block as a timestamp
    void dumpts(tlvParser b) {
        const auto* dat = b.data() + b.off();
        int len = b.len();
        if (len == 9) { ++dat; --len; } //XXX handle tagged values
        int64_t u{};
        while (--len >= 0) u = (u << 8) | *dat++;

        // we need 'us' to be a double to get the fractional part printed
        // but system clock date printing doesn't work unless it's an int.
        std::chrono::duration<double,std::micro> us{double(u)};
        std::chrono::sys_time<std::chrono::microseconds> ts{std::chrono::microseconds(u)};
        fmt::print(ss, "{:%g-%m-%d@%R}:{:.6%S}", ts, us);
    }

    // dump a block as characters
    void dumpstr(tlvParser b) {
        const auto dat = b.data() + b.off();
        int len = b.len();
        auto strt = ss.tellp();
        for (int i = 0; i < len; i++) {
            if (i && (i % 80) == 0) {
                ss << '\n';
                indent(ss);
                for (int j = strt; --j >= 0; ) ss << ' ';
            }
            ss << dat[i];
        }
    }

    // do a hex dump of a block
    void dumpbin(tlvParser b) {
        static const auto hex = "0123456789abcdef";
        const auto dat = b.data() + b.off();
        int len = b.len();
        auto strt = ss.tellp();
        for (int i = 0; i < len; i++) {
            if ((i & (2-1)) == 0 && i != 0) {
                if ((i & (32-1)) == 0) {
                    ss << '\n';
                    indent(ss);
                    for (int j = strt; --j >= 0; ) ss << ' ';
                } else if ((i & (8-1)) == 0) {
                    ss << ' ' << ' ';
                } else {
                    ss << ' ';
                }
            }
            ss << hex[dat[i] >> 4] << hex[dat[i] &0xf];
        }
    }

    // dump block as a decimal number (stored bigendian)
    void dumpnum(tlvParser b) {
        auto len = b.len();
        if (len > 8) return dumpbin(b);
        ss << b.toNumber();
    }

    void dump(tlvParser b, cFmt fmt) {
        switch (fmt) {

        case cFmt::str:
            dumpstr(b);
            return;

        case cFmt::num:
            dumpnum(b);
            return;

        case cFmt::tstamp:
            dumpts(b);
            return;

        case cFmt::bin:
            dumpbin(b);
            return;

        case cFmt::unknown:
            break;
        }
        // XXX hack to handle 'tagged' timestamps in name components

        if (b.len() == 9 && (tlv)b[0] == tlv::GenericNameComponent && b.cur() == 0xfc) {
            dumpts(b);
            return;
        }
        mostlyStr(b)? dumpstr(b) : dumpbin(b);
    }

    void printBlock(std::ostream& os, tlvParser b) {
        auto btype = (tlv)b.typ();
        auto blen = b.len();
        bdict.enter(btype);
        printTL(btype, blen);

        // if this block might contain nested TLVs, parse it (via counting blocks) to find out.
        size_t nblks{};
        if (blen > 0 && ! bdict.isLeaf(btype) && b.cur() != 0) {
            try {
                nblks = b.nBlks();
            } catch (const std::runtime_error& e) {
                // In general this 'error' is expected when parsing unknown content but uncommenting
                // this print can help find things that should be marked 'leaf' so they won't be parsed.
                //print(std::cerr, "Error parsing {}/{}: {}\n", (int)btype, blen, e.what());
            }
        }
        if (nblks == 0 && blen > 0) {
            // block doesn't contain TLVs so print its content on this line
            ss << "  ";
            if (vdict.enter(btype, (tlv)b.cur())) {
                printType((tlv)b.cur(), vdict);
                vdict.exit(btype);
            } else {
                dump(b, bdict.fmt(btype));
            }
        }
        indent(os);
        os << ss.str() << '\n'; //XXX should be ss.view() but doesn't work on a mac
        ss.str(std::string{}); //XXX this shouldn't be needed but macs don't support c++20
        if (nblks > 0) {
            indentMore();
            for (auto b2 : b) printBlock(os, b2);
            indentLess();
        }
        bdict.exit(btype);
    }

    void dissect(std::ostream& os, tlvParser b) {
        if (bdict.empty()) bdict.push(&blockTLV);
        try {
            printBlock(os, b);
        } catch (const std::exception& e) { std::cerr << "ERROR: " << e.what() << std::endl; }
    }

    void dissect(std::ostream& os, const std::vector<uint8_t>& v) {
        for (auto b : tlvParser(tlvParser::Blk(v), 0U)) dissect(os, b);
    }
};

#endif // DISSECT_HPP
