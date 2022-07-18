#ifndef TLV_ENCODER_HPP
#define TLV_ENCODER_HPP
/*
 * Data Centric Transport TLV encoder
 *
 * Copyright (C) 2020-2 Pollere LLC
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
 *  The DCT proof-of-concept is not intended as production code.
 *  More information on DCT is available from info@pollere.net
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>
#include <span>
#include <vector>
#include <utility>

using runtime_error = std::runtime_error;

// routines for encoding NDN tlv blocks
struct tlvEncoder {
    using Blk = std::vector<uint8_t>;
    static constexpr uint8_t extra_bytes_code{253};

    Blk m_blk{};    // vector to fill with TLVs
    size_t m_off{}; // start of current TLV

    auto& vec() const noexcept { return m_blk; }

    auto size() const noexcept { return m_blk.size(); }

    auto data() const noexcept { return m_blk.data(); }


    // add an uint64_t with tlv type 'typ'
    void addNumber(uint8_t typ, uint64_t num) {
        m_blk.emplace_back(typ);
        m_blk.emplace_back(8);
        m_blk.emplace_back(num >> 56);
        m_blk.emplace_back(num >> 48);
        m_blk.emplace_back(num >> 40);
        m_blk.emplace_back(num >> 32);
        m_blk.emplace_back(num >> 24);
        m_blk.emplace_back(num >> 16);
        m_blk.emplace_back(num >>  8);
        m_blk.emplace_back(num);
        m_off = m_blk.size();
    }

    // add a timestamp (tlv type 36)
    void addTimestamp(std::chrono::system_clock::time_point ts) {
        addNumber(36, std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count());
    }

    template <typename T1, typename T2>
    void appendItem(const std::pair<T1,T2>& p) {
        m_blk.insert(m_blk.end(), p.first.begin(), p.first.end());
        m_blk.insert(m_blk.end(), p.second.begin(), p.second.end());
    }

    void addArrayTlvHeader(uint8_t typ, size_t len) {
        m_blk.emplace_back(typ);
        if (len >= extra_bytes_code) {
            if (len > 0xffff) throw runtime_error("array too large to tlv encode");
            m_blk.emplace_back(extra_bytes_code);
            m_blk.emplace_back(len >> 8);
        }
        m_blk.emplace_back(len);
    }

    // Add the contents of container C. (For non-contiguous containers like maps or sets
    // use the 3 argument call that adds item-by-item.)
    template <typename C> requires std::is_trivially_copyable_v<typename C::value_type>
                                    && std::contiguous_iterator<typename C::iterator>
    void addArray(uint8_t typ, const C& c) {
        auto len = c.size() * sizeof(c.front());
        std::span s((const uint8_t*)c.data(), len);
        addArrayTlvHeader(typ, len);
        m_blk.insert(m_blk.end(), s.begin(), s.end());
        m_off = m_blk.size();
    }

    // Add up to 'n' of the items yielded by iterator 'In'.
    template <typename In> requires std::indirectly_readable<In>
    auto addArray(uint8_t typ, In in, size_t n) {
        auto len = n * sizeof(*in);
        addArrayTlvHeader(typ, len);

        // make space then add the items
        len += m_blk.size();
        m_off = len;
        m_blk.reserve(len);
        //return std::ranges::copy_n(t, n, m_blk.end()).in; // doesn't work on mac as of clang-13
        while (n-- > 0) appendItem(*in++);
        return in;
    }
};

#endif // TLV_ENCODER_HPP
