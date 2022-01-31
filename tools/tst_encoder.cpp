/*
 * test tlv_encoder
 *
 * Copyright (C) 2021-2 Pollere LLC
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
#include <iostream>
#include <fstream>
#include <string_view>

#include <ndn-ind/data.hpp>

#include "dct/format.hpp"
#include "dct/schema/tlv_encoder.hpp"
#include "dct/schema/tlv_parser.hpp"

static void usage(const char** argv) {
    print("- usage: {} -o outfile file ...\n", argv[0]);
    exit(1);
}

int main(int argc, const char* argv[]) {
    const char* outfile{};
    if (argc < 3) usage(argv);
    const char** ap = argv + 1;
    //const char** ape = argv + argc;
    if (std::string_view(*ap++) != "-o") usage(argv);
    outfile = *ap++;
    
    try {
        // build some test data for the encoder/decoder
        using kVal = std::array<uint8_t,8>;
        using fpVal = std::array<uint8_t,24>;
        kVal x = {0,1,2,3,4,5,6,7};
        fpVal y = {0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                   0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
        using keyItem = std::pair<kVal,fpVal>;
        std::vector<keyItem> kv{};
        for (auto i= 0u; i < 32*3; i += 32) {
            kv.emplace_back(x, y);
            x[0] += 32;
            y[0] += 32;
        }

        // encode the test content
        tlvEncoder enc{};
        auto now = std::chrono::system_clock::now();
        enc.addTimestamp(now);
        //enc.addArray(130, kv);
        enc.addArray(130, kv.cbegin(), kv.size());

        // make an NDN data packet, set its content to be the encoded test data
        // then wire-encode the result and write it to the output file (so it
        // can be inspected with a dump utility).
        ndn::Data data(ndn::Name("test/encoding"));
        data.setContent(enc.vec());
        auto& wf = *data.wireEncode();

        std::ofstream os(outfile, std::ios::binary);
        os.write((char*)wf.data(), wf.size());
        os.close();

        // decode the content section of the data packet constructed above and
        // validate that it's the same as the original. This tlvParser constructer
        // wraps a parser around a 'const vector<uint8_t>&' and ndn::Data::getContent
        // returns a pointer to such a vector.
        tlvParser decode(*data.getContent(), 0);

        // the first tlv should be type 36 and it should decode to a uint64_t
        auto ts = decode.nextBlk(36).toNumber();

        // check the original data survived the encode/decode cycle 
        uint64_t orig = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
        if (ts != orig) print("timestamps don't match, orig {:x}, decoded {:x}\n", orig, ts);

        // the second tlv should be type 130 and it should be a vector of 'keyItem's
        auto dkv = decode.nextBlk(130).toSpan<keyItem>();

        if (!std::equal(dkv.begin(), dkv.end(), kv.begin()))
            print(fmt::runtime("vectors don't match, orig:\n{:x}\ndecoded:\n{:x}\n"), kv, dkv);

    } catch (const std::runtime_error& se) { print("runtime error: {}\n", se.what()); }

    exit(0);
}
