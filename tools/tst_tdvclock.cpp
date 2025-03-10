/*
 * tst_tdvclock - tst tdv_clock behavior
 *
 * Copyright (C) 2024 Pollere LLC
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

#include "dct/format.hpp"
#include "dct/tdv_clock.hpp"

using namespace dct;
using namespace std::literals;
using sysc = std::chrono::system_clock;

static tdv_clock tdvc{};

auto sysDiff(tdv_clock::time_point t) {
    return t.time_since_epoch() - sysc::now().time_since_epoch();
}

auto p(const char* lbl, tdv_clock::time_point t) {
    print(" {} {:%T} sys {:%T} diff {} to_sys {:%T}\n", lbl, t, sysc::now(), sysDiff(t), tdvc.to_sys(t));
}

int main(int , const char* []) {
    //if (argc < 2) {
    //    print("- usage: {} \n", argv[0]);
    //    exit(1);
    //}

    // tdv clock now() should start out same as sys clock now().
    // After any adjustment, tdv clock now() should differ from sys clock now() by
    // sum of all adjustments. After reset should again be same as sys clock now().

    auto strt = tdvc.now();
    p("strt", strt);

    tdvc.adjust(42s);
    auto p42s = tdvc.now();
    p("p42s", p42s);

    tdvc.adjust(-877ms);
    auto m877ms = tdvc.now();
    p("m877ms", m877ms);

    tdvc.reset();
    p("reset", tdvc.now());

    tdvc.adjust(-11s);
    auto m11s = tdvc.now();
    p("m11s", m11s);

    p("svd  start", strt);
    p("svd   +42s", p42s);
    p("svd -877ms", m877ms);
    p("svd   -11s", m11s);

    exit(0);
}
