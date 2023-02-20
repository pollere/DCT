#ifndef DCT_EXAMPLE_HPP
#define DCT_EXAMPLE_HPP
#pragma once
/*
 * Core includes for a DCT example application.
 *
 * All the DCT example applications use MBPS (Message-based Pub/Sub)
 * to communicate and a cert bundle file to establish their identity.
 * This include sets up those two pieces and injects unqualified names
 * for their main API into the app namespace.
 *
 * Copyright (C) 2020-23 Pollere LLC
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

#include <dct/shims/mbps.hpp>
#include "identity_access.hpp"

using namespace std::literals;

// app interface to dct via mbps
using dct::mbps;
using dct::msgParms;
using dct::parItem;
using dct::mbpsMsg;

// DCT's secured identity bootstrap framework which, for development purposes,
// is mapped onto (insecure) bundle files by identity_access.hpp.
using dct::readBootstrap;
using dct::rootCert;
using dct::schemaCert;
using dct::identityChain;
using dct::currentSigningPair;

#endif // DCT_EXAMPLE_HPP
