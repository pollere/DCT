/*
 * basicRelay.cpp relays Publications between different DeftTs (that can be
 * attached to different network segments) whose identity bundles have the same trust anchor
 * and compatible trust schemas. A compatible trust schema has the same trust root and can be
 * identical, one a subset of the other, or overlap in a way that allows them to share some
 * publications as well as the certificates that sign them.
 *
 * The relay creates two or more transports with a ptps shim.
 * ptps does a "pass through" of publications and certificates unaltered.
 * A DeftT is created for each network interface in command line args. These
 * are listed as strings of the form "protocol:host:<opt>port" or "default"
 * paired with their bootstrap information (or identiy bundle).
 * The identity bundle has a role of "relay" so the trust schema needs
 * a signing key definition for that role (because the wire packets must be signed).
 *
 * Different relay DeftTs may use different "wire" validators but must all use the same
 * publication validator, even if going to a "pure" relay link
 *
 * After set up, basicRelay waits for a Publication to arrive from one of the transports.
 * Upon receipt, the Publication is published to all the attached DeftTs. If the DeftTs
 * do not have identical trust schemas, then pubRecv() must use publishValid() rather
 * than publish() when relaying publications. publishValid() applies a DeftT's trust schema
 * to publications which will filter publications not contained in that DeftT's trust schema.
 * (publishValid() can be used in all cases for extra security.)
 * basicRelay also supplies a callback for each transport to call when a new signing
 * cert is added to its cert store; the cert is passed to all the other DeftTs where they are
 * always validated before adding to their own cert stores (and publishing).
 * basicRelay also passes through all publications of a publication distributor to extend the
 * trust domain.
 *
 * basicRelay.cpp is not intended as production code.
 */
/*
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
 *
 *  You may contact Pollere LLC at info@pollere.net.
 */

#include <getopt.h>
#include <charconv>
#include <functional>
#include <iostream>
#include <chrono>

// app interface to dct via ptps
#include <dct/shims/ptps.hpp>
using dct::ptps;
using dct::parItem;
using dct::Publication;
using dct::rData;
using dct::certStore;

// DCT's secured identity bootstrap framework which, for development purposes,
// is mapped onto (insecure) bundle files by identity_access.hpp.
#include "../util/identity_access.hpp"
using dct::readBootstrap;
using dct::rootCert;
using dct::schemaCert;
using dct::identityChain;
using dct::currentSigningPair;

using namespace std::literals;

//using namespace dct;

// handles command line
static struct option opts[] = {
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'},
    {"listIOnames", required_argument, nullptr, 'l'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] -l list of io\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -d |--debug       enable debugging output\n"
           "  -h |--help        print help then exit\n"
           "  -l listIonames    defaults to ''\n";
}

/* Globals */

static std::vector<ptps*> dtList{};
bool skipValidatePubs = false;      // if set true, may skip validate on publish if DeftTs have the same trust schema
uint32_t failThresh = 0;   //defaults to not set
using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;

static constexpr bool deliveryConfirmation = false; // get per-publication delivery confirmation
                                                    //    which can be used for failure detection

/*
 * pubRecv is the callback passed to subscribe() which is invoked upon arrival of validated (crypto and
 * structural) Publications to DeftT s
 * Publication p is published to all the (other) DeftTs
 * publish() is used if schema is the same for all DeftTs or if the DeftTs with full schemas only subscribe to publications
 * that are defined in the sub-TSs. Otherwise publishValid() is recommended in order to check structural
 * validation against its schema.
 */
static void pubRecv(ptps* s, const Publication& p) {
    /*  auto now = std::chrono::system_clock::now();
     print("{:%M:%S} {}:{}:{}\tpubRcv {}\n", ticks(now.time_since_epoch()), s->attribute("_role"), s->attribute("_roleId"),
          (s->label().size()? s->label() : "default"), p.name()); */
    try {
        for (auto sp : dtList)  
            if (sp != s) {
                if(skipValidatePubs) {
                    // print("\trelayed w/o validate to interFace {}:{}\n", sp->label(), sp->attribute("_roleId"));
                    sp->publish(Publication(p));
                } else {
                    // print("\trelayed to validate for interFace {}:{}\n", sp->label(), sp->attribute("_roleId"));
                    sp->publishValid(Publication(p));
                }
            }
    } catch (const std::exception& e) {}
}

/*
 * chainRecv is callback set when each ptps is constructed.
 *  It is invoked upon reception of a crypto validated signing cert by DeftT s which contains its validated chain
 *  The chain's signging cert and pointer to the arrival cert store is then relayed to all the (other) DeftTs
 *  for validation and publication
 *
 *  Any cert that does not appear as an "is signed by" for a publication in a DeftT's trust schema should probably
 *  not be forwarded, but this needs further investigation as more subscription restrictions are added.
 *  Also it may be more costly to filter the cert chain than to forward it.
 */
static void chainRecv(ptps* s, const rData c, const certStore& cs) {
    /* auto now = std::chrono::system_clock::now();
     print("{:%M:%S} {}:{}:{}\trcvd signing cert {}\n", ticks(now.time_since_epoch()), s->attribute("_role"), s->attribute("_roleId"),
          (s->label().size()? s->label() : "default"), c.name()); */
    try {
        for (auto sp : dtList)
        if (sp != s) {
            //print("\trelaying a signing chain to interFace {}:{}\n", (sp->label().size()? sp->label() : "default"), sp->attribute("_roleId"));
            sp->addRelayedChain(c, cs);
        }
    } catch (const std::exception& e) { }
}

/*
 *  keyPubRecv is callback set when each ptps is constructed. If a publication key distributor
 *  is in use, it is used as a subscription callback to relay the publications of its syncps
 *  to other shims. Relays don't participate in pub encrypt/decrypt groups, merely
 *  validate and relay the encrypted pubs, but must pass through the key distribution publications
 *  (in PDU keys collection: <td_ID>/keys/pubs) to other shims.
 *
 *  Distributor publications do not currently appear in trust schemas, so instead, a test is made to
 *  determine if a  pub's signer is known (in the cert store) to a shim before it is forwarded there.
 */
static void keyPubRecv(ptps* s, const Publication& p) {
    /* auto now = std::chrono::system_clock::now();
    print("{:%M:%S} {}:{}:{}\trcvd KEYS pub {}", ticks(now.time_since_epoch()), s->attribute("_role"), s->attribute("_roleId"),
         (s->label().size()? s->label() : "default"), p.name()); */
    try {
        for (auto sp : dtList)
            if (sp != s) {
                sp->publishKnown(Publication(p));
            }
    } catch (const std::exception& e) {}
}

/*
 * If a failure callback is set for ptps s, this is called when a publication times
 * out without being seen in the digest of any other entity connected to the same Collection
 * This can be used to save the publications and republish to another DeftT if the number of failures
 * is large over some period (both the failure count and the saved pubs should be cleared periodically
 * or when there's a success)
 */
static void pubFailure(ptps* s, const Publication& pub) {
    print("pubFailure: {} timed out on DeftT interFace {}:{}\n", pub.name(), s->label(), s->attribute("_roleId"));
    if(failThresh && s->failCnt() > failThresh) {
        // [future] republish p on alternate link, set up alternate to be used
        // auto p = Publication(pub);  //save on republish list
        //on failover or if last failure was "a long time ago"
        s->clearFailures();
    }
}

/*
 * Main() for the basicRelay application.
 * First complete set up: parse input line for list of transports for the relay.
 *      IO labels can have the form "protocol:host:port" where protocol is tcp or udp
 *      The "default" Face is selected if no port is specified
 *      identity bundles are of the form <>.bundle and are separated from their label by a space
 *      IO label <sp> <>.bundle are separated by ","s
 *      Note that there will be no label, just <sp><>.bundle for the default face
 * Then make the ptps DeftT and connect.
 * Run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    std::string ccList{};
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, "l:dh", opts, nullptr)) != -1;) {
        switch (c) {
                case 'l':
                    ccList = optarg;
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
        }
    }
    if (ccList.size() == 0) {   //make sure there is a comma separated list
        usage(argv[0]);
        exit(1);
    }

    // parse ccList string of comma-separated specifications for each DeftT
    // list of pairs of labels with bootstrap trust bundles for each DeftT for this relay
    std::vector<std::string> dtLabel;
    size_t start = 0u;
    size_t end = 0u;
    while((end = ccList.find(",", start)) != std::string::npos) {
        dtLabel.push_back(ccList.substr(start,end-start));
        start = ++end;  //skip over comma
    }
    dtLabel.push_back(ccList.substr(start,ccList.size()-start));
    //for each entry on list, create a ptps
    // (for failovers, might consider only creating a deftt when it is needed, depends on application)
    dtList.reserve(dtLabel.size());
    for (const auto& l : dtLabel) {
        size_t m = l.find(" ", 0u);
        if(m == std::string::npos) {
            std::cerr << "basicRelay main: command line list of labels and id bundles misformatted" << std::endl;
        }
        auto s_id = dtList.size();
        readBootstrap(l.substr(m+1));    // parse the bootstrap file for this DeftT shim
        try {
            if(!deliveryConfirmation) {
                dtList.push_back( new ptps{rootCert,
                                           [i=s_id]{return schemaCert(i);},
                                           [i=s_id]{return identityChain(i);},
                                           [i=s_id]{return currentSigningPair(i);},
                                           l.substr(0u,m), chainRecv, keyPubRecv} );
            } else {
                dtList.push_back( new ptps{rootCert,
                                           [i=s_id]{return schemaCert(i);},
                                           [i=s_id]{return identityChain(i);},
                                           [i=s_id]{return currentSigningPair(i);},
                                           l.substr(0u,m), chainRecv, keyPubRecv, pubFailure} );
            }
        } catch (const std::exception& e) {
            std::cerr << "basicRelay: unable to create pass-through shim " << l << ": " << e.what() << std::endl;
            exit(1);
        }
        auto& s = *dtList.back();

        //role must be "relay" (could remove this)
        if(s.attribute("_role") != "relay") {
                print("basicRelay app got role {} for interFace {} instead of relay\n",
                      s.attribute("_role"), s.label());
                exit(1);
        }
        //single callback for all Publications in pubs
       // s.subscribe(pubRecv);
        // Connect and pass in the handler
        try {
            s.connect([&s](){
                print("basicRelay: DeftT connected on {}:{} interFace\n", s.label(), s.attribute("_roleId"));
                s.subscribe(pubRecv);} );
        } catch (const std::exception& e) {
            std::cerr << "main: encountered exception while trying to connect transport " << l << ": " << e.what() << std::endl;
            exit(1);
        } catch (int conn_code) {
            std::cerr << "main: transport " << l << " failed to connect with code " << conn_code << std::endl;
            exit(1);
        } catch (...) {
            std::cerr << "default exception";
            exit(1);
        }
    }
    //check if a "sub" trust schema is in use on a DeftT (thumbprint will differ)
    const auto& tp = dtList.front()->schemaTP();
    // this could be more complex with different DeftT shims checked for pub compatiblity before passing pubs
    // between them, but the trust schema will take care of this, silently discarding non-conforming pubs
    // This test is only done if skipValidatePubs is set true initially. Offered as a non-recommended option.
    if (skipValidatePubs)
        skipValidatePubs = std::all_of(dtList.begin(), dtList.end(), [&tp](const auto i){ return i->schemaTP() == tp;});
    dtList[0]->run();
}
