/*
 * relay.cpp relays Publications between different DeftTs (that can be
 * attached to different network segments) whose identity bundles have the same trust anchor
 * and compatible trust schemas. A compatible trust schema has the same trust root and can be
 * identical, one a subset of the other, or overlap in a way that allows them to share some
 * publications as well as the certificates that sign them.
 *
 * The relay creates two or more transports with a ptps shim.
 * ptps does a "pass through" of publications and certificates unaltered.
 * A DeftT is created for each identity bundle in command line args. The
 * bundles contain the bootstrap information including which network interface
 * to use, passed as an argument to a RLY capability. Network interfaces are
 * specified in strings of the form "protocol:<opt>host:port" where protocol is
 * udp, tcp, or llm (link layer multicast - udp) and host is provided for the active
 * member of a tcp or udp connection.
 *
 * Different relay DeftTs may use different "wire" validators but must all use the same
 * publication validator, even if going to a "pure" relay link
 *
 * After set up, relay waits for a Publication to arrive from one of the transports.
 * Upon receipt, the Publication is published to all the attached DeftTs. If the DeftTs
 * do not have identical schemas, then pubRecv() must use publishValid() rather
 * than publish() when relaying publications. publishValid() applies a DeftT's schema
 * to publications which will filter publications not contained in that DeftT's schema.
 * (publishValid() can be used in all cases for extra security.)
 * relay also supplies a callback for each transport to call when a new signing
 * cert is added to its cert store; the cert is passed to all the other DeftTs where they are
 * always validated before adding to their own cert stores (and publishing).
 * relay also passes through all publications of a publication distributor to extend the
 * trust domain.
 *
 * relay.cpp is not intended as production code.
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

#include "../util/dct_relay.hpp"

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

static std::vector<ptps*> transList{};  //list of transports for this relay
bool skipValidatePubs = false;      // if set true, may skip validate on publish if DeftTs have the same trust schema
uint32_t failThresh = 0;   //defaults to not set
using ticks = std::chrono::duration<double,std::ratio<1,1000000>>;

static constexpr bool deliveryConfirmation = false; // get per-publication delivery confirmation
                                                    //    which can be used for failure detection

/*
 * pubRecv is the callback passed to subscribe() which is invoked upon arrival of validated (crypto and
 * structural) Publications to DeftT s
 * Publication p is published to all the (other) DeftTs which will silently discard (returns false) if p is not in their schema
 * publish() is used if schema is the same for all DeftTs or if the DeftTs with full schemas only subscribe to publications
 * that are defined in the sub-TSs. Otherwise publishValid() is recommended in order to check structural
 * validation against its schema.
 */
static void pubRecv(ptps* s, const Publication& p) {
     /* auto now = std::chrono::system_clock::now();
     print("{:%M:%S} {}:{}:{}\tpubRcv {}\n", ticks(now.time_since_epoch()), s->attribute("_role"), s->label(), s->relayTo(), p.name());*/
    try {
        for (auto sp : transList)
            if (sp != s) {
                if(skipValidatePubs) {
                    // print("\trelayed w/o validate to interFace {}:{}\n", sp->label(), sp->relayTo());
                    sp->publish(Publication(p));
                } else {
                    sp->publishValid(Publication(p));
                   // if (sp->publishValid(Publication(p)))
                   //  print("{} relayed from {}:{} to interFace {}:{}\n", p.name(), s->label(), s->relayTo(), sp->label(), sp->relayTo());
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
    // don't pass through relay certs - only useful on their subnet
    if (s->isRelay(c.computeTP()))  return;
    try {
        for (auto sp : transList)
            if (sp != s) {
                // print("RELAY: {} signing chain from {}:{} to interFace {}:{}\n", c.name(), s->label(), s->relayTo(), sp->label(), sp->relayTo());
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
    print("{:%M:%S} relay:{}:{}\tkeyPubRcv {}", ticks(now.time_since_epoch()), s->label(), s->relayTo(), p.name()); */
    try {
        for (auto sp : transList)
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
    print("pubFailure: {} timed out on DeftT interFace {}:{}\n", pub.name(), s->label(), s->relayTo());
    if(failThresh && s->failCnt() > failThresh) {
        // [future] republish p on alternate link, set up alternate to be used
        // auto p = Publication(pub);  //save on republish list
        //on failover or if last failure was "a long time ago"
        s->clearFailures();
    }
}

/*
 * Main() for the relay application.
 * First complete set up: parse input line for list of transport bundles for the relay.
 *      identity bundles are of the form <>.bundle and are comma separated
 * Next make the ptps DeftT and connect.
 * Finally, run the context.
 */

static int debug = 0;

int main(int argc, char* argv[])
{
    std::string csList{};
    // parse input line
    for (int c;
        (c = getopt_long(argc, argv, "l:dh", opts, nullptr)) != -1;) {
        switch (c) {
                case 'l':
                    csList = optarg;
                    break;
                case 'd':
                    ++debug;
                    break;
                case 'h':
                    help(argv[0]);
                    exit(0);
        }
    }
    if (csList.size() == 0) {   //make sure there was a comma separated list of bundles
        usage(argv[0]);
        exit(1);
    }

    // parse csList string of comma-separated bundles and extract the identity bundles
    std::vector<std::string> idBun;
    size_t start = 0u;
    size_t end = 0u;
    while((end = csList.find(",", start)) != std::string::npos) {
        idBun.push_back(csList.substr(start,end-start));
        start = ++end;  //skip over comma
    }
    idBun.push_back(csList.substr(start,csList.size()-start));  // final list entry

    // create a transport for each identity bundle
    // (for failovers, might consider only creating a deftt when it is needed, depends on application)
    transList.reserve(idBun.size());
    for (const auto& l : idBun) {
        auto s_id = transList.size();
        readBootstrap(l);    // parse the bootstrap file for this transport - parse only, doesn't validate
        // get the transport's type and address from its RLY capability (error if none present)
        try {
            if(!deliveryConfirmation) {
                transList.push_back( new ptps{rootCert,
                                           [i=s_id]{return schemaCert(i);},
                                           [i=s_id]{return identityChain(i);},
                                           [i=s_id]{return getSigningPair(i);},
                                           "RLY", chainRecv, keyPubRecv} );
            } else {
                transList.push_back( new ptps{rootCert,
                                           [i=s_id]{return schemaCert(i);},
                                           [i=s_id]{return identityChain(i);},
                                           [i=s_id]{return getSigningPair(i);},
                                           "RLY", chainRecv, keyPubRecv, pubFailure} );
            }
        } catch (const std::exception& e) {
            std::cerr << "relay: unable to create pass-through shim " << l << ": " << e.what() << std::endl;
            exit(1);
        }
        auto& s = *transList.back();    // reach here implies must have RLY capability

        print("relay:: created a transport {} to {}\n", s.label(), s.relayTo());

        // Connect and pass in the handler
        try {
            s.connect([&s](){
                print("relay: DeftT transport {} relaying to {} is connected\n", s.label(), s.relayTo());
                s.subscribe(pubRecv);} );
        } catch (const std::exception& e) {
            std::cerr << "main: encountered exception while trying to connect transport " << s.label() << " relaying to " << s.relayTo() << " (bundle " << l << "): " << e.what() << std::endl;
            exit(1);
        } catch (int conn_code) {
            std::cerr << "main: transport from bundle " << l << " failed to connect with code " << conn_code << std::endl;
            exit(1);
        } catch (...) {
            std::cerr << "default exception";
            exit(1);
        }
    }
    //check if a "sub" trust schema is in use on a DeftT (thumbprint will differ)
    const auto& tp = transList.front()->schemaTP();
    // this could be more complex with different DeftT shims checked for pub compatiblity before passing pubs
    // between them, but the trust schema will take care of this, silently discarding non-conforming pubs
    // This test is only done if skipValidatePubs is set true initially. Offered as a non-recommended option.
    if (skipValidatePubs)
        skipValidatePubs = std::all_of(transList.begin(), transList.end(), [&tp](const auto i){ return i->schemaTP() == tp;});
    transList[0]->run();
}
