/*
 * relay.cpp relays Publications between different DeftTs (that may be
 * attached to different network segments) whose identity bundles have the same trust anchor
 * and compatible trust schemas. A compatible trust schema has the same trust root and can be
 * identical, one a subset of the other, or each is a subset of the domain schema and they overlap
 * in a way that allows them to share some publications as well as the certificates that sign them.
 *
 * The relay creates two or more transports with a ptps shim.
 * ptps does a "pass through" of publications subject to conformance with the
 * (sub)schema at each DeftT.
 * A DeftT is created for each identity bundle in command line args.
 * Bundles contain the bootstrap information including which network interface
 * to use, passed as an argument to a RLY capability. Network interfaces are
 * specified in strings of the form "protocol:<opt>host:port" where protocol is
 * udp, tcp, or llm (link layer multicast - udp) and host is provided for the active
 * member of a tcp or udp connection.
 * Different relay DeftTs may use different PDU validators but must all use the same
 * validators for msgs, cert, and keys Publications
 *
 * After set up, relay waits for a Publication to arrive from one of the transports.
 * Upon receipt, the Publication is published to all the attached DeftTs for which it is valid.
 * relay also supplies a callback for each transport to call when a new signing
 * cert is added to its cert store; the cert is passed to all the other DeftTs where they are
 * always validated before adding to their own cert stores (and publishing).
 * relay also passes through all publications of a publication group key distributor
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
#include "dct/rand.hpp"

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
dct::rand ran{};

static constexpr bool deliveryConfirmation = false; // get per-publication delivery confirmation
                                                    //    which can be used for failure detection

/*
 * msgsRecv is the callback passed to subscribe() which is invoked upon arrival of each validated (crypto
 * and structural) Publication in the msgs collection of DeftT s
 * This is only called for "connected" DeftTs
 * Publication p is published to all the (other) DeftTs for which it is structurally valid (against their schema)
 *
 * skipValidatePubs can be used if schema is the same for all DeftTs and the security through the relay is
 * not an issue, but it is not recommended
 */
static void msgsRecv(ptps* s, const Publication& p) {
     // auto now = std::chrono::system_clock::now();
    //  dct::print("{:%M:%S} {}:{}:{} receives {}\n", ticks(now.time_since_epoch()), s->attribute("_role"), s->label(), s->relayTo(), p.name());
    try {
        for (auto sp : transList)
            if (sp != s && sp->isConnected()) {
                if(skipValidatePubs || sp->validPub(p)) {
                    sp->publish(Publication(p));
                    // dct::print("\trelayed to {}-{}\n",  sp->label(), sp->relayTo());
                }   // else dct::print("\tdiscarded (not valid in subschema) at {}-{}\n", sp->label(), sp->relayTo());
            }
    } catch (const std::exception& e) {}
}

/*
 * chainRecv is callback set when each ptps is constructed.
 *  It is invoked upon reception of a crypto validated signing cert by DeftT s
 *  The chain's signing cert and pointer to the arrival cert store is then relayed to all (other) connected DeftTs
 *  for validation and publication. (cs will contain the entire chain or else c would not be validated)
 *
 *  Any cert that is not defined  in a DeftT's schema should not be forwarded.
 */
static void chainRecv(ptps* s, const rData c, const certStore& cs) {
    // don't pass through relay certs - only useful on their subnet
    if (s->isRelay(c.computeTP()))  return;
    try {
        for (auto sp : transList)
            if (sp != s && sp->isConnected()) {
                sp->addRelayedChain(c, cs);
                // if (!sp->addRelayedChain(c, cs))
                    // print("relay::chainRecv: {} signing chain from {}-{} does not validate at interFace {}-{}\n", c.name(), s->label(), s->relayTo(), sp->label(), sp->relayTo());
            }
    } catch (const std::exception& e) { }
}

/*
 *  keysRecv is callback set when each ptps is constructed and set as a subscription
 *  callback for the msgs key distributor's syncps, if any.
 *   It is used as a subscription callback to relay Publications in the keys/msgs collection
 *  to other shims.
 *  Relays don't participate in msgs encrypt/decrypt groups, merely
 *  validate and relay the encrypted Pubs, but must pass through the keys/msgs Publications
 *  (in collection: <td_ID>/keys/msgs) to other shims.
 *
 *  Distributor publications do not currently appear in schemas, so instead, a test is made to
 *  determine if a  pub's signer is known (in the  DeftT's cert store) to a shim before it is forwarded there.
 */
static void keysRecv(ptps* s, const Publication& p) {
    //auto now = std::chrono::system_clock::now();
    //print("{:%M:%S} relay:{}:{}\tkeyRcv {}\n", ticks(now.time_since_epoch()), s->label(), s->relayTo(), p.name());
    try {
        for (auto sp : transList)
            if (sp != s && sp->isConnected()) {
               //print("relay::keysRecv: {} from {}-{} to interFace {}-{}\n", p.name(), s->label(), s->relayTo(), sp->label(), sp->relayTo());
               sp->publishGKey(Publication(p));
            }
    } catch (const std::exception& e) {}
}

/*
 *  tdvcRecv is callback set when each ptps is constructed for its tdvc distributor
 *  callback for the trust domain virtual clock distributor's syncps.
 *
 *  Distributor publications do not currently appear in schemas, so instead, a test is made to
 *  determine if a  pub's signer is known (in the  DeftT's cert store) to a shim before it is forwarded there.
 *  Since need the same (within tolerance) vc throughout domain, this may cause problem?
 *  In a round, each deftt publishes setSz values separated by 2*nbhDly
 *
 *  ptps shim has calls that will call its tdvc distributor
 */
dct::tdv_clock::duration nhdDly{5ms}; // rough estimate of transit + process time between neighbors in my 'hood
size_t setSz = 3;
dct::tdv_clock::duration computeDly{5*setSz*2*nhdDly};  //needs to be long enough for the set to be sent for each transport
struct cdiff {
         size_t nhSz{};                // size of neighborhood used in this vc estimate
         uint8_t st{};                  // the state of this neighbor
         int64_t v{};                   // min of differences of my vc estimate and received value
         bool lives{true};
};
std::map<dct::thumbPrint,cdiff> clkDiffs{};
dct::tdv_clock::duration adjust{0us};         // in-progress adjustment to vc
int64_t calSp{300};  // number of seconds to space calibration
uint8_t myState = 0;    // 0 for not calibrating, 1 for localling in tolerance and counting nbrs, 2+ for calibrating
size_t myNbrs = 1;
size_t tolRnds = 0;

void computeOffset();
void scheduleCompute() {
     ptps* tr{};
     for (auto sp : transList) if (sp) { tr = sp; break; }
     tr->oneTime(computeDly, [](){ computeOffset(); });
}

 // starts the transport's tdvc distributor publishing its VC value if there are other members in its tdvc collection
 // have to schedule the computeOffset also
 void startCalibrate() {
     myState = 2;
     for (auto sp : transList) if (sp->VCisStarted()) sp->calibrate();
     scheduleCompute();
 }
 void finishCalibration(std::chrono::microseconds a) {
 dct::print("relay finished Calibration adding {} for ", adjust );
 for (auto sp : transList) dct::print("{} ", sp->label());
 dct::print("\n");
     myState = 0;
     tolRnds = 0;
     for (auto sp : transList) {
         if (sp->VCisStarted()) sp->finishCalibrate(a, myNbrs);
         else sp->tdvcAdjust(a,myNbrs); // whether started or not, need to have the same vc
     }
     adjust = 0us;
     for (auto& m : clkDiffs) m.second.nhSz = 0;    // clear last round's values
 }
 void calibrateRound() {
     for (auto sp : transList) if (sp->VCisStarted()) sp->vcRound(myState,adjust,myNbrs);
     scheduleCompute();
 }

    int zAdj;    // number of times I've used a zero adjustment
    int64_t tolVal = 20000; // integer us for tolerance check
  void computeOffset() { 
        // find my neighborhood size in this round and nbrs who are in tolerance
        size_t z = 0;
        size_t nbhd = 1;               // neighborhood always has at least one member
        size_t n = myNbrs; // to find smallest neighborhood among my neighbors
        for (auto& m : clkDiffs) {
            auto& cd = m.second;
            if (cd.nhSz != 0) {
                ++nbhd;                                // I have clks from this neighbor, increase
                if (cd.nhSz < n) n = cd.nhSz;
                if (cd.st <= 1) ++z;       // count neighbors who were in tolerance this round
            } else cd.lives = false;    // this will get set back to true if hear from it, else gets cleaned up later
        }
        ptps* tr{};
        for (auto sp : transList) if (sp) { tr = sp; break; }
        auto me =tr->label();
        if (nbhd==1) {
            if (tolRnds > 4) {
                finishCalibration(-adjust);  // no neighbors communicating
                return;
            }
           dct::print("relay.computeOffset(): {} found no neighbors, state={}, tolRnds={}\n", me, myState, tolRnds);
            if (myState > 1) myState = (myState == 255) ? 2 : ++myState;
           tr->oneTime(nhdDly, [](){ calibrateRound(); }); // prompts others to send clock values when receive mine
           return;
        }
        dct::print("rcomputeOffset(): {} state={}, tolRnds={} nbhd={}\n", me, myState, tolRnds, myNbrs);

        auto q = nhdDly.count();  // an estimate of tx+proc time in the neighborhood
        n -=1;                                      // replication factor
        std::vector<int64_t> ud{};  // for the microsecond differences from my virtual clock
        // put values from each tpId in a vector and sort
        // want to use those in largest neighborhoods preferentially so replicate them
        for (size_t i=0; i<myNbrs-n; ++i) ud.push_back(0);  // zero diffs for my clock
        for (auto& m : clkDiffs) {
            auto& cd = m.second;
            // replicate by nbrhd size - smallest nbrhd +1
            if (cd.nhSz != 0) for (size_t j=0; j<cd.nhSz-n; ++j)  ud.push_back(cd.v);
        }

        // sort differences from smallest to largest and find median
        // (this is amount by which my clock is ahead of others)
        int64_t adj;
        std::sort(ud.begin(), ud.end());

        // find the mode
        std::map<int64_t, int> freq;
        int64_t v;
        int c = 0;
        int64_t md = 0;
        for (int d : ud) {  // finding frequency of each quantized diff
            v = std::floor((double)(d)/q) * q;
            if (std::abs(v) > std::abs(md)) md = v; // largest abs value diff
            freq[v]++;
            if (freq[v] > c) c = freq[v];
        }
        std::erase_if(freq, [c](const auto& it) { return it.second != c; });
        int64_t md2 = md;   // set to largest abs value diff
        for (const auto& it : freq) {   // set md to the smallest abs diff, preferring neg
            if (std::abs(it.first) < std::abs(md) || (std::abs(it.first) == std::abs(md) && it.first < md)) {
                md2 = md;  // second smallest abs value difference
                md = it.first; // smallest abs value difference
            } else if (std::abs(it.first) < std::abs(md2) || (std::abs(it.first) == std::abs(md2) && it.first < md2))
                md2 = it.first;
        }
        // check for special cases:  more than one value has the max number of occurances?
        //  move toward smallest non-zero diff,  tie-breaker is move toward forward clock
        if (freq.size() > 1 && md == 0 && md2 < 0) adj = md2;
        else adj = md;
        if (adj == 0 && zAdj > 10 && myState > 12) {   // detect if I haven't moved in many rounds
            size_t i = 0;
            for ( ; i < ud.size(); ++i) if (ud[i] == 0) break; // find first zero
            if (i != 0) adj = std::floor((double)(ud[i-1])/q) * q; // use smallest neg value, if any
        }
        myNbrs = 1; // start by counting self as contributing to this vc used in  next samples
        for (const auto& m : clkDiffs)   // count number of neighbors quantized within q of adj
            if (m.second.nhSz != 0 && (m.second.v - adj) < 2*q && (m.second.v-adj ) > -q) ++myNbrs;
        if (myNbrs == nbhd) myState = 1; // this adjustment makes me in tolerance with all
        else myState =  (myState == 255) ? 2 : ++myState;    // if state was 1 for in tolerance, will start back at 2

         // add to adjust which is the running total for this calibration
        zAdj = adj == 0 ? ++zAdj : 0;   // track number of zero adjustments
        adjust += std::chrono::microseconds(adj);  // total amount being added to vc for next round

        /*
         * stopping criteria: all neighbors must be within tolerance of the median
         * compute this by my neighbors must all be sending rounds marked zero
         * and have completed some minimal number of rounds
         */
        // Note: used the previous value of adjust (-med) in computing the clkDiffs
        if (myState==1 && z == (nbhd - 1)) ++tolRnds;    // start counting rounds in tolerance
        else tolRnds = 0;                                         // reset count
        if (tolRnds > 4) {   // all in tolerance for more than 4 rounds?
            finishCalibration(-adjust); // calibrated: set the clock and related values
            //dct::print("\tcomputeOffset: {}  is calibrated with total tdvc offset {} from sysclk (counted {} values within {})\n\n", me, m_sync.tdvcAdjust(),k,tol);
        } else { // try again
            dct::print("computeOffset: {}  state={} tolcnt={}\n", me, myState, tolRnds);
            for (auto& m : clkDiffs) m.second.nhSz = 0; // clear this round's value
            tr->oneTime(computeDly/setSz + std::chrono::milliseconds(ran(3,47)), [](){ calibrateRound(); });
        }
     }

/*
 *  tdvcRecv is callback for tdvc distributor when it receives a clock value from a neighbor
 *  dist_tdvc *only* passes a value if it's needed for calibration
 *  Receiving a value while in state 0 means dist_tdvc found the received value exceeded tolerance
 */
 void tdvcRecv(dct::thumbPrint tp, int64_t diff, size_t nhd, size_t r, dct::tdv_clock::duration nd) {
     if (nd > nhdDly) dct::print("relay gets a new neighborhood rtt {} (old={}\n", nd, nhdDly);
       if (r != clkDiffs[tp].st ) {
            clkDiffs[tp].st = r;
            clkDiffs[tp].v = diff;
         } else if (clkDiffs[tp].nhSz == 0 || diff < clkDiffs[tp].v) clkDiffs[tp].v = diff;
        clkDiffs[tp].nhSz = nhd;    // use most recent value
        clkDiffs[tp].lives = true;
       // if not currently calibrating, launch a new session and schedule the compute phase
       if (myState == 0) {
          myState = 2;
          startCalibrate();
       }
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
                                           "RLY", chainRecv, keysRecv} );
                if (transList.back()->haveVC()) transList.back()->setupVC(setSz, tdvcRecv);
            } else {
                transList.push_back( new ptps{rootCert,
                                           [i=s_id]{return schemaCert(i);},
                                           [i=s_id]{return identityChain(i);},
                                           [i=s_id]{return getSigningPair(i);},
                                           "RLY", chainRecv, keysRecv, pubFailure} );
                if (transList.back()->haveVC()) transList.back()->setupVC(setSz, tdvcRecv);
            }
        } catch (const std::exception& e) {
            std::cerr << "relay: unable to create pass-through shim " << l << ": " << e.what() << std::endl;
            exit(1);
        }
        dct::print("relay:: created transport {}-{}\n", transList.back()->label(), transList.back()->relayTo());
    }

    // Connect each sibling transport and pass in the handler
    // The handler will go through all the sibling transports' collections and pull out active Publications
    for (const auto s : transList) {
        try {
            s->connect([s](){
                dct::print("relay: DeftT transport {}-{} is connected\n", s->label(), s->relayTo());
                s->setup(transList, skipValidatePubs);  // pulls publications from all connected sibs
                s->subscribe(msgsRecv); // first subscribe will get everything that is in the Collection
                } );
        } catch (const std::exception& e) {
            std::cerr << "main: encountered exception while trying to connect transport " << s->label() << " relaying to " << s->relayTo() << " : " << e.what() << std::endl;
            exit(1);
        } catch (int conn_code) {
            std::cerr << "main: transport " <<s->label() << " failed to connect with code " << conn_code << std::endl;
            exit(1);
        } catch (...) {
            std::cerr << "default exception";
            exit(1);
        }
    }
    //check if a "sub" schema is in use on a DeftT (thumbprint will differ)
    const auto& tp = transList.front()->schemaTP();
    // this could be more complex with different DeftT shims checked for pub compatiblity before passing pubs
    // between them, but the trust schema will take care of this, silently discarding non-conforming pubs
    // This test is only done if skipValidatePubs is set true initially. Offered as a non-recommended option.
    if (skipValidatePubs)
        skipValidatePubs = std::all_of(transList.begin(), transList.end(), [&tp](const auto i){ return i->schemaTP() == tp;});
    transList[0]->run();
}
