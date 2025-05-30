# Defined-trust Communications Toolkit (DCT)

This repository contains Pollere's **evolving** work on tools, libraries, defined-trust transport (DeftT), and proof-of-concept applications for the Defined-trust Communications (DC) framework. DC enables fine-grained non-perimeter-based trust domains and DeftT is a collection-based transport efficient on broadcast media. DeftT provides default deny networking for closed communities with dynamic membership. DCT grew out of our own work, so reflects the needs of Pollere and clients, but the toolkit may prove useful to others and the repo provides a reference implementation of DeftT. DCT aims to reduce the amount of installed code needed to write secure applications and to enable and enforce defined-trust applications: applications don't "do" security, the transport does.

Defined-trust Communications is influenced by a number of relatively recent advances: LangSec,  Set Reconciliation, Trust Schemas, Information-Centric Networking and the deployment of IPv6 with its multicast support. Operational Technologies like IoT and DER are its current focus.  Why "defined-trust"? Langsec ([langsec.org]()) "posits that the only path to trustworthy software that takes untrusted inputs is treating all valid or expected inputs as a formal language, and the respective input-handling routines as a *recognizer* for that language." In a 2016 paper, the Langsec Project authors note that the "robustness principle" of "be liberal in what you accept" should be replaced with "be definite in what you accept" and DCT provides the means to implement such an approach in a communication schema, tools and a run-time library for the DeftT protocol. DC provides a new way to implement and enforce secure communications policies on networks.

Information movement is according to trust rules, expressed in verifiable schemas. DeftT's default interface is broadcast media-friendly, using a multi-party collection-based transport and self-configuring UDP/IPv6 multicast. The examples/relay subdirectory contains examples of connecting different subnets and use of a unicast interface. 

Our current target use is creating secure communication domains for OT for which we developed DeftT. A trust domain is characterized by a particular signed set of communication rules used by DeftT. The trust domain owner generates a trust anchor and all the certificates specified by the rules, including the choin-of-trust identities for use by each entity that can join the trust domain (tools for this and examples are provided). All certificates' signing chains, including a compact binary representation of the rules, terminate at the same trust anchor. An entity's identity chain includes the private key of its leaf identity cert and the public certs of its entire chain-of-trust terminating at the trust anchor. This identity is bundled with the trust anchor and the signed schema, and configured in each enrolled entity, the private identity key being securely configured. In operation, this ensures a zero-trust domain for all the communications between the enrolled entities. More information is contained in subdirectory Readmes and the references included below.

DCT initially used a modified and restricted version of the Interest-Data semantics developed by the NDN project (named-data.net) and its current packet formats (cStates, cAdds, Publications) are evolved from NDN's packet format but are no longer compatible. DCT does **not** use an NDN Forwarder or NDN libraries. The only library DCT requires is the libsodium library.

Defined-trust Communications comprises elements that may be used separately, e.g., the model of securing data could be separated from the syncps protocol and syncps could be used without a trust management engine.

The version 10 release implements suppression of excess cStates and cAdds on a broadcast channel. It also adds a change to the cAdd format where only a hash of the associated cState iblt is used for increased efficiency. Version 10.2 adds support for self-configuring mesh communications even when a subnet is only partially connected. This can be tested on an actual topology that is not fully connected and/or using a simple hack we've made available if you are using a fully connected subnet. The examples/robust directory explains how to do this.

### Directories

This repository is organized into directories:

- tools: contains tools for creating the schemas and certs needed by a DCT-enabled application (described in its README) and two subdirectories:
  
  - compiler: description of the VerSec Language for expressing trust rules and source code for schemaCompile that turns the language into a binary schema. 
  
  - dctwatch: a tool that passively listens to the default DCT network interface and prints the packets it sees (helpful in debugging)

- include/dct: run-time transport modules developed and used by Pollere for DeftT:
  
  - syncps: the pub-sub sync protocol that maintains collections 
  - face: interface between syncps and the system-provided packet transport
  - schema: the run-time library that makes use of the binary schema
  - sigmgrs: supplies a range of signing and validation methods
  - distributors: distribute certs, keys, virtual clock and manage the associated collections
  - shims: library APIs for DeftT - mbps (message-based pub/sub) and ptps (pass-through pub/sub for relays)

- examples: this directory contains illustrative examples

Bug reports are welcome.

### Installing and building the pieces

All the modules are header-only C++ 'libraries' so the `DCT/include` tree has to be made available to programs using it via a `-I` c++ compiler flag or installed in a standard include path like `/usr/local/include`. The code requires c++20 and compiles with the current xcode compiler or clang-11 on MacOS and Linux and gcc-9 on Linux. It uses the new c++20 formatted output model which, unfortunately, is not yet in either compiler's standard library. To fill that gap we suggest using the excellent implementation available at https://fmt.dev/latest/index.html. This should be installed somewhere on your system and its `include/fmt` directory symlinked from `DCT/include`. (This distribution has a copy of the current 8.0.1 `fmt` dist in DCT/include/fmt; that should be removed and replaced with the symlink.) 

The included versec compiler is required to compile new schemas but pre-compiled schemas for the examples are available as a \*.scm file in the example source directory. To compile and run an example using the pre-compiled schema, for example, mbps:

- (one time) install libsodium from https://doc.libsodium.org/ if not already installed
- (one time) install boost includes (boost.org) if not already installed
- `cd DCT/examples/<*>`  then `make` to build the example. If the make is successful, follow the readme to create 'identity bundles' and run it.

### References and related work

DeftT is described in: https://pollere.net/Txtdocs/defTrust.html and in an internet draft: https://datatracker.ietf.org/doc/draft-nichols-iotops-defined-trust-transport/ with overview talk at: https://youtu.be/YSmxis1puuE?t=2170 slides at: http://pollere.net/Pdfdocs/slides-114-iotops-defined-trust-transport-00.pdf

A member-only discussion list for Defined-trust Communications and this codebase, deftrust@lists.pollere.net, can be joined via http://lists.pollere.com/listinfo.cgi/deftrust-pollere.net (or email "help" to deftrust-request@lists.pollere.net).

Some concepts here may be better understood by referencing earlier Pollere work: 

[Lessons Learned Building a Secure Network Measurement Framework using Basic NDN ](http://www.pollere.net/Pdfdocs/icn19-p20.pdf), K. Nichols, Proceedings of ACM ICN '19, September 24-16, Macao, China (available at http://www.pollere.net/publications.html)

"Trust schemas and ICN: key to secure home IoT", K. Nichols, Proceedings of ACM ICN '21, September 2021 (available at https://dl.acm.org/doi/10.1145/3460417.3482972)

Related talks at http://www.pollere.net/talks.html

See also GitHub.com/pollere/DNMP-v2 for Pollere's first bespoke transport.

"The Seven Turrets of Babel: A Taxonomy of LangSec Errors and How to Expunge Them" , F. Momot, S. Bratus, S. Hallberg, M. Patterson, IEEE Cybersecurity Development Conference (SecDev), November 2016

---

Copyright (C) 2021-2024 Pollere LLC 
