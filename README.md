# Defined-trust Communications Toolkit (DCT)

This repository contains Pollere's **evolving** work on tools, libraries, transport protocol, and proof-of-concept applications for defined-trust communications. DCT enables fine-grained non-perimeter-based trust domains and a collection-based transport efficient on broadcast media. DCT grew out of our own work so reflects Pollere's needs but we believe the toolkit may prove useful  Defined-trust Communications (DC) is influenced by a number of advances: LangSec, Information-Centric Networking, Set Reconciliation, Trust Schemas and the deployment of IPv6 with its multicast support. Focus applications are Operational Technologies, like IoT and DER.

Why "defined-trust"? Langsec ([langsec.org]()) "posits that the only path to trustworthy software that takes untrusted inputs is treating all valid or expected inputs as a formal language, and the respective input-handling routines as a *recognizer* for that language." In a 2016 paper, the Langsec Project authors note that the "robustness principle" of "be liberal in what you accept" should be replaced with "be definite in what you accept" and DCT provides the means to implement such an approach in a trust schema, tools and a run-time library for the transport protocol.

DCT shares some low-level protocol concepts with the NDN project ([named-data.net]()), as well as using a restricted version of NDN's packet format for its  transport PDUs, but does not implement the NDN architecture. In particular DCT does **not** use an NDN Forwarder. NDN libraries were used in initial prototypes of DCT but these are being removed (a work in progress) in favor of self-contained, efficient implementations.

Information security and movement is according to trust rules, expressed in verifiable trust schemas. DCT contains a broadcast media-friendly Face that implements its restricted Interest-Data semantics and communicates using self-configuring UDP/IPv6 multicast. A forthcoming release will contain examples of connecting different network segments and use of a unicast Face. DCT aims to reduce the amount of installed code needed to write applications and to enable and enforce defined-trust applications.

DCT's target use is creating secure multicast communications domains for OT. Each communication domain is characterized by a structured set of trust rules and an API for a DCT-based transport to send and receive data for that domain of applications. A specific deployment of a communication domain creates a run-time trust domain and requires generating a trust anchor and all the certificates specified by the trust rules, including signing identities for use by each entity that will become part of the trust domain. All certificates, including a compact binary representation of the trust rules, are (ultimately) signed by the same trust anchor. An entity's signing certificate(s) with private keys are bundled with the public certificates of each cert's entire signing chain, including the trust anchor, and given to each enrolled entity, the private signing key(s) being securely configured. In operation, this ensures a trust domain for all the communications between the enrolled entities. More information is contained in subdirectory Readmes and the references included below.

### Directories

This repository is organized into directories:

- tools: contains tools for creating the schemas and certs needed by a DCT-enabled application (described in its README). Two subdirectories:
  
  - compiler: description of the VerSec Language for expressing trust rules and source code for schemaCompile that turns the language into a binary trust schema. 
  
  - dctwatch: a tool that passively listens to the default DCT network interface and prints the packets it sees (helpful in debugging)

- include: bespoke transport modules developed and used by Pollere to handle secure data-centric communications:
  
  - syncps: the pub-sub sync protocol that interfaces with the packet forwarder
  - schema: the run-time library that makes use of the binary trust schema
  - sigmgrs: supplies a range of signing and validation methods
  - distributors: distribute certs and group keys and manage the associated collections
  - face: the DirectFace implementation

- examples:
  
  - shims: contains example(s) of DCT "shims" that provide an API for applications of a usage domain.  This includes mbps.hpp which provides message-based publish/subscribe.
  - hmIot, office:  The README in this directory may be useful in understanding how DCT's modules can be used.

Vversion 5 removed the use of NFD and the need for our previously required patches. 

Bug reports are welcome.

### Installing and building the pieces

All the modules are header-only C++ 'libraries' so the `DCT/include` tree has to be made available to programs using it via a `-I` c++ compiler flag or installed in a standard include path like `/usr/local/include`. The code requires c++20 and compiles with the current xcode compiler or clang-11 on MacOS and Linux and gcc-9 on Linux. It uses the new c++20 formatted output model which, unfortunately, is not yet in either compiler's standard library. To fill that gap we suggest using the excellent implementation available at https://fmt.dev/latest/index.html. This should be installed somewhere on your system and its `include/fmt` directory symlinked from `DCT/include`. (This distribution has a copy of the current 8.0.1 `fmt` dist in DCT/include/fmt; that should be removed and replaced with the symlink.) 

The included versec compiler is required to compile new schemas but pre-compiled schemas for the examples are available as a \*.scm file in the example source directory. To compile and run an example using the pre-compiled schema, for example, mbps:

- (one time) Install `ndn-ind` (from  https://github.com/operantnetworks/ndn-ind) version ee36771.
- (one time) `cd DCT/tools && make` to build all the tools needed.
- `cd DCT/examples/hmIoT`  then `make` to build the example. If the make is successful, follow the readme to create 'identity bundles' and run it.

### References and related work

Some concepts here may be better understood by referencing earlier Pollere work: 

[Lessons Learned Building a Secure Network Measurement Framework using Basic NDN ](http://www.pollere.net/Pdfdocs/icn19-p20.pdf), K. Nichols, Proceedings of ACM ICN '19, September 24-16, Macao, China (available at http://www.pollere.net/publications.html)

Trust schemas and ICN: key to secure home IoT, K. Nichols, Proceedings of ACM ICN '21, September 2021 (available at https://dl.acm.org/doi/10.1145/3460417.3482972)

Related talks at http://www.pollere.net/talks.html

See also GitHub.com/pollere/DNMP-v2 for Pollere's first bespoke transport.

"The Seven Turrets of Babel: A Taxonomy of LangSec Errors and How to Expunge Them" , F. Momot, S. Bratus, S. Hallberg, M. Patterson, IEEE Cybersecurity Development Conference (SecDev), November 2016

---

Copyright (C) 2021-2022 Pollere LLC 
