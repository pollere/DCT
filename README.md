# Data-centric Communications Toolkit (DCT)

This repository contains Pollere's **evolving** work on tools, a library and proof-of-concept applications for defined-trust data-centric communications. DCT grew out of our own work so reflects Pollere's needs but we believe the toolkit may prove useful to others. The architecture is derived from Named-Data Networking (NDN) but is being developed for Operational Technologies, like IoT and DER, to run over IPv6 networks. This results in architectural differences from the NDN project ([named-data.net]()) that has concentrated on a Future Internet Architecture, but uses the same packet structure and Interest-Data semantics. DCT does **not** use an NDN Forwarder; Data movement is according to trust rules, expressed in verifiable trust schemas. DCT applications use a broadcast media-friendly Direct Face that implements the required NDN semantics and communicates using self-configuring UDP/IPv6 multicast. A forthcoming release will contain examples of connecting different network segments. DCT aims to reduce the amount of installed code needed to write applications and to enable and enforce defined-trust applications.

DCT's target use is creating secure data-centric communication domains. Each communication domain is characterized by a structured set of trust rules and an API for a DCT-based transport to send and receive data for that domain of applications. A specific deployment of a communication domain creates a run-time trust zone and requires generating a trust anchor and all the certificates specified by the trust rules, including signing identities for use by each entity that will become part of the trust zone. All certificates, including a compact binary representation of the trust rules, are (ultimately) signed by the same trust anchor. An entity's signing certificate(s) with private keys are bundled with the public certificates of each cert's entire signing chain, including the trust anchor, and given to each enrolled entity, the private signing key(s) being securely configured. In operation, this ensures a trust zone for all the communications between the enrolled entities. More information is contained in subdirectory Readmes and the references included below.

### Directories

This repository is organized into directories:

- tools: contains tools for using trust schema-based security. The README in this directory describes how the tools can be used to configure a domain to use a DCT trust schema and applications created using DCT. The binary schemaCompile should be added to this directory: download the compressed tar file corresponding to your OS available with the latest release.

- versec: Includes a description of the VerSec Language for expressing trust rules and a compiler that turns the language into a binary trust schema. 

- include: bespoke transport modules developed and used by Pollere to handle secure data-centric communications:
  
  - syncps: the pub-sub sync protocol that interfaces with the packet forwarder
  - schema: the run-time library that makes use of the binary trust schema
  - sigmgrs: supplies a range of signing and validation methods
  - distributors: distribute certs and group keys and manage the associated collections
  - face: the DirectFace implementation
  
- examples:
  
  - shims: contains example(s) of DCT "shims" that provide an API for applications of a usage domain.  This includes mbps.hpp which provides message-based publish/subscribe.
  - hmIot, office:  The README in this directory may be useful in understanding how DCT's modules can be used.

Note that this version (version 5) removes the use of NFD and the need for our previously required patches. It adds a new Direct Face and updates the group key distributor. Copyright notices have changed as Pollere, Inc. has converted to Pollere LLC.

Bug reports are welcome.

### Installing and building the pieces

All the modules are header-only C++ 'libraries' so the `DCT/include` tree has to be made available to programs using it via a `-I` c++ compiler flag or installed in a standard include path like `/usr/local/include`. The code requires c++20 and compiles with the current xcode compiler or clang-11 on MacOS and Linux and gcc-9 on Linux. It uses the new c++20 formatted output model which, unfortunately, is not yet in either compiler's standard library. To fill that gap we suggest using the excellent implementation available at https://fmt.dev/latest/index.html. This should be installed somewhere on your system and its `include/fmt` directory symlinked from `DCT/include`. (This distribution has a copy of the current 8.0.1 `fmt` dist in DCT/include/fmt; that should be removed and replaced with the symlink.) 

The included versec compiler is required to compile new schemas but pre-compiled schemas for the examples are available as a \*.scm file in the example source directory. To compile and run an example using the pre-compiled schema, for example, mbps:

- (one time) Install `ndn-ind` (from  https://github.com/operantnetworks/ndn-ind) version ee36771.
- (one time) `cd DCT/tools && make` to build all the tools needed.
- `cd DCT/examples/hmIoT`  then `make` to build the example. If the make is successful, follow the readme to create 'identity bundles' and run it.

### References and related work

Some concepts here may be better understood by referencing earlier Pollere work: 

[Lessons Learned Building a Secure Network Measurement Framework using Basic NDN ](http://www.pollere.net/Pdfdocs/icn19-p20.pdf), K. Nichols, Proceedings of ACM ICN '19, September 24-16, Macao, China (available at http://www.pollere.net/publications.html)

Trust schemas and ICN: key to secure home IoT, K. Nichols, Proceedings of ACM ICN '21, September 2021 (available at https://dl.acm.org/doi/10.1145/3460417.3482972)

Related talks at http://www.pollere.net/talks.html

See also GitHub.com/pollere/DNMP-v2 for Pollere's first bespoke transport.

---

Copyright (C) 2021-2022 Pollere LLC 
