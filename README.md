# Data-Centric Toolkit

This repository contains Pollere's **evolving** work on tools to enable data-centric applications (with a focus on "edge" applications). DCT is an effort to make data/information-centric applications easier to write and secure. DCT reflects Pollere's needs and will update with our needs but the intention is a toolkit for general use. The toolkit currently uses a version of the Named-Data Networking Forwarder (NFD) with Pollere's patches, with a future goal of something less fragile and more broadcast media friendly.

This repository is organized into directories:

- tools: contains tools for using trust schema-based security. The README in this directory describes how the tools can be used to configure a domain to use a DCT trust schema and applications created using DCT. The binary schemaCompile should be added to this directory: download the compressed tar file corresponding to your OS available with the latest release.

- versec: Includes a description of the VerSec Language for expressing trust rules and a compiler that turns the language into a binary trust schema. 

- include: bespoke transport modules developed and used by Pollere to handle secure data-centric communications:
  
  - syncps: the pub-sub transport protocol that interfaces with the packet forwarder
  
  - schema: the run-time library that makes use of the binary trust schema
  
  - sigmgrs: supplies a range of signing and validation types
  
  - distributors: distribute certs and group keys and manage the associated Collections

- examples:
  
  - mbps: bespoke transport that provides message-based publish/subscribe. The README in this directory may be useful in understanding how DCT's modules can be used.

This version (version 3) adds signature managers employing libsodium and removes the legacy EcDSA signature. It also includes distributors for certificate chains and group keys, certificate and publication validation, and tools for creating identity bundles of certificates. This has led to some changes in how modules interface to one another. Bug reports are welcome.

### Installing and building the pieces

All the modules are header-only C++ 'libraries' so the `DCT/include` tree has to be made available to programs using it via a `-I` c++ compiler flag or installed in a standard include path like `/usr/local/include`. The code requires c++20 and compiles with the current xcode compiler or clang-11 on MacOS and Linux and gcc-9 on Linux. It uses the new c++20 formatted output model which, unfortunately, is not yet in either compiler's standard library. To fill that gap we suggest using the excellent implementation available at https://fmt.dev/latest/index.html. This should be installed somewhere on your system and its `include/fmt` directory symlinked from `DCT/include` (this distribution has a sample symlink assuming that the `fmt` dist was placed in a `src` tree at the same level as DCT). Patches available at https://github.com/pollere/NDNpatches will be needed.

The included versec compiler is required to compile new schemas but pre-compiled schemas for the examples are available as a \*.scm file in the example source directory. To compile and run an example using the pre-compiled schema, for example, mbps:

- (one time) `cd DCT/tools && make` to build the `schema_install` tool to install schema into your NDN PIB.
- `cd DCT/examples/mbps`  then `make` to build the example. If the make is successful, run `../../tools/schema_install mbps.scm`  to install the example's trust schema then follow the readme or its help text to run it. **Don't** install trust schemas without installing the ndn-cxx patch and https://github.com/operantnetworks/ndn-ind version b72bbf7e (5March21) or later (otherwise issues with certificate handling may make it difficult to manage your PIB). Ndn-ind b72bbf7e doesn't contain the async-face needed by these tools. To add it, apply the Pollere patch patch.ndn-ind  immediately after cloning the Operant Networks ndn-ind github repo.

### References and related work

Some concepts here may be better understood by referencing earlier Pollere work: 

[Lessons Learned Building a Secure Network Measurement Framework using Basic NDN ](http://www.pollere.net/Pdfdocs/icn19-p20.pdf), K. Nichols, Proceedings of ACM ICN '19, September 24-16, Macao, China (available at http://www.pollere.net/publications.html)

Related talks at http://www.pollere.net/talks.html

See also GitHub.com/pollere/DNMP-v2 for Pollere's first bespoke transport.

---

Copyright (C) 2021 Pollere, Inc 
