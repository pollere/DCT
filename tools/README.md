# Tools for setting up certs for DCT-enabled applications

The domain trust schema and the signing certs it specifies are central to DCT-enabled applications. The DCT/versec directory covers the language for expressing the trust rules and a compiler to check those rules and, optionally, create a binary output file, readable by DCT library modules, that contains the rules. Since DCT trust schemas *require* signing keys for all communications, this directory provides the tools to simplify that process. DCT/tools contains utilities that can be used to go from that trust schema to identity *bundles* of certificates for each entity of the domain. These provide primitives that can be used as part of a secure configuration procedure. This document outlines how to make identity bundles and a basic configuration procedure that could be further enhanced. Note that DCT certificates are derived from NDN Data, not from NDN Certificates.

## From Trust Schema to Identity Bundle

Bundles contain the information needed to start a DCT-enabled application organized (using TLVs), in the required order of:

- 0: the trust anchor (sample.root)
- 1: the schema (sample.schema)
- 2...(n-2): the signing cert's signing chain
- n-1: the signing cert and its key

An application can receive its bundle via the command line, a pipe or some other method. The bundle is used by DCT's run-time modules (consult DCT/examples for applications). The identity bundle can itself be used by a utility on each device to create signing certs for applications rather than using the top-level identity directly. Steps to make a bundle:

1. Starting from a text trust schema file, a binary version is compiled, e.g. for sample.trust in DCT/versec:
  
    `schemaCompile -o sampe.scm sample.trust`

2. A trust anchor (root) cert for the domain must be created in order to sign all the required certs.  sample.trust  gives the Name prefix required so the root is created as a self-signed cert:
  
    `make_cert -o sample.root myHouse`
   
   The output file  sample.root contains a cert with the public key as content and the associated signing (private) key. 

3. The next step is to make a cert holding the binary trust schema and signed by the root cert: 
  
   ​    `schema_cert -o sample.schema sample.scm sample.root`
   
   The cert content is the trust schema binary so there is no signing key in the sample.schema output file. 

4. Next, make identity certs for each planned entity, particularizing by role (either **operator** or **user** in sample.trust) and by specifying an id within that role. For example, setting an operator role with identifier "alice":
  
    `    make_cert -o myHouse.alice myHouse/operator/alice sample.root`

5. Make an identity bundle for each of the identity certs using the make_bundle utility in the tools directory and listing, in order, the certs to be included, e.g.:
  
    `make_bundle -o alice sample.root sample.schema +myHouse.alice`
   
   The "+" on the role cert indicates that its signing (private) key should be included in the bundle. The other certs in the bundle don't (and shouldn't) have their signing keys. This bundle is given the identity name (alice). The *examples/mbps* directory contains a script to do these steps (mkIDs.sh) for those applications.

## Configuration

A secure commissioning procedure can be employed to configure devices with a bootstrap identity bundle. DCT does not include such a procedure; we recommend using the best practice suitable for your particular installation. A simple example is to have the Configurer set up devices by being in physical contact with them and using a USB stick or a dedicated connection. The general steps in configuration are shown in the figure, where the process of making identity certs and identity bundles is repeated for all devices to be configured. Every time a device is added, the trust anchor signing key can be used by the Configurer to make a new identity and identity bundle and add it to the device.

![config](config.png)

Using the DCT run-time library, programs could be written to add updated trust schemas to the domain's cert collection and methods added to update validated trust schema. Once devices are part of the domain, signing chains can be updated over the network by using the cert Collection and encrypting new signing keys with the previous public signing key. Examples and methods for this will likely be added to DCT in the future but, it's best to make your own if you need this functionality.

---

Copyright (C) 2021 Pollere, Inc
