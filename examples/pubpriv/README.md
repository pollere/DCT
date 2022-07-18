# Location Reporter Example to show Publisher Privacy

This example is to illustrate the use of the publisher privacy signature managers *sigmgr_ppaead.hpp* and *sigmgr_ppsigned.hpp*. There are two types of applications: a location reporter that periodically publishes pseudo coordinates and a monitor that subscribes to these location reports. To keep locations private from other location reporters, the loc.trust schema adds privacy by encrypting cAdds using a "publisher privacy" version of AEAD where subscribers must have a specific *capability* in their signing chain in order to decrypt Publications of the Collection. The automatically deployed group key distributor, *dist_sgkey.hpp* creates a public/private key pair. In the key distribution publication, the public key is in the clear while the private key is encrypted for each entity with the *Subscriber Group* (SG) capability. Each publisher computes an encryption key using its own private key and the SG public key. SG entities use the SG private key with the publisher public key to compute the same symmetric key and decrypt.  Any entity whose role (from its signing identity) both puts it in the SG and permits it to create and distribute group keys attempts to become the key maker for the domain. The PPAEAD signature manager is used to encrypt/decrypt cAdds while the Publications use EdDSA.

#### Running the example

First, use included script and trust schema to make identity bundles

```
mkdir bundles
cd bundles
../mkIDs.sh ../loc.trust
cd ..
```

In a terminal window:

`mon monitor1.bundle`

Optionally, in another terminal window:

`mon monitor2.bundle`

In another terminal window:

`runLocrs.sh` or `loc bundles/locRptr1.bundle`

There should be some command line output. Use of **dctwatch** in another window lets you observe the packets.

#### Add provenance

PPAEAD has the possible vulnerability that a SG member can create the encryption key that any publisher could create and thus fake the provenance. In PPsigned the encrypted packet is additionally signed to ensure provenance. This adds overhead, of course, so should only be used if this is a threat in your deployment. To see this, uncomment the PPSIGN line in loc.trust and comment out the PPAEAD line and remake the bundles and rerun the example.

#### Note

Currently, publisher privacy can only be applied on the cAdd transport packets. This is temporary until some minor changes are made in syncps.hpp. Applying publisher privacy on the Publication packet may be a better strategy for most applications.

Copyright (C) 2022 Pollere LLC :q
