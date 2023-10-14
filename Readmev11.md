# Changes with version 11

Version 11.0 cleans up some misleading naming terminology so there are changes in the *.rules files as well as scripts for making identity bundles. If you have your own *.rules files and identity bundle scripts, you will need to make a few changes.

Deprecated the use of **wire** and changed it to the more accurate **pdu** for protocol data unit. The action to take is to look for #wireValidator in your *.rules files (and scripts) and change to #pubValidator

Clarified the use of the **Publication** term. All of the named information objects that are kept in syncps collections are **Publications**. There are currently three main types of Publication collections kept by a DeftT:

**cert** for trust domain certificates. An integral part of every DeftT

**msgs** for the Publications that carry application message information. An integral part of every DeftT

**keys** for the Publications that implement cover key management and only present when symmetric key encryption (e.g., AEAD) is specified in the rules file. There are two types of **keys** collections possible:

- **keys/pdus** for pduValidator distributor
- **keys/msgs** for msgsValidator distributor

Previous use of #pubValidator in rules files should be changed to #msgsValidator and all rules files should contain a #certValidator setting though currently only EdDSA is used for cert signing. As of v11.0, the keys validator is still hard-coded but should be settable in rules files in the future.

The above changes have been made to the rules files and scripts in the example subdirectory. After changes, rules need to be recompiled into schemas and new versions of identity bundles made.