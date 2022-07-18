# Signature Managers for DCT

Signature Managers (sigmgrs) implement the signing and validation of both Publication and cAdd pdus which may include encryption. Currently, they can operate on both the actual TLV Data and and ndn::Data version. DCT is moving away from the ndn::Data representation; the TLV format (or *rData*)  is currently available in the receive path, i.e. for validation.

Six sigmgrs are currently available:

**sigmgr_eddsa.hpp** implements EdDSA signing and validation using the DCT identity cert associated with the Transport

**sigmgr_rfc7693.hpp** and **sigmgr_sha256.hpp** implement iintegrity signing and validation

**sigmgr_aead.hpp** implements AEAD encryption/decryption for an entire trust zone where the key is created, distributed and updated by the group key distributor,  **dist_gkey.hpp** in **include/distributors**. The key distributor encrypts the group key individually for each valid signing identity that has been published in the cert Collection (validated and stored locally). This means that members are added to the group as their validated signing identities become known and no members are added apriori.

 **sigmgr_ppaead.hpp** is a version of AEAD encryption/decrytion where the encryption key is unique to a particular publisher and the group of authorized subscribers. Authorized subscribers must have the required capability in their signing chain and the subscriber group key pair is distributed by **dist_sgkey.hpp** which creates (and updates) a key pair for the subscriber group, putting the public key in the clear and encrypting the secret key for each subscriber group member.  Data can only be decrypted by authorized subscribers (subscriber group members).

**sigmgr_ppsigned.hpp**  adds EdDSA signing and validation to the the publisher privacy AEAD (ppaead). Its use is indicated if there is a need to protect against authorized members of the subscriber group forging packets from Collection publishers. The encrypted packet is also signed by the publisher.

### Notes

Integrity signing is not available for use in trust schemas and is only used in key distribution (see the **distributors** directory). Use of an encryption sigmgr requires a group key distributor, either for all identities in the trust zone, *dist_gkey.hpp*, or for those with the subscriber capability in their identity chain, *dist_sgkey.hpp*. Required key distributor(s) are automatically instantiated by a defined-trust communications transport. The **sigmgr_null.hpp** is not available to trust schemas, is only used in the identity cert distribution process (and not externally to a transport), and should be ignored by users.

To add a new sigmgr (derived from the base class), a type name and unused SIGNER_TYPE  identifier must be selected and added to **sigmgr.hpp** as well as **sigmgr_by_type.hpp** and a file that implements the functions, e.g. **sigmgr_mine.hpp**, added to this directory. 
