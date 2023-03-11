# Signature Managers for DCT

Signature Managers (sigmgrs) implement the signing (may include encryption) and validation (may include decryption) of both Publications and cAdd PDUs. These have the same underlying structure, an *rData* with TLV format, and thus can use the same sigmgrs. Publications, however, MUST be signed by their originator and thus cannot use any "encryption only" sigmgrs (e.g. AEAD or PPAEAD). Sign and encrypt sigmgrs like AEADSGN and PPSIGN must supply a validate and a decrypt method in addition to the validateDecrypt (which can just call the two methods) because decryption is done on subscriber upcalls and is bypassed for Relays and is not done on locally unsubscribed Publications.

The following sigmgrs are currently available for specification in trust schemas:

**sigmgr_eddsa.hpp** implements EdDSA signing and validation using the DCT identity cert associated with the Transport

**sigmgr_aead.hpp** implements AEAD encryption/decryption for an entire subnet ()sync zone) where a symmetric key is created, distributed and updated by the group key maker, using **dist_gkey.hpp** in **include/distributors**. The key maker encrypts the group key individually for each valid signing identity that has been published in the subnet's cert Collection (validated and stored locally). This means that members are added to the group as their validated signing identities become known and no members are added apriori.

**sigmgr_aeadsgn.hpp** performs AEAD encryption/decryption as above with the additional step that the rData is signed with the originator's identity. Publications MUST be signed so this version can be used to encrypt Publications.

**sigmgr_ppaead.hpp** is a version of AEAD encryption/decrytion where the encryption key is unique to a particular publisher and a restricted group of authorized subscribers, ensuring privacy between (pure) publishers and limiting the group of subscribers. Authorized subscribers must have the required subscriber group capability in their signing chain and the subscriber group key pair is distributed by **dist_sgkey.hpp** which creates (and updates) a key pair for the subscriber group, putting the public key in the clear and encrypting the secret key for each subscriber group member. Data can only be decrypted by authorized subscribers (subscriber group members), implementing privacy between non-subscriber originators.

**sigmgr_ppaeadsgn.hpp** adds EdDSA signing and validation to the **sigmgr_ppaead.hpp** as the encrypted packet is also signed by the originator. Its use is indicated if 1) there is a need to protect against authorized members of the subscriber group forging cAdd PDUs from Collection publishers and 2) for Publications (which must be signed).

Note that **sigmgr_rfc7693.hpp**, **sigmgr_null.hpp** and **sigmgr_sha256.hpp** are only used internally and are not available for trust schemas.

### Notes

Use of an encryption sigmgr requires a group key distributor, either for all identities in the trust zone, *dist_gkey.hpp*, or for those with the subscriber capability in their identity chain, *dist_sgkey.hpp*. Required key distributor(s) are automatically instantiated by a defined-trust communications transport. The **sigmgr_null.hpp** is not available to trust schemas, is only used in the identity cert distribution process (and not externally to a transport), and should be ignored by users.

To add a new sigmgr (derived from the base class), a type name and unused SIGNER_TYPE  identifier must be selected and added to **sigmgr.hpp** as well as **sigmgr_by_type.hpp** and a file that implements the functions, e.g. **sigmgr_<*mine*>.hpp**, added to this directory. 
