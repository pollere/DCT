#include <stdint.h>
#include <string.h>

#include "sodium/crypto_hash_sha3.h"
#include "sodium/crypto_kem_mlkem768.h"
#include "sodium/crypto_kem_xwing.h"
#include "sodium/crypto_scalarmult_curve25519.h"
#include "sodium/crypto_xof_shake256.h"
#include "sodium/randombytes.h"

static void
expand_decaps_key(unsigned char       pk_mlkem[crypto_kem_mlkem768_PUBLICKEYBYTES],
                  unsigned char       sk_mlkem[crypto_kem_mlkem768_SECRETKEYBYTES],
                  unsigned char       pk_x25519[crypto_scalarmult_curve25519_BYTES],
                  unsigned char       sk_x25519[crypto_scalarmult_curve25519_SCALARBYTES],
                  const unsigned char seed[crypto_kem_xwing_SEEDBYTES])
{
    unsigned char expanded[96];
    unsigned char mlkem_seed[crypto_kem_mlkem768_SEEDBYTES];

    crypto_xof_shake256(expanded, 96, seed, crypto_kem_xwing_SEEDBYTES);

    memcpy(mlkem_seed, expanded, 64);
    memcpy(sk_x25519, expanded + 64, 32);

    crypto_kem_mlkem768_seed_keypair(pk_mlkem, sk_mlkem, mlkem_seed);
    crypto_scalarmult_curve25519_base(pk_x25519, sk_x25519);

    sodium_memzero(expanded, sizeof expanded);
    sodium_memzero(mlkem_seed, sizeof mlkem_seed);
}

static const unsigned char gk_label[6] = { 0x5c, 0xae, 0x2f, 0xaf, 0x5e, 0xdc };

static void
gk_combiner(unsigned char       ss[crypto_kem_xwing_SHAREDSECRETBYTES],
         const unsigned char ss_mlkem[crypto_kem_mlkem768_SHAREDSECRETBYTES],
         const unsigned char ss_x25519[crypto_scalarmult_curve25519_BYTES],
         const unsigned char ct_x25519[crypto_scalarmult_curve25519_BYTES],
         const unsigned char pk_x25519[crypto_scalarmult_curve25519_BYTES])
{
    crypto_hash_sha3256_state state;

    crypto_hash_sha3256_init(&state);
    crypto_hash_sha3256_update(&state, ss_mlkem, crypto_kem_mlkem768_SHAREDSECRETBYTES);
    crypto_hash_sha3256_update(&state, ss_x25519, crypto_scalarmult_curve25519_BYTES);
    //crypto_hash_sha3256_update(&state, ct_x25519, crypto_scalarmult_curve25519_BYTES);
    //crypto_hash_sha3256_update(&state, pk_x25519, crypto_scalarmult_curve25519_BYTES);
    crypto_hash_sha3256_update(&state, gk_label, sizeof gk_label);
    crypto_hash_sha3256_final(&state, ss);
}

static int
crypto_kem_xwing_enc_gk(unsigned char *ct, unsigned char *ss, const unsigned char *pk,
                                   const unsigned char *seed)
{
    const unsigned char *pk_mlkem  = pk;
    const unsigned char *pk_x25519 = pk + crypto_kem_mlkem768_PUBLICKEYBYTES;

    const unsigned char *seed_mlkem  = seed;
    const unsigned char *sk_e_x25519 = seed + 32;

    unsigned char ct_mlkem[crypto_kem_mlkem768_CIPHERTEXTBYTES];
    unsigned char ss_mlkem[crypto_kem_mlkem768_SHAREDSECRETBYTES];
    unsigned char ct_x25519[crypto_scalarmult_curve25519_BYTES];
    unsigned char ss_x25519[crypto_scalarmult_curve25519_BYTES];

    if (crypto_kem_mlkem768_enc_deterministic(ct_mlkem, ss_mlkem, pk_mlkem, seed_mlkem) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }

    crypto_scalarmult_curve25519_base(ct_x25519, sk_e_x25519);

    if (crypto_scalarmult_curve25519(ss_x25519, sk_e_x25519, pk_x25519) != 0) {
        sodium_memzero(ss_mlkem, sizeof ss_mlkem); /* LCOV_EXCL_LINE */
        return -1;                                 /* LCOV_EXCL_LINE */
    }

    memcpy(ct, ct_mlkem, crypto_kem_mlkem768_CIPHERTEXTBYTES);
    memcpy(ct + crypto_kem_mlkem768_CIPHERTEXTBYTES, ct_x25519, crypto_scalarmult_curve25519_BYTES);

    gk_combiner(ss, ss_mlkem, ss_x25519, ct_x25519, pk_x25519);

    sodium_memzero(ss_mlkem, sizeof ss_mlkem);
    sodium_memzero(ss_x25519, sizeof ss_x25519);

    return 0;
}

static int
crypto_kem_xwing_dec_gk(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    unsigned char pk_mlkem[crypto_kem_mlkem768_PUBLICKEYBYTES];
    unsigned char sk_mlkem[crypto_kem_mlkem768_SECRETKEYBYTES];
    unsigned char pk_x25519[crypto_scalarmult_curve25519_BYTES];
    unsigned char sk_x25519[crypto_scalarmult_curve25519_SCALARBYTES];

    const unsigned char *ct_mlkem  = ct;
    const unsigned char *ct_x25519 = ct + crypto_kem_mlkem768_CIPHERTEXTBYTES;

    unsigned char ss_mlkem[crypto_kem_mlkem768_SHAREDSECRETBYTES];
    unsigned char ss_x25519[crypto_scalarmult_curve25519_BYTES];

    expand_decaps_key(pk_mlkem, sk_mlkem, pk_x25519, sk_x25519, sk);

    /* LCOV_EXCL_START */
    if (crypto_kem_mlkem768_dec(ss_mlkem, ct_mlkem, sk_mlkem) != 0) {
        sodium_memzero(sk_mlkem, sizeof sk_mlkem);
        sodium_memzero(sk_x25519, sizeof sk_x25519);
        return -1;
    }

    if (crypto_scalarmult_curve25519(ss_x25519, sk_x25519, ct_x25519) != 0) {
        sodium_memzero(ss_mlkem, sizeof ss_mlkem);
        sodium_memzero(sk_mlkem, sizeof sk_mlkem);
        sodium_memzero(sk_x25519, sizeof sk_x25519);
        return -1;
    }
    /* LCOV_EXCL_STOP */

    gk_combiner(ss, ss_mlkem, ss_x25519, ct_x25519, pk_x25519);

    sodium_memzero(ss_mlkem, sizeof ss_mlkem);
    sodium_memzero(ss_x25519, sizeof ss_x25519);
    sodium_memzero(sk_mlkem, sizeof sk_mlkem);
    sodium_memzero(sk_x25519, sizeof sk_x25519);

    return 0;
}
