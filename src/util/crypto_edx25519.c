/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/crypto_edx25519.c
 * @brief An variant of EdDSA which allows for iterative derivation of key pairs.
 * @author Özgür Kesim
 * @author Christian Grothoff
 * @author Florian Dold
 * @author Martin Schanzenbach
 */

#include <gcrypt.h>
#include <sodium.h>
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"

#define CURVE "Ed25519"

void
GNUNET_CRYPTO_edx25519_key_clear (struct GNUNET_CRYPTO_Edx25519PrivateKey *pk)
{
  memset (pk, 0, sizeof(struct GNUNET_CRYPTO_Edx25519PrivateKey));
}


void
GNUNET_CRYPTO_edx25519_key_create_from_seed (
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PrivateKey *pk)
{

  GNUNET_static_assert (sizeof(*pk) == sizeof(struct GNUNET_HashCode));
  GNUNET_CRYPTO_hash (seed,
                      seedsize,
                      (struct GNUNET_HashCode *) pk);

  /* Clamp the first half of the key. The second half is used in the signature
   * process. */
  pk->a[0] &= 248;
  pk->a[31] &= 127;
  pk->a[31] |= 64;
}


void
GNUNET_CRYPTO_edx25519_key_create (
  struct GNUNET_CRYPTO_Edx25519PrivateKey *pk)
{
  char seed[256 / 8];
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              seed,
                              sizeof (seed));
  GNUNET_CRYPTO_edx25519_key_create_from_seed (seed,
                                               sizeof(seed),
                                               pk);
}


void
GNUNET_CRYPTO_edx25519_key_get_public (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  struct GNUNET_CRYPTO_Edx25519PublicKey *pub)
{
  crypto_scalarmult_ed25519_base_noclamp (pub->q_y,
                                          priv->a);
}


/**
 * This function operates the basically same way as the signature function for
 * EdDSA. But instead of expanding a private seed (which is usually the case
 * for crypto APIs) and using the resulting scalars, it takes the scalars
 * directly from Edx25519PrivateKey.  We require this functionality in order to
 * use derived private keys for signatures.
 *
 * The resulting signature is a standard EdDSA signature
 * which can be verified using the usual APIs.
 *
 * @param priv the private key (containing two scalars .a and .b)
 * @param purp the signature purpose
 * @param sig the resulting signature
 */
enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_edx25519_sign_ (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_Edx25519Signature *sig)
{

  crypto_hash_sha512_state hs;
  unsigned char r[64];
  unsigned char hram[64];
  unsigned char P[32];
  unsigned char r_mod[64];
  unsigned char R[32];
  unsigned char tmp[32];

  crypto_hash_sha512_init (&hs);

  /**
   * Calculate the public key P from the private scalar in the key.
   */
  crypto_scalarmult_ed25519_base_noclamp (P,
                                          priv->a);

  /**
   * Calculate r:
   * r = SHA512 (b ∥ M)
   * where M is our message (purpose).
   */
  crypto_hash_sha512_update (&hs,
                             priv->b,
                             sizeof(priv->b));
  crypto_hash_sha512_update (&hs,
                             (uint8_t*) purpose,
                             ntohl (purpose->size));
  crypto_hash_sha512_final (&hs,
                            r);

  /**
   * Temporarily put P into S
   */
  memcpy (sig->s, P, 32);

  /**
   * Reduce the scalar value r
   */
  crypto_core_ed25519_scalar_reduce (r_mod, r);

  /**
   * Calculate R := r * G of the signature
   */
  crypto_scalarmult_ed25519_base_noclamp (R, r_mod);
  memcpy (sig->r, R, sizeof (R));

  /**
   * Calculate
   * hram := SHA512 (R ∥ P ∥ M)
   */
  crypto_hash_sha512_init (&hs);
  crypto_hash_sha512_update (&hs, (uint8_t*) sig, 64);
  crypto_hash_sha512_update (&hs, (uint8_t*) purpose,
                             ntohl (purpose->size));
  crypto_hash_sha512_final (&hs, hram);

  /**
   * Reduce the resulting scalar value
   */
  unsigned char hram_mod[64];
  crypto_core_ed25519_scalar_reduce (hram_mod, hram);

  /**
   * Calculate
   * S := r + hram * s mod L
   */
  crypto_core_ed25519_scalar_mul (tmp, hram_mod, priv->a);
  crypto_core_ed25519_scalar_add (sig->s, tmp, r_mod);

  sodium_memzero (r, sizeof (r));
  sodium_memzero (r_mod, sizeof (r_mod));

  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_edx25519_verify_ (
  uint32_t purpose,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
  const struct GNUNET_CRYPTO_Edx25519Signature *sig,
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub)
{
  const unsigned char *m = (const void *) validate;
  size_t mlen = ntohl (validate->size);
  const unsigned char *s = (const void *) sig;

  int res;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR; /* purpose mismatch */

  res = crypto_sign_verify_detached (s, m, mlen, pub->q_y);
  return (res == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Derive the 'h' value for key derivation, where
 * 'h = H(P ∥ seed) mod n' and 'n' is the size of the cyclic subroup.
 *
 * @param pub public key for deriviation
 * @param seed seed for key the deriviation
 * @param seedsize the size of the seed
 * @param[out] phc if not NULL, the output of H() will be written into
 * return h_mod_n (allocated by this function)
 */
static void
derive_h (
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub,
  const void *seed,
  size_t seedsize,
  struct GNUNET_HashCode *phc)
{
  static const char *const salt = "edx25519-derivation";

  GNUNET_CRYPTO_kdf (/* output*/
                     phc, sizeof(*phc),
                     /* salt */
                     seed, seedsize,
                     /* ikm */
                     pub, sizeof(*pub),
                     /* ctx chunks*/
                     salt, strlen (salt),
                     NULL, 0);

}


void
GNUNET_CRYPTO_edx25519_private_key_derive (
  const struct GNUNET_CRYPTO_Edx25519PrivateKey *priv,
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PrivateKey *result)
{
  struct GNUNET_CRYPTO_Edx25519PublicKey pub;
  struct GNUNET_HashCode hc;
  uint8_t a[32];
  uint8_t eight[32] = { 8 };
  uint8_t eight_inv[32];
  uint8_t h[64] = { 0 };

  GNUNET_CRYPTO_edx25519_key_get_public (priv, &pub);

  /* Get h mod n */
  derive_h (&pub,
            seed,
            seedsize,
            &hc);

  memcpy (h, &hc, 64);
  crypto_core_ed25519_scalar_reduce (h,
                                     h);
#ifdef CHECK_RARE_CASES
  /**
   * Note that the following cases would be problematic:
   *	1.) h == 0 mod n
   *	2.) h == 1 mod n
   *	3.) [h] * P == E
   * We assume that the probalities for these cases to occur are neglegible.
   */
  {
    char zero[32] = { 0 };
    char one[32] = { 1 };

    GNUNET_assert (0 != memcmp (zero, h, 32));
    GNUNET_assert (0 != memcmp (one, h, 32));
  }
#endif

  /**
   * dc now contains the private scalar "a".
   * We carefully remove the clamping and derive a'.
   * Calculate:
   * a1 := a / 8
   * a2 := h * a1 mod n
   * a' := a2 * 8 mod n
   */

  GNUNET_assert (0 == crypto_core_ed25519_scalar_invert (eight_inv,
                                                         eight));

  crypto_core_ed25519_scalar_mul (a, priv->a, eight_inv);
  crypto_core_ed25519_scalar_mul (a, a, h);
  crypto_core_ed25519_scalar_mul (a, a, eight);

#ifdef CHECK_RARE_CASES
  /* The likelihood for a' == 0 or a' == 1 is neglegible */
  {
    char zero[32] = { 0 };
    char one[32] = { 1 };

    GNUNET_assert (0 != memcmp (zero, a, 32));
    GNUNET_assert (0 != memcmp (one, a, 32));
  }
#endif

  /* We hash the derived "h" parameter with the other half of the expanded
   * private key (that is: priv->b). This ensures that for signature
   * generation, the "R" is derived from the same derivation path as "h" and is
   * not reused. */
  {
    struct GNUNET_HashCode hcb;
    struct GNUNET_HashContext *hctx;

    hctx = GNUNET_CRYPTO_hash_context_start ();
    GNUNET_CRYPTO_hash_context_read (hctx, priv->b, sizeof(priv->b));
    GNUNET_CRYPTO_hash_context_read (hctx, (unsigned char*) &hc, sizeof (hc));
    GNUNET_CRYPTO_hash_context_finish (hctx, &hcb);

    /* Truncate result, effectively doing SHA512/256 */
    for (size_t i = 0; i < 32; i++)
      result->b[i] = ((unsigned char *) &hcb)[i];
  }

  for (size_t i = 0; i < 32; i++)
    result->a[i] = a[i];

  sodium_memzero (a, sizeof(a));
}


void
GNUNET_CRYPTO_edx25519_public_key_derive (
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub,
  const void *seed,
  size_t seedsize,
  struct GNUNET_CRYPTO_Edx25519PublicKey *result)
{
  struct GNUNET_HashCode hc;
  uint8_t h[64] = { 0 };

  derive_h (pub,
            seed,
            seedsize,
            &hc);
  memcpy (h,
          &hc,
          64);
  crypto_core_ed25519_scalar_reduce (h,
                                     h);
  GNUNET_assert (0 == crypto_scalarmult_ed25519_noclamp (result->q_y,
                                                         h,
                                                         pub->q_y));
}
