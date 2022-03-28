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
#include "platform.h"
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
 * @param n The value for the modulus 'n'
 * @param[out] phc if not NULL, the output of H() will be written into
 * return h_mod_n (allocated by this function)
 */
static gcry_mpi_t
derive_h_mod_n (
  const struct GNUNET_CRYPTO_Edx25519PublicKey *pub,
  const void *seed,
  size_t seedsize,
  const gcry_mpi_t n,
  struct GNUNET_HashCode *phc)
{
  static const char *const salt = "edx2559-derivation";
  struct GNUNET_HashCode hc;
  gcry_mpi_t h;
  gcry_mpi_t h_mod_n;

  if (NULL == phc)
    phc = &hc;

  GNUNET_CRYPTO_kdf (phc, sizeof(*phc),
                     salt, strlen (salt),
                     pub, sizeof(*pub),
                     seed, seedsize,
                     NULL, 0);

  /* calculate h_mod_n = h % n */
  GNUNET_CRYPTO_mpi_scan_unsigned (&h,
                                   (unsigned char *) phc,
                                   sizeof(*phc));
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);

#ifdef CHECK_RARE_CASES
  /**
   * Note that the following cases would be problematic:
   *	1.) h == 0 mod n
   *	2.) h == 1 mod n
   *	3.) [h] * P == E
   * We assume that the probalities for these cases to occur are neglegible.
   */
  GNUNET_assert (! gcry_mpi_cmp_ui (h_mod_n, 0));
  GNUNET_assert (! gcry_mpi_cmp_ui (h_mod_n, 1));
#endif

  gcry_mpi_release(h);
  return h_mod_n;
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
  unsigned char sk[64];
  gcry_ctx_t ctx;
  gcry_mpi_t h;
  gcry_mpi_t h_mod_n;
  gcry_mpi_t x;
  gcry_mpi_t n;
  gcry_mpi_t a1;
  gcry_mpi_t a2;
  gcry_mpi_t ap; // a'

  GNUNET_CRYPTO_edx25519_key_get_public (priv, &pub);

  /**
   * Libsodium does not offer an API with arbitrary arithmetic.
   * Hence we have to use libgcrypt here.
   */
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, "Ed25519"));

  /**
   * Get our modulo
   */
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_assert (NULL != n);

  /**
   * Get h mod n
   */
  h_mod_n = derive_h_mod_n (&pub,
                            seed,
                            seedsize,
                            n,
                            &hc);

  /* Convert priv->a scalar to big endian for libgcrypt */
  for (size_t i = 0; i < 32; i++)
    a[i] = priv->a[31 - i];

  /**
   * dc now contains the private scalar "a".
   * We carefully remove the clamping and derive a'.
   * Calculate:
   * a1 := a / 8
   * a2 := h * a1 mod n
   * a' := a2 * 8 mod n
   */
  GNUNET_CRYPTO_mpi_scan_unsigned (&x, a, sizeof(a)); // a
  a1 = gcry_mpi_new (256);
  gcry_mpi_t eight = gcry_mpi_set_ui (NULL, 8);
  gcry_mpi_div (a1, NULL, x, eight, 0); // a1 := a / 8
  a2 = gcry_mpi_new (256);
  gcry_mpi_mulm (a2, h_mod_n, a1, n); // a2 := h * a1 mod n
  ap = gcry_mpi_new (256);
  gcry_mpi_mul (ap, a2, eight); // a' := a2 * 8

#ifdef CHECK_RARE_CASES
  /* The likelihood for a' == 0 or a' == 1 is neglegible */
  GNUNET_assert (! gcry_mpi_cmp_ui (ap, 0));
  GNUNET_assert (! gcry_mpi_cmp_ui (ap, 1));
#endif

  gcry_mpi_release (h_mod_n);
  gcry_mpi_release (eight);
  gcry_mpi_release (h);
  gcry_mpi_release (x);
  gcry_mpi_release (n);
  gcry_mpi_release (a1);
  gcry_mpi_release (a2);
  gcry_ctx_release (ctx);
  GNUNET_CRYPTO_mpi_print_unsigned (a, sizeof(a), ap);
  gcry_mpi_release (ap);

  /**
   * We hash the derived "h" parameter with the other half of the expanded
   * private key (that is: priv->b). This ensures that for signature
   * generation, the "R" is derived from the same derivation path as "h" and is
   * not reused.
   */
  {
    crypto_hash_sha256_state hs;
    crypto_hash_sha256_init (&hs);
    crypto_hash_sha256_update (&hs, priv->b, sizeof(priv->b));
    crypto_hash_sha256_update (&hs, (unsigned char*) &hc, sizeof (hc));
    crypto_hash_sha256_final (&hs, result->b);
  }

  /* Convert to little endian for libsodium */
  for (size_t i = 0; i < 32; i++)
    result->a[i] = a[31 - i];

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
  gcry_ctx_t ctx;
  gcry_mpi_t q_y;
  gcry_mpi_t h;
  gcry_mpi_t n;
  gcry_mpi_t h_mod_n;
  gcry_mpi_point_t q;
  gcry_mpi_point_t v;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, "Ed25519"));

  /* obtain point 'q' from original public key.  The provided 'q' is
     compressed thus we first store it in the context and then get it
     back as a (decompresssed) point.  */
  q_y = gcry_mpi_set_opaque_copy (NULL,
                                  pub->q_y,
                                  8 * sizeof(pub->q_y));
  GNUNET_assert (NULL != q_y);
  GNUNET_assert (0 == gcry_mpi_ec_set_mpi ("q", q_y, ctx));
  gcry_mpi_release (q_y);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  GNUNET_assert (q);

  /**
   * Get h mod n
   */
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_assert (NULL != n);
  GNUNET_assert (NULL != pub);
  h_mod_n = derive_h_mod_n (pub,
                            seed,
                            seedsize,
                            n,
                            NULL /* We don't need hc here */);

  /* calculate v = h_mod_n * q */
  v = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (v, h_mod_n, q, ctx);
  gcry_mpi_release (h_mod_n);
  gcry_mpi_release (h);
  gcry_mpi_release (n);
  gcry_mpi_point_release (q);

  /* convert point 'v' to public key that we return */
  GNUNET_assert (0 == gcry_mpi_ec_set_point ("q", v, ctx));
  gcry_mpi_point_release (v);
  q_y = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q_y);
  GNUNET_CRYPTO_mpi_print_unsigned (result->q_y, sizeof(result->q_y), q_y);
  gcry_mpi_release (q_y);
  gcry_ctx_release (ctx);

}
