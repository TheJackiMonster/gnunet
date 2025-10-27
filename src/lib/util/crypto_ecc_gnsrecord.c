/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2015 GNUnet e.V.

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
 * @file util/crypto_ecc_gnsrecord.c
 * @brief public key cryptography (ECC) for GNS records (LSD0001)
 * @author Christian Grothoff
 * @author Florian Dold
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include <gcrypt.h>
#include <sodium.h>
#include "gnunet_util_lib.h"

#define CURVE "Ed25519"

/**
 * Derive the 'h' value for key derivation, where
 * 'h = H(l,P)'.
 *
 * @param pub public key for deriviation
 * @param pubsize the size of the public key
 * @param label label for deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @param hc where to write the result
 */
static void
derive_h (const void *pub,
          size_t pubsize,
          const char *label,
          const char *context,
          struct GNUNET_HashCode *hc)
{
  /** NOTE: While (H)KDF calls this value a salt
   *  it is not necessary for it to be a random value.
   *  It is more common to use a NULL value here
   *  (https://www.rfc-editor.org/rfc/rfc8446#section-7.1)
   *  But it is safe either way (See RFC 5869)
   */
  static const char *const salt = "key-derivation";

  GNUNET_CRYPTO_kdf (hc,
                     sizeof(*hc),
                     salt,
                     strlen (salt),
                     pub,
                     pubsize,
                     label,
                     strlen (label),
                     context,
                     strlen (context),
                     NULL,
                     0);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_eddsa_sign_derived (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *pkey,
  const char *label,
  const char *context,
  const struct GNUNET_CRYPTO_SignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  struct GNUNET_CRYPTO_EddsaPrivateScalar priv;
  crypto_hash_sha512_state hs;
  unsigned char sk[64];
  unsigned char r[64];
  unsigned char hram[64];
  unsigned char R[32];
  unsigned char zk[32];
  unsigned char tmp[32];
  unsigned char r_mod[64];
  unsigned char hram_mod[64];

  /**
   * Derive the private key
   */
  GNUNET_CRYPTO_eddsa_private_key_derive (pkey,
                                          label,
                                          context,
                                          &priv);

  crypto_hash_sha512_init (&hs);

  /**
   * Instead of expanding the private here, we already
   * have the secret scalar as input. Use it.
   * Note that sk is not plain SHA512 (d).
   * sk[0..31] contains the derived private scalar
   * sk[0..31] = h * SHA512 (d)[0..31]
   * sk[32..63] = SHA512 (d)[32..63]
   */
  memcpy (sk, priv.s, 64);

  /**
   * Calculate the derived zone key zk' from the
   * derived private scalar.
   */
  crypto_scalarmult_ed25519_base_noclamp (zk,
                                          sk);

  /**
   * Calculate r:
   * r = SHA512 (sk[32..63] | M)
   * where M is our message (purpose).
   * Note that sk[32..63] is the other half of the
   * expansion from the original, non-derived private key
   * "d".
   */
  crypto_hash_sha512_update (&hs, sk + 32, 32);
  crypto_hash_sha512_update (&hs, (uint8_t*) purpose, ntohl (purpose->size));
  crypto_hash_sha512_final (&hs, r);

  /**
   * Temporarily put zk into S
   */
  memcpy (sig->s, zk, 32);

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
   * hram := SHA512 (R | zk' | M)
   */
  crypto_hash_sha512_init (&hs);
  crypto_hash_sha512_update (&hs, (uint8_t*) sig, 64);
  crypto_hash_sha512_update (&hs, (uint8_t*) purpose,
                             ntohl (purpose->size));
  crypto_hash_sha512_final (&hs, hram);

  /**
   * Reduce the resulting scalar value
   */
  crypto_core_ed25519_scalar_reduce (hram_mod, hram);

  /**
   * Calculate
   * S := r + hram * s mod L
   */
  crypto_core_ed25519_scalar_mul (tmp, hram_mod, sk);
  crypto_core_ed25519_scalar_add (sig->s, tmp, r_mod);

  sodium_memzero (sk, sizeof (sk));
  sodium_memzero (r, sizeof (r));
  sodium_memzero (r_mod, sizeof (r_mod));
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_ecdsa_sign_derived (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const char *label,
  const char *context,
  const struct GNUNET_CRYPTO_SignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EcdsaSignature *sig)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *key;
  enum GNUNET_GenericReturnValue res;
  key = GNUNET_CRYPTO_ecdsa_private_key_derive (priv,
                                                label,
                                                context);
  res = GNUNET_CRYPTO_ecdsa_sign_ (key,
                                   purpose,
                                   sig);
  GNUNET_free (key);
  return res;
}


struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_private_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const char *label,
  const char *context)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *ret;
  struct GNUNET_HashCode hc;
  uint8_t dc[32];
  gcry_mpi_t h;
  gcry_mpi_t x;
  gcry_mpi_t d;
  gcry_mpi_t n;
  gcry_ctx_t ctx;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_CRYPTO_ecdsa_key_get_public (priv, &pub);

  derive_h (&pub, sizeof (pub), label, context, &hc);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof(hc));

  /* Convert to big endian for libgcrypt */
  for (size_t i = 0; i < 32; i++)
    dc[i] = priv->d[31 - i];
  GNUNET_CRYPTO_mpi_scan_unsigned (&x, dc, sizeof(dc));
  d = gcry_mpi_new (256);
  gcry_mpi_mulm (d, h, x, n);
  gcry_mpi_release (h);
  gcry_mpi_release (x);
  gcry_mpi_release (n);
  gcry_ctx_release (ctx);
  ret = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  GNUNET_CRYPTO_mpi_print_unsigned (dc, sizeof(dc), d);
  /* Convert to big endian for libgcrypt */
  for (size_t i = 0; i < 32; i++)
    ret->d[i] = dc[31 - i];
  sodium_memzero (dc, sizeof(dc));
  gcry_mpi_release (d);
  return ret;
}


void
GNUNET_CRYPTO_ecdsa_public_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EcdsaPublicKey *result)
{
  struct GNUNET_HashCode hc;
  gcry_ctx_t ctx;
  gcry_mpi_t q_y;
  gcry_mpi_t h;
  gcry_mpi_t n;
  gcry_mpi_t h_mod_n;
  gcry_mpi_point_t q;
  gcry_mpi_point_t v;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  /* obtain point 'q' from original public key.  The provided 'q' is
     compressed thus we first store it in the context and then get it
     back as a (decompresssed) point.  */
  q_y = gcry_mpi_set_opaque_copy (NULL, pub->q_y, 8 * sizeof(pub->q_y));
  GNUNET_assert (NULL != q_y);
  GNUNET_assert (0 == gcry_mpi_ec_set_mpi ("q", q_y, ctx));
  gcry_mpi_release (q_y);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  GNUNET_assert (q);

  /* calculate h_mod_n = h % n */
  derive_h (pub, sizeof (*pub), label, context, &hc);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof(hc));
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);
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


void
GNUNET_CRYPTO_eddsa_private_key_derive (
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EddsaPrivateScalar *result)
{
  struct GNUNET_CRYPTO_EddsaPublicKey pub;
  struct GNUNET_HashCode hc;
  uint8_t dc[32];
  unsigned char sk[64];
  gcry_mpi_t h;
  gcry_mpi_t h_mod_L;
  gcry_mpi_t a;
  gcry_mpi_t d;
  gcry_mpi_t L;
  gcry_ctx_t ctx;

  /**
   * Libsodium does not offer an API with arbitrary arithmetic.
   * Hence we have to use libgcrypt here.
   */
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, "Ed25519"));

  /**
   * Get our modulo L
   */
  L = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_CRYPTO_eddsa_key_get_public (priv, &pub);

  /**
   * This is the standard private key expansion in Ed25519.
   * The first 32 octets are used as a little-endian private
   * scalar.
   * We derive this scalar using our "h".
   */
  crypto_hash_sha512 (sk, priv->d, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;

  /**
   * Get h mod L
   */
  derive_h (&pub, sizeof (pub), label, context, &hc);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof(hc));
  h_mod_L = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_L, h, L);
  /* Convert scalar to big endian for libgcrypt */
  for (size_t i = 0; i < 32; i++)
    dc[i] = sk[31 - i];

  /**
   * dc now contains the private scalar "a".
   * We calculate:
   * d' := h * a mod L
   */
  GNUNET_CRYPTO_mpi_scan_unsigned (&a, dc, sizeof(dc)); // a
  d = gcry_mpi_new (256);
  gcry_mpi_mulm (d, h_mod_L, a, L); // d := h * a mod L
  gcry_mpi_release (h);
  gcry_mpi_release (a);
  gcry_mpi_release (L);
  gcry_mpi_release (h_mod_L);
  gcry_ctx_release (ctx);
  GNUNET_CRYPTO_mpi_print_unsigned (dc, sizeof(dc), d);
  {
    /**
     * We hash the derived "h" parameter with the
     * other half of the expanded private key. This ensures
     * that for signature generation, the "R" is derived from
     * the same derivation path as "h" and is not reused.
     */
    crypto_hash_sha256_state hs;
    crypto_hash_sha256_init (&hs);
    crypto_hash_sha256_update (&hs, sk + 32, 32);
    crypto_hash_sha256_update (&hs, (unsigned char*) &hc, sizeof (hc));
    crypto_hash_sha256_final (&hs, result->s + 32);
  }
  /* Convert to little endian for libsodium */
  for (size_t i = 0; i < 32; i++)
    result->s[i] = dc[31 - i];

  sodium_memzero (dc, sizeof(dc));
  gcry_mpi_release (d);
}


void
GNUNET_CRYPTO_eddsa_public_key_derive (
  const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
  const char *label,
  const char *context,
  struct GNUNET_CRYPTO_EddsaPublicKey *result)
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
  q_y = gcry_mpi_set_opaque_copy (NULL, pub->q_y, 8 * sizeof(pub->q_y));
  GNUNET_assert (NULL != q_y);
  GNUNET_assert (0 == gcry_mpi_ec_set_mpi ("q", q_y, ctx));
  gcry_mpi_release (q_y);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  GNUNET_assert (q);

  /* calculate h_mod_n = h % n */
  derive_h (pub, sizeof (*pub), label, context, &hc);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof(hc));

  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);

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


void
GNUNET_CRYPTO_eddsa_key_get_public_from_scalar (
  const struct GNUNET_CRYPTO_EddsaPrivateScalar *priv,
  struct GNUNET_CRYPTO_EddsaPublicKey *pkey)
{
  unsigned char sk[32];

  memcpy (sk, priv->s, 32);

  /**
   * Calculate the derived zone key zk' from the
   * derived private scalar.
   */
  crypto_scalarmult_ed25519_base_noclamp (pkey->q_y,
                                          sk);
}
