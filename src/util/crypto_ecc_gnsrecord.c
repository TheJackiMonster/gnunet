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
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"

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
 * @return h value
 */
static gcry_mpi_t
derive_h (const void *pub,
          size_t pubsize,
          const char *label,
          const char *context)
{
  gcry_mpi_t h;
  struct GNUNET_HashCode hc;
  static const char *const salt = "key-derivation";

  GNUNET_CRYPTO_kdf (&hc,
                     sizeof(hc),
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
  GNUNET_CRYPTO_mpi_scan_unsigned (&h, (unsigned char *) &hc, sizeof(hc));
  return h;
}


/**
 * This is a signature function for EdDSA which takes the
 * secret scalar sk instead of the private seed which is
 * usually the case for crypto APIs. We require this functionality
 * in order to use derived private keys for signatures we
 * cannot calculate the inverse of a sk to find the seed
 * efficiently.
 *
 * The resulting signature is a standard EdDSA signature
 * which can be verified using the usual APIs.
 *
 * @param sk the secret scalar
 * @param purp the signature purpose
 * @param sig the resulting signature
 */
void
GNUNET_CRYPTO_eddsa_sign_with_scalar (
  const struct GNUNET_CRYPTO_EddsaPrivateScalar *priv,
  const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
  struct GNUNET_CRYPTO_EddsaSignature *sig)
{

  crypto_hash_sha512_state hs;
  unsigned char az[64];
  unsigned char nonce[64];
  unsigned char hram[64];
  unsigned char R[32];
  unsigned char pk[32];

  crypto_hash_sha512_init (&hs);

  // crypto_hash_sha512 (az, sk, 32); DO NOT EXPAND, WE HAVE A KEY
  memcpy (az, priv->s, 64);
  crypto_scalarmult_ed25519_base_noclamp (pk,
                                          priv->s);
  crypto_hash_sha512_update (&hs, az + 32, 32);

  crypto_hash_sha512_update (&hs, (uint8_t*) purpose, ntohl (purpose->size));
  crypto_hash_sha512_final (&hs, nonce);

  // This effectively creates R || A in sig
  memcpy (sig->s, pk, 32);

  unsigned char nonce_mod[64];
  crypto_core_ed25519_scalar_reduce (nonce_mod, nonce);
  // nonce == r; r * G == R
  crypto_scalarmult_ed25519_base_noclamp (R, nonce_mod);
  memcpy (sig->r, R, sizeof (R));

  // SHA512 (R | A | M) == k
  crypto_hash_sha512_init (&hs);
  crypto_hash_sha512_update (&hs, (uint8_t*) sig, 64);
  crypto_hash_sha512_update (&hs, (uint8_t*) purpose,
                             ntohl (purpose->size));
  crypto_hash_sha512_final (&hs, hram);

  unsigned char hram_mod[64];
  crypto_core_ed25519_scalar_reduce (hram_mod, hram);
  az[0] &= 248;
  az[31] &= 127;
  az[31] |= 64;

  unsigned char tmp[32];
  // r + k * s mod L == S
  crypto_core_ed25519_scalar_mul (tmp, hram_mod, az);
  crypto_core_ed25519_scalar_add (sig->s, tmp, nonce_mod);

  sodium_memzero (az, sizeof az);
  sodium_memzero (nonce, sizeof nonce);
}


struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_private_key_derive (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
  const char *label,
  const char *context)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *ret;
  uint8_t dc[32];
  gcry_mpi_t h;
  gcry_mpi_t x;
  gcry_mpi_t d;
  gcry_mpi_t n;
  gcry_ctx_t ctx;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_CRYPTO_ecdsa_key_get_public (priv, &pub);

  h = derive_h (&pub, sizeof (pub), label, context);
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
  h = derive_h (pub, sizeof (pub), label, context);
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
  uint8_t dc[32];
  unsigned char sk[64];
  gcry_mpi_t h;
  gcry_mpi_t h_mod_n;
  gcry_mpi_t x;
  gcry_mpi_t d;
  gcry_mpi_t n;
  gcry_mpi_t a1;
  gcry_mpi_t a2;
  gcry_ctx_t ctx;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, "Ed25519"));

  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_CRYPTO_eddsa_key_get_public (priv, &pub);
  crypto_hash_sha512 (sk, priv->d, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  h = derive_h (&pub, sizeof (pub), label, context);
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);
  /* Convert to big endian for libgcrypt */
  for (size_t i = 0; i < 32; i++)
    dc[i] = sk[31 - i];
  GNUNET_CRYPTO_mpi_scan_unsigned (&x, dc, sizeof(dc)); // a
  a1 = gcry_mpi_new (256);
  gcry_mpi_t eight = gcry_mpi_set_ui (NULL, 8);
  gcry_mpi_div (a1, NULL, x, eight, 0); // a1 := a / 8
  a2 = gcry_mpi_new (256);
  gcry_mpi_mulm (a2, h_mod_n, a1, n); // a2 := h * a1 mod n
  d = gcry_mpi_new (256);
  // gcry_mpi_mulm (d, a2, eight, n); // a' := a2 * 8 mod n
  gcry_mpi_mul (d, a2, eight); // a' := a2 * 8
  gcry_mpi_release (h);
  gcry_mpi_release (x);
  gcry_mpi_release (n);
  gcry_mpi_release (a1);
  gcry_mpi_release (a2);
  gcry_ctx_release (ctx);
  GNUNET_CRYPTO_mpi_print_unsigned (dc, sizeof(dc), d);
  memcpy (result->s, sk, sizeof (sk));
  /* Convert to little endian for libsodium */
  for (size_t i = 0; i < 32; i++)
    result->s[i] = dc[31 - i];
  result->s[0] &= 248;
  result->s[31] &= 127;
  result->s[31] |= 64;

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
  h = derive_h (pub, sizeof (*pub), label, context);
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
