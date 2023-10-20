/*
   This file is part of GNUnet
   Copyright (C) 2014,2016,2019, 2023 GNUnet e.V.

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
 * @file util/crypto_cs.c
 * @brief Clause Blind Schnorr signatures using Curve25519
 * @author Lucien Heuzeveldt <lucienclaude.heuzeveldt@students.bfh.ch>
 * @author Gian Demarmels <gian@demarmels.org>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <sodium.h>
#include <gcrypt.h>

/**
 * IMPLEMENTATION NOTICE:
 *
 * This is an implementation of the Clause Blind Schnorr Signature Scheme using Curve25519.
 * Further details about the Clause Blind Schnorr Signature Scheme can be found here:
 * https://eprint.iacr.org/2019/877.pdf
 *
 * We use libsodium wherever possible.
 */


void
GNUNET_CRYPTO_cs_private_key_generate (struct GNUNET_CRYPTO_CsPrivateKey *priv)
{
  crypto_core_ed25519_scalar_random (priv->scalar.d);
}


void
GNUNET_CRYPTO_cs_private_key_get_public (
  const struct GNUNET_CRYPTO_CsPrivateKey *priv,
  struct GNUNET_CRYPTO_CsPublicKey *pub)
{
  GNUNET_assert (0 ==
                 crypto_scalarmult_ed25519_base_noclamp (pub->point.y,
                                                         priv->scalar.d));
}


/**
 * Maps 32 random bytes to a scalar.  This is necessary because libsodium
 * expects scalar to be in the prime order subgroup.
 *
 * @param[in,out] scalar containing 32 byte char array, is modified to be in prime order subgroup
 */
static void
map_to_scalar_subgroup (struct GNUNET_CRYPTO_Cs25519Scalar *scalar)
{
  /* perform clamping as described in RFC7748 */
  scalar->d[0] &= 248;
  scalar->d[31] &= 127;
  scalar->d[31] |= 64;
}


void
GNUNET_CRYPTO_cs_r_derive (const struct GNUNET_CRYPTO_CsSessionNonce *nonce,
                           const char *seed,
                           const struct GNUNET_CRYPTO_CsPrivateKey *lts,
                           struct GNUNET_CRYPTO_CsRSecret r[2])
{
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CRYPTO_kdf (
      r,     sizeof (struct GNUNET_CRYPTO_CsRSecret) * 2,
      seed,  strlen (seed),
      lts,   sizeof (*lts),
      nonce, sizeof (*nonce),
      NULL,  0));
  map_to_scalar_subgroup (&r[0].scalar);
  map_to_scalar_subgroup (&r[1].scalar);
}


void
GNUNET_CRYPTO_cs_r_get_public (const struct GNUNET_CRYPTO_CsRSecret *r_priv,
                               struct GNUNET_CRYPTO_CsRPublic *r_pub)
{
  GNUNET_assert (0 ==
                 crypto_scalarmult_ed25519_base_noclamp (r_pub->point.y,
                                                         r_priv->scalar.d));
}


void
GNUNET_CRYPTO_cs_blinding_secrets_derive (
  const struct GNUNET_CRYPTO_CsBlindingNonce *blind_seed,
  struct GNUNET_CRYPTO_CsBlindingSecret bs[2])
{
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CRYPTO_hkdf (bs,
                        sizeof (struct GNUNET_CRYPTO_CsBlindingSecret) * 2,
                        GCRY_MD_SHA512,
                        GCRY_MD_SHA256,
                        "alphabeta",
                        strlen ("alphabeta"),
                        blind_seed,
                        sizeof(*blind_seed),
                        NULL,
                        0));
  map_to_scalar_subgroup (&bs[0].alpha);
  map_to_scalar_subgroup (&bs[0].beta);
  map_to_scalar_subgroup (&bs[1].alpha);
  map_to_scalar_subgroup (&bs[1].beta);
}


/*
order of subgroup required for scalars by libsodium
2^252 + 27742317777372353535851937790883648493
copied from https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
and converted to big endian
*/
static const unsigned char L_BIG_ENDIAN[32] = {
  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7,
  0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};


/**
 * Computes a Hash of (R', m) mapped to a Curve25519 scalar
 *
 * @param hash initial hash of the message to be signed
 * @param pub denomination public key (used as salt)
 * @param[out] c C containing scalar
 */
static void
cs_full_domain_hash (const struct GNUNET_CRYPTO_CsRPublic *r_dash,
                     const void *msg,
                     size_t msg_len,
                     const struct GNUNET_CRYPTO_CsPublicKey *pub,
                     struct GNUNET_CRYPTO_CsC *c)
{
  // SHA-512 hash of R' and message
  size_t r_m_concat_len = sizeof(struct GNUNET_CRYPTO_CsRPublic) + msg_len;
  char r_m_concat[r_m_concat_len];
  memcpy (r_m_concat, r_dash, sizeof(struct GNUNET_CRYPTO_CsRPublic));
  memcpy (r_m_concat + sizeof(struct GNUNET_CRYPTO_CsRPublic), msg, msg_len);
  struct GNUNET_HashCode prehash;

  GNUNET_CRYPTO_hash (r_m_concat,
                      r_m_concat_len,
                      &prehash);

  // modulus converted to MPI representation
  gcry_mpi_t l_mpi;
  GNUNET_CRYPTO_mpi_scan_unsigned (&l_mpi,
                                   L_BIG_ENDIAN,
                                   sizeof(L_BIG_ENDIAN));

  // calculate full domain hash
  gcry_mpi_t c_mpi;
  GNUNET_CRYPTO_kdf_mod_mpi (&c_mpi,
                             l_mpi,
                             pub,
                             sizeof(struct GNUNET_CRYPTO_CsPublicKey),
                             &prehash,
                             sizeof(struct GNUNET_HashCode),
                             "Curve25519FDH");
  gcry_mpi_release (l_mpi);

  // convert c from mpi
  unsigned char c_big_endian[256 / 8];
  GNUNET_CRYPTO_mpi_print_unsigned (c_big_endian,
                                    sizeof(c_big_endian),
                                    c_mpi);
  gcry_mpi_release (c_mpi);
  for (size_t i = 0; i<32; i++)
    c->scalar.d[i] = c_big_endian[31 - i];
}


/**
 * calculate R'
 *
 * @param bs blinding secret
 * @param r_pub R
 * @param pub public key
 * @param[out] blinded_r_pub R'
 */
static void
calc_r_dash (const struct GNUNET_CRYPTO_CsBlindingSecret *bs,
             const struct GNUNET_CRYPTO_CsRPublic *r_pub,
             const struct GNUNET_CRYPTO_CsPublicKey *pub,
             struct GNUNET_CRYPTO_CsRPublic *blinded_r_pub)
{
  // R'i = Ri + alpha i*G + beta i*pub
  struct GNUNET_CRYPTO_Cs25519Point alpha_mul_base;
  GNUNET_assert (0 ==
                 crypto_scalarmult_ed25519_base_noclamp (
                   alpha_mul_base.y,
                   bs->alpha.d));
  struct GNUNET_CRYPTO_Cs25519Point beta_mul_pub;
  GNUNET_assert (0 == crypto_scalarmult_ed25519_noclamp (beta_mul_pub.y,
                                                         bs->beta.d,
                                                         pub->point.y));
  struct GNUNET_CRYPTO_Cs25519Point alpha_mul_base_plus_beta_mul_pub;
  GNUNET_assert (0 == crypto_core_ed25519_add (
                   alpha_mul_base_plus_beta_mul_pub.y,
                   alpha_mul_base.y,
                   beta_mul_pub.y));
  GNUNET_assert (0 == crypto_core_ed25519_add (blinded_r_pub->point.y,
                                               r_pub->point.y,
                                               alpha_mul_base_plus_beta_mul_pub.
                                               y));
}


void
GNUNET_CRYPTO_cs_calc_blinded_c (
  const struct GNUNET_CRYPTO_CsBlindingSecret bs[2],
  const struct GNUNET_CRYPTO_CsRPublic r_pub[2],
  const struct GNUNET_CRYPTO_CsPublicKey *pub,
  const void *msg,
  size_t msg_len,
  struct GNUNET_CRYPTO_CsC blinded_c[2],
  struct GNUNET_CRYPTO_CsRPublic blinded_r_pub[2])
{
  // for i 0/1: R'i = Ri + alpha i*G + beta i*pub
  calc_r_dash (&bs[0], &r_pub[0], pub, &blinded_r_pub[0]);
  calc_r_dash (&bs[1], &r_pub[1], pub, &blinded_r_pub[1]);

  // for i 0/1: c'i = H(R'i, msg)
  struct GNUNET_CRYPTO_CsC c_dash_0;
  struct GNUNET_CRYPTO_CsC c_dash_1;
  cs_full_domain_hash (&blinded_r_pub[0], msg, msg_len, pub, &c_dash_0);
  cs_full_domain_hash (&blinded_r_pub[1], msg, msg_len, pub, &c_dash_1);

  // for i 0/1: ci = c'i + beta i mod p
  crypto_core_ed25519_scalar_add (blinded_c[0].scalar.d,
                                  c_dash_0.scalar.d,
                                  bs[0].beta.d);
  crypto_core_ed25519_scalar_add (blinded_c[1].scalar.d,
                                  c_dash_1.scalar.d,
                                  bs[1].beta.d);
}


void
GNUNET_CRYPTO_cs_sign_derive (
  const struct GNUNET_CRYPTO_CsPrivateKey *priv,
  const struct GNUNET_CRYPTO_CsRSecret r[2],
  const struct GNUNET_CRYPTO_CsBlindedMessage *bm,
  struct GNUNET_CRYPTO_CsBlindSignature *cs_blind_sig)
{
  struct GNUNET_CRYPTO_Cs25519Scalar c_b_mul_priv;
  uint32_t hkdf_out;

  /* derive clause session identifier b (random bit) */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_hkdf (&hkdf_out,
                                     sizeof (hkdf_out),
                                     GCRY_MD_SHA512,
                                     GCRY_MD_SHA256,
                                     "b",
                                     strlen ("b"),
                                     priv,
                                     sizeof (*priv),
                                     &bm->nonce,
                                     sizeof (bm->nonce),
                                     NULL,
                                     0));
  cs_blind_sig->b = hkdf_out % 2;

  /* s = r_b + c_b * priv */
  crypto_core_ed25519_scalar_mul (c_b_mul_priv.d,
                                  bm->c[cs_blind_sig->b].scalar.d,
                                  priv->scalar.d);
  crypto_core_ed25519_scalar_add (cs_blind_sig->s_scalar.scalar.d,
                                  r[cs_blind_sig->b].scalar.d,
                                  c_b_mul_priv.d);
}


void
GNUNET_CRYPTO_cs_unblind (
  const struct GNUNET_CRYPTO_CsBlindS *blinded_signature_scalar,
  const struct GNUNET_CRYPTO_CsBlindingSecret *bs,
  struct GNUNET_CRYPTO_CsS *signature_scalar)
{
  crypto_core_ed25519_scalar_add (signature_scalar->scalar.d,
                                  blinded_signature_scalar->scalar.d,
                                  bs->alpha.d);
}


enum GNUNET_GenericReturnValue
GNUNET_CRYPTO_cs_verify (const struct GNUNET_CRYPTO_CsSignature *sig,
                         const struct GNUNET_CRYPTO_CsPublicKey *pub,
                         const void *msg,
                         size_t msg_len)
{
  // calculate c' = H(R, m)
  struct GNUNET_CRYPTO_CsC c_dash;

  cs_full_domain_hash (&sig->r_point,
                       msg,
                       msg_len,
                       pub,
                       &c_dash);

  // s'G ?= R' + c' pub
  struct GNUNET_CRYPTO_Cs25519Point sig_scal_mul_base;
  GNUNET_assert (0 ==
                 crypto_scalarmult_ed25519_base_noclamp (
                   sig_scal_mul_base.y,
                   sig->s_scalar.scalar.d));
  struct GNUNET_CRYPTO_Cs25519Point c_dash_mul_pub;
  GNUNET_assert (0 == crypto_scalarmult_ed25519_noclamp (c_dash_mul_pub.y,
                                                         c_dash.scalar.d,
                                                         pub->point.y));
  struct GNUNET_CRYPTO_Cs25519Point R_add_c_dash_mul_pub;
  GNUNET_assert (0 == crypto_core_ed25519_add (R_add_c_dash_mul_pub.y,
                                               sig->r_point.point.y,
                                               c_dash_mul_pub.y));

  return 0 == GNUNET_memcmp (&sig_scal_mul_base,
                             &R_add_c_dash_mul_pub)
    ? GNUNET_OK
    : GNUNET_SYSERR;
}
