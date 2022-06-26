/*
   This file is part of GNUnet
   Copyright (C) 2021,2022 GNUnet e.V.

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
 * @file util/test_crypto_cs.c
 * @brief testcase for utility functions for clause blind schnorr signature scheme cryptography
 * @author Lucien Heuzeveldt <lucienclaude.heuzeveldt@students.bfh.ch>
 * @author Gian Demarmels <gian@demarmels.org>
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <sodium.h>

#define ITER 25

static void
test_create_priv (struct GNUNET_CRYPTO_CsPrivateKey *priv)
{
  /* TEST 1
   * Check that privkey is set
   */
  struct GNUNET_CRYPTO_CsPrivateKey other_priv;

  other_priv = *priv;
  GNUNET_CRYPTO_cs_private_key_generate (priv);
  GNUNET_assert (0 !=
                 GNUNET_memcmp (&other_priv.scalar,
                                &priv->scalar));
}


static void
test_generate_pub (const struct GNUNET_CRYPTO_CsPrivateKey *priv,
                   struct GNUNET_CRYPTO_CsPublicKey *pub)
{
  /* TEST 1
   * Check that pubkey is set
   */
  struct GNUNET_CRYPTO_CsPublicKey other_pub;

  other_pub = *pub;
  GNUNET_CRYPTO_cs_private_key_get_public (priv,
                                           pub);
  GNUNET_assert (0 !=
                 GNUNET_memcmp (&other_pub.point,
                                &pub->point));

  /* TEST 2
   * Check that pubkey is a valid point
   */
  GNUNET_assert (1 ==
                 crypto_core_ed25519_is_valid_point (pub->point.y));

  /* TEST 3
   * Check if function gives the same result for the same output
   */
  other_pub = *pub;
  for (unsigned int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_private_key_get_public (priv,
                                             pub);
    GNUNET_assert (0 ==
                   GNUNET_memcmp (&other_pub.point,
                                  &pub->point));
  }
}


static void
test_derive_rsecret (const struct GNUNET_CRYPTO_CsNonce *nonce,
                     const struct GNUNET_CRYPTO_CsPrivateKey *priv,
                     struct GNUNET_CRYPTO_CsRSecret r[2])
{
  /* TEST 1
   * Check that r are set
   */
  struct GNUNET_CRYPTO_CsPrivateKey other_r[2];

  memcpy (other_r,
          r,
          sizeof(struct GNUNET_CRYPTO_CsPrivateKey) * 2);
  GNUNET_CRYPTO_cs_r_derive (nonce,
                             "nw",
                             priv,
                             r);
  GNUNET_assert (0 !=
                 memcmp (&other_r[0],
                         &r[0],
                         sizeof(struct GNUNET_CRYPTO_CsPrivateKey) * 2));

  /* TEST 2
   * Check if function gives the same result for the same input.
   * This test ensures that the derivation is deterministic.
   */
  memcpy (other_r,
          r,
          sizeof(struct GNUNET_CRYPTO_CsPrivateKey) * 2);
  for (unsigned int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_r_derive (nonce,
                               "nw",
                               priv,
                               r);
    GNUNET_assert (0 ==
                   memcmp (other_r,
                           r,
                           sizeof(struct GNUNET_CRYPTO_CsPrivateKey) * 2));
  }
}


static void
test_generate_rpublic (const struct GNUNET_CRYPTO_CsRSecret *r_priv,
                       struct GNUNET_CRYPTO_CsRPublic *r_pub)
{
  /* TEST 1
   * Check that r_pub is set
   */
  struct GNUNET_CRYPTO_CsRPublic other_r_pub;

  other_r_pub = *r_pub;
  GNUNET_CRYPTO_cs_r_get_public (r_priv,
                                 r_pub);
  GNUNET_assert (0 !=
                 GNUNET_memcmp (&other_r_pub.point,
                                &r_pub->point));
  /* TEST 2
   * Check that r_pub is a valid point
   */
  GNUNET_assert (1 ==
                 crypto_core_ed25519_is_valid_point (r_pub->point.y));

  /* TEST 3
   * Check if function gives the same result for the same output
   */
  other_r_pub.point = r_pub->point;
  for (int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_r_get_public (r_priv,
                                   r_pub);
    GNUNET_assert (0 ==
                   GNUNET_memcmp (&other_r_pub.point,
                                  &r_pub->point));
  }
}


static void
test_derive_blindingsecrets (const struct GNUNET_CRYPTO_CsNonce *blind_seed,
                             struct GNUNET_CRYPTO_CsBlindingSecret bs[2])
{
  /* TEST 1
   * Check that blinding secrets are set
   */
  struct GNUNET_CRYPTO_CsBlindingSecret other_bs[2];

  memcpy (other_bs,
          bs,
          sizeof(struct GNUNET_CRYPTO_CsBlindingSecret) * 2);

  GNUNET_CRYPTO_cs_blinding_secrets_derive (blind_seed, bs);

  GNUNET_assert (0 !=
                 memcmp (other_bs,
                         bs,
                         sizeof(struct GNUNET_CRYPTO_CsBlindingSecret)
                         * 2));

  /* TEST 2
   * Check if function gives the same result for the same input.
   * This test ensures that the derivation is deterministic.
   */
  memcpy (other_bs,
          bs,
          sizeof(struct GNUNET_CRYPTO_CsBlindingSecret) * 2);
  for (unsigned int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_blinding_secrets_derive (blind_seed, bs);
    GNUNET_assert (0 == memcmp (&other_bs[0],
                                &bs[0],
                                sizeof(struct GNUNET_CRYPTO_CsBlindingSecret)
                                * 2));
  }
}


static void
test_calc_blindedc (const struct GNUNET_CRYPTO_CsBlindingSecret bs[2],
                    const struct GNUNET_CRYPTO_CsRPublic r_pub[2],
                    const struct GNUNET_CRYPTO_CsPublicKey *pub,
                    const void *msg,
                    size_t msg_len,
                    struct GNUNET_CRYPTO_CsC blinded_cs[2],
                    struct GNUNET_CRYPTO_CsRPublic blinded_r_pub[2])
{
  /* TEST 1
   * Check that the blinded c's and blinded r's
   */
  struct GNUNET_CRYPTO_CsC other_blinded_c[2];

  memcpy (&other_blinded_c[0],
          &blinded_cs[0],
          sizeof(struct GNUNET_CRYPTO_CsC) * 2);

  struct GNUNET_CRYPTO_CsRPublic other_blinded_r_pub[2];
  memcpy (&other_blinded_r_pub[0],
          &blinded_r_pub[0],
          sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2);

  GNUNET_CRYPTO_cs_calc_blinded_c (bs,
                                   r_pub,
                                   pub,
                                   msg,
                                   msg_len,
                                   blinded_cs,
                                   blinded_r_pub);

  GNUNET_assert (0 != memcmp (&other_blinded_c[0],
                              &blinded_cs[0],
                              sizeof(struct GNUNET_CRYPTO_CsC) * 2));
  GNUNET_assert (0 != memcmp (&other_blinded_r_pub[0],
                              &blinded_r_pub[0],
                              sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2));

  /* TEST 2
   * Check if R' - aG -bX = R for b = 0
   * This test does the opposite operations and checks whether the equation is still correct.
   */
  for (unsigned int b = 0; b <= 1; b++)
  {
    struct GNUNET_CRYPTO_Cs25519Point aG;
    struct GNUNET_CRYPTO_Cs25519Point bX;
    struct GNUNET_CRYPTO_Cs25519Point r_min_aG;
    struct GNUNET_CRYPTO_CsRPublic res;

    GNUNET_assert (0 == crypto_scalarmult_ed25519_base_noclamp (
                     aG.y,
                     bs[b].alpha.d));

    GNUNET_assert (0 == crypto_scalarmult_ed25519_noclamp (
                     bX.y,
                     bs[b].beta.d,
                     pub->point.y));

    GNUNET_assert (0 == crypto_core_ed25519_sub (
                     r_min_aG.y,
                     blinded_r_pub[b].point.y,
                     aG.y));

    GNUNET_assert (0 == crypto_core_ed25519_sub (
                     res.point.y,
                     r_min_aG.y,
                     bX.y));

    GNUNET_assert (0 == memcmp (&res, &r_pub[b], sizeof(struct
                                                        GNUNET_CRYPTO_CsRPublic)));
  }


  /* TEST 3
   * Check that the blinded r_pubs' are valid points
   */
  GNUNET_assert (1 == crypto_core_ed25519_is_valid_point (
                   blinded_r_pub[0].point.y));
  GNUNET_assert (1 == crypto_core_ed25519_is_valid_point (
                   blinded_r_pub[1].point.y));

  /* TEST 4
   * Check if function gives the same result for the same input.
   */
  memcpy (&other_blinded_c[0],
          &blinded_cs[0],
          sizeof(struct GNUNET_CRYPTO_CsC) * 2);
  memcpy (&other_blinded_r_pub[0],
          &blinded_r_pub[0],
          sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2);

  for (unsigned int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_calc_blinded_c (bs,
                                     r_pub,
                                     pub,
                                     msg,
                                     msg_len,
                                     blinded_cs,
                                     blinded_r_pub);
    GNUNET_assert (0 == memcmp (&other_blinded_c[0],
                                &blinded_cs[0],
                                sizeof(struct GNUNET_CRYPTO_CsC) * 2));
    GNUNET_assert (0 == memcmp (&other_blinded_r_pub[0],
                                &blinded_r_pub[0],
                                sizeof(struct GNUNET_CRYPTO_CsRPublic) * 2));
  }
}


static void
test_blind_sign (unsigned int *b,
                 const struct GNUNET_CRYPTO_CsPrivateKey *priv,
                 const struct GNUNET_CRYPTO_CsRSecret r[2],
                 const struct GNUNET_CRYPTO_CsC c[2],
                 const struct GNUNET_CRYPTO_CsNonce *nonce,
                 struct GNUNET_CRYPTO_CsBlindS *blinded_s)
{
  /* TEST 1
   * Check that blinded_s is set
   */
  struct GNUNET_CRYPTO_CsC other_blinded_s;
  memcpy (&other_blinded_s, blinded_s, sizeof(struct GNUNET_CRYPTO_CsBlindS));

  *b = GNUNET_CRYPTO_cs_sign_derive (priv,
                                     r,
                                     c,
                                     nonce,
                                     blinded_s);

  GNUNET_assert (0 == *b || 1 == *b);
  GNUNET_assert (0 != memcmp (&other_blinded_s,
                              blinded_s,
                              sizeof(struct GNUNET_CRYPTO_CsBlindS)));

  /* TEST 2
   * Check if s := rb + cbX
   * This test does the opposite operations and checks whether the equation is still correct.
   */
  struct GNUNET_CRYPTO_Cs25519Scalar cb_mul_x;
  struct GNUNET_CRYPTO_Cs25519Scalar s_min_rb;

  crypto_core_ed25519_scalar_mul (cb_mul_x.d,
                                  c[*b].scalar.d,
                                  priv->scalar.d);

  crypto_core_ed25519_scalar_sub (s_min_rb.d,
                                  blinded_s->scalar.d,
                                  r[*b].scalar.d);

  GNUNET_assert (0 == memcmp (&s_min_rb, &cb_mul_x, sizeof(struct
                                                           GNUNET_CRYPTO_Cs25519Scalar)));

  /* TEST 3
   * Check if function gives the same result for the same input.
   */
  memcpy (&other_blinded_s, blinded_s, sizeof(struct GNUNET_CRYPTO_CsBlindS));
  for (unsigned int i = 0; i<ITER; i++)
  {
    unsigned int other_b;

    other_b = GNUNET_CRYPTO_cs_sign_derive (priv, r, c, nonce, blinded_s);

    GNUNET_assert (other_b == *b);
    GNUNET_assert (0 == memcmp (&other_blinded_s,
                                blinded_s,
                                sizeof(struct GNUNET_CRYPTO_CsBlindS)));
  }
}


static void
test_unblinds (const struct GNUNET_CRYPTO_CsBlindS *blinded_signature_scalar,
               const struct GNUNET_CRYPTO_CsBlindingSecret *bs,
               struct GNUNET_CRYPTO_CsS *signature_scalar)
{
  /* TEST 1
   * Check that signature_scalar is set
   */
  struct GNUNET_CRYPTO_CsS other_signature_scalar;
  memcpy (&other_signature_scalar,
          signature_scalar,
          sizeof(struct GNUNET_CRYPTO_CsS));

  GNUNET_CRYPTO_cs_unblind (blinded_signature_scalar, bs, signature_scalar);

  GNUNET_assert (0 != memcmp (&other_signature_scalar,
                              signature_scalar,
                              sizeof(struct GNUNET_CRYPTO_CsS)));

  /* TEST 2
   * Check if s' := s + a mod p
   * This test does the opposite operations and checks whether the equation is still correct.
   */
  struct GNUNET_CRYPTO_Cs25519Scalar s_min_a;

  crypto_core_ed25519_scalar_sub (s_min_a.d,
                                  signature_scalar->scalar.d,
                                  bs->alpha.d);

  GNUNET_assert (0 == memcmp (&s_min_a, &blinded_signature_scalar->scalar,
                              sizeof(struct
                                     GNUNET_CRYPTO_Cs25519Scalar)));

  /* TEST 3
   * Check if function gives the same result for the same input.
   */
  memcpy (&other_signature_scalar, signature_scalar,
          sizeof(struct GNUNET_CRYPTO_CsS));

  for (unsigned int i = 0; i<ITER; i++)
  {
    GNUNET_CRYPTO_cs_unblind (blinded_signature_scalar, bs, signature_scalar);
    GNUNET_assert (0 == memcmp (&other_signature_scalar,
                                signature_scalar,
                                sizeof(struct GNUNET_CRYPTO_CsS)));
  }
}


static void
test_blind_verify (const struct GNUNET_CRYPTO_CsSignature *sig,
                   const struct GNUNET_CRYPTO_CsPublicKey *pub,
                   const struct GNUNET_CRYPTO_CsC *c)
{
  /* TEST 1
   * Test verifies the blinded signature sG == Rb + cbX
   */
  struct GNUNET_CRYPTO_Cs25519Point sig_scal_mul_base;
  GNUNET_assert (0 == crypto_scalarmult_ed25519_base_noclamp (
                   sig_scal_mul_base.y,
                   sig->s_scalar.scalar.d));

  struct GNUNET_CRYPTO_Cs25519Point c_mul_pub;
  GNUNET_assert (0 == crypto_scalarmult_ed25519_noclamp (c_mul_pub.y,
                                                         c->scalar.d,
                                                         pub->point.y));

  struct GNUNET_CRYPTO_Cs25519Point r_add_c_mul_pub;
  GNUNET_assert (0 == crypto_core_ed25519_add (r_add_c_mul_pub.y,
                                               sig->r_point.point.y,
                                               c_mul_pub.y));

  GNUNET_assert (0 == memcmp (sig_scal_mul_base.y,
                              r_add_c_mul_pub.y,
                              sizeof(struct GNUNET_CRYPTO_Cs25519Point)));
}


static void
test_verify (const struct GNUNET_CRYPTO_CsSignature *sig,
             const struct GNUNET_CRYPTO_CsPublicKey *pub,
             const void *msg,
             size_t msg_len)
{
  /* TEST 1
   * Test simple verification
   */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_cs_verify (sig,
                                          pub,
                                          msg,
                                          msg_len));
  /* TEST 2
   * Test verification of "wrong" message
   */
  char other_msg[] = "test massege";
  size_t other_msg_len = strlen ("test massege");
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_CRYPTO_cs_verify (sig,
                                          pub,
                                          other_msg,
                                          other_msg_len));
}


int
main (int argc,
      char *argv[])
{
  printf ("Test started\n");

  // ---------- actions performed by signer
  char message[] = "test message";
  size_t message_len = strlen ("test message");

  struct GNUNET_CRYPTO_CsPrivateKey priv;

  memset (&priv,
          42,
          sizeof (priv));
  test_create_priv (&priv);

  struct GNUNET_CRYPTO_CsPublicKey pub;

  memset (&pub,
          42,
          sizeof (pub));
  test_generate_pub (&priv,
                     &pub);

  // derive nonce
  struct GNUNET_CRYPTO_CsNonce nonce;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (nonce.nonce,
                                    sizeof(nonce.nonce),
                                    "nonce",
                                    strlen ("nonce"),
                                    "nonce_secret",
                                    strlen ("nonce_secret"),
                                    NULL,
                                    0));

  // generate r, R
  struct GNUNET_CRYPTO_CsRSecret r_secrets[2];

  memset (r_secrets,
          42,
          sizeof (r_secrets));
  test_derive_rsecret (&nonce,
                       &priv,
                       r_secrets);

  struct GNUNET_CRYPTO_CsRPublic r_publics[2];

  memset (r_publics,
          42,
          sizeof (r_publics));
  test_generate_rpublic (&r_secrets[0],
                         &r_publics[0]);
  test_generate_rpublic (&r_secrets[1],
                         &r_publics[1]);

  // ---------- actions performed by user

  // generate blinding secrets
  struct GNUNET_CRYPTO_CsBlindingSecret blindingsecrets[2];

  memset (blindingsecrets,
          42,
          sizeof (blindingsecrets));
  test_derive_blindingsecrets (&nonce,
                               blindingsecrets);

  // calculate blinded c's
  struct GNUNET_CRYPTO_CsC blinded_cs[2];
  struct GNUNET_CRYPTO_CsRPublic blinded_r_pubs[2];

  memset (blinded_cs,
          42,
          sizeof (blinded_cs));
  memset (blinded_r_pubs,
          42,
          sizeof (blinded_r_pubs));
  test_calc_blindedc (blindingsecrets,
                      r_publics,
                      &pub,
                      message,
                      message_len,
                      blinded_cs,
                      blinded_r_pubs);

  // ---------- actions performed by signer
  // sign blinded c's and get b and s in return
  unsigned int b;
  struct GNUNET_CRYPTO_CsBlindS blinded_s;

  memset (&blinded_s,
          42,
          sizeof (blinded_s));
  test_blind_sign (&b,
                   &priv,
                   r_secrets,
                   blinded_cs,
                   &nonce,
                   &blinded_s);

  // verify blinded signature
  struct GNUNET_CRYPTO_CsSignature blinded_signature;

  blinded_signature.r_point = r_publics[b];
  blinded_signature.s_scalar.scalar = blinded_s.scalar;
  test_blind_verify (&blinded_signature,
                     &pub,
                     &blinded_cs[b]);

  // ---------- actions performed by user
  struct GNUNET_CRYPTO_CsS sig_scalar;

  memset (&sig_scalar,
          42,
          sizeof (sig_scalar));
  test_unblinds (&blinded_s,
                 &blindingsecrets[b],
                 &sig_scalar);

  // verify unblinded signature
  struct GNUNET_CRYPTO_CsSignature signature;
  signature.r_point = blinded_r_pubs[b];
  signature.s_scalar = sig_scalar;
  test_verify (&signature,
               &pub,
               message,
               message_len);
  return 0;
}
