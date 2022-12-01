/*
     This file is part of GNUnet.
     Copyright (C) 2014 GNUnet e.V.

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
 * @author Lucien Heuzeveldt <lucienclaude.heuzeveldt@students.bfh.ch>
 * @author Gian Demarmels <gian@demarmels.org>
 * @file util/perf_crypto_cs.c
 * @brief measure performance of Clause Blind Schnorr Signatures
 */


#include "gnunet_util_lib.h"
#include <gauger.h>

#define ITER 10

/**
 * Evaluate Clause Blind Schnorr Signature performance.
 *
 */
static void
eval ()
{
  struct GNUNET_TIME_Absolute start;
  unsigned int i;

  struct GNUNET_CRYPTO_CsPrivateKey priv;
  struct GNUNET_CRYPTO_CsPublicKey pub;

  struct GNUNET_CRYPTO_CsRSecret r_priv[2];
  struct GNUNET_CRYPTO_CsRPublic r_pub[2];

  char message[] = "test message";
  size_t message_len = strlen ("test message");

  // derive a test nonce
  struct GNUNET_CRYPTO_CsNonce nonce;
  GNUNET_assert (GNUNET_YES == GNUNET_CRYPTO_hkdf (nonce.nonce,
                                                   sizeof(nonce.nonce),
                                                   GCRY_MD_SHA512,
                                                   GCRY_MD_SHA256,
                                                   "nonce",
                                                   strlen ("nonce"),
                                                   "nonce_secret",
                                                   strlen ("nonce_secret"),
                                                   NULL,
                                                   0));

  struct GNUNET_CRYPTO_CsBlindingSecret bs[2];
  struct GNUNET_CRYPTO_CsC blinded_cs[2];
  struct GNUNET_CRYPTO_CsRPublic blinded_r_pub[2];
  struct GNUNET_CRYPTO_CsBlindS blinded_s;
  struct GNUNET_CRYPTO_CsS signature_scalar;
  struct GNUNET_CRYPTO_CsSignature sig;

  // BENCHMARK keygen
  start = GNUNET_TIME_absolute_get ();

  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_private_key_generate (&priv);
    GNUNET_CRYPTO_cs_private_key_get_public (&priv, &pub);
  }
  printf ("10x key generation took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));


  // BENCHMARK r derive and calc R pub
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_r_derive (&nonce, &priv, r_priv);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv[0], &r_pub[0]);
    GNUNET_CRYPTO_cs_r_get_public (&r_priv[1], &r_pub[1]);
  }
  printf ("10x r0, r1 derive and R1,R2 calculation took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));


  // BENCHMARK derive blinding secrets
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_blinding_secrets_derive (&nonce,
                                              bs);
  }
  printf ("10x derive blinding secrets took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));


  // BENCHMARK calculating C
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_calc_blinded_c (bs,
                                     r_pub,
                                     &pub,
                                     message,
                                     message_len,
                                     blinded_cs,
                                     blinded_r_pub);
  }
  printf ("10x calculating the blinded c took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));


  // BENCHMARK sign derive
  unsigned int b;
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    b = GNUNET_CRYPTO_cs_sign_derive (&priv,
                                      r_priv,
                                      blinded_cs,
                                      &nonce,
                                      &blinded_s);
  }
  printf ("10x signing blinded c took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));


  // BENCHMARK unblind signature
  start = GNUNET_TIME_absolute_get ();

  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_unblind (&blinded_s, &bs[b], &signature_scalar);
    sig.r_point = blinded_r_pub[b];
    sig.s_scalar = signature_scalar;
  }
  printf ("10x unblinding s took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));

  // BENCHMARK verify signature
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    GNUNET_CRYPTO_cs_verify (&sig,
                             &pub,
                             message,
                             message_len);
  }
  printf ("10x verifying signatures took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
}

int
main (int argc, char *argv[])
{
  eval ();
  return 0;
}
