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
 * @author Christian Grothoff
 * @file util/perf_crypto_rsa.c
 * @brief measure performance of RSA signing
 */

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Evaluate RSA performance.
 *
 * @param len keylength to evaluate with
 */
static void
eval (unsigned int len)
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignature *rsig;
  struct GNUNET_CRYPTO_RsaPublicKey *public_key;
  struct GNUNET_CRYPTO_RsaPrivateKey *private_key;
  struct GNUNET_CRYPTO_RsaBlindingKeySecret bsec[10];
  unsigned int i;
  char sbuf[128];
  struct GNUNET_HashCode hc;
  struct GNUNET_CRYPTO_RsaBlindedMessage bm;

  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < 10; i++)
  {
    private_key = GNUNET_CRYPTO_rsa_private_key_create (len);
    GNUNET_CRYPTO_rsa_private_key_free (private_key);
  }
  printf ("10x %u-key generation took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GNUNET_snprintf (sbuf,
                   sizeof(sbuf),
                   "RSA %u-key generation",
                   len);
  private_key = GNUNET_CRYPTO_rsa_private_key_create (len);
  public_key = GNUNET_CRYPTO_rsa_private_key_get_public (private_key);
  for (i = 0; i < 10; i++)
    GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                                &bsec[i], sizeof(bsec[0]));
  /*
     start = GNUNET_TIME_absolute_get ();
     for (i=0;i<10;i++)
     rsa_blinding_key_derive(public_key, &bsec[i]);
     printf ("10x %u-blinding key generation took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
                                                  GNUNET_YES));
     GNUNET_snprintf (sbuf,
                   sizeof (sbuf),
                   "RSA %u-blinding key generation",
                   len);
     GAUGER ("UTIL", sbuf,
          64 * 1024 / (1 +
                       GNUNET_TIME_absolute_get_duration
                       (start).rel_value_us / 1000LL), "keys/ms");
   */
  start = GNUNET_TIME_absolute_get ();
  GNUNET_CRYPTO_hash ("test", 4, &hc);
  for (i = 0; i < 10; i++)
  {
    GNUNET_CRYPTO_rsa_blind (&hc,
                             sizeof (hc),
                             &bsec[i],
                             public_key,
                             &bm);
    GNUNET_CRYPTO_rsa_blinded_message_free (&bm);
  }
  printf ("10x %u-blinding took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            true));
  GNUNET_snprintf (sbuf,
                   sizeof(sbuf),
                   "RSA %u-blinding",
                   len);
  GNUNET_CRYPTO_rsa_blind (&hc,
                           sizeof (hc),
                           &bsec[0],
                           public_key,
                           &bm);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < 10; i++)
  {
    sig = GNUNET_CRYPTO_rsa_sign_blinded (private_key,
                                          &bm);
    GNUNET_CRYPTO_rsa_signature_free (sig);
  }
  printf ("10x %u-signing took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GNUNET_snprintf (sbuf,
                   sizeof(sbuf),
                   "RSA %u-signing",
                   len);
  sig = GNUNET_CRYPTO_rsa_sign_blinded (private_key,
                                        &bm);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < 10; i++)
  {
    rsig = GNUNET_CRYPTO_rsa_unblind (sig,
                                      &bsec[0],
                                      public_key);
    GNUNET_CRYPTO_rsa_signature_free (rsig);
  }
  printf ("10x %u-unblinding took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            true));
  GNUNET_snprintf (sbuf,
                   sizeof(sbuf),
                   "RSA %u-unblinding",
                   len);
  rsig = GNUNET_CRYPTO_rsa_unblind (sig,
                                    &bsec[0],
                                    public_key);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < 10; i++)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_verify (&hc,
                                             sizeof (hc),
                                             rsig,
                                             public_key));
  }
  printf ("10x %u-verifying took %s\n",
          len,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GNUNET_snprintf (sbuf,
                   sizeof(sbuf),
                   "RSA %u-verification",
                   len);
  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_public_key_free (public_key);
  GNUNET_CRYPTO_rsa_private_key_free (private_key);
  GNUNET_CRYPTO_rsa_blinded_message_free (&bm);
}


int
main (int argc, char *argv[])
{
  eval (1024);
  eval (2048);
  eval (3072);
  eval (4096);
  return 0;
}


/* end of perf_crypto_rsa.c */
