/*
     This file is part of GNUnet.
     Copyright (C) 2002-2013 GNUnet e.V.

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
 * @file util/test_crypto_eddsa.c
 * @brief testcase for ECC public key crypto
 * @author Christian Grothoff
 */

#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include <gcrypt.h>

#define ITER 25

#define KEYFILE "/tmp/test-gnunet-crypto-eddsa.key"

#define PERF GNUNET_YES


static struct GNUNET_CRYPTO_EddsaPrivateKey key;


static int
testSignVerify (void)
{
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EddsaPublicKey pkey;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  fprintf (stderr, "%s", "W");
  GNUNET_CRYPTO_eddsa_key_get_public (&key,
                                      &pkey);
  start = GNUNET_TIME_absolute_get ();
  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", "."); fflush (stderr);
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_sign_ (&key,
                                                    &purp,
                                                    &sig))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_eddsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_eddsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                     &purp,
                                     &sig,
                                     &pkey))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_eddsa_verify failed!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR !=
        GNUNET_CRYPTO_eddsa_verify_ (
          GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
          &purp,
          &sig,
          &pkey))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_eddsa_verify failed to fail!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  fprintf (stderr, "\n");
  printf ("%d EdDSA sign/verify operations %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


static int
testDeriveSignVerify (void)
{
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EddsaPrivateScalar dpriv;
  struct GNUNET_CRYPTO_EddsaPublicKey pkey;
  struct GNUNET_CRYPTO_EddsaPublicKey dpub;
  struct GNUNET_CRYPTO_EddsaPublicKey dpub2;

  GNUNET_CRYPTO_eddsa_private_key_derive (&key,
                                          "test-derive",
                                          "test-CTX",
                                          &dpriv);
  GNUNET_CRYPTO_eddsa_key_get_public (&key,
                                      &pkey);
  GNUNET_CRYPTO_eddsa_public_key_derive (&pkey,
                                         "test-derive",
                                         "test-CTX",
                                         &dpub);
  GNUNET_CRYPTO_eddsa_key_get_public_from_scalar (&dpriv, &dpub2);
  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  if (0 != GNUNET_memcmp (&dpub.q_y, &dpub2.q_y))
  {
    fprintf (stderr, "%s", "key derivation failed\n");
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_eddsa_sign_derived (&key,
                                    "test-derive",
                                    "test-CTX",
                                    &purp,
                                    &sig);
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_eddsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                   &purp,
                                   &sig,
                                   &dpub))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_eddsa_verify failed!\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR !=
      GNUNET_CRYPTO_eddsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                   &purp,
                                   &sig,
                                   &pkey))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_eddsa_verify failed to fail!\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR !=
      GNUNET_CRYPTO_eddsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                   &purp,
                                   &sig,
                                   &dpub))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_eddsa_verify failed to fail!\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


#if PERF
static int
testSignPerformance ()
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_CRYPTO_EddsaPublicKey pkey;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  fprintf (stderr, "%s", "W");
  GNUNET_CRYPTO_eddsa_key_get_public (&key,
                                      &pkey);
  start = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", ".");
    fflush (stderr);
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_eddsa_sign_ (&key,
                                   &purp,
                                   &sig))
    {
      fprintf (stderr, "%s", "GNUNET_CRYPTO_eddsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  fprintf (stderr, "\n");
  printf ("%d EdDSA sign operations %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


#endif


static int
testCreateFromFile (void)
{
  struct GNUNET_CRYPTO_EddsaPublicKey p1;
  struct GNUNET_CRYPTO_EddsaPublicKey p2;

  /* do_create == GNUNET_YES and non-existing file MUST return GNUNET_YES */
  GNUNET_assert (0 == unlink (KEYFILE) || ENOENT == errno);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_eddsa_key_from_file (KEYFILE,
                                                    GNUNET_YES,
                                                    &key));
  GNUNET_CRYPTO_eddsa_key_get_public (&key,
                                      &p1);

  /* do_create == GNUNET_YES and _existing_ file MUST return GNUNET_NO */
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_CRYPTO_eddsa_key_from_file (KEYFILE,
                                                    GNUNET_YES,
                                                    &key));
  GNUNET_CRYPTO_eddsa_key_get_public (&key,
                                      &p2);
  GNUNET_assert (0 ==
                 GNUNET_memcmp (&p1,
                                &p2));

  /* do_create == GNUNET_NO and non-existing file MUST return GNUNET_SYSERR */
  GNUNET_assert (0 == unlink (KEYFILE));
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_CRYPTO_eddsa_key_from_file (KEYFILE,
                                                    GNUNET_NO,
                                                    &key));
  return GNUNET_OK;
}


static void
perf_keygen (void)
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CRYPTO_EddsaPrivateKey pk;

  fprintf (stderr, "%s", "W");
  start = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < 10; i++)
  {
    fprintf (stderr, ".");
    fflush (stderr);
    GNUNET_CRYPTO_eddsa_key_create (&pk);
  }
  fprintf (stderr, "\n");
  printf ("10 EdDSA keys created in %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start), GNUNET_YES));
}


int
main (int argc, char *argv[])
{
  int failure_count = 0;

  if (! gcry_check_version ("1.6.0"))
  {
    fprintf (stderr,
             "libgcrypt has not the expected version (version %s is required).\n",
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  GNUNET_log_setup ("test-crypto-eddsa",
                    "WARNING",
                    NULL);
  GNUNET_CRYPTO_eddsa_key_create (&key);
  if (GNUNET_OK != testDeriveSignVerify ())
  {
    failure_count++;
    fprintf (stderr,
             "\n\n%d TESTS FAILED!\n\n", failure_count);
    return -1;
  }
#if PERF
  if (GNUNET_OK != testSignPerformance ())
    failure_count++;
#endif
  if (GNUNET_OK != testSignVerify ())
    failure_count++;
  if (GNUNET_OK != testCreateFromFile ())
    failure_count++;
  perf_keygen ();

  if (0 != failure_count)
  {
    fprintf (stderr,
             "\n\n%d TESTS FAILED!\n\n",
             failure_count);
    return -1;
  }
  return 0;
}


/* end of test_crypto_eddsa.c */
