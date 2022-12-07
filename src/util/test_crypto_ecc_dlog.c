/*
     This file is part of GNUnet.
     Copyright (C) 2015 GNUnet e.V.

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
 * @file util/test_crypto_ecc_dlog.c
 * @brief testcase for ECC DLOG calculation
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"

/**
 * Maximum value we test dlog for.
 */
#define MAX_FACT 100

/**
 * Maximum memory to use, sqrt(MAX_FACT) is a good choice.
 */
#define MAX_MEM 10

/**
 * How many values do we test?
 */
#define TEST_ITER 100

/**
 * Range of values to use for MATH tests.
 */
#define MATH_MAX 5


/**
 * Do some DLOG operations for testing.
 *
 * @param edc context for ECC operations
 */
static void
test_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  for (unsigned int i = 0; i < TEST_ITER; i++)
  {
    struct GNUNET_CRYPTO_EccScalar fact;
    struct GNUNET_CRYPTO_EccScalar n;
    struct GNUNET_CRYPTO_EccPoint q;
    int x;

    fprintf (stderr, ".");
    x = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  MAX_FACT);
    memset (&n,
            0,
            sizeof (n));
    for (unsigned int j = 0; j < x; j++)
      sodium_increment (n.v,
                        sizeof (n.v));
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       2))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Trying negative %d\n",
                  -x);
      crypto_core_ed25519_scalar_negate (fact.v,
                                         n.v);
      x = -x;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Trying positive %d\n",
                  x);
      fact = n;
    }
    if (0 == x)
    {
      /* libsodium does not like to multiply with zero; make sure
         'q' is a valid point (g) first, then use q = q - q to get
         the product with zero */
      sodium_increment (fact.v,
                        sizeof (fact.v));
      GNUNET_assert (0 ==
                     crypto_scalarmult_ed25519_base_noclamp (q.v,
                                                             fact.v));
      GNUNET_assert (
        0 ==
        crypto_core_ed25519_sub (q.v,
                                 q.v,
                                 q.v));
    }
    else
      GNUNET_assert (0 ==
                     crypto_scalarmult_ed25519_base_noclamp (q.v,
                                                             fact.v));
    {
      int iret;

      if (x !=
          (iret = GNUNET_CRYPTO_ecc_dlog (edc,
                                          &q)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "DLOG failed for value %d (got: %d)\n",
                    x,
                    iret);
        GNUNET_assert (0);
      }
    }
  }
  fprintf (stderr,
           "\n");
}


/**
 * Do some arithmetic operations for testing.
 *
 * @param edc context for ECC operations
 */
static void
test_math (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  int i;
  int j;
  struct GNUNET_CRYPTO_EccPoint ip;
  struct GNUNET_CRYPTO_EccPoint jp;
  struct GNUNET_CRYPTO_EccPoint r;
  struct GNUNET_CRYPTO_EccPoint ir;
  struct GNUNET_CRYPTO_EccPoint irj;
  struct GNUNET_CRYPTO_EccPoint r_inv;
  struct GNUNET_CRYPTO_EccPoint sum;

  for (i = -MATH_MAX; i < MATH_MAX; i++)
  {
    GNUNET_CRYPTO_ecc_dexp (i, &ip);
    for (j = -MATH_MAX; j < MATH_MAX; j++)
    {
      fprintf (stderr, ".");
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%d + %d\n",
                  i,
                  j);
      GNUNET_CRYPTO_ecc_dexp (j, &jp);
      GNUNET_CRYPTO_ecc_rnd (&r,
                             &r_inv);
      GNUNET_CRYPTO_ecc_add (&ip, &r, &ir);
      GNUNET_CRYPTO_ecc_add (&ir, &jp, &irj);
      GNUNET_CRYPTO_ecc_add (&irj, &r_inv, &sum);
      int res = GNUNET_CRYPTO_ecc_dlog (edc, &sum);
      if (i + j != res)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Got %d, expected %d\n",
                    res,
                    i + j);
        // GNUNET_assert (0);
      }
    }
  }
  fprintf (stderr, "\n");
}


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;

  if (! gcry_check_version ("1.6.0"))
  {
    fprintf (stderr,
             _
             (
               "libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  GNUNET_log_setup ("test-crypto-ecc-dlog",
                    "WARNING",
                    NULL);
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (MAX_FACT,
                                        MAX_MEM);
  test_dlog (edc);
  test_math (edc);
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}


/* end of test_crypto_ecc_dlog.c */
