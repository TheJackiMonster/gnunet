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
 * @file util/perf_crypto_ecc_dlog.c
 * @brief benchmark for ECC DLOG calculation
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
 * Maximum value we benchmark dlog for.
 */
#define MAX_FACT (1024 * 1024)

/**
 * Maximum memory to use, sqrt(MAX_FACT) is a good choice.
 */
#define MAX_MEM 1024

/**
 * How many values do we test?
 */
#define TEST_ITER 10


/**
 * Do some DLOG operations for testing.
 *
 * @param edc context for ECC operations
 * @param do_dlog true if we want to actually do the bencharked operation
 */
static void
test_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc,
           bool do_dlog)
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
    if (do_dlog)
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


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative delta;

  GNUNET_log_setup ("perf-crypto-ecc-dlog",
                    "WARNING",
                    NULL);
  start = GNUNET_TIME_absolute_get ();
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (MAX_FACT,
                                        MAX_MEM);
  printf ("DLOG precomputation 1M/1K took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  start = GNUNET_TIME_absolute_get ();
  /* first do a baseline run without the DLOG */
  test_dlog (edc, false);
  delta = GNUNET_TIME_absolute_get_duration (start);
  start = GNUNET_TIME_absolute_get ();
  test_dlog (edc, true);
  delta = GNUNET_TIME_relative_subtract (GNUNET_TIME_absolute_get_duration (
                                           start),
                                         delta);
  printf ("%u DLOG calculations took %s\n",
          TEST_ITER,
          GNUNET_STRINGS_relative_time_to_string (delta,
                                                  GNUNET_YES));
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}


/* end of perf_crypto_ecc_dlog.c */
