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
 * @file util/test_ecc_scalarproduct.c
 * @brief testcase for math behind ECC SP calculation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

/**
 * Global context.
 */
static struct GNUNET_CRYPTO_EccDlogContext *edc;


/**
 * Perform SP calculation.
 *
 * @param avec 0-terminated vector of Alice's values
 * @param bvec 0-terminated vector of Bob's values
 * @return avec * bvec
 */
static int
test_sp (const unsigned int *avec,
         const unsigned int *bvec)
{
  unsigned int len;
  struct GNUNET_CRYPTO_EccScalar a;
  struct GNUNET_CRYPTO_EccScalar a_neg;
  struct GNUNET_CRYPTO_EccPoint *g;
  struct GNUNET_CRYPTO_EccPoint *h;
  struct GNUNET_CRYPTO_EccPoint pg;
  struct GNUNET_CRYPTO_EccPoint ph;

  /* determine length */
  for (len = 0; 0 != avec[len]; len++)
    ;
  if (0 == len)
    return 0;

  /* Alice */
  GNUNET_CRYPTO_ecc_rnd_mpi (&a,
                             &a_neg);
  g = GNUNET_new_array (len,
                        struct GNUNET_CRYPTO_EccPoint);
  h = GNUNET_new_array (len,
                        struct GNUNET_CRYPTO_EccPoint);
  for (unsigned int i = 0; i < len; i++)
  {
    struct GNUNET_CRYPTO_EccScalar tmp;
    struct GNUNET_CRYPTO_EccScalar ri;
    struct GNUNET_CRYPTO_EccScalar ria;

    GNUNET_CRYPTO_ecc_random_mod_n (&ri);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_dexp_mpi (&ri,
                                               &g[i]));
    /* ria = ri * a mod L, where L is the order of the main subgroup */
    crypto_core_ed25519_scalar_mul (ria.v,
                                    ri.v,
                                    a.v);
    /* tmp = ria + avec[i] */
    {
      int64_t val = avec[i];
      struct GNUNET_CRYPTO_EccScalar vali;

      GNUNET_assert (INT64_MIN != val);
      GNUNET_CRYPTO_ecc_scalar_from_int (val > 0 ? val : -val,
                                         &vali);
      if (val > 0)
        crypto_core_ed25519_scalar_add (tmp.v,
                                        ria.v,
                                        vali.v);
      else
        crypto_core_ed25519_scalar_sub (tmp.v,
                                        ria.v,
                                        vali.v);
    }
    /* h[i] = g^tmp = g^{ria + avec[i]} */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_dexp_mpi (&tmp,
                                               &h[i]));
  }

  /* Bob */
  for (unsigned int i = 0; i < len; i++)
  {
    struct GNUNET_CRYPTO_EccPoint gm;
    struct GNUNET_CRYPTO_EccPoint hm;

    {
      int64_t val = bvec[i];
      struct GNUNET_CRYPTO_EccScalar vali;

      GNUNET_assert (INT64_MIN != val);
      GNUNET_CRYPTO_ecc_scalar_from_int (val > 0 ? val : -val,
                                         &vali);
      if (val < 0)
        crypto_core_ed25519_scalar_negate (vali.v,
                                           vali.v);
      /* gm = g[i]^vali */
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CRYPTO_ecc_pmul_mpi (&g[i],
                                                 &vali,
                                                 &gm));
      /* hm = h[i]^vali */
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CRYPTO_ecc_pmul_mpi (&h[i],
                                                 &vali,
                                                 &hm));
    }
    if (0 != i)
    {
      /* pg += gm */
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CRYPTO_ecc_add (&gm,
                                            &pg,
                                            &pg));
      /* ph += hm */
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CRYPTO_ecc_add (&hm,
                                            &ph,
                                            &ph));
    }
    else
    {
      pg = gm;
      ph = hm;
    }
  }
  GNUNET_free (g);
  GNUNET_free (h);

  /* Alice */
  {
    struct GNUNET_CRYPTO_EccPoint pgi;
    struct GNUNET_CRYPTO_EccPoint gsp;

    /* pgi = pg^inv */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_pmul_mpi (&pg,
                                               &a_neg,
                                               &pgi));
    /* gsp = pgi + ph */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecc_add (&pgi,
                                          &ph,
                                          &gsp));
    return GNUNET_CRYPTO_ecc_dlog (edc,
                                   &gsp);
  }
}


/**
 * Macro that checks that @a want is equal to @a have and
 * if not returns with a failure code.
 */
#define CHECK(want,have) do { \
    if (want != have) {         \
      GNUNET_break (0);         \
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, \
                  "Wanted %d, got %d\n", want, have);   \
      GNUNET_CRYPTO_ecc_dlog_release (edc); \
      return 1; \
    } } while (0)


int
main (int argc, char *argv[])
{
  static unsigned int v11[] = { 1, 1, 0 };
  static unsigned int v22[] = { 2, 2, 0 };
  static unsigned int v35[] = { 3, 5, 0 };
  static unsigned int v24[] = { 2, 4, 0 };

  GNUNET_log_setup ("test-ecc-scalarproduct",
                    "WARNING",
                    NULL);
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (128, 128);
  CHECK (2, test_sp (v11, v11));
  CHECK (4, test_sp (v22, v11));
  CHECK (8, test_sp (v35, v11));
  CHECK (26, test_sp (v35, v24));
  CHECK (26, test_sp (v24, v35));
  CHECK (16, test_sp (v22, v35));
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}


/* end of test_ecc_scalarproduct.c */
