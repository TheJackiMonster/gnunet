/*
     This file is part of GNUnet.
     Copyright (C) 2010 GNUnet e.V.

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
 * @file src/util/crypto_kdf.c
 * @brief Key derivation
 * @author Nils Durner
 * @author Jeffrey Burdges <burdges@gnunet.org>
 */

#include "platform.h"
#include <gcrypt.h>


#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-kdf", __VA_ARGS__)


void
GNUNET_CRYPTO_kdf_mod_mpi (gcry_mpi_t *r,
                           gcry_mpi_t n,
                           const void *xts, size_t xts_len,
                           const void *skm, size_t skm_len,
                           const char *ctx)
{
  gcry_error_t rc;
  unsigned int nbits;
  size_t rsize;
  uint16_t ctr;

  nbits = gcry_mpi_get_nbits (n);
  /* GNUNET_assert (nbits > 512); */
  ctr = 0;
  while (1)
  {
    /* Ain't clear if n is always divisible by 8 */
    size_t bsize = (nbits - 1) / 8 + 1;
    uint8_t buf[bsize];
    uint16_t ctr_nbo = htons (ctr);

    rc = GNUNET_CRYPTO_hkdf_gnunet (buf,
                                    bsize,
                                    xts, xts_len,
                                    skm, skm_len,
                                    GNUNET_CRYPTO_kdf_arg_string (ctx),
                                    GNUNET_CRYPTO_kdf_arg_auto (&ctr_nbo))
    ;
    GNUNET_assert (GNUNET_YES == rc);
    rc = gcry_mpi_scan (r,
                        GCRYMPI_FMT_USG,
                        (const unsigned char *) buf,
                        bsize,
                        &rsize);
    GNUNET_assert (GPG_ERR_NO_ERROR == rc);  /* Allocation error? */
    GNUNET_assert (rsize == bsize);
    gcry_mpi_clear_highbit (*r,
                            nbits);
    GNUNET_assert (0 ==
                   gcry_mpi_test_bit (*r,
                                      nbits));
    ++ctr;
    /* We reject this FDH if either *r > n and retry with another ctr */
    if (0 > gcry_mpi_cmp (*r, n))
      break;
    gcry_mpi_release (*r);
  }
}


/* end of crypto_kdf.c */
