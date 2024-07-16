/*
     This file is part of GNUnet.
     Copyright (C) 2024 GNUnet e.V.

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
 * @file util/test_crypto_kem.c
 * @brief testcase for KEMs including RFC9180 DHKEM
 * @author Martin Schanzenbach
 */

#include "gnunet_common.h"
#include "platform.h"
#include "gnunet_util_lib.h"

static char *rfc9180_a1_skEm_str =
  "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
static char *rfc9180_a1_skRm_str =
  "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
static char *rfc9180_a1_enc_str =
  "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
static char *rfc9180_a1_shared_secret_str =
  "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";




static int
parsehex (char *src, char *dst, size_t dstlen, int invert)
{
  char *line = src;
  char *data = line;
  int off;
  int read_byte;
  int data_len = 0;

  while (sscanf (data, " %02x%n", &read_byte, &off) == 1)
  {
    if (invert)
      dst[dstlen - 1 - data_len++] = read_byte;
    else
      dst[data_len++] = read_byte;
    data += off;
  }
  return data_len;
}


static void
print_bytes_ (void *buf,
              size_t buf_len,
              int fold,
              int in_be)
{
  int i;

  for (i = 0; i < buf_len; i++)
  {
    if (0 != i)
    {
      if ((0 != fold) && (i % fold == 0))
        printf ("\n  ");
      else
        printf (" ");
    }
    else
    {
      printf ("  ");
    }
    if (in_be)
      printf ("%02x", ((unsigned char*) buf)[buf_len - 1 - i]);
    else
      printf ("%02x", ((unsigned char*) buf)[i]);
  }
  printf ("\n");
}


static void
print_bytes (void *buf,
             size_t buf_len,
             int fold)
{
  print_bytes_ (buf, buf_len, fold, 0);
}

int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a1_skEm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a1_pkEm;
  struct GNUNET_CRYPTO_EcdhePrivateKey rfc9180_a1_skRm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a1_pkRm;
  struct GNUNET_CRYPTO_EcdhePublicKey rfc9180_a1_enc;
  struct GNUNET_CRYPTO_EcdhePublicKey enc;
  struct GNUNET_ShortHashCode rfc9180_a1_shared_secret;
  struct GNUNET_ShortHashCode shared_secret;

  GNUNET_log_setup ("test-crypto-kem", "WARNING", NULL);

  parsehex (rfc9180_a1_skEm_str,
            (char*)&rfc9180_a1_skEm.d,
            sizeof rfc9180_a1_skEm, 0);
  parsehex (rfc9180_a1_skRm_str,
            (char*)&rfc9180_a1_skRm.d,
            sizeof rfc9180_a1_skRm, 0);
  parsehex (rfc9180_a1_enc_str,
            (char*)&rfc9180_a1_enc,
            sizeof rfc9180_a1_enc, 0);
  parsehex (rfc9180_a1_shared_secret_str,
            (char*)&rfc9180_a1_shared_secret,
            sizeof rfc9180_a1_shared_secret, 0);
  GNUNET_CRYPTO_ecdhe_key_get_public(&rfc9180_a1_skEm, &rfc9180_a1_pkEm);
  GNUNET_CRYPTO_ecdhe_key_get_public(&rfc9180_a1_skRm, &rfc9180_a1_pkRm);
  printf ("pkRm: ");
  print_bytes(&rfc9180_a1_pkRm, sizeof rfc9180_a1_pkRm, 0);
  printf ("\n");
  printf ("pkEm: ");
  print_bytes(&rfc9180_a1_pkEm, sizeof rfc9180_a1_pkEm, 0);
  printf ("\n");
  GNUNET_CRYPTO_kem_encaps_norand(&rfc9180_a1_pkRm, &enc, &rfc9180_a1_skEm, &shared_secret);
  GNUNET_assert (0 == GNUNET_memcmp(&enc, &rfc9180_a1_enc));
  printf ("enc: ");
  print_bytes(&enc, sizeof enc, 0);
  printf ("\n");
  printf ("shared_secret: ");
  print_bytes(&shared_secret, sizeof shared_secret, 0);
  GNUNET_assert (0 == GNUNET_memcmp(&shared_secret, &rfc9180_a1_shared_secret));
  printf ("\n");
  return 0;
}


/* end of test_crypto_kem.c */
