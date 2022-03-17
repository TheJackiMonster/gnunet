/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

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
 * @file util/gnunet-revocation-tvg.c
 * @brief Generate test vectors for revocation.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_revocation_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include "revocation.h"
#include <inttypes.h>

#define TEST_EPOCHS 2
#define TEST_DIFFICULTY 5

static char* d_pkey =
"6fea32c05af58bfa979553d188605fd57d8bf9cc263b78d5f7478c07b998ed70";

int parsehex(char *src, char *dst, size_t dstlen, int invert)
{
  char *line = src;
  char *data = line;
  int off;
  int read_byte;
  int data_len = 0;

  while (sscanf(data, " %02x%n", &read_byte, &off) == 1) {
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
    if ((0 != i) && (0 != fold) && (i % fold == 0))
      printf ("\n");
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



/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_IDENTITY_PrivateKey id_priv;
  struct GNUNET_IDENTITY_PublicKey id_pub;
  struct GNUNET_REVOCATION_PowP *pow;
  struct GNUNET_REVOCATION_PowCalculationHandle *ph;
  struct GNUNET_TIME_Relative exp;
  char ztld[128];

  id_priv.type = htonl (GNUNET_IDENTITY_TYPE_ECDSA);
  GNUNET_CRYPTO_ecdsa_key_create (&id_priv.ecdsa_key);
  parsehex(d_pkey,(char*)&id_priv.ecdsa_key, sizeof (id_priv.ecdsa_key), 1);
  GNUNET_IDENTITY_key_get_public (&id_priv,
                                  &id_pub);
  GNUNET_STRINGS_data_to_string (&id_pub,
                                 GNUNET_IDENTITY_key_get_length (&id_pub),
                                 ztld,
                                 sizeof (ztld));
  fprintf (stdout, "Zone private key (d, big-endian scalar):\n");
  print_bytes_ (&id_priv.ecdsa_key, sizeof(id_priv.ecdsa_key), 8, 1);
  fprintf (stdout, "\n");
  fprintf (stdout, "Zone identifier (ztype|zkey):\n");
  print_bytes (&id_pub, GNUNET_IDENTITY_key_get_length (&id_pub), 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "Encoded zone identifier (zkl = zTLD):\n");
  fprintf (stdout, "%s\n", ztld);
  fprintf (stdout, "\n");
  pow = GNUNET_malloc (GNUNET_REVOCATION_MAX_PROOF_SIZE);
  GNUNET_REVOCATION_pow_init (&id_priv,
                              pow);
  ph = GNUNET_REVOCATION_pow_start (pow,
                                    TEST_EPOCHS,
                                    TEST_DIFFICULTY);
  fprintf (stdout, "Difficulty (%d base difficulty + %d epochs): %d\n\n",
           TEST_DIFFICULTY,
           TEST_EPOCHS,
           TEST_DIFFICULTY + TEST_EPOCHS);
  uint64_t pow_passes = 0;
  while (GNUNET_YES != GNUNET_REVOCATION_pow_round (ph))
  {
    pow_passes++;
  }
  struct GNUNET_REVOCATION_SignaturePurposePS *purp;
  purp = REV_create_signature_message (pow);
  fprintf (stdout, "Signed message:\n");
  print_bytes (purp,
               ntohl (purp->purpose.size),
               8);
  printf ("\n");
  GNUNET_free (purp);

  exp = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS,
                                       TEST_EPOCHS);
  GNUNET_assert (GNUNET_OK == GNUNET_REVOCATION_check_pow (pow,
                                                           TEST_DIFFICULTY,
                                                           exp));
  fprintf (stdout, "Proof:\n");
  print_bytes (pow,
               GNUNET_REVOCATION_proof_get_size (pow),
               8);
  GNUNET_free (ph);
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_log_setup ("gnunet-revocation-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-revocation-tvg",
                          "Generate test vectors for revocation",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-revocation-tvg.c */
