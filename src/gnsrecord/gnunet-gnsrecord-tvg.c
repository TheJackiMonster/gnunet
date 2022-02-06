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
 * @file util/gnunet-gns-tvg.c
 * @brief Generate test vectors for GNS.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include <inttypes.h>
#include "gnsrecord_crypto.h"

#define TEST_RECORD_LABEL "test"
#define TEST_RECORD_A "1.2.3.4"
#define TEST_RRCOUNT 2

static char *d_pkey =
  "50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98";

static char *d_edkey =
  "5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65";

int parsehex (char *src, char *dst, size_t dstlen, int invert)
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


static void
print_record (const struct GNUNET_GNSRECORD_Data *rd)
{

  fprintf (stdout,
           "EXPIRATION: %" PRIu64 "\n", rd->expiration_time);
  fprintf (stdout,
           "DATA_SIZE: %zu\n", rd->data_size);
  fprintf (stdout,
           "TYPE: %d\n", rd->record_type);
  fprintf (stdout,
           "FLAGS: %d\n", rd->flags);
  fprintf (stdout,
           "DATA:\n");
  print_bytes ((char*) rd->data, rd->data_size, 8);
  fprintf (stdout, "\n");
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
run_pkey (void)
{
  struct GNUNET_GNSRECORD_Data rd[2];
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute exp1;
  struct GNUNET_TIME_Absolute exp2;
  struct GNUNET_TIME_Relative delta1;
  struct GNUNET_TIME_Relative delta2;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  struct GNUNET_IDENTITY_PrivateKey id_priv;
  struct GNUNET_IDENTITY_PublicKey id_pub;
  struct GNUNET_IDENTITY_PrivateKey pkey_data_p;
  struct GNUNET_IDENTITY_PublicKey pkey_data;
  struct GNUNET_HashCode query;
  void *data;
  size_t data_size;
  char *rdata;
  size_t rdata_size;
  uint32_t rd_count_nbo;
  char ztld[128];
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char skey[GNUNET_CRYPTO_AES_KEY_LENGTH];

  /*
   * Make two different expiration times
   */
  GNUNET_STRINGS_fancy_time_to_absolute ("2048-01-23 10:51:34",
                                         &exp1);
  GNUNET_STRINGS_fancy_time_to_absolute ("3540-05-22 07:55:01",
                                         &exp2);


  id_priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&id_priv.ecdsa_key);
  parsehex (d_pkey,
            (char*) &id_priv.ecdsa_key,
            sizeof (id_priv.ecdsa_key), 1);

  GNUNET_IDENTITY_key_get_public (&id_priv,
                                  &id_pub);
  fprintf (stdout,
           "Zone private key (d, big-endian):\n");
  print_bytes_ (&id_priv.ecdsa_key,
                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey), 8, 1);
  fprintf (stdout, "\n");
  fprintf (stdout, "Zone identifier (ztype|zkey):\n");
  print_bytes (&id_pub, GNUNET_IDENTITY_key_get_length (&id_pub), 8);
  GNUNET_STRINGS_data_to_string (&id_pub,
                                 GNUNET_IDENTITY_key_get_length (&id_pub),
                                 ztld,
                                 sizeof (ztld));
  fprintf (stdout, "\n");
  fprintf (stdout, "Encoded zone identifier (zkl = zTLD):\n");
  fprintf (stdout, "%s\n", ztld);
  fprintf (stdout, "\n");

  pkey_data_p.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&pkey_data_p.ecdsa_key);
  GNUNET_IDENTITY_key_get_public (&pkey_data_p,
                                  &pkey_data);
  fprintf (stdout,
           "Label: %s\nRRCOUNT: %d\n\n", TEST_RECORD_LABEL, TEST_RRCOUNT);
  memset (rd, 0, sizeof (struct GNUNET_GNSRECORD_Data) * 2);
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (
                   GNUNET_DNSPARSER_TYPE_A, TEST_RECORD_A, &data, &data_size));
  rd[0].data = data;
  rd[0].data_size = data_size;
  rd[0].expiration_time = exp1.abs_value_us;
  rd[0].record_type = GNUNET_DNSPARSER_TYPE_A;
  fprintf (stdout, "Record #0\n");
  print_record (&rd[0]);

  rd[1].data = "Some nick";
  rd[1].data_size = sizeof (struct GNUNET_IDENTITY_PublicKey);
  rd[1].expiration_time = exp2.abs_value_us;
  rd[1].record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;
  fprintf (stdout, "Record #1\n");
  print_record (&rd[1]);

  rdata_size = GNUNET_GNSRECORD_records_get_size (TEST_RRCOUNT,
                                                  rd);
  rdata = GNUNET_malloc (rdata_size);
  GNUNET_GNSRECORD_records_serialize (2,
                                      rd,
                                      rdata_size,
                                      rdata);
  fprintf (stdout, "RDATA:\n");
  print_bytes (rdata, rdata_size, 8);
  fprintf (stdout, "\n");
  expire = GNUNET_GNSRECORD_record_get_expiration_time (TEST_RRCOUNT, rd,
                                                        GNUNET_TIME_UNIT_FOREVER_ABS);
  GNR_derive_block_aes_key (ctr,
                            skey,
                            TEST_RECORD_LABEL,
                            GNUNET_TIME_absolute_hton (
                              expire).abs_value_us__,
                            &id_pub.ecdsa_key);

  fprintf (stdout, "Encryption NONCE|EXPIRATION|BLOCK COUNTER:\n");
  print_bytes (ctr, sizeof (ctr), 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "Encryption key (K):\n");
  print_bytes (skey, sizeof (skey), 8);
  fprintf (stdout, "\n");
  GNUNET_GNSRECORD_query_from_public_key (&id_pub,
                                          TEST_RECORD_LABEL,
                                          &query);
  fprintf (stdout, "Storage key (q):\n");
  print_bytes (&query, sizeof (query), 8);
  fprintf (stdout, "\n");
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create (&id_priv,
                                                             expire,
                                                             TEST_RECORD_LABEL,
                                                             rd,
                                                             TEST_RRCOUNT,
                                                             &rrblock));
  size_t bdata_size = ntohl(rrblock->size) - sizeof (struct GNUNET_GNSRECORD_Block);

  bdata = (char*) &(&rrblock->ecdsa_block)[1];
  fprintf (stdout, "BDATA:\n");
  print_bytes (bdata, bdata_size, 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "RRBLOCK:\n");
  print_bytes (rrblock, ntohl(rrblock->size), 8);
  fprintf (stdout, "\n");
  GNUNET_free (rdata);
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
run_edkey (void)
{
  struct GNUNET_GNSRECORD_Data rd[2];
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute exp1;
  struct GNUNET_TIME_Absolute exp2;
  struct GNUNET_TIME_Relative delta1;
  struct GNUNET_TIME_Relative delta2;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  struct GNUNET_IDENTITY_PrivateKey id_priv;
  struct GNUNET_IDENTITY_PublicKey id_pub;
  struct GNUNET_IDENTITY_PrivateKey pkey_data_p;
  struct GNUNET_IDENTITY_PublicKey pkey_data;
  struct GNUNET_HashCode query;
  void *data;
  size_t data_size;
  char *rdata;
  size_t rdata_size;
  uint32_t rd_count_nbo;
  char ztld[128];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char skey[crypto_secretbox_KEYBYTES];

  /*
   * Make two different expiration times
   */
  GNUNET_STRINGS_fancy_time_to_absolute ("%2048-01-23 10:51:34",
                                         &exp1);
  GNUNET_STRINGS_fancy_time_to_absolute ("3540-05-22 07:55:01",
                                         &exp2);

  id_priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&id_priv.ecdsa_key);
  GNUNET_IDENTITY_key_get_public (&id_priv,
                                  &id_pub);

  id_priv.type = htonl (GNUNET_IDENTITY_TYPE_EDDSA);
  GNUNET_CRYPTO_eddsa_key_create (&id_priv.eddsa_key);
  parsehex (d_edkey,
            (char*) &id_priv.eddsa_key,
            sizeof (id_priv.eddsa_key), 0);
  GNUNET_IDENTITY_key_get_public (&id_priv,
                                  &id_pub);
  fprintf (stdout,
           "Zone private key (d):\n");
  print_bytes (&id_priv.eddsa_key, sizeof (struct
                                           GNUNET_CRYPTO_EddsaPrivateKey), 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "Zone identifier (ztype|zkey):\n");
  print_bytes (&id_pub, GNUNET_IDENTITY_key_get_length (&id_pub), 8);
  GNUNET_STRINGS_data_to_string (&id_pub,
                                 GNUNET_IDENTITY_key_get_length (&id_pub),
                                 ztld,
                                 sizeof (ztld));
  fprintf (stdout, "\n");
  fprintf (stdout, "Encoded zone identifier (zkl = zTLD):\n");
  fprintf (stdout, "%s\n", ztld);
  fprintf (stdout, "\n");

  pkey_data_p.type = htonl (GNUNET_GNSRECORD_TYPE_EDKEY);
  GNUNET_CRYPTO_eddsa_key_create (&pkey_data_p.eddsa_key);
  GNUNET_IDENTITY_key_get_public (&pkey_data_p,
                                  &pkey_data);
  fprintf (stdout,
           "Label: %s\nRRCOUNT: %d\n\n", TEST_RECORD_LABEL, TEST_RRCOUNT);
  memset (rd, 0, sizeof (struct GNUNET_GNSRECORD_Data) * 2);
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (
                   GNUNET_DNSPARSER_TYPE_A, TEST_RECORD_A, &data, &data_size));
  rd[0].data = data;
  rd[0].data_size = data_size;
  rd[0].expiration_time = exp1.abs_value_us;
  rd[0].record_type = GNUNET_DNSPARSER_TYPE_A;
  fprintf (stdout, "Record #0\n");
  print_record (&rd[0]);

  rd[1].data = "My Nick";
  rd[1].data_size = sizeof (struct GNUNET_IDENTITY_PublicKey);
  rd[1].expiration_time = exp2.abs_value_us;
  rd[1].record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;
  fprintf (stdout, "Record #1\n");
  print_record (&rd[1]);

  rdata_size = GNUNET_GNSRECORD_records_get_size (TEST_RRCOUNT,
                                                  rd);
  expire = GNUNET_GNSRECORD_record_get_expiration_time (TEST_RRCOUNT,
                                                        rd,
                                                        GNUNET_TIME_UNIT_FOREVER_ABS);
  rdata = GNUNET_malloc (rdata_size);
  GNUNET_GNSRECORD_records_serialize (2,
                                      rd,
                                      rdata_size,
                                      rdata);
  fprintf (stdout, "RDATA:\n");
  print_bytes (rdata, rdata_size, 8);
  fprintf (stdout, "\n");
  GNR_derive_block_xsalsa_key (nonce,
                               skey,
                               TEST_RECORD_LABEL,
                               GNUNET_TIME_absolute_hton (
                                 expire).abs_value_us__,
                               &id_pub.eddsa_key);
  fprintf (stdout, "Encryption NONCE|EXPIRATION:\n");
  print_bytes (nonce, sizeof (nonce), 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "Encryption key (K):\n");
  print_bytes (skey, sizeof (skey), 8);
  fprintf (stdout, "\n");
  GNUNET_GNSRECORD_query_from_public_key (&id_pub,
                                          TEST_RECORD_LABEL,
                                          &query);
  fprintf (stdout, "Storage key (q):\n");
  print_bytes (&query, sizeof (query), 8);
  fprintf (stdout, "\n");

  GNUNET_assert (GNUNET_OK ==  GNUNET_GNSRECORD_block_create (&id_priv,
                                                              expire,
                                                              TEST_RECORD_LABEL,
                                                              rd,
                                                              TEST_RRCOUNT,
                                                              &rrblock));
  size_t bdata_size = ntohl(rrblock->size) - sizeof (struct GNUNET_GNSRECORD_Block);

  bdata = (char*) &(&rrblock->eddsa_block)[1];
  fprintf (stdout, "BDATA:\n");
  print_bytes (bdata, bdata_size, 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "RRBLOCK:\n");
  print_bytes (rrblock, ntohl(rrblock->size), 8);
  fprintf (stdout, "\n");
  GNUNET_free (rdata);
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
  run_pkey ();
  run_edkey ();
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
                 GNUNET_log_setup ("gnunet-gns-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-gns-tvg",
                          "Generate test vectors for GNS",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-gns-tvg.c */
