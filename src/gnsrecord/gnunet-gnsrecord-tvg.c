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
#include "gnunet_testing_lib.h"
#include "gnsrecord_crypto.h"
#include <inttypes.h>


static char *d_pkey =
  "50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98";

static char *d_edkey =
  "5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65";


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


static void
print_record (const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Absolute at;
  uint16_t flags = htons (rd->flags);
  uint64_t abs_nbo = GNUNET_htonll (rd->expiration_time);
  uint16_t size_nbo = htons (rd->data_size);
  uint32_t type_nbo = htonl (rd->record_type);
  at.abs_value_us = GNUNET_ntohll (abs_nbo);
  if (0 != (rd->flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
  {
    rt.rel_value_us = rd->expiration_time;
    at = GNUNET_TIME_relative_to_absolute (rt);
    abs_nbo = GNUNET_htonll (at.abs_value_us);
  }
  printf ("EXPIRATION: %" PRIu64 " us\n", rd->expiration_time);
  print_bytes (&abs_nbo, sizeof (abs_nbo), 8);
  printf ("\nDATA_SIZE:\n");
  print_bytes (&size_nbo, sizeof (size_nbo), 8);
  printf ("\nTYPE:\n");
  print_bytes (&type_nbo, sizeof (type_nbo), 8);
  printf ("\nFLAGS: ");
  print_bytes ((void*) &flags, sizeof (flags), 8);
  printf ("\n");
  fprintf (stdout,
           "DATA:\n");
  print_bytes ((char*) rd->data, rd->data_size, 8);
  printf ("\n");
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
run_pkey (struct GNUNET_GNSRECORD_Data *rd, int rd_count, const char *label)
{
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  struct GNUNET_IDENTITY_PrivateKey id_priv;
  struct GNUNET_IDENTITY_PublicKey id_pub;
  struct GNUNET_IDENTITY_PrivateKey pkey_data_p;
  struct GNUNET_IDENTITY_PublicKey pkey_data;
  struct GNUNET_HashCode query;
  char *rdata;
  char *conv_lbl;
  size_t rdata_size;
  char ztld[128];
  unsigned char ctr[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
  unsigned char skey[GNUNET_CRYPTO_AES_KEY_LENGTH];

  id_priv.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&id_priv.ecdsa_key);
  parsehex (d_pkey,
            (char*) &id_priv.ecdsa_key,
            sizeof (id_priv.ecdsa_key), 1);

  GNUNET_IDENTITY_key_get_public (&id_priv,
                                  &id_pub);
  printf ("Zone private key (d, big-endian):\n");
  print_bytes_ (&id_priv.ecdsa_key,
                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey), 8, 1);
  printf ("\n");
  printf ("Zone identifier (ztype|zkey):\n");
  GNUNET_assert (0 < GNUNET_IDENTITY_public_key_get_length (&id_pub));
  print_bytes (&id_pub, GNUNET_IDENTITY_public_key_get_length (&id_pub), 8);
  GNUNET_STRINGS_data_to_string (&id_pub,
                                 GNUNET_IDENTITY_public_key_get_length (
                                   &id_pub),
                                 ztld,
                                 sizeof (ztld));
  printf ("\n");
  printf ("zTLD:\n");
  printf ("%s\n", ztld);
  printf ("\n");

  pkey_data_p.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&pkey_data_p.ecdsa_key);
  GNUNET_IDENTITY_key_get_public (&pkey_data_p,
                                  &pkey_data);
  conv_lbl = GNUNET_GNSRECORD_string_normalize (label);
  printf ("Label:\n");
  print_bytes (conv_lbl, strlen (conv_lbl), 8);
  GNUNET_free (conv_lbl);
  printf ("\nNumber of records (integer): %d\n\n", rd_count);

  for (int i = 0; i < rd_count; i++)
  {
    printf ("Record #%d := (\n", i);
    print_record (&rd[i]);
    printf (")\n\n");
  }

  rdata_size = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                  rd);
  rdata = GNUNET_malloc (rdata_size);
  GNUNET_GNSRECORD_records_serialize (rd_count,
                                      rd,
                                      (size_t) rdata_size,
                                      rdata);
  printf ("RDATA:\n");
  print_bytes (rdata,
               (size_t) rdata_size,
               8);
  printf ("\n");
  expire = GNUNET_GNSRECORD_record_get_expiration_time (rd_count, rd,
                                                        GNUNET_TIME_UNIT_ZERO_ABS);
  GNR_derive_block_aes_key (ctr,
                            skey,
                            label,
                            GNUNET_TIME_absolute_hton (
                              expire).abs_value_us__,
                            &id_pub.ecdsa_key);

  printf ("Encryption NONCE|EXPIRATION|BLOCK COUNTER:\n");
  print_bytes (ctr, sizeof (ctr), 8);
  printf ("\n");
  printf ("Encryption key (K):\n");
  print_bytes (skey, sizeof (skey), 8);
  printf ("\n");
  GNUNET_GNSRECORD_query_from_public_key (&id_pub,
                                          label,
                                          &query);
  printf ("Storage key (q):\n");
  print_bytes (&query, sizeof (query), 8);
  printf ("\n");
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_create (&id_priv,
                                                             expire,
                                                             label,
                                                             rd,
                                                             rd_count,
                                                             &rrblock));
  struct GNUNET_CRYPTO_EcdsaPublicKey derived_key;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *derived_privkey;
  GNUNET_CRYPTO_ecdsa_public_key_derive (&id_pub.ecdsa_key,
                                         label,
                                         "gns",
                                         &derived_key);
  derived_privkey = GNUNET_CRYPTO_ecdsa_private_key_derive (&id_priv.ecdsa_key,
                                                            label,
                                                            "gns");
  printf ("ZKDF(zkey):\n");
  print_bytes (&derived_key, sizeof (derived_key), 8);
  printf ("\n");
  printf ("Derived private key (d'):\n");
  print_bytes (derived_privkey, sizeof (*derived_privkey), 8);
  printf ("\n");
  size_t bdata_size = ntohl (rrblock->size) - sizeof (struct
                                                      GNUNET_GNSRECORD_Block);

  GNUNET_free (derived_privkey);

  bdata = (char*) &(&rrblock->ecdsa_block)[1];
  printf ("BDATA:\n");
  print_bytes (bdata, bdata_size, 8);
  printf ("\n");
  printf ("RRBLOCK:\n");
  print_bytes (rrblock, ntohl (rrblock->size), 8);
  printf ("\n");
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
run_edkey (struct GNUNET_GNSRECORD_Data *rd, int rd_count, const char*label)
{
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  struct GNUNET_IDENTITY_PrivateKey id_priv;
  struct GNUNET_IDENTITY_PublicKey id_pub;
  struct GNUNET_IDENTITY_PrivateKey pkey_data_p;
  struct GNUNET_IDENTITY_PublicKey pkey_data;
  struct GNUNET_HashCode query;
  char *rdata;
  char *conv_lbl;
  size_t rdata_size;

  char ztld[128];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char skey[crypto_secretbox_KEYBYTES];

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
  printf ("\n");
  printf ("Zone identifier (ztype|zkey):\n");
  GNUNET_assert (0 < GNUNET_IDENTITY_public_key_get_length (&id_pub));
  print_bytes (&id_pub, GNUNET_IDENTITY_public_key_get_length (&id_pub), 8);
  GNUNET_STRINGS_data_to_string (&id_pub,
                                 GNUNET_IDENTITY_public_key_get_length (
                                   &id_pub),
                                 ztld,
                                 sizeof (ztld));
  printf ("\n");
  printf ("zTLD:\n");
  printf ("%s\n", ztld);
  printf ("\n");

  pkey_data_p.type = htonl (GNUNET_GNSRECORD_TYPE_EDKEY);
  GNUNET_CRYPTO_eddsa_key_create (&pkey_data_p.eddsa_key);
  GNUNET_IDENTITY_key_get_public (&pkey_data_p,
                                  &pkey_data);
  conv_lbl = GNUNET_GNSRECORD_string_normalize (label);
  printf ("Label:\n");
  print_bytes (conv_lbl, strlen (conv_lbl), 8);
  GNUNET_free (conv_lbl);
  fprintf (stdout,
           "\nNumber of records (integer): %d\n\n", rd_count);

  for (int i = 0; i < rd_count; i++)
  {
    printf ("Record #%d := (\n", i);
    print_record (&rd[i]);
    printf (")\n\n");
  }

  rdata_size = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                  rd);
  expire = GNUNET_GNSRECORD_record_get_expiration_time (rd_count,
                                                        rd,
                                                        GNUNET_TIME_UNIT_ZERO_ABS);
  GNUNET_assert (0 < rdata_size);
  rdata = GNUNET_malloc ((size_t) rdata_size);
  GNUNET_GNSRECORD_records_serialize (rd_count,
                                      rd,
                                      (size_t) rdata_size,
                                      rdata);
  printf ("RDATA:\n");
  print_bytes (rdata,
               (size_t) rdata_size,
               8);
  printf ("\n");
  GNR_derive_block_xsalsa_key (nonce,
                               skey,
                               label,
                               GNUNET_TIME_absolute_hton (
                                 expire).abs_value_us__,
                               &id_pub.eddsa_key);
  printf ("Encryption NONCE|EXPIRATION:\n");
  print_bytes (nonce, sizeof (nonce), 8);
  printf ("\n");
  printf ("Encryption key (K):\n");
  print_bytes (skey, sizeof (skey), 8);
  printf ("\n");
  GNUNET_GNSRECORD_query_from_public_key (&id_pub,
                                          label,
                                          &query);
  printf ("Storage key (q):\n");
  print_bytes (&query, sizeof (query), 8);
  printf ("\n");

  GNUNET_assert (GNUNET_OK ==  GNUNET_GNSRECORD_block_create (&id_priv,
                                                              expire,
                                                              label,
                                                              rd,
                                                              rd_count,
                                                              &rrblock));

  struct GNUNET_CRYPTO_EddsaPublicKey derived_key;
  struct GNUNET_CRYPTO_EddsaPrivateScalar derived_privkey;
  GNUNET_CRYPTO_eddsa_public_key_derive (&id_pub.eddsa_key,
                                         label,
                                         "gns",
                                         &derived_key);
  GNUNET_CRYPTO_eddsa_private_key_derive (&id_priv.eddsa_key,
                                          label,
                                          "gns", &derived_privkey);
  printf ("ZKDF(zkey):\n");
  print_bytes (&derived_key, sizeof (derived_key), 8);
  printf ("\n");
  printf ("nonce := SHA-256 (dh[32..63] || h):\n");
  print_bytes (&derived_privkey + 32, sizeof (derived_privkey) - 32, 8);
  printf ("\n");
  char derived_privkeyNBO[32];
  /* Convert from little endian */
  for (size_t i = 0; i < 32; i++)
    derived_privkeyNBO[i] = derived_privkey.s[31 - i];
  printf ("Derived private key (d', big-endian):\n");
  print_bytes (derived_privkeyNBO, sizeof (derived_privkeyNBO), 8);
  printf ("\n");
  size_t bdata_size = ntohl (rrblock->size) - sizeof (struct
                                                      GNUNET_GNSRECORD_Block);


  bdata = (char*) &(&rrblock->eddsa_block)[1];
  printf ("BDATA:\n");
  print_bytes (bdata, bdata_size, 8);
  printf ("\n");
  printf ("RRBLOCK:\n");
  print_bytes (rrblock, ntohl (rrblock->size), 8);
  printf ("\n");
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
  struct GNUNET_GNSRECORD_Data rd_pkey;
  struct GNUNET_GNSRECORD_Data rd[3];
  struct GNUNET_TIME_Absolute exp1;
  struct GNUNET_TIME_Absolute exp2;
  struct GNUNET_TIME_Absolute exp3;
  size_t pkey_data_size;
  size_t ip_data_size;
  char *pkey_data;
  char *ip_data;

  /*
   * Make different expiration times
   */
  GNUNET_STRINGS_fancy_time_to_absolute ("2228-01-23 10:51:34",
                                         &exp1);
  GNUNET_STRINGS_fancy_time_to_absolute ("2540-05-22 07:55:01",
                                         &exp2);
  GNUNET_STRINGS_fancy_time_to_absolute ("2333-04-21 06:07:09",
                                         &exp3);


  memset (&rd_pkey, 0, sizeof (struct GNUNET_GNSRECORD_Data));
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (
                   GNUNET_GNSRECORD_TYPE_PKEY,
                   "000G0011WESGZY9VRV9NNJ66W3GKNZFZF56BFD2BQF3MHMJST2G2GKDYGG",
                   (void**) &pkey_data,
                   &pkey_data_size));
  rd_pkey.data = pkey_data;
  rd_pkey.data_size = pkey_data_size;
  rd_pkey.expiration_time = exp1.abs_value_us;
  rd_pkey.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  rd_pkey.flags = GNUNET_GNSRECORD_RF_CRITICAL;
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (
                   GNUNET_DNSPARSER_TYPE_AAAA,
                   "::dead:beef",
                   (void**) &ip_data,
                   &ip_data_size));

  rd[0].data = ip_data;
  rd[0].data_size = ip_data_size;
  rd[0].expiration_time = exp1.abs_value_us;
  rd[0].record_type = GNUNET_DNSPARSER_TYPE_AAAA;
  rd[0].flags = GNUNET_GNSRECORD_RF_NONE;

  rd[1].data = "\u611b\u79f0";
  rd[1].data_size = strlen (rd[1].data);
  rd[1].expiration_time = exp2.abs_value_us;
  rd[1].record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd[1].flags = GNUNET_GNSRECORD_RF_NONE;

  rd[2].data = "Hello World";
  rd[2].data_size = strlen (rd[2].data);
  rd[2].expiration_time = exp3.abs_value_us;
  rd[2].record_type = GNUNET_DNSPARSER_TYPE_TXT;
  rd[2].flags = GNUNET_GNSRECORD_RF_SUPPLEMENTAL;

  run_pkey (&rd_pkey, 1, "testdelegation");
  run_pkey (rd, 3, "\u5929\u4e0b\u7121\u6575");
  run_edkey (&rd_pkey, 1, "testdelegation");
  run_edkey (rd, 3, "\u5929\u4e0b\u7121\u6575");
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
