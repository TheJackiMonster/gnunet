/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * @file util/gnunet-ecc.c
 * @brief tool to manipulate EDDSA key files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include <gcrypt.h>

/**
 * Number of characters a Base32-encoded public key requires.
 */
#define KEY_STR_LEN sizeof(struct GNUNET_CRYPTO_EddsaPublicKey) * 8 / 5 + 1

/**
 * Flag for listing public key.
 */
static int list_keys;

/**
 * Flag for listing public key.
 */
static unsigned int list_keys_count;

/**
 * Flag for printing public key.
 */
static int print_public_key;

/**
 * Flag for printing private key.
 */
static int print_private_key;

/**
 * Flag for printing public key in hex.
 */
static int print_public_key_hex;

/**
 * Flag for printing the output of random example operations.
 */
static int print_examples_flag;

/**
 * Option set to create a bunch of keys at once.
 */
static unsigned int make_keys;


/**
 * Create a flat file with a large number of key pairs for testing.
 *
 * @param fn File name to store the keys.
 * @param prefix Desired prefix for the public keys, NULL if any key is OK.
 */
static void
create_keys (const char *fn, const char *prefix)
{
  FILE *f;
  struct GNUNET_CRYPTO_EddsaPrivateKey pk;
  struct GNUNET_CRYPTO_EddsaPublicKey target_pub;
  static char vanity[KEY_STR_LEN + 1];
  size_t len;
  size_t n;
  size_t rest;
  unsigned char mask;
  unsigned target_byte;
  char *s;

  if (NULL == (f = fopen (fn, "w+")))
  {
    fprintf (stderr, _ ("Failed to open `%s': %s\n"), fn, strerror (errno));
    return;
  }
  if (NULL != prefix)
  {
    len = GNUNET_strlcpy (vanity, prefix, sizeof(vanity));
    n = len * 5 / 8;
    rest = len * 5 % 8;

    memset (&vanity[len], '0', KEY_STR_LEN - len);
    vanity[KEY_STR_LEN] = '\0';
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_public_key_from_string (vanity,
                                                               KEY_STR_LEN,
                                                               &target_pub));
    if (0 != rest)
    {
      /**
       * Documentation by example:
       * vanity = "A"
       * len = 1
       * n = 5/8 = 0 (bytes)
       * rest = 5%8 = 5 (bits)
       * mask = ~(2**(8 - 5) - 1) = ~(2**3 - 1) = ~(8 - 1) = ~b111 = b11111000
       */mask = ~((int) pow (2, 8 - rest) - 1);
      target_byte = ((unsigned char *) &target_pub)[n] & mask;
    }
    else
    {
      /* Just so old (debian) versions of GCC calm down with the warnings. */
      mask = target_byte = 0;
    }
    s = GNUNET_CRYPTO_eddsa_public_key_to_string (&target_pub);
    fprintf (stderr,
             _ ("Generating %u keys like %s, please wait"),
             make_keys,
             s);
    GNUNET_free (s);
    fprintf (stderr, "\nattempt %s [%u, %X]\n", vanity, (unsigned int) n, mask);
  }
  else
  {
    fprintf (stderr, _ ("Generating %u keys, please wait"), make_keys);
    /* Just so old (debian) versions of GCC calm down with the warnings. */
    n = rest = target_byte = mask = 0;
  }

  while (0 < make_keys--)
  {
    fprintf (stderr, ".");
    GNUNET_CRYPTO_eddsa_key_create (&pk);
    if (NULL != prefix)
    {
      struct GNUNET_CRYPTO_EddsaPublicKey newkey;

      GNUNET_CRYPTO_eddsa_key_get_public (&pk,
                                          &newkey);
      if (0 != memcmp (&target_pub,
                       &newkey,
                       n))
      {
        make_keys++;
        continue;
      }
      if (0 != rest)
      {
        unsigned char new_byte;

        new_byte = ((unsigned char *) &newkey)[n] & mask;
        if (target_byte != new_byte)
        {
          make_keys++;
          continue;
        }
      }
    }
    if (sizeof (struct GNUNET_PeerIdentity) !=
        fwrite (&pk,
                1,
                sizeof (struct GNUNET_PeerIdentity),
                f))
    {
      fprintf (stderr,
               _ ("\nFailed to write to `%s': %s\n"),
               fn,
               strerror (errno));
      break;
    }
  }
  if (UINT_MAX == make_keys)
    fprintf (stderr, _ ("\nFinished!\n"));
  else
    fprintf (stderr, _ ("\nError, %u keys not generated\n"), make_keys);
  fclose (f);
}


static void
print_hex (const char *msg, const void *buf, size_t size)
{
  printf ("%s: ", msg);
  for (size_t i = 0; i < size; i++)
  {
    printf ("%02hhx", ((const uint8_t *) buf)[i]);
  }
  printf ("\n");
}


static void
print_examples_ecdh (void)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey dh_priv1;
  struct GNUNET_CRYPTO_EcdhePublicKey dh_pub1;
  struct GNUNET_CRYPTO_EcdhePrivateKey dh_priv2;
  struct GNUNET_CRYPTO_EcdhePublicKey dh_pub2;
  struct GNUNET_HashCode hash;
  char buf[128];

  GNUNET_CRYPTO_ecdhe_key_create (&dh_priv1);
  GNUNET_CRYPTO_ecdhe_key_create (&dh_priv2);
  GNUNET_CRYPTO_ecdhe_key_get_public (&dh_priv1,
                                      &dh_pub1);
  GNUNET_CRYPTO_ecdhe_key_get_public (&dh_priv2,
                                      &dh_pub2);

  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (&dh_priv1,
                                                sizeof (dh_priv1),
                                                buf,
                                                sizeof (buf)));
  printf ("ECDHE key 1:\n");
  printf ("private: %s\n",
          buf);
  print_hex ("private(hex)",
             &dh_priv1, sizeof (dh_priv1));
  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (&dh_pub1,
                                                sizeof (dh_pub1),
                                                buf,
                                                sizeof (buf)));
  printf ("public: %s\n",
          buf);
  print_hex ("public(hex)",
             &dh_pub1,
             sizeof (dh_pub1));

  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (&dh_priv2,
                                                sizeof (dh_priv2),
                                                buf,
                                                sizeof (buf)));
  printf ("ECDHE key 2:\n");
  printf ("private: %s\n", buf);
  print_hex ("private(hex)",
             &dh_priv2,
             sizeof (dh_priv2));
  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (&dh_pub2,
                                                sizeof (dh_pub2),
                                                buf,
                                                sizeof (buf)));
  printf ("public: %s\n", buf);
  print_hex ("public(hex)",
             &dh_pub2,
             sizeof (dh_pub2));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecc_ecdh (&dh_priv1,
                                         &dh_pub2,
                                         &hash));
  GNUNET_assert (NULL !=
                 GNUNET_STRINGS_data_to_string (&hash,
                                                sizeof (hash),
                                                buf,
                                                sizeof (buf)));
  printf ("ECDH shared secret: %s\n",
          buf);

}


/**
 * Print some random example operations to stdout.
 */
static void
print_examples (void)
{
  print_examples_ecdh ();
  // print_examples_ecdsa ();
  // print_examples_eddsa ();
}


static void
print_key (const char *filename)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key;
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
  char *hostkeys_data;
  char *hostkey_str;
  uint64_t fs;
  unsigned int total_hostkeys;
  unsigned int c;
  ssize_t sret;

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    fprintf (stderr, _ ("Hostkeys file `%s' not found\n"), filename);
    return;
  }

  /* Check hostkey file size, read entire thing into memory */
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename,
                             &fs,
                             GNUNET_YES,
                             GNUNET_YES))
    fs = 0;
  if (0 == fs)
  {
    fprintf (stderr,
             _ ("Hostkeys file `%s' is empty\n"), filename);
    return;   /* File is empty */
  }
  if (0 != (fs % sizeof (struct GNUNET_PeerIdentity)))
  {
    fprintf (stderr,
             _ ("Incorrect hostkey file format: %s\n"),
             filename);
    return;
  }
  fd = GNUNET_DISK_file_open (filename,
                              GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return;
  }
  hostkeys_data = GNUNET_malloc (fs);
  sret = GNUNET_DISK_file_read (fd, hostkeys_data, fs);
  if ((sret < 0) || (fs != (size_t) sret))
  {
    fprintf (stderr, _ ("Could not read hostkey file: %s\n"), filename);
    GNUNET_free (hostkeys_data);
    GNUNET_DISK_file_close (fd);
    return;
  }
  GNUNET_DISK_file_close (fd);

  if (NULL == hostkeys_data)
    return;
  total_hostkeys = fs / sizeof (struct GNUNET_PeerIdentity);
  for (c = 0; (c < total_hostkeys) && (c < list_keys_count); c++)
  {
    GNUNET_memcpy (&private_key,
                   hostkeys_data + (c * sizeof (struct GNUNET_PeerIdentity)),
                   sizeof (struct GNUNET_PeerIdentity));
    GNUNET_CRYPTO_eddsa_key_get_public (&private_key, &public_key);
    hostkey_str = GNUNET_CRYPTO_eddsa_public_key_to_string (&public_key);
    if (NULL != hostkey_str)
    {
      fprintf (stderr, "%4u: %s\n", c, hostkey_str);
      GNUNET_free (hostkey_str);
    }
    else
      fprintf (stderr, "%4u: %s\n", c, "invalid");
  }
  GNUNET_free (hostkeys_data);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure, NULL
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
  (void) cls;
  (void) cfgfile;
  (void) cfg;

  if (print_examples_flag)
  {
    print_examples ();
    return;
  }
  if (NULL == args[0])
  {
    fprintf (stderr, "%s", _ ("No hostkey file specified on command line\n"));
    return;
  }
  if (list_keys)
  {
    print_key (args[0]);
    return;
  }
  if (make_keys > 0)
  {
    create_keys (args[0], args[1]);
    return;
  }
  if (print_public_key || print_public_key_hex || print_private_key)
  {
    char *str;
    struct GNUNET_DISK_FileHandle *keyfile;
    struct GNUNET_CRYPTO_EddsaPrivateKey pk;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;

    keyfile = GNUNET_DISK_file_open (args[0],
                                     GNUNET_DISK_OPEN_READ,
                                     GNUNET_DISK_PERM_NONE);
    if (NULL == keyfile)
      return;
    while (sizeof(pk) == GNUNET_DISK_file_read (keyfile, &pk, sizeof(pk)))
    {
      GNUNET_CRYPTO_eddsa_key_get_public (&pk, &pub);
      if (print_public_key_hex)
      {
        print_hex ("HEX:", &pub, sizeof(pub));
      }
      else if (print_public_key)
      {
        str = GNUNET_CRYPTO_eddsa_public_key_to_string (&pub);
        fprintf (stdout, "%s\n", str);
        GNUNET_free (str);
      }
      else if (print_private_key)
      {
        str = GNUNET_CRYPTO_eddsa_private_key_to_string (&pk);
        fprintf (stdout, "%s\n", str);
        GNUNET_free (str);
      }
    }
    GNUNET_DISK_file_close (keyfile);
  }
}


/**
 * Program to manipulate ECC key files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_flag ('i',
                               "iterate",
                               gettext_noop (
                                 "list keys included in a file (for testing)"),
                               &list_keys),
    GNUNET_GETOPT_option_uint (
      'e',
      "end=",
      "COUNT",
      gettext_noop ("number of keys to list included in a file (for testing)"),
      &list_keys_count),
    GNUNET_GETOPT_option_uint (
      'g',
      "generate-keys",
      "COUNT",
      gettext_noop ("create COUNT public-private key pairs (for testing)"),
      &make_keys),
    GNUNET_GETOPT_option_flag ('p',
                               "print-public-key",
                               gettext_noop (
                                 "print the public key in ASCII format"),
                               &print_public_key),
    GNUNET_GETOPT_option_flag ('P',
                               "print-private-key",
                               gettext_noop (
                                 "print the private key in ASCII format"),
                               &print_private_key),
    GNUNET_GETOPT_option_flag ('x',
                               "print-hex",
                               gettext_noop (
                                 "print the public key in HEX format"),
                               &print_public_key_hex),
    GNUNET_GETOPT_option_flag (
      'E',
      "examples",
      gettext_noop (
        "print examples of ECC operations (used for compatibility testing)"),
      &print_examples_flag),
    GNUNET_GETOPT_OPTION_END };
  int ret;

  list_keys_count = UINT32_MAX;
  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                             argc,
                             argv,
                             "gnunet-ecc [OPTIONS] keyfile [VANITY_PREFIX]",
                             gettext_noop (
                               "Manipulate GNUnet private ECC key files"),
                             options,
                             &run,
                             NULL))
        ? 0
        : 1;
  return ret;
}


/* end of gnunet-ecc.c */
