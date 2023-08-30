/*
     This file is part of GNUnet.
     Copyright (C) 2025 GNUnet e.V.

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
 * @file util/gnunet-pils-tvg.c
 * @brief Generate test vectors for PILS.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_pils_service.h"
#include "pils.h"
#include <inttypes.h>


static const char *d_seed =
  "50d7b652a4efeadff37396909785e5952171a02178c8e7d450fa907925fafd98";

static uint8_t seed_key[256/ 8];

static void
print_addr (void *cls,
            const struct GNUNET_PeerIdentity *pid,
            const char *uri)
{
  printf ("%s\n", uri);
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
run (void                                     *cls,
     char *const                              *args,
     const char                               *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg
     )
{
  struct GNUNET_HELLO_Builder *b;
  struct GNUNET_HashCode hash;
  struct GNUNET_CRYPTO_EddsaPrivateKey derived_key;

  b = GNUNET_HELLO_builder_new ();
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_builder_add_address (b,
                                                                "gnunet+tcp://1.2.3.4"));
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_builder_add_address (b,
                                                                "gnunet+udp://6.7.8.9"));
  GNUNET_assert (GNUNET_OK == GNUNET_HELLO_builder_add_address (b,
                                                                "gnunet+https://example.gnu"));

  printf ("Addresses (sorted):\n");
  GNUNET_HELLO_builder_iterate (b, print_addr, NULL);
  printf ("\n");
  GNUNET_HELLO_builder_hash_addresses (b, &hash);
  printf ("Address hash:\n");
  GNUNET_print_bytes (&hash, sizeof hash, 8, 0);
  printf ("\n");

  GNUNET_hex2b(d_seed, seed_key, sizeof seed_key, 0);
  printf("Seed key:\n");
  GNUNET_print_bytes(seed_key, sizeof seed_key, 8, 0);
  printf ("\n");

  printf("Derived key:\n");
  GNUNET_PILS_derive_pid(sizeof seed_key, seed_key, &hash, &derived_key);
  GNUNET_print_bytes(&derived_key, sizeof derived_key, 8, 0);
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
      char *const *argv
      )
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==GNUNET_log_setup ("gnunet-gns-tvg", "INFO", NULL));
  // gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  // gcry_control (GCRYCTL_SET_VERBOSITY, 99);
  if (GNUNET_OK !=GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                                      argc,
                                      argv,
                                      "gnunet-pils-tvg",
                                      "Generate test vectors for PILS",
                                      options,
                                      &run,
                                      NULL))
    return 1;
  return 0;
}


/* end of gnunet-gns-tvg.c */
