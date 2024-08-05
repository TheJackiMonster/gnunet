/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file peerstore/gnunet-peerstore.c
 * @brief peerstore tool
 * @author Omar Tarabai
 */
#include "gnunet_common.h"
#include "platform.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerstore_service.h"

static int ret;

/*
 * Handle to PEERSTORE service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore_handle;

static struct GNUNET_PEERSTORE_IterateContext *iter_ctx;

static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

static struct GNUNET_PeerIdentity my_full_id;

static int export_own_hello_uri;

static int print_hellos;

/**
 * Run on shutdown
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  if (NULL != peerstore_handle)
  {
    GNUNET_PEERSTORE_disconnect (peerstore_handle);
    peerstore_handle = NULL;
  }
}


/**
 * Callback function used to extract URIs from a builder.
 * Called when we should consider connecting to a peer.
 *
 * @param cls closure pointing to a `struct GNUNET_PeerIdentity *`
 * @param uri one of the URIs
 */
void
print_hello_addrs (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   const char *uri)
{
  (void) cls;


  printf (" `%s'\n", uri);
}


void
hello_iter (void *cls, const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  struct GNUNET_HELLO_Builder *hb;
  const struct GNUNET_PeerIdentity *pid;
  char *url;

  if ((NULL == record) && (NULL == emsg))
  {
    /** If we ever get here, we are newer than the existing record
     *  or the only/first record.
     */
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GNUNET_PEERSTORE_iteration_next (iter_ctx, 1);
    return;
  }
  hb = GNUNET_HELLO_builder_from_msg (record->value);
  pid = GNUNET_HELLO_builder_get_id (hb);
  if (export_own_hello_uri)
  {
    if (0 == GNUNET_memcmp (&my_full_id,
                            pid))
    {
      url = GNUNET_HELLO_builder_to_url (hb, my_private_key);
      printf ("%s\n", url);
      GNUNET_free (url);
      GNUNET_PEERSTORE_iteration_stop (iter_ctx);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  else if (print_hellos)
  {
    printf ("`%s':\n", GNUNET_i2s (pid));
    GNUNET_HELLO_builder_iterate (hb, &print_hello_addrs, NULL);
  }
  GNUNET_PEERSTORE_iteration_next (iter_ctx, 1);
}


/**
 * Main function that will be run by the scheduler.
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

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  if (!print_hellos && !export_own_hello_uri)
  {
    fprintf (stderr, "No arguments provided\n");
    GNUNET_SCHEDULER_shutdown();
    ret = 1;
    return;
  }
  peerstore_handle = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != peerstore_handle);
  my_private_key =
    GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key,
                                      &my_full_id.public_key);
  iter_ctx = GNUNET_PEERSTORE_iteration_start (peerstore_handle,
                                               "peerstore",
                                               NULL,
                                               GNUNET_PEERSTORE_HELLO_KEY,
                                               &hello_iter,
                                               NULL);
  ret = 0;
}


/**
 * The main function to peerstore.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('H',
                               "hello-uri",
                               gettext_noop ("Print a HELLO URI for our peer identity"),
                               &export_own_hello_uri),
    GNUNET_GETOPT_option_flag ('D',
                               "dump",
                               gettext_noop ("List all known HELLOs in peerstore"),
                               &print_hellos),
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-peerstore [options [value]]",
                              gettext_noop ("peerstore"), options, &run,
                              NULL)) ? ret : 1;
}


/* end of gnunet-peerstore.c */
