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
 * @file cli/hello/gnunet-hello.c
 * @brief Export/import/print HELLOs.
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerstore_service.h"

/**
 * Return code
 */
static int ret;

/*
 * Handle to PEERSTORE service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore_handle;

/**
 * PEERSTORE iteration context
 */
static struct GNUNET_PEERSTORE_IterateContext *iter_ctx;

/**
 * HELLO store context handle
 */
static struct GNUNET_PEERSTORE_StoreHelloContext *shc;

/**
 * Peer private key
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey my_private_key;

/**
 * Peer identity
 */
static struct GNUNET_PeerIdentity my_full_id;

/**
 * HELLO URI export option -H
 */
static int export_own_hello_uri;

/**
 * Hello list option -D
 */
static int print_hellos;

/**
 * HELLO URI import option -I
 */
static char *import_uri;

/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  if (NULL != shc)
  {
    GNUNET_PEERSTORE_hello_add_cancel (shc);
    shc = NULL;
  }
  if (NULL != iter_ctx)
  {
    GNUNET_PEERSTORE_iteration_stop (iter_ctx);
  }
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


  printf ("|- %s\n", uri);
}


void
hello_iter (void *cls, const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  struct GNUNET_HELLO_Builder *hb;
  struct GNUNET_TIME_Absolute hello_exp;
  const struct GNUNET_PeerIdentity *pid;
  char *url;

  if ((NULL == record) && (NULL == emsg))
  {
    /** If we ever get here, we are newer than the existing record
     *  or the only/first record.
     */
    iter_ctx = NULL;
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
  hello_exp = GNUNET_HELLO_builder_get_expiration_time (record->value);
  pid = GNUNET_HELLO_builder_get_id (hb);
  if (export_own_hello_uri)
  {
    if (0 == GNUNET_memcmp (&my_full_id,
                            pid))
    {
      url = GNUNET_HELLO_builder_to_url (hb, &my_private_key);
      printf ("%s\n", url);
      GNUNET_free (url);
      GNUNET_PEERSTORE_iteration_stop (iter_ctx);
      iter_ctx = NULL;
      GNUNET_HELLO_builder_free (hb);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  else if (print_hellos)
  {
    printf ("`%s' (expires: %s):\n", GNUNET_i2s (pid),
            GNUNET_STRINGS_absolute_time_to_string (hello_exp));
    GNUNET_HELLO_builder_iterate (hb, &print_hello_addrs, NULL);
  }
  GNUNET_HELLO_builder_free (hb);
  GNUNET_PEERSTORE_iteration_next (iter_ctx, 1);
}


static void
hello_store_success (void *cls, int success)
{
  shc = NULL;
  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Storing hello uri failed\n");
  }
  GNUNET_SCHEDULER_shutdown ();
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
  struct GNUNET_HELLO_Builder *hb;
  struct GNUNET_MQ_Envelope *env;
  char *keyfile;
  (void) cls;
  (void) cfgfile;

  if (NULL != args[0])
  {
    fprintf (stderr, _ ("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  if (! print_hellos &&
      ! export_own_hello_uri &&
      (NULL == import_uri))
  {
    fprintf (stderr, "%s", _ ("No argument given.\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "PEER",
                                               "PRIVATE_KEY",
                                               &keyfile))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_ERROR,
      _ ("Core service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret =  1;
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_eddsa_key_from_file (keyfile,
                                         GNUNET_YES,
                                         &my_private_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read peer's private key!\n");
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    GNUNET_free (keyfile);
    return;
  }
  GNUNET_free (keyfile);
  GNUNET_CRYPTO_eddsa_key_get_public (&my_private_key, &my_full_id.public_key);
  peerstore_handle = GNUNET_PEERSTORE_connect (cfg);
  GNUNET_assert (NULL != peerstore_handle);
  if (NULL != import_uri)
  {
    hb = GNUNET_HELLO_builder_from_url (import_uri);
    env = GNUNET_HELLO_builder_to_env (hb, NULL, GNUNET_TIME_UNIT_ZERO);
    shc = GNUNET_PEERSTORE_hello_add (peerstore_handle,
                                      GNUNET_MQ_env_get_msg (env),
                                      &hello_store_success, NULL);
    GNUNET_HELLO_builder_free (hb);
    return;
  }

  iter_ctx = GNUNET_PEERSTORE_iteration_start (peerstore_handle,
                                               "peerstore",
                                               NULL,
                                               GNUNET_PEERSTORE_HELLO_KEY,
                                               &hello_iter,
                                               NULL);

}


/**
 * The main function to obtain peer information from CORE.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  struct GNUNET_GETOPT_CommandLineOption options[] =
  {
    GNUNET_GETOPT_option_flag ('H',
                               "export-hello-uri",
                               gettext_noop (
                                 "Print a HELLO URI for our peer identity"),
                               &export_own_hello_uri),
    GNUNET_GETOPT_option_string ('I',
                                 "import-hello",
                                 gettext_noop ("Import a HELLO URI"),
                                 "URI",
                                 &import_uri),
    GNUNET_GETOPT_option_flag ('D',
                               "dump-hellos",
                               gettext_noop (
                                 "List all known HELLOs in peerstore"),
                               &print_hellos),    GNUNET_GETOPT_OPTION_END };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  res = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-hello",
                            gettext_noop (
                              "Import/export/print HELLOs."),
                            options,
                            &run,
                            NULL);

  GNUNET_free_nz ((void *) argv);
  if (GNUNET_OK == res)
    return ret;
  return 1;
}


/* end of gnunet-hello.c */