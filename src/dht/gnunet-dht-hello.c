/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

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
 * @file dht/gnunet-dht-hello.c
 * @brief Obtain HELLO from DHT for bootstrapping
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_dht_service.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "dht-clients", __VA_ARGS__)

/**
 * Handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Handle to the DHT hello get operation.
 */
static struct GNUNET_DHT_HelloGetHandle *get_hello_handle;

/**
 * Global status value
 */
static int global_ret;


/**
 * Task run to clean up on shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  if (NULL != get_hello_handle)
  {
    GNUNET_DHT_hello_get_cancel (get_hello_handle);
    get_hello_handle = NULL;
  }
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Task run when we are finished. Triggers shutdown.
 *
 * @param cls unused
 */
static void
hello_done_cb (void *cls)
{
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called on our HELLO.
 *
 * @param cls closure
 * @param url the HELLO URL
 */
static void
hello_result_cb (void *cls,
                 const char *url)
{
  get_hello_handle = NULL;
  fprintf (stdout,
           "%s\n",
           url);
  GNUNET_SCHEDULER_shutdown ();
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
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task,
                                 NULL);
  if (NULL == (dht_handle = GNUNET_DHT_connect (cfg,
                                                1)))
  {
    fprintf (stderr,
             _ ("Failed to connect to DHT service!\n"));
    global_ret = EXIT_NOTCONFIGURED;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL == args[0])
  {
    get_hello_handle = GNUNET_DHT_hello_get (dht_handle,
                                             &hello_result_cb,
                                             NULL);
    GNUNET_break (NULL != get_hello_handle);
  }
  else
  {
    GNUNET_DHT_hello_offer (dht_handle,
                            args[0],
                            &hello_done_cb,
                            NULL);
  }
}


/**
 * Entry point for gnunet-dht-hello
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue iret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  iret = GNUNET_PROGRAM_run (
    argc,
    argv,
    "gnunet-dht-hello [URL]",
    gettext_noop (
      "Obtain HELLO from DHT or provide HELLO to DHT for bootstrapping"),
    options,
    &run,
    NULL);
  if (GNUNET_SYSERR == iret)
    return EXIT_FAILURE;
  if (GNUNET_NO == iret)
    return EXIT_SUCCESS;
  return global_ret;
}


/* end of gnunet-dht-hello.c */
