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
 * @file pils/gnunet-pils.c
 * @brief Print information about the peer identity.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_pils_service.h"

/**
 * Return code
 */
static int ret;

/**
 * Option -i.
 */
static int once;

/**
 * Handle to PILS.
 */
static struct GNUNET_PILS_Handle *pils;

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
  if (NULL != pils)
  {
    GNUNET_PILS_disconnect (pils);
    pils = NULL;
  }
}

void
pid_change_cb (void *cls,
               const struct GNUNET_HELLO_Parser *hparser,
               const struct GNUNET_HashCode *addr_hash)
{
  printf ("%s\n",
          GNUNET_i2s (GNUNET_HELLO_parser_get_id(hparser)));
  if (once)
    GNUNET_SCHEDULER_shutdown();
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
  (void) cls;
  (void) cfgfile;

  if (NULL != args[0])
  {
    fprintf (stderr, _ ("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  pils = GNUNET_PILS_connect (cfg, &pid_change_cb, NULL);
  if (NULL == pils)
  {
    fprintf (stderr, "%s", _ ("Unable to connect to service.\n"));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function to obtain peer information from PILS.
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
    GNUNET_GETOPT_option_flag (
      '1',
      "once",
      gettext_noop (
        "Show our current peer identity and exit"
        ),
      &once),
    GNUNET_GETOPT_OPTION_END };

  res = GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                            argc,
                            argv,
                            "gnunet-pils",
                            gettext_noop (
                              "Print information about our peer identity."),
                            options,
                            &run,
                            NULL);

  if (GNUNET_OK == res)
    return ret;
  return 1;
}


/* end of gnunet-core.c */
