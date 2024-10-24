/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2019, 2022 GNUnet e.V.

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
 * @file gnunet-namestore-dbtool.c
 * @brief command line tool to manipulate the database backends for the namestore
 * @author Martin Schanzenbach
 *
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_namestore_plugin.h>

/**
 * Name of the plugin argument
 */
static char *pluginname;

/**
 * Reset argument
 */
static int reset;

/**
 * Initialize argument
 */
static int init;

/**
 * Return code
 */
static int ret = 0;

/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != pluginname)
    GNUNET_free (pluginname);
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
  char *db_lib_name;
  struct GNUNET_NAMESTORE_PluginFunctions *plugin;

  (void) cls;
  (void) args;
  (void) cfgfile;
  if (NULL != args[0])
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ ("Superfluous command line arguments (starting with `%s') ignored\n"),
      args[0]);

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 (void *) cfg);
  if (NULL == pluginname)
  {
    fprintf (stderr, "No plugin given!\n");
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_namestore_%s",
                   pluginname);
  plugin = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
  if (NULL == plugin)
  {
    fprintf (stderr,
             "Failed to load %s!\n",
             db_lib_name);
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (db_lib_name);
    return;
  }
  if (reset)
  {
    if (GNUNET_OK !=
        plugin->drop_tables (plugin->cls))
    {
      fprintf (stderr,
               "Failed to reset database\n");
      ret = 1;
      GNUNET_free (db_lib_name);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  if (init || reset)
  {
    if (GNUNET_OK !=
        plugin->create_tables (plugin->cls))
    {
      fprintf (stderr,
               "Failed to initialize database\n");
      ret = 1;
      GNUNET_free (db_lib_name);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  GNUNET_SCHEDULER_shutdown ();
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name,
                                              plugin));
  GNUNET_free (db_lib_name);
}


/**
 * The main function for gnunet-namestore-dbtool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('i', "init",
                               gettext_noop ("initialize database"),
                               &init),
    GNUNET_GETOPT_option_flag ('r',
                               "reset",
                               gettext_noop (
                                 "reset database (DANGEROUS: All existing data is lost!"),
                               &reset),
    GNUNET_GETOPT_option_string (
      'p',
      "plugin",
      "PLUGIN",
      gettext_noop (
        "the namestore plugin to work with, e.g. 'sqlite'"),
      &pluginname),
    GNUNET_GETOPT_OPTION_END
  };
  int lret;

  GNUNET_log_setup ("gnunet-namestore-dbtool",
                    "WARNING",
                    NULL);
  if (GNUNET_OK !=
      (lret = GNUNET_PROGRAM_run (argc,
                                  argv,
                                  "gnunet-namestore-dbtool",
                                  _ (
                                    "GNUnet namestore database manipulation tool"),
                                  options,
                                  &run,
                                  NULL)))
  {
    return lret;
  }
  return ret;
}
