/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
/*
 * @file namecache/test_plugin_namecache.c
 * @brief Test for the namecache plugins
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_testing_lib.h"


static int ok;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


/**
 * Function called when the service shuts down.  Unloads our namecache
 * plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_NAMECACHE_PluginFunctions *api)
{
  char *libname;

  GNUNET_asprintf (&libname, "libgnunet_plugin_namecache_%s", plugin_name);
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (libname, api));
  GNUNET_free (libname);
}


/**
 * Load the namecache plugin.
 *
 * @param cfg configuration to pass
 * @return NULL on error
 */
static struct GNUNET_NAMECACHE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMECACHE_PluginFunctions *ret;
  char *libname;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Loading `%s' namecache plugin\n"),
              plugin_name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_namecache_%s", plugin_name);
  if (NULL == (ret = GNUNET_PLUGIN_load (GNUNET_OS_project_data_gnunet (),
                                         libname,
                                         (void *) cfg)))
  {
    fprintf (stderr, "Failed to load plugin `%s'!\n", plugin_name);
    GNUNET_free (libname);
    return NULL;
  }
  GNUNET_free (libname);
  return ret;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMECACHE_PluginFunctions *nsp;

  ok = 0;
  nsp = load_plugin (cfg);
  if (NULL == nsp)
  {
    fprintf (stderr,
             "%s",
             "Failed to initialize namecache.  Database likely not setup, skipping test.\n");
    return;
  }

  unload_plugin (nsp);
}


int
main (int argc, char *argv[])
{
  char cfg_name[PATH_MAX];
  char *const xargv[] = {
    "test-plugin-namecache",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  plugin_name = GNUNET_STRINGS_get_suffix_from_binary_name (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof(cfg_name), "test_plugin_namecache_%s.conf",
                   plugin_name);

  GNUNET_DISK_purge_cfg_dir (GNUNET_OS_project_data_gnunet (),
                             cfg_name,
                             "GNUNET_TEST_HOME");

  GNUNET_log_setup ("test-plugin-namecache",
                    "WARNING",
                    NULL);
  GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                      (sizeof(xargv) / sizeof(char *)) - 1, xargv,
                      "test-plugin-namecache", "nohelp", options, &run, NULL);

  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %d\n", ok);
  GNUNET_DISK_purge_cfg_dir (GNUNET_OS_project_data_gnunet (),
                             cfg_name,
                             "GNUNET_TEST_HOME");
  return ok;
}


/* end of test_plugin_namecache.c */
