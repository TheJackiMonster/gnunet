/*
     This file is part of GNUnet.
     Copyright (C) 2012-2021 GNUnet e.V.

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
 * @file util/gnunet-config.c
 * @brief tool to access and manipulate GNUnet configuration files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Backend to check if the respective plugin is
 * loadable. NULL if no check is to be performed.
 * The value is the "basename" of the plugin to load.
 */
static char *backend_check;


/**
 * If printing the value of CFLAGS has been requested.
 */
static int cflags;


/**
 * If printing the value of LIBS has been requested.
 */
static int libs;


/**
 * If printing the value of PREFIX has been requested.
 */
static int prefix;


/**
 * Print each option in a given section.
 * Main task to run to perform operations typical for
 * gnunet-config as per the configuration settings
 * given in @a cls.
 *
 * @param cls closure with the `struct GNUNET_CONFIGURATION_ConfigSettings`
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving,
 *                                                     can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_ConfigSettings *cs = cls;

  if (1 == cflags || 1 == libs || 1 == prefix)
  {
    char *prefixdir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_PREFIX);
    char *libdir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBDIR);

    if (1 == cflags)
    {
      fprintf (stdout, "-I%sinclude\n", prefixdir);
    }
    if (1 == libs)
    {
      fprintf (stdout, "-L%s -lgnunetutil\n", libdir);
    }
    if (1 == prefix)
    {
      fprintf (stdout, "%s\n", prefixdir);
    }
    cs->global_ret = 0;
    GNUNET_free (prefixdir);
    GNUNET_free (libdir);
    return;
  }
  if (NULL != backend_check)
  {
    char *name;

    GNUNET_asprintf (&name,
                     "libgnunet_plugin_%s",
                     backend_check);
    cs->global_ret = (GNUNET_OK ==
                      GNUNET_PLUGIN_test (name)) ? 0 : 77;
    GNUNET_free (name);
    return;
  }
  GNUNET_CONFIGURATION_config_tool_run (cs,
                                        args,
                                        cfgfile,
                                        cfg);
}


/**
 * Program to manipulate configuration files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_CONFIGURATION_ConfigSettings cs = {
    .api_version = GNUNET_UTIL_VERSION,
    .global_ret = EXIT_SUCCESS
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_exclusive (
      GNUNET_GETOPT_option_string (
        'b',
        "supported-backend",
        "BACKEND",
        gettext_noop (
          "test if the current installation supports the specified BACKEND"),
        &backend_check)),
    GNUNET_GETOPT_option_flag (
      'C',
      "cflags",
      gettext_noop (
        "Provide an appropriate value for CFLAGS to applications building on top of GNUnet"),
      &cflags),
    GNUNET_GETOPT_option_flag (
      'j',
      "libs",
      gettext_noop (
        "Provide an appropriate value for LIBS to applications building on top of GNUnet"),
      &libs),
    GNUNET_GETOPT_option_flag (
      'p',
      "prefix",
      gettext_noop (
        "Provide the path under which GNUnet was installed"),
      &prefix),
    GNUNET_CONFIGURATION_CONFIG_OPTIONS (&cs),
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return EXIT_FAILURE;
  ret =
    GNUNET_PROGRAM_run (argc,
                        argv,
                        "gnunet-config [OPTIONS]",
                        gettext_noop ("Manipulate GNUnet configuration files"),
                        options,
                        &run,
                        &cs);
  GNUNET_free_nz ((void *) argv);
  GNUNET_CONFIGURATION_config_settings_free (&cs);
  if (GNUNET_NO == ret)
    return 0;
  if (GNUNET_SYSERR == ret)
    return EXIT_INVALIDARGUMENT;
  return cs.global_ret;
}


/* end of gnunet-config.c */
