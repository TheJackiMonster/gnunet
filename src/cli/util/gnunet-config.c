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
 * Check if this is an experimental build
 */
static int is_experimental;

/**
 * Do not load default configuration
 */
static int no_defaults;

/**
 * Parse configuration from this memory.
 */
static char *ram_config;

/**
 * If printing the value of LIBS has been requested.
 */
static int libs;

/**
 * If printing the value of PREFIX has been requested.
 */
static int prefix;


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
  const struct GNUNET_OS_ProjectData *pd
    = GNUNET_OS_project_data_get ();
  char *cfgfile = NULL;
  char *loglev = NULL;
  char *logfile = NULL;
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_cfgfile (&cfgfile),
    GNUNET_GETOPT_option_help ("gnunet-config [OPTIONS]"),
    GNUNET_GETOPT_option_loglevel (&loglev),
    GNUNET_GETOPT_option_logfile (&logfile),
    GNUNET_GETOPT_option_version (pd->version),
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
      'E',
      "is-experimental",
      gettext_noop ("Is this an experimental build of GNUnet"),
      &is_experimental),
    GNUNET_GETOPT_option_flag (
      'j',
      "libs",
      gettext_noop (
        "Provide an appropriate value for LIBS to applications building on top of GNUnet"),
      &libs),
    GNUNET_GETOPT_option_flag (
      'n',
      "no-defaults",
      gettext_noop ("Do not parse default configuration files"),
      &no_defaults),
    GNUNET_GETOPT_option_flag (
      'p',
      "prefix",
      gettext_noop (
        "Provide the path under which GNUnet was installed"),
      &prefix),
    GNUNET_GETOPT_option_string (
      'R',
      "ram-config",
      "CONFIG_DATA",
      gettext_noop (
        "Parse main configuration from this command-line argument and not from disk"),
      &ram_config),
    GNUNET_CONFIGURATION_CONFIG_OPTIONS (&cs),
    GNUNET_GETOPT_OPTION_END
  };
  int iret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return EXIT_FAILURE;
  if ( (NULL != pd->config_file) &&
       (NULL != pd->user_config_file) )
    cfgfile = GNUNET_CONFIGURATION_default_filename ();
  iret = GNUNET_GETOPT_run ("gnunet-config",
                            options,
                            argc,
                            argv);
  if (GNUNET_SYSERR == iret)
  {
    GNUNET_free_nz ((void *) argv);
    GNUNET_free (cfgfile);
    GNUNET_free (loglev);
    GNUNET_free (logfile);
    return EXIT_INVALIDARGUMENT;
  }
  if (GNUNET_OK !=
      GNUNET_log_setup ("gnunet-config",
                        loglev,
                        logfile))
  {
    GNUNET_free_nz ((void *) argv);
    GNUNET_free (cfgfile);
    GNUNET_free (loglev);
    GNUNET_free (logfile);
    return EXIT_FAILURE;
  }
  GNUNET_free (loglev);
  GNUNET_free (logfile);
  if (1 == is_experimental)
  {
    GNUNET_free_nz ((void *) argv);
    GNUNET_free (cfgfile);
#ifdef GNUNET_EXPERIMENTAL
    return 0;
#else
    return 1;
#endif
  }
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
    GNUNET_free (prefixdir);
    GNUNET_free (libdir);
    GNUNET_free (cfgfile);
    GNUNET_free_nz ((void *) argv);
    return 0;
  }
  if (NULL != backend_check)
  {
    char *name;

    GNUNET_asprintf (&name,
                     "libgnunet_plugin_%s",
                     backend_check);
    iret = (GNUNET_OK ==
            GNUNET_PLUGIN_test (name)) ? 0 : 77;
    GNUNET_free (name);
    GNUNET_free (cfgfile);
    GNUNET_free_nz ((void *) argv);
    return iret;
  }

  {
    struct GNUNET_CONFIGURATION_Handle *cfg;

    cfg = GNUNET_CONFIGURATION_create ();

    if (NULL != ram_config)
    {
      if ( (! no_defaults) &&
           (GNUNET_SYSERR ==
            GNUNET_CONFIGURATION_load (cfg,
                                       NULL)) )
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to load default configuration, exiting ...\n"));
        GNUNET_free_nz ((void *) argv);
        GNUNET_CONFIGURATION_destroy (cfg);
        GNUNET_free (cfgfile);
        return EXIT_FAILURE;
      }
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_deserialize (cfg,
                                            ram_config,
                                            strlen (ram_config),
                                            NULL))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to parse configuration, exiting ...\n"));
        GNUNET_free_nz ((void *) argv);
        GNUNET_CONFIGURATION_destroy (cfg);
        GNUNET_free (cfgfile);
        return EXIT_FAILURE;
      }
    }
    else
    {
      if (GNUNET_YES !=
          GNUNET_DISK_file_test (cfgfile))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unreadable configuration file `%s', exiting ...\n"),
                    cfgfile);
        GNUNET_free_nz ((void *) argv);
        GNUNET_CONFIGURATION_destroy (cfg);
        GNUNET_free (cfgfile);
        return EXIT_FAILURE;
      }
      if (GNUNET_SYSERR ==
          (no_defaults
        ? GNUNET_CONFIGURATION_parse (cfg,
                                      cfgfile)
         : GNUNET_CONFIGURATION_load (cfg,
                                      cfgfile)) )
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Malformed configuration file `%s', exiting ...\n"),
                    cfgfile);
        GNUNET_free_nz ((void *) argv);
        GNUNET_CONFIGURATION_destroy (cfg);
        GNUNET_free (cfgfile);
        return EXIT_FAILURE;
      }
    }
    GNUNET_CONFIGURATION_config_tool_run (&cs,
                                          &argv[iret],
                                          cfgfile,
                                          cfg);
    GNUNET_free_nz ((void *) argv);
    GNUNET_CONFIGURATION_config_settings_free (&cs);
    GNUNET_CONFIGURATION_destroy (cfg);
  }
  GNUNET_free (cfgfile);
  return cs.global_ret;
}


/* end of gnunet-config.c */
