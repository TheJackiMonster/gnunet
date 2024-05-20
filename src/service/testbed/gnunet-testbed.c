/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FORp A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file testbed/gnunet-testbed.c
 * @brief tool to use testing functionality from cmd line
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_lib.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "gnunet-testbed", __VA_ARGS__)


/**
 * Final status code.
 */
static int ret;

/**
 * Number of config files to create.
 */
static unsigned int create_no;

/**
 * Filename of the config template to be written.
 */
static char *create_cfg_template;


static int
create_unique_cfgs (const char *template,
                    const unsigned int no)
{
  struct GNUNET_TESTBED_System *system;
  int fail;
  char *cur_file;
  struct GNUNET_CONFIGURATION_Handle *cfg_new;
  struct GNUNET_CONFIGURATION_Handle *cfg_tmpl;

  if (GNUNET_NO == GNUNET_DISK_file_test (template))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Configuration template `%s': file not found\n",
                create_cfg_template);
    return 1;
  }
  cfg_tmpl = GNUNET_CONFIGURATION_create ();

  /* load template */
  if ((create_cfg_template != NULL) &&
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_load (cfg_tmpl,
                                  create_cfg_template)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load template `%s'\n",
                create_cfg_template);
    GNUNET_CONFIGURATION_destroy (cfg_tmpl);

    return 1;
  }
  /* load defaults */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (cfg_tmpl,
                                 NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load template `%s'\n",
                create_cfg_template);
    GNUNET_CONFIGURATION_destroy (cfg_tmpl);
    return 1;
  }

  fail = GNUNET_NO;
  system =
    GNUNET_TESTBED_system_create ("testing",
                                  NULL /* controller */,
                                  NULL);
  for (unsigned int cur = 0; cur < no; cur++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating configuration no. %u \n",
                cur);
    if (create_cfg_template != NULL)
      GNUNET_asprintf (&cur_file, "%04u-%s", cur, create_cfg_template);
    else
      GNUNET_asprintf (&cur_file, "%04u%s", cur, ".conf");

    cfg_new = GNUNET_CONFIGURATION_dup (cfg_tmpl);
    if (GNUNET_OK != GNUNET_TESTBED_configuration_create (system, cfg_new))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not create another configuration\n");
      GNUNET_CONFIGURATION_destroy (cfg_new);
      fail = GNUNET_YES;
      break;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Writing configuration no. %u to file `%s' \n",
                cur,
                cur_file);
    if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg_new, cur_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to write configuration no. %u \n",
                  cur);
      fail = GNUNET_YES;
    }
    GNUNET_CONFIGURATION_destroy (cfg_new);
    GNUNET_free (cur_file);
    if (GNUNET_YES == fail)
      break;
  }
  GNUNET_CONFIGURATION_destroy (cfg_tmpl);
  GNUNET_TESTBED_system_destroy (system, GNUNET_NO);
  if (GNUNET_YES == fail)
    return 1;
  return 0;
}


/**
 * Main function that will be running without scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run_no_scheduler (void *cls,
                  char *const *args,
                  const char *cfgfile,
                  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (create_no > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating %u configuration files based on template `%s'\n",
                create_no,
                create_cfg_template);
    ret = create_unique_cfgs (create_cfg_template,
                              create_no);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing arguments!\n");
    ret = 1;
  }
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint (
      'n',
      "number",
      "NUMBER",
      gettext_noop ("number of unique configuration files to create"),
      &create_no),
    GNUNET_GETOPT_option_string (
      't',
      "template",
      "FILENAME",
      gettext_noop ("configuration template"),
      &create_cfg_template),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;

  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run2 (argc,
                          argv,
                          "gnunet-testing",
                          gettext_noop (
                            "Command line tool to access the testing library"),
                          options,
                          &run_no_scheduler,
                          NULL,
                          GNUNET_YES))
    ? ret
    : 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-testbed.c */
