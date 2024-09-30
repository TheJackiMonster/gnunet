/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2007, 2008, 2009, 2013, 2020, 2021 GNUnet e.V.

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
 * @file src/util/configuration_helper.c
 * @brief helper logic for gnunet-config
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Print each option in a given section as a filename.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
print_filename_option (void *cls,
                       const char *section,
                       const char *option,
                       const char *value)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  char *value_fn;
  char *fn;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                          section,
                                                          option,
                                                          &value_fn));
  fn = GNUNET_STRINGS_filename_expand (value_fn);
  if (NULL == fn)
    fn = value_fn;
  else
    GNUNET_free (value_fn);
  fprintf (stdout,
           "%s = %s\n",
           option,
           fn);
  GNUNET_free (fn);
}


/**
 * Print each option in a given section.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
print_option (void *cls,
              const char *section,
              const char *option,
              const char *value)
{
  (void) cls;
  (void) section;

  fprintf (stdout,
           "%s = %s\n",
           option,
           value);
}


/**
 * Print out given section name.
 *
 * @param cls unused
 * @param section a section in the configuration file
 */
static void
print_section_name (void *cls,
                    const char *section)
{
  (void) cls;
  fprintf (stdout,
           "%s\n",
           section);
}


void
GNUNET_CONFIGURATION_config_tool_run (
  void *cls,
  char *const *args,
  const char *cfgfile,
  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_ConfigSettings *cs = cls;
  struct GNUNET_CONFIGURATION_Handle *out = NULL;
  struct GNUNET_CONFIGURATION_Handle *ncfg = NULL;

  (void) args;
  if (cs->diagnostics)
  {
    /* Re-parse the configuration with diagnostics enabled. */
    ncfg = GNUNET_CONFIGURATION_create ();
    GNUNET_CONFIGURATION_enable_diagnostics (ncfg);
    if (GNUNET_OK != GNUNET_CONFIGURATION_load (ncfg,
                                                cfgfile))
    {
      fprintf (stderr,
               _("Failed to load config file `%s'"), cfgfile);
      return;
    }
    cfg = ncfg;
  }

  if (cs->full)
    cs->rewrite = GNUNET_YES;
  if (cs->list_sections)
  {
    fprintf (stderr,
             _ ("The following sections are available:\n"));
    GNUNET_CONFIGURATION_iterate_sections (cfg,
                                           &print_section_name,
                                           NULL);
    return;
  }
  if ( (! cs->rewrite) &&
       (NULL == cs->section) )
  {
    char *serialization;

    if (! cs->diagnostics)
    {
      fprintf (stderr,
               _ ("%s, %s or %s argument is required\n"),
               "--section",
               "--list-sections",
               "--diagnostics");
      cs->global_ret = EXIT_INVALIDARGUMENT;
      return;
    }
    serialization = GNUNET_CONFIGURATION_serialize_diagnostics (cfg);
    fprintf (stdout,
             "%s",
             serialization);
    GNUNET_free (serialization);
  }
  else if ( (NULL != cs->section) &&
            (NULL == cs->value) )
  {
    if (NULL == cs->option)
    {
      GNUNET_CONFIGURATION_iterate_section_values (
        cfg,
        cs->section,
        cs->is_filename
        ? &print_filename_option
        : &print_option,
        (void *) cfg);
    }
    else
    {
      char *value;

      if (cs->is_filename)
      {
        if (GNUNET_OK !=
            GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                     cs->section,
                                                     cs->option,
                                                     &value))
        {
          GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                     cs->section,
                                     cs->option);
          cs->global_ret = EXIT_NOTCONFIGURED;
          return;
        }
      }
      else
      {
        if (GNUNET_OK !=
            GNUNET_CONFIGURATION_get_value_string (cfg,
                                                   cs->section,
                                                   cs->option,
                                                   &value))
        {
          GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                     cs->section,
                                     cs->option);
          cs->global_ret = EXIT_NOTCONFIGURED;
          return;
        }
      }
      fprintf (stdout,
               "%s\n",
               value);
      GNUNET_free (value);
    }
  }
  else if (NULL != cs->section)
  {
    if (NULL == cs->option)
    {
      fprintf (stderr,
               _ ("--option argument required to set value\n"));
      cs->global_ret = EXIT_INVALIDARGUMENT;
      return;
    }
    out = GNUNET_CONFIGURATION_dup (cfg);
    GNUNET_CONFIGURATION_set_value_string (out,
                                           cs->section,
                                           cs->option,
                                           cs->value);
    cs->rewrite = GNUNET_YES;
  }
  if (cs->rewrite)
  {
    char *cfg_fn = NULL;

    if (NULL == out)
      out = GNUNET_CONFIGURATION_dup (cfg);

    if (NULL == cfgfile)
    {
      const char *xdg = getenv ("XDG_CONFIG_HOME");

      if (NULL != xdg)
        GNUNET_asprintf (&cfg_fn,
                         "%s%s%s",
                         xdg,
                         DIR_SEPARATOR_STR,
                         GNUNET_OS_project_data_get ()->config_file);
      else
        cfg_fn = GNUNET_strdup (
          GNUNET_OS_project_data_get ()->user_config_file);
      cfgfile = cfg_fn;
    }

    if (! cs->full)
    {
      struct GNUNET_CONFIGURATION_Handle *def;

      def = GNUNET_CONFIGURATION_create ();
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_load (def,
                                     NULL))
      {
        fprintf (stderr,
                 _ ("failed to load configuration defaults"));
        cs->global_ret = 1;
        GNUNET_CONFIGURATION_destroy (def);
        GNUNET_CONFIGURATION_destroy (out);
        GNUNET_free (cfg_fn);
        return;
      }
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write_diffs (def,
                                            out,
                                            cfgfile))
        cs->global_ret = 2;
      GNUNET_CONFIGURATION_destroy (def);
    }
    else
    {
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_write (out,
                                      cfgfile))
        cs->global_ret = 2;
    }
    GNUNET_free (cfg_fn);
  }
  if (NULL != out)
    GNUNET_CONFIGURATION_destroy (out);
  if (NULL != ncfg)
    GNUNET_CONFIGURATION_destroy (ncfg);
}


void
GNUNET_CONFIGURATION_config_settings_free (
  struct GNUNET_CONFIGURATION_ConfigSettings *cs)
{
  GNUNET_free (cs->option);
  GNUNET_free (cs->section);
  GNUNET_free (cs->value);
}


/* end of configuration_helper.c */
