/*
   This file is part of GNUnet
   Copyright (C) 2014-2017, 2021 GNUnet e.V.

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
 * @file json/json.c
 * @brief functions to parse JSON snippets
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"


enum GNUNET_GenericReturnValue
GNUNET_JSON_parse (const json_t *root,
                   struct GNUNET_JSON_Specification *spec,
                   const char **error_json_name,
                   unsigned int *error_line)
{
  if (NULL == root)
    return GNUNET_SYSERR;
  for (unsigned int i = 0; NULL != spec[i].parser; i++)
  {
    json_t *pos;

    if (NULL == spec[i].field)
      pos = (json_t *) root;
    else
      pos = json_object_get (root,
                             spec[i].field);
    if ( ( (NULL == pos) ||
           (json_is_null (pos) ) ) &&
         (spec[i].is_optional) )
      continue;
    if ( (NULL == pos) ||
         (GNUNET_OK !=
          spec[i].parser (spec[i].cls,
                          pos,
                          &spec[i])) )
    {
      if (NULL != error_json_name)
        *error_json_name = spec[i].field;
      else
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Parsing failed for field `%s:%u`\n",
                    spec[i].field,
                    i);
      if (NULL != error_line)
        *error_line = i;
      GNUNET_JSON_parse_free (spec);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK; /* all OK! */
}


struct GNUNET_JSON_Specification
GNUNET_JSON_spec_mark_optional (struct GNUNET_JSON_Specification spec)
{
  struct GNUNET_JSON_Specification ret = spec;

  ret.is_optional = true;
  return ret;
}


void
GNUNET_JSON_parse_free (struct GNUNET_JSON_Specification *spec)
{
  for (unsigned int i = 0; NULL != spec[i].parser; i++)
    if (NULL != spec[i].cleaner)
      spec[i].cleaner (spec[i].cls,
                       &spec[i]);
}


/**
 * Set an option with a JSON value from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'json_t *')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_json (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
          void *scls,
          const char *option,
          const char *value)
{
  json_t **json = scls;
  json_error_t error;

  *json = json_loads (value, JSON_REJECT_DUPLICATES, &error);
  if (NULL == *json)
  {
    fprintf (stderr,
             _ ("Failed to parse JSON in option `%s': %s (%s)\n"),
             option,
             error.text,
             error.source);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


struct GNUNET_GETOPT_CommandLineOption
GNUNET_JSON_getopt (char shortName,
                    const char *name,
                    const char *argumentHelp,
                    const char *description,
                    json_t **json)
{
  struct GNUNET_GETOPT_CommandLineOption clo = { .shortName = shortName,
                                                 .name = name,
                                                 .argumentHelp = argumentHelp,
                                                 .description = description,
                                                 .require_argument = 1,
                                                 .processor = &set_json,
                                                 .scls = (void *) json };

  return clo;
}


/* end of json.c */
