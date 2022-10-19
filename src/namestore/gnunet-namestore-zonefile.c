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
  char buf[5000];   /* buffer to hold entire line (adjust MAXC as needed) */
  char *next;
  char *token;
  char origin[255];
  char lastname[255];
  int origin_line = 0;

  /* use filename provided as 1st argument (stdin by default) */
  int i = 0;
  while (fgets (buf, 5000, stdin))                     /* read each line of input */
  {
    origin_line = 0;
    /* Find space */
    next = strchr (buf, ' ');
    if (NULL == next)
    {
      fprintf (stderr, "End?\n");
      break;
    }
    next[0] = '\0';
    next++;
    if (0 == (strcmp (buf, "$ORIGIN")))
      origin_line = 1;
    else if (0 == (strcmp (buf, "$TTL")))
      continue; // FIXME
    else
    {
      if (0 == strlen (buf)) // Inherit name from before
      {
        printf ("Old name: %s\n", lastname);
      }
      else if (buf[strlen (buf) - 1] != '.') // no fqdn
      {
        printf ("New name: %s\n", buf);
        strcpy (lastname, buf);
      }
      else if (0 == strcmp (buf, origin))
      {
        printf ("New name: @\n");
        strcpy (lastname, "@");
      }
      else
      {
        if (strlen (buf) < strlen (origin))
        {
          fprintf (stderr, "Wrong origin: %s (expected %s)\n", buf, origin);
          break; // FIXME error?
        }
        if (0 != strcmp (buf + (strlen (buf) - strlen (origin)), origin))
        {
          fprintf (stderr, "Wrong origin: %s (expected %s)\n", buf, origin);
          break;
        }
        buf[strlen (buf) - strlen (origin) - 1] = '\0';
        printf ("New name: %s\n", buf);
        strcpy (lastname, buf);
      }
    }
    while (*next == ' ')
      next++;
    token = next;

    if (origin_line)
    {
      next = strchr (token, ';');
      if (NULL != next)
        next[0] = '\0';
      next = strchr (token, ' ');
      if (NULL != next)
        next[0] = '\0';
      strcpy (origin, token);
      printf ("Origin is: %s\n", origin);
      continue;
    }
    next = strchr (token, ' ');
    if (NULL == next)
    {
      fprintf (stderr, "Error, last token: %s\n", token);
      break;
    }
    next[0] = '\0';
    next++;
    printf ("class is: %s\n", token);
    while (*next == ' ')
      next++;
    token = next;
    next = strchr (token, ' ');
    if (NULL == next)
    {
      fprintf (stderr, "Error\n");
      break;
    }
    next[0] = '\0';
    next++;
    printf ("type is: %s\n", token);
    while (*next == ' ')
      next++;
    token = next;
    next = strchr (token, ';');
    if (NULL != next)
      next[0] = '\0';
    printf ("data is: %s\n\n", token);
  }

  GNUNET_SCHEDULER_shutdown ();
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
    GNUNET_GETOPT_OPTION_END
  };
  int lret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-namestore-dbtool", "WARNING", NULL);
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
    GNUNET_free_nz ((void *) argv);
    return lret;
  }
  GNUNET_free_nz ((void *) argv);
  return ret;
}
