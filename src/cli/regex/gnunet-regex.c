/*
   This file is part of GNUnet.
   Copyright (C) 2026 GNUnet e.V.

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
 * @author Tobias Frisch
 * @file src/cli/regex/gnunet-regex.c
 * @brief Use regex service from terminal.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gnunet_common.h"
#include "gnunet_regex_service.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

struct GNUNET_REGEX_Announcement *announcement;
struct GNUNET_REGEX_Search *search;

int announcing;

struct GNUNET_TIME_Relative refresh_delay;
uint16_t compression;

struct GNUNET_CONTAINER_MultiHashMap *matches;
struct GNUNET_SCHEDULER_Task *shutdown_task;
struct GNUNET_SCHEDULER_Task *delay_task;

char *expression;


static void
shutdown_hook (GNUNET_UNUSED void *cls)
{
  shutdown_task = NULL;

  if (search)
    GNUNET_REGEX_search_cancel (search);

  if (announcement)
    GNUNET_REGEX_announce_cancel (announcement);

  if (delay_task)
    GNUNET_SCHEDULER_cancel (delay_task);

  if (matches)
    GNUNET_CONTAINER_multihashmap_destroy (matches);

  if (expression)
    GNUNET_free (expression);
}


/**
 * Search callback function, invoked for every result that was found.
 *
 * @param cls Closure provided in #GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Length of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 */
static void
regex_found (GNUNET_UNUSED void *cls,
             const struct GNUNET_PeerIdentity *id,
             const struct GNUNET_PeerIdentity *get_path,
             unsigned int get_path_length,
             const struct GNUNET_PeerIdentity *put_path,
             unsigned int put_path_length)
{
  struct GNUNET_HashCode hash;
  size_t get_path_size, put_path_size;
  unsigned int i;

  get_path_size = sizeof (struct GNUNET_PeerIdentity) * get_path_length;
  put_path_size = sizeof (struct GNUNET_PeerIdentity) * put_path_length;

  if (GNUNET_YES != GNUNET_CRYPTO_kdf (&hash, sizeof (hash),
                                       "regex_match", 11,
                                       id, sizeof (*id),
                                       get_path, get_path_size,
                                       put_path, put_path_size,
                                       NULL))
    return;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (matches, &hash))
    return;

  printf ("%s ( get: %u, put: %u )\n", GNUNET_i2s_full (id), get_path_length,
          put_path_length);

  for (i = 0; i < get_path_length; i++)
    printf (" - get: %s\n", GNUNET_i2s_full (&(get_path[i])));

  for (i = 0; i < put_path_length; i++)
    printf (" - put: %s\n", GNUNET_i2s_full (&(put_path[i])));

  GNUNET_CONTAINER_multihashmap_put (
    matches, &hash, NULL,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
}


static void
print_announcement (void *cls)
{
  delay_task = NULL;

  printf ("> %s\n", expression);

  if (cls)
    delay_task = GNUNET_SCHEDULER_add_delayed (refresh_delay,
                                               print_announcement,
                                               cls);
}


static void
drop_announcement (void *cls)
{
  delay_task = NULL;

  print_announcement (NULL);

  if (announcement)
  {
    GNUNET_REGEX_announce_cancel (announcement);
    announcement = NULL;
  }

  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param[in/out] cls closure
 * @param[in] args remaining command-line arguments
 * @param[in] cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param[in] cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int argc;
  size_t len, pos;
  unsigned int i;

  for (argc = 0; NULL != args[argc]; argc++)
    ;

  len = 0;
  for (i = 0; i < argc; i++)
    len += strlen (args[i]);

  if (argc > 0)
    len += (argc - 1);

  expression = GNUNET_malloc (len + 1);
  GNUNET_assert (expression);
  expression[len] = '\0';
  pos = 0;
  for (i = 0; i < argc; i++)
  {
    size_t s;
    s = strlen (args[i]);
    GNUNET_memcpy (expression + pos, args[i], s);
    pos += s;

    if (i + 1 < argc)
    {
      expression[pos] = ' ';
      pos++;
    }
  }

  matches = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, NULL);

  GNUNET_assert (pos == len);
  if (announcing)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Announcing regular expression: %s\n",
                expression);

    announcement = GNUNET_REGEX_announce (cfg, expression, refresh_delay,
                                          compression);

    if (GNUNET_TIME_relative_is_zero (refresh_delay))
      delay_task = GNUNET_SCHEDULER_add_now (drop_announcement, NULL);
    else
      print_announcement (expression);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Observing peers that announced matching regular expressions to: %s\n",
                expression);

    search = GNUNET_REGEX_search (cfg, expression, &regex_found, NULL);
  }
}


/**
 * The main function to announce regular expressions or observe announcing peers.
 *
 * @param[in] argc number of arguments from the command line
 * @param[in] argv command line arguments
 * @return #EXIT_SUCCESS ok, #EXIT_FAILURE on error
 */
int
main (int argc,
      char **argv)
{
  const char *description =
    "Announce regular expressions and observe announcing peers.";

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('a', "announce",
                               "flag to announce an expression",
                               &announcing),
    GNUNET_GETOPT_option_relative_time ('r', "refresh", "DELAY",
                                        "refresh delay of announcement",
                                        &refresh_delay),
    GNUNET_GETOPT_option_uint16 ('c', "compression", "AMOUNT",
                                 "amount of characters per edge to squeeze",
                                 &compression),
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                              argc,
                              argv,
                              "gnunet-regex [OPTIONS] EXPRESSION\0",
                              gettext_noop (description), options,
                              &run,
                              NULL) ? EXIT_SUCCESS : EXIT_FAILURE);
}
