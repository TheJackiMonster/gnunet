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
 * Name of the ego
 */
static char *ego_name = NULL;

/**
 * Handle to identity lookup.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Private key for the our zone.
 */
static struct GNUNET_IDENTITY_PrivateKey zone_pkey;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != ego_name)
    GNUNET_free (ego_name);
  if (NULL != el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    el = NULL;
  }
  if (NULL != ns_qe)
    GNUNET_NAMESTORE_cancel (ns_qe);
  if (NULL != ns)
    GNUNET_NAMESTORE_disconnect (ns);

}

static void
tx_end (void *cls, int32_t success, const char *emsg)
{
  ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
             _ ("Ego `%s' not known to identity service\n"),
             ego_name);
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run.
 *
 * TODO:
 *  - We need to actually create and store the records with in begin/commit
 *  - We need to get as argument for what zone to import
 *  - We must assume that names are not repeated later in the zonefile because
 *    our _store APIs are replacing. No sure if that is common in zonefiles.
 *  - We must only actually store a record set when the name to store changes or
 *    the end of the file is reached.
 *    that way we can group them and add (see above).
 *  - We currently do not allow multiline payloads which seem to be common
 *  - We currently do not sanitize payloads (e.g. `()')
 *  - We need to hope our string formats are compatible, but seems ok.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
parse (void *cls)
{
  struct GNUNET_GNSRECORD_Data rd[50]; // Let's hope we do not need more
  struct GNUNET_GNSRECORD_Data *cur_rd = rd;
  char buf[5000];   /* buffer to hold entire line (adjust MAXC as needed) */
  char *next;
  char *token;
  char origin[255];
  char lastname[255];
  void *data;
  size_t data_size;
  struct GNUNET_TIME_Relative ttl;
  int origin_line = 0;
  int ttl_line = 0;
  int type;
  unsigned int rd_count = 0;
  uint32_t ttl_tmp;

/* use filename provided as 1st argument (stdin by default) */
  int i = 0;
  while (fgets (buf, 5000, stdin))                     /* read each line of input */
  {
    i++;
    origin_line = 0;
    ttl_line = 0;
    /* Find space */
    next = strchr (buf, ' ');
    if (NULL == next)
    {
      fprintf (stderr, "Error at line %u: %s\n", i, buf);
      break;
    }
    next[0] = '\0';
    next++;
    if (0 == (strcmp (buf, "$ORIGIN")))
      origin_line = 1;
    else if (0 == (strcmp (buf, "$TTL")))
    {
      ttl_line = 1;
    }
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

    if (ttl_line)
    {
      next = strchr (token, ';');
      if (NULL != next)
        next[0] = '\0';
      next = strchr (token, ' ');
      if (NULL != next)
        next[0] = '\0';
      if (1 != sscanf (token, "%u", &ttl_tmp))
      {
        fprintf (stderr, "Unable to parse TTL `%s'\n", token);
        break;
      }
      printf ("TTL is: %u\n", ttl_tmp);
      ttl.rel_value_us = ttl_tmp * 1000 * 1000;
      continue;
    }
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
    // This is a record, let's go
    cur_rd->flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    cur_rd->expiration_time = ttl.rel_value_us;
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
    type = GNUNET_GNSRECORD_typename_to_number (token);
    cur_rd->record_type = type;
    while (*next == ' ')
      next++;
    token = next;
    next = strchr (token, ';');
    if (NULL != next)
      next[0] = '\0';
    while (token[strlen (token) - 1] == ' ')
      token[strlen (token) - 1] = '\0';
    printf ("data is: %s\n\n", token);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, token,
                                          &data,
                                          &data_size))
    {
      fprintf (stderr,
               _ ("Data `%s' invalid\n"),
               token);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  ns_qe = GNUNET_NAMESTORE_transaction_commit (ns,
                                               &tx_end,
                                               NULL);
}

static void
tx_start (void *cls, int32_t success, const char *emsg)
{
  ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
             _ ("Ego `%s' not known to identity service\n"),
             ego_name);
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  GNUNET_SCHEDULER_add_now (&parse, NULL);
}

static void
identity_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  el = NULL;

  if (NULL == ego)
  {
    if (NULL != ego_name)
    {
      fprintf (stderr,
               _ ("Ego `%s' not known to identity service\n"),
               ego_name);
    }
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
    return;
  }
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  ns_qe = GNUNET_NAMESTORE_transaction_begin (ns,
                                              &tx_start,
                                              NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ns = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, (void *) cfg);
  if (NULL == ns)
  {
    fprintf (stderr,
             _ ("Failed to connect to namestore\n"));
    return;
  }
  if (NULL == ego_name)
  {
    fprintf (stderr, _ ("You must provide a zone ego to use\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &identity_cb, (void *) cfg);

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
    GNUNET_GETOPT_option_string ('z',
                                 "zone",
                                 "EGO",
                                 gettext_noop (
                                   "name of the ego controlling the zone"),
                                 &ego_name),
    GNUNET_GETOPT_OPTION_END
  };
  int lret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-namestore-dbtool", "WARNING", NULL);
  if (GNUNET_OK !=
      (lret = GNUNET_PROGRAM_run (argc,
                                  argv,
                                  "gnunet-namestore-zonefile",
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
