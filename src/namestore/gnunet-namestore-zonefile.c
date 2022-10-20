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
 * Currently read line or NULL on EOF
 */
static char *res;


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

static void
parse (void *cls);

static void
add_continuation (void *cls, int32_t success, const char *emsg)
{
  ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    fprintf (stderr,
             _ ("Failed to store records...\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
  }
  GNUNET_SCHEDULER_add_now (&parse, NULL);
}

static char*
trim (char *line)
{
  char *ltrimmed = line;
  int ltrimmed_len;
  int quoted = 0;

  // Trim all whitespace to the left
  while (*ltrimmed == ' ')
    ltrimmed++;
  ltrimmed_len = strlen (ltrimmed);
  // Find the first occurence of an unqoted ';', which is our comment
  for (int i = 0; i < ltrimmed_len; i++)
  {
    if (ltrimmed[i] == '"')
      quoted = ! quoted;
    if ((ltrimmed[i] != ';') || quoted)
      continue;
    ltrimmed[i] = '\0';
  }
  ltrimmed_len = strlen (ltrimmed);
  // Remove trailing whitespace
  for (int i = ltrimmed_len; i > 0; i--)
  {
    if (ltrimmed[i - 1] != ' ')
      break;
    ltrimmed[i - 1] = '\0';
  }
  ltrimmed_len = strlen (ltrimmed);
  if (ltrimmed[ltrimmed_len - 1] == '\n')
    ltrimmed[ltrimmed_len - 1] = ' ';
  return ltrimmed;
}

static char*
next_token (char *token)
{
  char *next = token;
  while (*next == ' ')
    next++;
  return next;
}

/**
 * Main function that will be run.
 *
 * TODO:
 *  - We must assume that names are not repeated later in the zonefile because
 *    our _store APIs are replacing. No sure if that is common in zonefiles.
 *  - We must only actually store a record set when the name to store changes or
 *    the end of the file is reached.
 *    that way we can group them and add (see above).
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
  static struct GNUNET_GNSRECORD_Data rd[50]; // Let's hope we do not need more
  char buf[5000];   /* buffer to hold entire line (adjust MAXC as needed) */
  char payload[5000];
  char *next;
  char *token;
  char *payload_pos;
  char origin[255];
  static char lastname[255];
  char newname[255];
  void *data;
  size_t data_size;
  struct GNUNET_TIME_Relative ttl;
  int origin_line = 0;
  int ttl_line = 0;
  int type;
  static unsigned int rd_count = 0;
  uint32_t ttl_tmp;
  int name_changed = 0;
  int bracket_unclosed = 0;
  int quoted = 0;
  static unsigned int published_sets = 0;
  static unsigned int published_records = 0;

  /* use filename provided as 1st argument (stdin by default) */
  int i = 0;
  while (res = fgets (buf, 5000, stdin))                     /* read each line of input */
  {
    i++;
    origin_line = 0;
    ttl_line = 0;
    token = trim (buf);
    printf ("Trimmed line (bracket %s): `%s'\n",
            (bracket_unclosed > 0) ? "unclosed" : "closed",
            token);
    if (bracket_unclosed == 0)
    {
      /* Payload is already parsed */
      payload_pos = payload;
      /* Find space */
      next = strchr (token, ' ');
      if (NULL == next)
      {
        fprintf (stderr, "Error at line %u: %s\n", i, token);
        break;
      }
      next[0] = '\0';
      next++;
      if (0 == (strcmp (token, "$ORIGIN")))
      {
        origin_line = 1;
        token = next_token (next);
      }
      else if (0 == (strcmp (token, "$TTL")))
      {
        ttl_line = 1;
        token = next_token (next);
      }
      else
      {
        printf ("TOKEN: %s\n", token);
        if (0 == strcmp (token, "IN")) // Inherit name from before
        {
          printf ("Old name: %s\n", lastname);
          strcpy (newname, lastname);
          token[strlen (token)] = ' ';
        }
        else if (token[strlen (token) - 1] != '.') // no fqdn
        {
          printf ("New name: %s\n", token);
          strcpy (newname, token);
          token = next_token (next);
        }
        else if (0 == strcmp (token, origin))
        {
          printf ("New name: @\n");
          strcpy (newname, "@");
          token = next_token (next);
        }
        else
        {
          if (strlen (token) < strlen (origin))
          {
            fprintf (stderr, "Wrong origin: %s (expected %s)\n", token, origin);
            break; // FIXME error?
          }
          if (0 != strcmp (token + (strlen (token) - strlen (origin)), origin))
          {
            fprintf (stderr, "Wrong origin: %s (expected %s)\n", token, origin);
            break;
          }
          token[strlen (token) - strlen (origin) - 1] = '\0';
          printf ("New name: %s\n", token);
          strcpy (newname, token);
          token = next_token (next);
        }
        if (0 != strcmp (newname, lastname) &&
            (0 < rd_count))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Name changed %s->%s, storing record set of %u elements\n",
                      lastname, newname,
                      rd_count);
          name_changed = 1;
        }
        else {
          name_changed = 0;
          strcpy (lastname, newname);
        }
      }

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
      rd[rd_count].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      rd[rd_count].expiration_time = ttl.rel_value_us;
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
      rd[rd_count].record_type = type;
      while (*next == ' ')
        next++;
      token = next;
    }
    for (int i = 0; i < strlen (token); i++)
    {
      if (token[i] == '"')
        quoted = ! quoted;
      if ((token[i] == '(') && ! quoted)
        bracket_unclosed++;
      if ((token[i] == ')') && ! quoted)
        bracket_unclosed--;
    }
    memcpy (payload_pos, token, strlen (token));
    payload_pos += strlen (token);
    if (bracket_unclosed > 0)
    {
      *payload_pos = ' ';
      payload_pos++;
      continue;
    }
    *payload_pos = '\0';
    printf ("data is: %s\n\n", payload);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, payload,
                                          &data,
                                          &data_size))
    {
      // FIXME free rd
      fprintf (stderr,
               _ ("Data `%s' invalid\n"),
               payload);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    rd[rd_count].data = data;
    rd[rd_count].data_size = data_size;
    if (name_changed)
      break;
    rd_count++;
  }
  if (rd_count > 0)
  {
    ns_qe = GNUNET_NAMESTORE_records_store (ns,
                                            &zone_pkey,
                                            lastname,
                                            rd_count,
                                            rd,
                                            &add_continuation,
                                            NULL);
    published_sets++;
    published_records += rd_count;
    // FIXME cleanup rd
    if (name_changed)
    {
    rd[0] = rd[rd_count]; // recover last rd parsed.
    rd_count = 1;
    strcpy (lastname, newname);
    } else
      rd_count = 0;
    return;
  }
  printf ("Published %u records sets with total %u records\n",
          published_sets, published_records);
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
