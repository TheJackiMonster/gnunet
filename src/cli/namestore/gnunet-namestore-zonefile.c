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

#define MAX_RECORDS_PER_NAME 50

/**
 * Maximum length of a zonefile line
 */
#define MAX_ZONEFILE_LINE_LEN 4096

/**
 * FIXME: Soft limit this?
 */
#define MAX_ZONEFILE_RECORD_DATA_LEN 2048

/**
 * The record data under a single label. Reused.
 * Hard limit.
 */
static struct GNUNET_GNSRECORD_Data rd[MAX_RECORDS_PER_NAME];

/**
 * Current record $TTL to use
 */
static struct GNUNET_TIME_Relative ttl;

/**
 * Current origin
 */
static char origin[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

/**
 * Number of records for currently parsed set
 */
static unsigned int rd_count = 0;

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
 * Statistics, how many published record sets
 */
static unsigned int published_sets = 0;

/**
 * Statistics, how many records published in aggregate
 */
static unsigned int published_records = 0;


/**
 * Handle to identity lookup.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_PrivateKey zone_pkey;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Origin create operations
 */
static struct GNUNET_IDENTITY_Operation *id_op;

/**
 * Handle to IDENTITY
 */
static struct GNUNET_IDENTITY_Handle *id;

/**
 * Current configurataion
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Scheduled parse task
 */
static struct GNUNET_SCHEDULER_Task *parse_task;

/**
 * The current state of the parser
 */
static int state;

enum ZonefileImportState
{

  /* Uninitialized */
  ZS_READY,

  /* The initial state */
  ZS_ORIGIN_SET,

  /* The $ORIGIN has changed */
  ZS_ORIGIN_CHANGED,

  /* The record name/label has changed */
  ZS_NAME_CHANGED

};


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
  if (NULL != id_op)
    GNUNET_IDENTITY_cancel (id_op);
  if (NULL != ns)
    GNUNET_NAMESTORE_disconnect (ns);
  if (NULL != id)
    GNUNET_IDENTITY_disconnect (id);
  for (int i = 0; i < rd_count; i++)
  {
    void *rd_ptr = (void*) rd[i].data;
    GNUNET_free (rd_ptr);
  }
  if (NULL != parse_task)
    GNUNET_SCHEDULER_cancel (parse_task);
}


static void
parse (void *cls);

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
  // Find the first occurrence of an unqoted ';', which is our comment
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


static int
parse_ttl (char *token, struct GNUNET_TIME_Relative *pttl)
{
  char *next;
  unsigned int ttl_tmp;

  next = strchr (token, ';');
  if (NULL != next)
    next[0] = '\0';
  next = strchr (token, ' ');
  if (NULL != next)
    next[0] = '\0';
  if (1 != sscanf (token, "%u", &ttl_tmp))
  {
    fprintf (stderr, "Unable to parse TTL `%s'\n", token);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TTL is: %u\n", ttl_tmp);
  pttl->rel_value_us = ttl_tmp * 1000 * 1000;
  return GNUNET_OK;
}


static int
parse_origin (char *token, char *porigin)
{
  char *next;
  next = strchr (token, ';');
  if (NULL != next)
    next[0] = '\0';
  next = strchr (token, ' ');
  if (NULL != next)
    next[0] = '\0';
  strcpy (porigin, token);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Origin is: %s\n", porigin);
  return GNUNET_OK;
}


static void
origin_create_cb (void *cls, const struct GNUNET_CRYPTO_PrivateKey *pk,
                  enum GNUNET_ErrorCode ec)
{
  id_op = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr, "Error: %s\n", GNUNET_ErrorCode_get_hint (ec));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  state = ZS_ORIGIN_SET;
  zone_pkey = *pk;
  parse_task = GNUNET_SCHEDULER_add_now (&parse, NULL);
}


static void
origin_lookup_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{

  el = NULL;

  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "$ORIGIN %s does not exist, creating...\n", ego_name);
    id_op = GNUNET_IDENTITY_create (id, ego_name, NULL,
                                    GNUNET_PUBLIC_KEY_TYPE_ECDSA, // FIXME make configurable
                                    origin_create_cb,
                                    NULL);
    return;
  }
  state = ZS_ORIGIN_SET;
  zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  parse_task = GNUNET_SCHEDULER_add_now (&parse, NULL);
}


static void
add_continuation (void *cls, enum GNUNET_ErrorCode ec)
{
  ns_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr,
             _ ("Failed to store records...\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = -1;
  }
  if (ZS_ORIGIN_CHANGED == state)
  {
    if (NULL != ego_name)
      GNUNET_free (ego_name);
    ego_name = GNUNET_strdup (origin);
    if (ego_name[strlen (ego_name) - 1] == '.')
      ego_name[strlen (ego_name) - 1] = '\0';
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Changing origin to %s\n", ego_name);
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name,
                                     &origin_lookup_cb, NULL);
    return;
  }
  parse_task = GNUNET_SCHEDULER_add_now (&parse, NULL);
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
  char buf[MAX_ZONEFILE_LINE_LEN];
  char payload[MAX_ZONEFILE_RECORD_DATA_LEN];
  char *next;
  char *token;
  char *payload_pos;
  static char lastname[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];
  char newname[GNUNET_DNSPARSER_MAX_LABEL_LENGTH];
  void *data;
  size_t data_size;
  int ttl_line = 0;
  int type;
  int bracket_unclosed = 0;
  int quoted = 0;
  int ln = 0;

  parse_task = NULL;
  /* use filename provided as 1st argument (stdin by default) */
  while ((res = fgets (buf, sizeof(buf), stdin)))                     /* read each line of input */
  {
    ln++;
    ttl_line = 0;
    token = trim (buf);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trimmed line (bracket %s): `%s'\n",
                (bracket_unclosed > 0) ? "unclosed" : "closed",
                token);
    if ((0 == strlen (token)) ||
        ((1 == strlen (token)) && (' ' == *token)))
      continue; // I guess we can safely ignore blank lines
    if (bracket_unclosed == 0)
    {
      /* Payload is already parsed */
      payload_pos = payload;
      /* Find space */
      next = strchr (token, ' ');
      if (NULL == next)
      {
        fprintf (stderr, "Error at line %u: %s\n", ln, token);
        ret = 1;
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      next[0] = '\0';
      next++;
      if (0 == (strcmp (token, "$ORIGIN")))
      {
        state = ZS_ORIGIN_CHANGED;
        token = next_token (next);
      }
      else if (0 == (strcmp (token, "$TTL")))
      {
        ttl_line = 1;
        token = next_token (next);
      }
      else
      {
        if (0 == strcmp (token, "IN")) // Inherit name from before
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Old name: %s\n", lastname);
          strcpy (newname, lastname);
          token[strlen (token)] = ' ';
        }
        else if (token[strlen (token) - 1] != '.') // no fqdn
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New name: %s\n", token);
          if (GNUNET_DNSPARSER_MAX_LABEL_LENGTH < strlen (token))
          {
            fprintf (stderr,
                     _ ("Name `%s' is too long\n"),
                     token);
            ret = 1;
            GNUNET_SCHEDULER_shutdown ();
            return;
          }
          strcpy (newname, token);
          token = next_token (next);
        }
        else if (0 == strcmp (token, origin))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New name: @\n");
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
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New name: %s\n", token);
          if (GNUNET_DNSPARSER_MAX_LABEL_LENGTH < strlen (token))
          {
            fprintf (stderr,
                     _ ("Name `%s' is too long\n"),
                     token);
            ret = 1;
            GNUNET_SCHEDULER_shutdown ();
            return;
          }
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
          state = ZS_NAME_CHANGED;
        }
        else
        {
          strcpy (lastname, newname);
        }
      }

      if (ttl_line)
      {
        if (GNUNET_SYSERR == parse_ttl (token, &ttl))
        {
          fprintf (stderr, _ ("Failed to parse $TTL\n"));
          ret = 1;
          GNUNET_SCHEDULER_shutdown ();
          return;
        }
        continue;
      }
      if (ZS_ORIGIN_CHANGED == state)
      {
        if (GNUNET_SYSERR == parse_origin (token, origin))
        {
          fprintf (stderr, _ ("Failed to parse $ORIGIN from %s\n"), token);
          ret = 1;
          GNUNET_SCHEDULER_shutdown ();
          return;
        }
        break;
      }
      if (ZS_READY == state)
      {
        fprintf (stderr,
                 _ (
                   "You must provide $ORIGIN in your zonefile or via arguments (--zone)!\n"));
        ret = 1;
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      // This is a record, let's go
      if (MAX_RECORDS_PER_NAME == rd_count)
      {
        fprintf (stderr,
                 _ ("Only %u records per unique name supported.\n"),
                 MAX_RECORDS_PER_NAME);
        ret = 1;
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      rd[rd_count].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      rd[rd_count].expiration_time = ttl.rel_value_us;
      next = strchr (token, ' ');
      if (NULL == next)
      {
        fprintf (stderr, "Error, last token: %s\n", token);
        ret = 1;
        GNUNET_SCHEDULER_shutdown ();
        break;
      }
      next[0] = '\0';
      next++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "class is: %s\n", token);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "type is: %s\n", token);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "data is: %s\n\n", payload);
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, payload,
                                          &data,
                                          &data_size))
    {
      fprintf (stderr,
               _ ("Data `%s' invalid\n"),
               payload);
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    rd[rd_count].data = data;
    rd[rd_count].data_size = data_size;
    if (ZS_NAME_CHANGED == state)
      break;
    rd_count++;
  }
  if (rd_count > 0)
  {
    ns_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                               &zone_pkey,
                                               lastname,
                                               rd_count,
                                               rd,
                                               &add_continuation,
                                               NULL);
    published_sets++;
    published_records += rd_count;
    for (int i = 0; i < rd_count; i++)
    {
      data = (void*) rd[i].data;
      GNUNET_free (data);
    }
    if (ZS_NAME_CHANGED == state)
    {
      rd[0] = rd[rd_count]; // recover last rd parsed.
      rd_count = 1;
      strcpy (lastname, newname);
      state = ZS_ORIGIN_SET;
    }
    else
      rd_count = 0;
    return;
  }
  if (ZS_ORIGIN_CHANGED == state)
  {
    if (NULL != ego_name)
      GNUNET_free (ego_name);
    ego_name = GNUNET_strdup (origin);
    if (ego_name[strlen (ego_name) - 1] == '.')
      ego_name[strlen (ego_name) - 1] = '\0';
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Changing origin to %s\n", ego_name);
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name,
                                     &origin_lookup_cb, NULL);
    return;
  }
  printf ("Published %u records sets with total %u records\n",
          published_sets, published_records);
  GNUNET_SCHEDULER_shutdown ();
}


static void
identity_cb (void *cls, struct GNUNET_IDENTITY_Ego *ego)
{

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
  sprintf (origin, "%s.", ego_name);
  state = ZS_ORIGIN_SET;
  parse_task = GNUNET_SCHEDULER_add_now (&parse, NULL);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *_cfg)
{
  cfg = _cfg;
  ns = GNUNET_NAMESTORE_connect (cfg);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, (void *) cfg);
  if (NULL == ns)
  {
    fprintf (stderr,
             _ ("Failed to connect to NAMESTORE\n"));
    return;
  }
  id = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  if (NULL == id)
  {
    fprintf (stderr,
             _ ("Failed to connect to IDENTITY\n"));
    return;
  }
  if (NULL != ego_name)
    el = GNUNET_IDENTITY_ego_lookup (cfg, ego_name, &identity_cb, (void *) cfg);
  else
    parse_task = GNUNET_SCHEDULER_add_now (&parse, NULL);
  state = ZS_READY;
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

  GNUNET_log_setup ("gnunet-namestore-dbtool", "WARNING", NULL);
  if (GNUNET_OK !=
      (lret = GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                                  argc,
                                  argv,
                                  "gnunet-namestore-zonefile",
                                  _ (
                                    "GNUnet namestore database manipulation tool"),
                                  options,
                                  &run,
                                  NULL)))
  {
    return lret;
  }
  return ret;
}
