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

#if HAVE_LIBIDN2
#if HAVE_IDN2_H
#include <idn2.h>
#elif HAVE_IDN2_IDN2_H
#include <idn2/idn2.h>
#endif
#elif HAVE_LIBIDN
#if HAVE_IDNA_H
#include <idna.h>
#elif HAVE_IDN_IDNA_H
#include <idn/idna.h>
#endif
#endif

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
 * Maximum number of queries pending at the same time.
 */
#define THRESH 100

/**
 * TIME_THRESH is in usecs.  How quickly do we submit fresh queries.
 * Used as an additional throttle.
 */
#define TIME_THRESH 10

/**
 * How long do we wait at least between series of requests?
 */
#define SERIES_DELAY \
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS, 10)

/**
 * Egos / Zones
 */
struct Zone
{
  /**
   * Kept in a DLL.
   */
  struct Zone *next;

  /**
   * Kept in a DLL.
   */
  struct Zone *prev;

  /**
   * Domain of the zone (i.e. "fr" or "com.fr")
   */
  char *domain;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_BlindablePrivateKey key;
};

/**
 * Missing identity creation context
 */
struct MissingZoneCreationCtx
{
  // DLL
  struct MissingZoneCreationCtx *next;

  // DLL
  struct MissingZoneCreationCtx *prev;

  // Operation
  struct GNUNET_IDENTITY_Operation *id_op;

  // NS Operation
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  // Request
  struct Job *job;

  // Name
  char *name;
};

/**
 * Request we should make.  We keep this struct in memory per request,
 * thus optimizing it is crucial for the overall memory consumption of
 * the zonefile importer.
 */
struct Job
{
  /**
   * Requests are kept in a heap while waiting to be resolved.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Active requests are kept in a DLL.
   */
  struct Job *next;

  /**
   * Active requests are kept in a DLL.
   */
  struct Job *prev;

  /**
   * Head of records that should be published in GNS for
   * this hostname.
   */
  struct Record *rec_head;

  /**
   * Tail of records that should be published in GNS for
   * this hostname.
   */
  struct Record *rec_tail;

  /**
   * Hostname we are resolving.
   */
  char label[GNUNET_DNSPARSER_MAX_NAME_LENGTH];

  /**
   * Namestore operation pending for this record.
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  /**
   * Zone responsible for this request.
   */
  const struct Zone *zone;

  /**
   * At what time does the (earliest) of the returned records
   * for this name expire? At this point, we need to re-fetch
   * the record.
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * While we are fetching the record, the value is set to the
   * starting time of the DNS operation.  While doing a
   * NAMESTORE store, again set to the start time of the
   * NAMESTORE operation.
   */
  struct GNUNET_TIME_Absolute op_start_time;

  // Records to store in job
  struct GNUNET_GNSRECORD_Data *rd;

  // Number of records to store in job
  uint32_t rd_count;
};

/**
 * Heap of all requests to perform, sorted by
 * the time we should next do the request (i.e. by expires).
 */
static struct GNUNET_CONTAINER_Heap *req_heap;

/**
 * Active requests are kept in a DLL.
 */
static struct Job *req_head;

/**
 * Active requests are kept in a DLL.
 */
static struct Job *req_tail;


/**
 * Head of list of zones we are managing.
 */
static struct Zone *zone_head;

/**
 * Tail of list of zones we are managing.
 */
static struct Zone *zone_tail;


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
 * Private key for the our zone.
 */
static struct Zone *current_zone;

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
 * Main task.
 */
static struct GNUNET_SCHEDULER_Task *t;

/**
 * The number of DNS queries that are outstanding
 */
static unsigned int pending;

/**
 * The number of NAMESTORE record store operations that are outstanding
 */
static unsigned int pending_rs;


/**
 * The current state of the parser
 */
static int state;

/**
 * Last time we worked before going idle.
 */
static struct GNUNET_TIME_Absolute sleep_time_reg_proc;

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
  if (NULL != t)
    GNUNET_SCHEDULER_cancel (t);
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
origin_create_cb (void *cls,
                  const struct GNUNET_CRYPTO_BlindablePrivateKey *pk,
                  enum GNUNET_ErrorCode ec)
{
  struct Zone *zone;
  id_op = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr, "Error: %s\n", GNUNET_ErrorCode_get_hint (ec));
    ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Created missing ego `%s'\n",
              ego_name);
  zone = GNUNET_new (struct Zone);
  zone->key = *pk;
  zone->domain = GNUNET_strdup (ego_name);
  GNUNET_CONTAINER_DLL_insert (zone_head, zone_tail, zone);
  // FIXME add delegation to parent zone
  state = ZS_ORIGIN_SET;
  current_zone = zone;
  t = GNUNET_SCHEDULER_add_now (&parse, NULL);
}


static void
ensure_ego_and_continue (const char*ego_name)
{
  struct Zone *zone;
  for (zone = zone_head; NULL != zone; zone = zone->next)
    if (0 == strcmp (zone->domain, ego_name))
      break;
  if (NULL == zone)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "$ORIGIN %s does not exist, creating...\n", ego_name);
    id_op = GNUNET_IDENTITY_create (id, ego_name, NULL,
                                    GNUNET_PUBLIC_KEY_TYPE_EDDSA, // FIXME make configurable
                                    origin_create_cb,
                                    NULL);
    return;
  }
  state = ZS_ORIGIN_SET;
  current_zone = zone;
  t = GNUNET_SCHEDULER_add_now (&parse, NULL);
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
    ensure_ego_and_continue (ego_name);
    return;
  }
  t = GNUNET_SCHEDULER_add_now (&parse, NULL);
}


/**
 * Process as many requests as possible from the queue.
 *
 * @param cls NULL
 */
static void
process_queue (void *cls)
{
  struct Job *job;

  (void) cls;
  t = NULL;
  while (pending + pending_rs < THRESH)
  {
    job = GNUNET_CONTAINER_heap_peek (req_heap);
    if (NULL == job)
      break;
    if (NULL != job->qe)
      return;   /* namestore op still pending */
    if (GNUNET_TIME_absolute_get_remaining (job->expires).rel_value_us > 0)
      break;
    GNUNET_assert (job == GNUNET_CONTAINER_heap_remove_root (req_heap));
    job->hn = NULL;
    GNUNET_CONTAINER_DLL_insert (req_head, req_tail, job);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Requesting store for `%s'\n",
                job->label);
    job->op_start_time = GNUNET_TIME_absolute_get ();
    job->qe = GNUNET_NAMESTORE_record_set_store (ns,
                                                 &job->zone->key,
                                                 job->label,
                                                 job->rd_count,
                                                 job->rd,
                                                 &add_continuation,
                                                 job);
    GNUNET_assert (NULL != job->qe);
    pending++;
  }
  if (pending + pending_rs >= THRESH)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopped processing queue (%u+%u/%u)]\n",
                pending,
                pending_rs,
                THRESH);
    return;   /* wait for replies */
  }
  job = GNUNET_CONTAINER_heap_peek (req_heap);
  if (NULL == job)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopped processing queue: empty queue\n");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Throttling\n");
  if (NULL != t)
    GNUNET_SCHEDULER_cancel (t);
  sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
  t = GNUNET_SCHEDULER_add_delayed (SERIES_DELAY, &process_queue, NULL);
}


/**
 * Insert @a req into DLL sorted by next fetch time.
 *
 * @param req request to insert into #req_heap
 */
static void
insert_sorted (struct Job *job)
{
  job->hn =
    GNUNET_CONTAINER_heap_insert (req_heap, job, job->expires.abs_value_us);
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
queue (const char *label,
       uint32_t rd_count,
       struct GNUNET_GNSRECORD_Data *rd,
       const struct Zone *zone)
{
  struct Job *job;
  struct GNUNET_HashContext *hctx;
  struct GNUNET_HashCode hc;
  size_t hlen;

  hlen = strlen (label) + 1;
  job = GNUNET_new (struct Job);
  job->rd = rd;
  job->rd_count = rd_count;
  GNUNET_assert (NULL != zone);
  job->zone = zone;
  GNUNET_memcpy (job->label, label, hlen);
  hctx = GNUNET_CRYPTO_hash_context_start ();
  GNUNET_CRYPTO_hash_context_read (hctx, job->label, hlen);
  GNUNET_CRYPTO_hash_context_read (hctx, job->zone, sizeof *zone);
  GNUNET_CRYPTO_hash_context_finish (hctx, &hc),
  insert_sorted (job);
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

  t = NULL;
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
    GNUNET_assert (strlen (token) < sizeof payload - (payload_pos - payload));
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
    // We need to encode the lastname from punycode potentially.
    // FIXME we want to probably queue this request here.
    char *lastname_utf8;
    idna_to_unicode_8z8z (lastname,
                          &lastname_utf8,
                          IDNA_ALLOW_UNASSIGNED);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Queueing %d records\n",
                rd_count);
    queue (lastname_utf8,
           rd_count,
           rd,
           current_zone);
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
    if (ZS_ORIGIN_CHANGED == state)
    {
      if (NULL != ego_name)
        GNUNET_free (ego_name);
      ego_name = GNUNET_strdup (origin);
      if (ego_name[strlen (ego_name) - 1] == '.')
        ego_name[strlen (ego_name) - 1] = '\0';
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Changing origin to %s\n", ego_name);
      ensure_ego_and_continue (ego_name);
      return;
    }
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    t = GNUNET_SCHEDULER_add_now (&parse, NULL);
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
    ensure_ego_and_continue (ego_name);
    return;
  }
  sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
  t = GNUNET_SCHEDULER_add_now (&process_queue, NULL);
  printf ("Published %u records sets with total %u records\n",
          published_sets, published_records);
  GNUNET_SCHEDULER_shutdown ();
}


static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  (void) cls;
  (void) ctx;
  static int initial_iteration = GNUNET_YES;
  static int ego_zone_found = GNUNET_NO;

  if (GNUNET_NO == initial_iteration)
    return;
  if (NULL == ego)
  {
    if (NULL == zone_head)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No zones found\n");
      ret = 1;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if ((NULL != ego_name) &&
        (GNUNET_NO == ego_zone_found))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Zone `%s' not found\n",
                  ego_name);
      ret = 2;
      GNUNET_SCHEDULER_shutdown ();
    }
    initial_iteration = GNUNET_NO;
    t = GNUNET_SCHEDULER_add_now (&parse, NULL);
    return;
  }
  if (NULL != name)
  {
    struct Zone *zone;

    zone = GNUNET_new (struct Zone);
    zone->key = *GNUNET_IDENTITY_ego_get_private_key (ego);
    zone->domain = GNUNET_strdup (name);
    GNUNET_CONTAINER_DLL_insert (zone_head, zone_tail, zone);

    if ((NULL != ego_name) &&
        (0 == strcmp (name,
                      ego_name)))
    {
      ego_zone_found = GNUNET_YES;
      sprintf (origin, "%s.", ego_name);
      state = ZS_ORIGIN_SET;
    }
  }
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *_cfg)
{
  cfg = _cfg;
  req_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, (void *) cfg);
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    fprintf (stderr,
             _ ("Failed to connect to NAMESTORE\n"));
    return;
  }
  id = GNUNET_IDENTITY_connect (cfg, identity_cb, NULL);
  if (NULL == id)
  {
    fprintf (stderr,
             _ ("Failed to connect to IDENTITY\n"));
    return;
  }
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
