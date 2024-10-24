/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2019 GNUnet e.V.

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
 * @file gnunet-namestore.c
 * @brief command line tool to manipulate the local zone
 * @author Christian Grothoff
 *
 * TODO:
 * - test
 */
#include "platform.h"
#include "gnunet_common.h"
#include <gnunet_util_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_gns_service.h>
#include <gnunet_namestore_service.h>
#include <inttypes.h>

/**
 * The upper bound for the zone iteration interval
 * (per record).
 */
#define WARN_RELATIVE_EXPIRATION_LIMIT GNUNET_TIME_relative_multiply ( \
          GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * Entry in record set for bulk processing.
 */
struct RecordSetEntry
{
  /**
   * Kept in a linked list.
   */
  struct RecordSetEntry *next;

  /**
   * The record to add/remove.
   */
  struct GNUNET_GNSRECORD_Data record;
};

/**
 * The record marked for deletion
 */
struct MarkedRecord
{
  /**
   * DLL
   */
  struct MarkedRecord *next;

  /**
   * DLL
   */
  struct MarkedRecord *prev;

  /**
   * Ego Identifier
   */
  char *name;

  /**
   * The zone key
   */
  struct GNUNET_CRYPTO_PrivateKey key;
};

/**
 * The default namestore ego
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_PrivateKey zone_pkey;

/**
 * Identity service handle
 */
static struct GNUNET_IDENTITY_Handle *idh;

/**
 * Name of the ego controlling the zone.
 */
static char *ego_name;

/**
 * Queue entry for the 'add-uri' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe_uri;

/**
 * Queue entry for the 'add' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *add_qe;

/**
 * Queue entry for the 'lookup' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *get_qe;

/**
 * Queue entry for the 'reverse lookup' operation (in combination with a name).
 */
static struct GNUNET_NAMESTORE_QueueEntry *reverse_qe;

/**
 * Marked record list
 */
static struct MarkedRecord *marked_head;

/**
 * Marked record list
 */
static struct MarkedRecord *marked_tail;

/**
 * Configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Ego list
 */
static struct EgoEntry *ego_head;

/**
 * Ego list
 */
static struct EgoEntry *ego_tail;

/**
 * List iterator for the 'list' operation.
 */
static struct GNUNET_NAMESTORE_ZoneIterator *list_it;

/**
 * Run in read from stdin mode.
 */
static int read_from_stdin;

/**
 * Desired action is to list records.
 */
static int list;

/**
 * Desired action is to add a record.
 */
static int add;

/**
 * Desired action is to remove a record.
 */
static int del;

/**
 * Is record public (opposite of #GNUNET_GNSRECORD_RF_PRIVATE)
 */
static int is_public;

/**
 * Is record a shadow record (#GNUNET_GNSRECORD_RF_SHADOW)
 */
static int is_shadow;

/**
 * Is record a maintenance record (#GNUNET_GNSRECORD_RF_MAINTENANCE)
 */
static int is_maintenance;

/**
 * Filter private records
 */
static int omit_private;

/**
 * Output in recordline format
 */
static int output_recordline;


/**
 * Purge zone contents
 */
static int purge_zone;

/**
 * Do not filter maintenance records
 */
static int include_maintenance;

/**
 * Purge orphaned records
 */
static int purge_orphaned;

/**
 * List records and zone keys of orphaned records
 */
static int list_orphaned;

/**
 * Queue entry for the 'del' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *del_qe;

/**
 * Queue entry for the 'set/replace' operation.
 */
static struct GNUNET_NAMESTORE_QueueEntry *set_qe;

/**
 * Queue entry for begin/commit
 */
static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

/**
 * Name of the records to add/list/remove.
 */
static char *name;

/**
 * Value of the record to add/remove.
 */
static char *value;

/**
 * URI to import.
 */
static char *uri;

/**
 * Reverse lookup to perform.
 */
static char *reverse_pkey;

/**
 * Type of the record to add/remove, NULL to remove all.
 */
static char *typestring;

/**
 * Desired expiration time.
 */
static char *expirationstring;

/**
 * Desired nick name.
 */
static char *nickstring;

/**
 * Global return value
 */
static int ret;

/**
 * Type string converted to DNS type value.
 */
static uint32_t type;

/**
 * Value in binary format.
 */
static void *data;

/**
 * Number of bytes in #data.
 */
static size_t data_size;

/**
 * Expiration string converted to numeric value.
 */
static uint64_t etime;

/**
 * Is expiration time relative or absolute time?
 */
static int etime_is_rel = GNUNET_SYSERR;

/**
 * Monitor handle.
 */
static struct GNUNET_NAMESTORE_ZoneMonitor *zm;

/**
 * Enables monitor mode.
 */
static int monitor;

/**
 * Entry in record set for processing records in bulk.
 */
static struct RecordSetEntry *recordset;

/**
 * Purge task
 */
static struct GNUNET_SCHEDULER_Task *purge_task;

/* FIXME: Make array and grow as needed */
#define INITIAL_RI_BUFFER_SIZE 5000

static unsigned int ri_count = 0;

static struct GNUNET_NAMESTORE_RecordInfo *record_info;

/** Maximum capacity of record_info array **/
static unsigned int record_info_capacity = 0;

/* How many records to put simulatneously */
static unsigned int max_batch_size = 1000;

/**
 * Parse expiration time.
 *
 * @param expirationstring text to parse
 * @param[out] etime_is_rel set to #GNUNET_YES if time is relative
 * @param[out] etime set to expiration time (abs or rel)
 * @return #GNUNET_OK on success
 */
static int
parse_expiration (const char *exp_str,
                  int *is_rel,
                  uint64_t *exptime)
{
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute etime_abs;

  if (0 == strcmp (exp_str, "never"))
  {
    *exptime = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
    *is_rel = GNUNET_NO;
    return GNUNET_OK;
  }
  if (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_relative (exp_str, &etime_rel))
  {
    *is_rel = GNUNET_YES;
    *exptime = etime_rel.rel_value_us;
    if (GNUNET_TIME_relative_cmp (etime_rel, <, WARN_RELATIVE_EXPIRATION_LIMIT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Relative expiration times of less than %s are not recommended. To improve availability, consider increasing this value.\n",
                  GNUNET_STRINGS_relative_time_to_string (
                    WARN_RELATIVE_EXPIRATION_LIMIT, GNUNET_NO));
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing record with relative expiration time of %s\n",
                GNUNET_STRINGS_relative_time_to_string (etime_rel, GNUNET_NO));
    return GNUNET_OK;
  }
  if (GNUNET_OK ==
      GNUNET_STRINGS_fancy_time_to_absolute (exp_str, &etime_abs))
  {
    *is_rel = GNUNET_NO;
    *exptime = etime_abs.abs_value_us;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing record with absolute expiration time of %s\n",
                GNUNET_STRINGS_absolute_time_to_string (etime_abs));
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


static int
parse_recordline (const char *line)
{
  struct RecordSetEntry *r;
  struct GNUNET_GNSRECORD_Data record;
  char *cp;
  char *tok;
  char *saveptr;
  void *raw_data;

  cp = GNUNET_strdup (line);
  tok = strtok_r (cp, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Missing entries in record line `%s'.\n"),
                line);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  record.record_type = GNUNET_GNSRECORD_typename_to_number (tok);
  if (UINT32_MAX == record.record_type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Unknown record type `%s'\n"), tok);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  tok = strtok_r (NULL, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Empty record line argument is not allowed.\n"));
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  if (1 != sscanf (tok, "%" SCNu64, &record.expiration_time))
  {
    fprintf (stderr,
             _ ("Error parsing expiration time %s.\n"), tok);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  tok = strtok_r (NULL, " ", &saveptr);
  if (NULL == tok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Empty record line argument is not allowed.\n"));
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  record.flags = GNUNET_GNSRECORD_RF_NONE;
  if (NULL != strchr (tok, (unsigned char) 'r'))
    record.flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  if (NULL == strchr (tok, (unsigned char) 'p')) /* p = public */
    record.flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  if (NULL != strchr (tok, (unsigned char) 'S'))
    record.flags |= GNUNET_GNSRECORD_RF_SUPPLEMENTAL;
  if (NULL != strchr (tok, (unsigned char) 's'))
    record.flags |= GNUNET_GNSRECORD_RF_SHADOW;
  if (NULL != strchr (tok, (unsigned char) 'C'))
    record.flags |= GNUNET_GNSRECORD_RF_CRITICAL;
  tok += strlen (tok) + 1;
  if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (record.record_type,
                                                     tok,
                                                     &raw_data,
                                                     &record.data_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Invalid record data for type %s: `%s'.\n"),
                GNUNET_GNSRECORD_number_to_typename (record.record_type),
                tok);
    GNUNET_free (cp);
    return GNUNET_SYSERR;
  }
  GNUNET_free (cp);

  r = GNUNET_malloc (sizeof(struct RecordSetEntry) + record.data_size);
  r->next = recordset;
  record.data = &r[1];
  memcpy (&r[1], raw_data, record.data_size);
  GNUNET_free (raw_data);
  r->record = record;
  recordset = r;
  return GNUNET_OK;
}


static void
clear_recordset ()
{
  struct RecordSetEntry *rs_entry;

  while (NULL != (rs_entry = recordset))
  {
    recordset = recordset->next;
    GNUNET_free (rs_entry);
  }
  recordset = NULL;
}


static void
reset_handles (void)
{
  struct MarkedRecord *mrec;
  struct MarkedRecord *mrec_tmp;
  clear_recordset ();
  if (NULL != ego_name)
  {
    GNUNET_free (ego_name);
    ego_name = NULL;
  }
  if (NULL != name)
  {
    GNUNET_free (name);
    name = NULL;
  }
  if (NULL != value)
  {
    GNUNET_free (value);
    value = NULL;
  }
  if (NULL != uri)
  {
    GNUNET_free (uri);
    uri = NULL;
  }
  if (NULL != expirationstring)
  {
    GNUNET_free (expirationstring);
    expirationstring = NULL;
  }
  if (NULL != purge_task)
  {
    GNUNET_SCHEDULER_cancel (purge_task);
    purge_task = NULL;
  }
  for (mrec = marked_head; NULL != mrec;)
  {
    mrec_tmp = mrec;
    mrec = mrec->next;
    GNUNET_free (mrec_tmp->name);
    GNUNET_free (mrec_tmp);
  }
  if (NULL != list_it)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (list_it);
    list_it = NULL;
  }
  if (NULL != add_qe)
  {
    GNUNET_NAMESTORE_cancel (add_qe);
    add_qe = NULL;
  }
  if (NULL != set_qe)
  {
    GNUNET_NAMESTORE_cancel (set_qe);
    set_qe = NULL;
  }
  if (NULL != add_qe_uri)
  {
    GNUNET_NAMESTORE_cancel (add_qe_uri);
    add_qe_uri = NULL;
  }
  if (NULL != get_qe)
  {
    GNUNET_NAMESTORE_cancel (get_qe);
    get_qe = NULL;
  }
  if (NULL != del_qe)
  {
    GNUNET_NAMESTORE_cancel (del_qe);
    del_qe = NULL;
  }
  if (NULL != reverse_qe)
  {
    GNUNET_NAMESTORE_cancel (reverse_qe);
    reverse_qe = NULL;
  }
  memset (&zone_pkey, 0, sizeof(zone_pkey));
  if (NULL != zm)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (zm);
    zm = NULL;
  }
  if (NULL != data)
  {
    GNUNET_free (data);
    data = NULL;
  }
  if (NULL != typestring)
  {
    GNUNET_free (typestring);
    typestring = NULL;
  }
  list = 0;
  is_public = 0;
  is_shadow = 0;
  is_maintenance = 0;
  purge_zone = 0;
}


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;
  (void) cls;

  reset_handles ();
  if (NULL != record_info)
    GNUNET_free (record_info);
  record_info = NULL;
  if (NULL != ns_qe)
  {
    GNUNET_NAMESTORE_cancel (ns_qe);
    ns_qe = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
  if (NULL != idh)
  {
    GNUNET_IDENTITY_disconnect (idh);
    idh = NULL;
  }
  for (ego_entry = ego_head; NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp);
  }
}


static void
process_command_stdin (void);

static unsigned int ri_sent = 0;

/**
 * We have obtained the zone's private key, so now process
 * the main commands using it.
 *
 * @param cfg configuration to use
 */
static void
batch_insert_recordinfo (const struct GNUNET_CONFIGURATION_Handle *cfg);

static void
finish_command (void)
{
  // if (ri_sent < ri_count)
  // {
  //  batch_insert_recordinfo (cfg);
  //  return;
  // }
  // reset_handles ();
  if (read_from_stdin)
  {
    process_command_stdin ();
    return;
  }
  GNUNET_SCHEDULER_shutdown ();
}


static void
add_continuation (void *cls, enum GNUNET_ErrorCode ec)
{
  struct GNUNET_NAMESTORE_QueueEntry **qe = cls;

  *qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr,
             _ ("Adding record failed: %s\n"),
             GNUNET_ErrorCode_get_hint (ec));
    if (GNUNET_EC_NAMESTORE_RECORD_EXISTS != ec)
      ret = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ret = 0;
  finish_command ();
}


static void
del_continuation (void *cls, enum GNUNET_ErrorCode ec)
{
  (void) cls;
  del_qe = NULL;
  if (GNUNET_EC_NAMESTORE_RECORD_NOT_FOUND == ec)
  {
    fprintf (stderr,
             _ ("Deleting record failed: %s\n"), GNUNET_ErrorCode_get_hint (
               ec));
  }
  finish_command ();
}


static void
purge_next_record (void *cls);

static void
marked_deleted (void *cls, enum GNUNET_ErrorCode ec)
{
  del_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    fprintf (stderr,
             _ ("Deleting record failed: %s\n"),
             GNUNET_ErrorCode_get_hint (ec));
  }
  purge_task = GNUNET_SCHEDULER_add_now (&purge_next_record, NULL);
}


static void
purge_next_record (void *cls)
{
  struct MarkedRecord *mrec;
  purge_task = NULL;

  if (NULL == marked_head)
  {
    ret = 0;
    finish_command ();
    return;
  }
  mrec = marked_head;
  GNUNET_CONTAINER_DLL_remove (marked_head,
                               marked_tail,
                               mrec);
  del_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                              &mrec->key,
                                              mrec->name,
                                              0, NULL,
                                              &marked_deleted,
                                              NULL);
  GNUNET_free (mrec->name);
  GNUNET_free (mrec);
}


/**
 * Function called when we are done with a zone iteration.
 */
static void
zone_iteration_finished (void *cls)
{
  (void) cls;
  list_it = NULL;
  if (purge_orphaned || purge_zone)
  {
    purge_task = GNUNET_SCHEDULER_add_now (&purge_next_record, NULL);
    return;
  }
  ret = 0;
  finish_command ();
}


/**
 * Function called when we encountered an error in a zone iteration.
 */
static void
zone_iteration_error_cb (void *cls)
{
  (void) cls;
  list_it = NULL;
  fprintf (stderr, "Error iterating over zone\n");
  ret = 1;
  finish_command ();
}


static void
collect_zone_records_to_purge (const struct
                               GNUNET_CRYPTO_PrivateKey *zone_key,
                               const char *rname,
                               unsigned int rd_len,
                               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct MarkedRecord *mrec;

  mrec = GNUNET_new (struct MarkedRecord);
  mrec->key = *zone_key;
  mrec->name = GNUNET_strdup (rname);
  GNUNET_CONTAINER_DLL_insert (marked_head,
                               marked_tail,
                               mrec);
}


static void
collect_orphans (const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                 const char *rname,
                 unsigned int rd_len,
                 const struct GNUNET_GNSRECORD_Data *rd)
{
  struct EgoEntry *ego;
  struct MarkedRecord *orphan;
  int is_orphaned = 1;

  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == memcmp (GNUNET_IDENTITY_ego_get_private_key (ego->ego),
                     zone_key,
                     sizeof (*zone_key)))
    {
      is_orphaned = 0;
      break;
    }
  }
  if (is_orphaned)
  {
    orphan = GNUNET_new (struct MarkedRecord);
    orphan->key = *zone_key;
    orphan->name = GNUNET_strdup (rname);
    GNUNET_CONTAINER_DLL_insert (marked_head,
                                 marked_tail,
                                 orphan);
  }
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record (const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                const char *rname,
                unsigned int rd_len,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typestr;
  char *s;
  const char *ets;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;
  struct EgoEntry *ego;
  int have_record;
  int is_orphaned = 1;
  char *orphaned_str;

  if ((NULL != name) && (0 != strcmp (name, rname)))
    return;
  have_record = GNUNET_NO;
  for (unsigned int i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
        (0 != strcmp (rname, GNUNET_GNS_EMPTY_LABEL_AT)))
      continue;
    if ((type != rd[i].record_type) && (GNUNET_GNSRECORD_TYPE_ANY != type))
      continue;
    have_record = GNUNET_YES;
    break;
  }
  if (GNUNET_NO == have_record)
    return;
  for (ego = ego_head; NULL != ego; ego = ego->next)
  {
    if (0 == memcmp (GNUNET_IDENTITY_ego_get_private_key (ego->ego),
                     zone_key,
                     sizeof (*zone_key)))
    {
      is_orphaned = 0;
      break;
    }
  }
  if (list_orphaned && ! is_orphaned)
    return;
  if (! list_orphaned && is_orphaned)
    return;
  orphaned_str = GNUNET_CRYPTO_private_key_to_string (zone_key);
  fprintf (stdout, "%s.%s:\n", rname, is_orphaned ? orphaned_str :
           ego->identifier);
  GNUNET_free (orphaned_str);
  if (NULL != typestring)
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
  else
    type = GNUNET_GNSRECORD_TYPE_ANY;
  for (unsigned int i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
        (0 != strcmp (rname, GNUNET_GNS_EMPTY_LABEL_AT)))
      continue;
    if ((type != rd[i].record_type) && (GNUNET_GNSRECORD_TYPE_ANY != type))
      continue;
    typestr = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    s = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                          rd[i].data,
                                          rd[i].data_size);
    if (NULL == s)
    {
      fprintf (stdout,
               _ ("\tCorrupt or unsupported record of type %u\n"),
               (unsigned int) rd[i].record_type);
      continue;
    }
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value_us = rd[i].expiration_time;
      ets = GNUNET_STRINGS_relative_time_to_string (rt, GNUNET_YES);
    }
    else
    {
      at.abs_value_us = rd[i].expiration_time;
      ets = GNUNET_STRINGS_absolute_time_to_string (at);
    }
    {
      char flgstr[16];
      sprintf (flgstr, "[%s%s%s%s%s]",
               (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE) ? "" : "p",
               (rd[i].flags & GNUNET_GNSRECORD_RF_SUPPLEMENTAL) ? "S" : "",
               (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION) ? "r" :
               "",
               (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW) ? "S" : "",
               (rd[i].flags & GNUNET_GNSRECORD_RF_CRITICAL) ? "C" : "");
      if (output_recordline)
        fprintf (stdout,
                 "  %s %" PRIu64 " %s %s\n",
                 typestr,
                 rd[i].expiration_time,
                 flgstr,
                 s);
      else
        fprintf (stdout,
                 "\t%s: %s (%s)\t%s\t%s\t%s\n",
                 typestr,
                 s,
                 ets,
                 (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE)) ? "PRIVATE"
             : "PUBLIC",
                 (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW)) ? "SHADOW"
               : "",
                 (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_MAINTENANCE)) ?
                 "MAINTENANCE"
             : "");
      GNUNET_free (s);
    }
  }
  // fprintf (stdout, "%s", "\n");
}


static void
purge_zone_iterator (void *cls,
                     const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                     const char *rname,
                     unsigned int rd_len,
                     const struct GNUNET_GNSRECORD_Data *rd,
                     struct GNUNET_TIME_Absolute expiry)
{
  (void) cls;
  (void) zone_key;
  (void) expiry;
  collect_zone_records_to_purge (zone_key, rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_iterator_next (list_it, 1);
}


static void
purge_orphans_iterator (void *cls,
                        const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                        const char *rname,
                        unsigned int rd_len,
                        const struct GNUNET_GNSRECORD_Data *rd,
                        struct GNUNET_TIME_Absolute expiry)
{
  (void) cls;
  (void) zone_key;
  (void) expiry;
  collect_orphans (zone_key, rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_iterator_next (list_it, 1);
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key private key of the zone
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record_iterator (void *cls,
                         const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                         const char *rname,
                         unsigned int rd_len,
                         const struct GNUNET_GNSRECORD_Data *rd,
                         struct GNUNET_TIME_Absolute expiry)
{
  (void) cls;
  (void) zone_key;
  (void) expiry;
  display_record (zone_key, rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_iterator_next (list_it, 1);
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key private key of the zone
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record_monitor (void *cls,
                        const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                        const char *rname,
                        unsigned int rd_len,
                        const struct GNUNET_GNSRECORD_Data *rd,
                        struct GNUNET_TIME_Absolute expiry)
{
  (void) cls;
  (void) zone_key;
  (void) expiry;
  display_record (zone_key, rname, rd_len, rd);
  GNUNET_NAMESTORE_zone_monitor_next (zm, 1);
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key private key of the zone
 * @param rname name that is being mapped (at most 255 characters long)
 * @param rd_len number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
display_record_lookup (void *cls,
                       const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                       const char *rname,
                       unsigned int rd_len,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  (void) cls;
  (void) zone_key;
  get_qe = NULL;
  display_record (zone_key, rname, rd_len, rd);
  finish_command ();
}


/**
 * Function called once we are in sync in monitor mode.
 *
 * @param cls NULL
 */
static void
sync_cb (void *cls)
{
  (void) cls;
  fprintf (stdout, "%s", "Monitor is now in sync.\n");
}


/**
 * Function called on errors while monitoring.
 *
 * @param cls NULL
 */
static void
monitor_error_cb (void *cls)
{
  (void) cls;
  fprintf (stderr, "%s", "Monitor disconnected and out of sync.\n");
}


/**
 * Function called on errors while monitoring.
 *
 * @param cls NULL
 */
static void
lookup_error_cb (void *cls)
{
  (void) cls;
  get_qe = NULL;
  fprintf (stderr, "%s", "Failed to lookup record.\n");
  finish_command ();
}


/**
 * Function called if lookup fails.
 */
static void
add_error_cb (void *cls)
{
  (void) cls;
  add_qe = NULL;
  GNUNET_break (0);
  ret = 1;
  finish_command ();
}


/**
 * We're storing a record; this function is given the existing record
 * so that we can merge the information.
 *
 * @param cls closure, unused
 * @param zone_key private key of the zone
 * @param rec_name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
get_existing_record (void *cls,
                     const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                     const char *rec_name,
                     unsigned int rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rdn[rd_count + 1];
  struct GNUNET_GNSRECORD_Data *rde;

  (void) cls;
  (void) zone_key;
  add_qe = NULL;
  if (0 != strcmp (rec_name, name))
  {
    GNUNET_break (0);
    ret = 1;
    finish_command ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u records for name `%s'\n",
              rd_count,
              rec_name);
  for (unsigned int i = 0; i < rd_count; i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_SOA:
      if (GNUNET_DNSPARSER_TYPE_SOA == type)
      {
        fprintf (
          stderr,
          _ (
            "A SOA record exists already under `%s', cannot add a second SOA to the same zone.\n"),
          rec_name);
        ret = 1;
        finish_command ();
        return;
      }
      break;
    }
  }
  memset (rdn, 0, sizeof(struct GNUNET_GNSRECORD_Data));
  GNUNET_memcpy (&rdn[1], rd, rd_count * sizeof(struct GNUNET_GNSRECORD_Data));
  rde = &rdn[0];
  rde->data = data;
  rde->data_size = data_size;
  rde->record_type = type;
  if (1 == is_shadow)
    rde->flags |= GNUNET_GNSRECORD_RF_SHADOW;
  if (1 == is_maintenance)
    rde->flags |= GNUNET_GNSRECORD_RF_MAINTENANCE;
  if (1 != is_public)
    rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  rde->expiration_time = etime;
  if (GNUNET_YES == etime_is_rel)
    rde->flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  else if (GNUNET_NO != etime_is_rel)
    rde->expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  GNUNET_assert (NULL != name);
  add_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                              &zone_pkey,
                                              name,
                                              rd_count + 1,
                                              rde,
                                              &add_continuation,
                                              &add_qe);
}


/**
 * Function called if we encountered an error in zone-to-name.
 */
static void
reverse_error_cb (void *cls)
{
  (void) cls;
  reverse_qe = NULL;
  fprintf (stdout, "%s.zkey\n", reverse_pkey);
}


/**
 * Function called with the result of our attempt to obtain a name for a given
 * public key.
 *
 * @param cls NULL
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
handle_reverse_lookup (void *cls,
                       const struct GNUNET_CRYPTO_PrivateKey *zone,
                       const char *label,
                       unsigned int rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  (void) cls;
  (void) zone;
  (void) rd_count;
  (void) rd;
  reverse_qe = NULL;
  if (NULL == label)
    fprintf (stdout, "%s\n", reverse_pkey);
  else
    fprintf (stdout, "%s.%s\n", label, ego_name);
  finish_command ();
}


/**
 * Function called if lookup for deletion fails.
 */
static void
del_lookup_error_cb (void *cls)
{
  (void) cls;
  del_qe = NULL;
  GNUNET_break (0);
  ret = 1;
  finish_command ();
}


/**
 * We were asked to delete something; this function is called with
 * the existing records. Now we should determine what should be
 * deleted and then issue the deletion operation.
 *
 * @param cls NULL
 * @param zone private key of the zone we are deleting from
 * @param label name of the records we are editing
 * @param rd_count size of the @a rd array
 * @param rd existing records
 */
static void
del_monitor (void *cls,
             const struct GNUNET_CRYPTO_PrivateKey *zone,
             const char *label,
             unsigned int rd_count,
             const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data rdx[rd_count];
  unsigned int rd_left;
  uint32_t del_type;
  char *vs;

  (void) cls;
  (void) zone;
  del_qe = NULL;
  if (0 == rd_count)
  {
    fprintf (stderr,
             _ (
               "There are no records under label `%s' that could be deleted.\n")
             ,
             label);
    ret = 1;
    finish_command ();
    return;
  }
  if ((NULL == value) && (NULL == typestring))
  {
    /* delete everything */
    del_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                                &zone_pkey,
                                                name,
                                                0,
                                                NULL,
                                                &del_continuation,
                                                NULL);
    return;
  }
  rd_left = 0;
  if (NULL != typestring)
    del_type = GNUNET_GNSRECORD_typename_to_number (typestring);
  else
    del_type = GNUNET_GNSRECORD_TYPE_ANY;
  for (unsigned int i = 0; i < rd_count; i++)
  {
    vs = NULL;
    if (! (((GNUNET_GNSRECORD_TYPE_ANY == del_type) ||
            (rd[i].record_type == del_type)) &&
           ((NULL == value) ||
            (NULL ==
             (vs = (GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                      rd[i].data,
                                                      rd[i].data_size)))) ||
            (0 == strcmp (vs, value)))))
      rdx[rd_left++] = rd[i];
    GNUNET_free (vs);
  }
  if (rd_count == rd_left)
  {
    /* nothing got deleted */
    fprintf (
      stderr,
      _ (
        "There are no records under label `%s' that match the request for deletion.\n"),
      label);
    finish_command ();
    return;
  }
  /* delete everything but what we copied to 'rdx' */
  del_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                              &zone_pkey,
                                              name,
                                              rd_left,
                                              rdx,
                                              &del_continuation,
                                              NULL);
}


static void
schedule_finish (void*cls)
{
  finish_command ();
}


static void
replace_cont (void *cls, enum GNUNET_ErrorCode ec)
{
  (void) cls;

  set_qe = NULL;
  if (GNUNET_EC_NONE != ec)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                _ ("%s\n"),
                GNUNET_ErrorCode_get_hint (ec));
    ret = 1;   /* fail from 'main' */
  }
  GNUNET_SCHEDULER_add_now (&schedule_finish, NULL);
}


/**
 * We have obtained the zone's private key, so now process
 * the main commands using it.
 *
 * @param cfg configuration to use
 */
static void
batch_insert_recordinfo (const struct GNUNET_CONFIGURATION_Handle *batch_cfg)
{
  unsigned int sent_here;

  GNUNET_assert (0 != ri_count);
  set_qe = GNUNET_NAMESTORE_records_store (ns,
                                           &zone_pkey,
                                           ri_count - ri_sent,
                                           record_info + ri_sent,
                                           &sent_here,
                                           &replace_cont,
                                           NULL);
  ri_sent += sent_here;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent %d/%d record infos\n", ri_sent,
              ri_count);
  if (ri_sent == ri_count)
  {
    for (int i = 0; i < ri_count; i++)
    {
      GNUNET_free (record_info[i].a_rd);
      record_info[i].a_rd = NULL;
    }
    ri_count = 0;
    ri_sent = 0;
  }
  return;
}


/**
 * We have obtained the zone's private key, so now process
 * the main commands using it.
 *
 * @param cfg configuration to use
 */
static void
run_with_zone_pkey (const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  struct GNUNET_GNSRECORD_Data rd;
  enum GNUNET_GNSRECORD_Filter filter_flags = GNUNET_GNSRECORD_FILTER_NONE;

  if (omit_private)
    filter_flags |= GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE;
  if (include_maintenance)
    filter_flags |= GNUNET_GNSRECORD_FILTER_INCLUDE_MAINTENANCE;
  if (! (add | del | list | (NULL != nickstring) | (NULL != uri)
         | (NULL != reverse_pkey) | (NULL != recordset) | (monitor)
         | (purge_orphaned) | (list_orphaned) | (purge_zone)) )
  {
    /* nothing more to be done */
    fprintf (stderr, _ ("No options given\n"));
    finish_command ();
    return;
  }

  if (NULL != recordset)
  {
    /* replace entire record set */
    unsigned int rd_count;
    struct GNUNET_GNSRECORD_Data *rd_tmp;

    /* FIXME: We could easily support append and delete with this as well */
    if (! add)
    {
      fprintf (stderr, _ ("Recordlines only work with option `%s'\n"),
               "-a");
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-n",
               _ ("name"));
      ret = 1;
      finish_command ();
      return;
    }
    rd_count = 0;
    for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
      rd_count++;
    rd_tmp = GNUNET_new_array (rd_count, struct GNUNET_GNSRECORD_Data);
    rd_count = 0;
    for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
    {
      rd_tmp[rd_count] = e->record;
      rd_count++;
    }
    set_qe = GNUNET_NAMESTORE_record_set_store (ns,
                                                &zone_pkey,
                                                name,
                                                rd_count,
                                                rd_tmp,
                                                &replace_cont,
                                                NULL);
    GNUNET_free (rd_tmp);
    return;
  }
  if (NULL != nickstring)
  {
    if (0 == strlen (nickstring))
    {
      fprintf (stderr, _ ("Invalid nick `%s'\n"), nickstring);
      ret = 1;
      finish_command ();
      return;
    }
    add = 1;
    typestring = GNUNET_strdup (GNUNET_GNSRECORD_number_to_typename (
                                  GNUNET_GNSRECORD_TYPE_NICK));
    name = GNUNET_strdup (GNUNET_GNS_EMPTY_LABEL_AT);
    value = GNUNET_strdup (nickstring);
    is_public = 0;
    expirationstring = GNUNET_strdup ("never");
    GNUNET_free (nickstring);
    nickstring = NULL;
  }

  if (add)
  {
    if (NULL == ego_name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-z",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-n",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == typestring)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-t",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    type = GNUNET_GNSRECORD_typename_to_number (typestring);
    if (UINT32_MAX == type)
    {
      fprintf (stderr, _ ("Unsupported type `%s'\n"), typestring);
      ret = 1;
      finish_command ();
      return;
    }
    if ((GNUNET_DNSPARSER_TYPE_SRV == type) ||
        (GNUNET_DNSPARSER_TYPE_TLSA == type) ||
        (GNUNET_DNSPARSER_TYPE_SMIMEA == type) ||
        (GNUNET_DNSPARSER_TYPE_OPENPGPKEY == type))
    {
      fprintf (stderr,
               _ (
                 "For DNS record types `SRV', `TLSA', `SMIMEA' and `OPENPGPKEY'"));
      fprintf (stderr, ", please use a `BOX' record instead\n");
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == value)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-V",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    if (GNUNET_OK !=
        GNUNET_GNSRECORD_string_to_value (type, value, &data, &data_size))
    {
      fprintf (stderr,
               _ ("Value `%s' invalid for record type `%s'\n"),
               value,
               typestring);
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == expirationstring)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-e",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    if (GNUNET_OK != parse_expiration (expirationstring, &etime_is_rel, &etime))
    {
      fprintf (stderr, _ ("Invalid time format `%s'\n"), expirationstring);
      ret = 1;
      finish_command ();
      return;
    }
    add_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                              &zone_pkey,
                                              name,
                                              &add_error_cb,
                                              NULL,
                                              &get_existing_record,
                                              NULL);
  }
  if (del)
  {
    if (NULL == ego_name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-z",
               _ ("del"));
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-n",
               _ ("del"));
      ret = 1;
      finish_command ();
      return;
    }
    del_qe = GNUNET_NAMESTORE_records_lookup2 (ns,
                                               &zone_pkey,
                                               name,
                                               &del_lookup_error_cb,
                                               NULL,
                                               &del_monitor,
                                               NULL,
                                               filter_flags);
  }
  if (purge_orphaned)
  {
    list_it = GNUNET_NAMESTORE_zone_iteration_start2 (ns,
                                                      NULL,
                                                      &zone_iteration_error_cb,
                                                      NULL,
                                                      &purge_orphans_iterator,
                                                      NULL,
                                                      &zone_iteration_finished,
                                                      NULL,
                                                      filter_flags);

  }
  else if (purge_zone)
  {
    if (NULL == ego_name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-z",
               _ ("purge-zone"));
      ret = 1;
      finish_command ();
      return;
    }
    list_it = GNUNET_NAMESTORE_zone_iteration_start2 (ns,
                                                      &zone_pkey,
                                                      &zone_iteration_error_cb,
                                                      NULL,
                                                      &purge_zone_iterator,
                                                      NULL,
                                                      &zone_iteration_finished,
                                                      NULL,
                                                      filter_flags);

  }
  else if (list || list_orphaned)
  {
    if (NULL != name)
    {
      if (NULL == ego_name)
      {
        fprintf (stderr,
                 _ ("Missing option `%s' for operation `%s'\n"),
                 "-z",
                 _ ("list"));
        ret = 1;
        finish_command ();
        return;
      }
      get_qe = GNUNET_NAMESTORE_records_lookup (ns,
                                                &zone_pkey,
                                                name,
                                                &lookup_error_cb,
                                                NULL,
                                                &display_record_lookup,
                                                NULL);
    }
    else
      list_it = GNUNET_NAMESTORE_zone_iteration_start2 (ns,
                                                        (NULL == ego_name) ?
                                                        NULL : &zone_pkey,
                                                        &zone_iteration_error_cb
                                                        ,
                                                        NULL,
                                                        &display_record_iterator
                                                        ,
                                                        NULL,
                                                        &zone_iteration_finished
                                                        ,
                                                        NULL,
                                                        filter_flags);
  }
  if (NULL != reverse_pkey)
  {
    struct GNUNET_CRYPTO_PublicKey pubkey;

    if (NULL == ego_name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-z",
               _ ("reverse-pkey"));
      ret = 1;
      finish_command ();
      return;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_public_key_from_string (reverse_pkey,
                                              &pubkey))
    {
      fprintf (stderr,
               _ ("Invalid public key for reverse lookup `%s'\n"),
               reverse_pkey);
      ret = 1;
      finish_command ();
      return;
    }
    reverse_qe = GNUNET_NAMESTORE_zone_to_name (ns,
                                                &zone_pkey,
                                                &pubkey,
                                                &reverse_error_cb,
                                                NULL,
                                                &handle_reverse_lookup,
                                                NULL);
  }
  if (NULL != uri)
  {
    char sh[105];
    char sname[64];
    struct GNUNET_CRYPTO_PublicKey pkey;
    if (NULL == ego_name)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-z",
               _ ("uri"));
      ret = 1;
      finish_command ();
      return;
    }

    memset (sh, 0, 105);
    memset (sname, 0, 64);

    if ((2 != (sscanf (uri, "gnunet://gns/%58s/%63s", sh, sname))) ||
        (GNUNET_OK !=
         GNUNET_CRYPTO_public_key_from_string (sh, &pkey)))
    {
      fprintf (stderr, _ ("Invalid URI `%s'\n"), uri);
      ret = 1;
      finish_command ();
      return;
    }
    if (NULL == expirationstring)
    {
      fprintf (stderr,
               _ ("Missing option `%s' for operation `%s'\n"),
               "-e",
               _ ("add"));
      ret = 1;
      finish_command ();
      return;
    }
    if (GNUNET_OK != parse_expiration (expirationstring, &etime_is_rel, &etime))
    {
      fprintf (stderr, _ ("Invalid time format `%s'\n"), expirationstring);
      ret = 1;
      finish_command ();
      return;
    }
    memset (&rd, 0, sizeof(rd));
    rd.data = &pkey;
    rd.data_size = GNUNET_CRYPTO_public_key_get_length (&pkey);
    rd.record_type = ntohl (pkey.type);
    rd.expiration_time = etime;
    if (GNUNET_YES == etime_is_rel)
      rd.flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
    if (1 == is_shadow)
      rd.flags |= GNUNET_GNSRECORD_RF_SHADOW;
    if (1 == is_maintenance)
      rd.flags |= GNUNET_GNSRECORD_RF_MAINTENANCE;
    add_qe_uri = GNUNET_NAMESTORE_record_set_store (ns,
                                                    &zone_pkey,
                                                    sname,
                                                    1,
                                                    &rd,
                                                    &add_continuation,
                                                    &add_qe_uri);
  }
  if (monitor)
  {
    zm = GNUNET_NAMESTORE_zone_monitor_start2 (cfg_,
                                               (NULL != ego_name) ?
                                               &zone_pkey : NULL,
                                               GNUNET_YES,
                                               &monitor_error_cb,
                                               NULL,
                                               &display_record_monitor,
                                               NULL,
                                               &sync_cb,
                                               NULL,
                                               filter_flags);
  }
}


#define MAX_LINE_LEN 4086

#define MAX_ARGS 20

static int
get_identity_for_string (const char *str,
                         struct GNUNET_CRYPTO_PrivateKey *zk)
{
  const struct GNUNET_CRYPTO_PrivateKey *privkey;
  struct GNUNET_CRYPTO_PublicKey pubkey;
  struct GNUNET_CRYPTO_PublicKey ego_pubkey;
  struct EgoEntry *ego_entry;

  if (GNUNET_OK == GNUNET_CRYPTO_public_key_from_string (str,
                                                         &pubkey))
  {
    for (ego_entry = ego_head;
         NULL != ego_entry; ego_entry = ego_entry->next)
    {
      privkey = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
      GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &ego_pubkey);
      if (0 == memcmp (&ego_pubkey, &pubkey, sizeof (pubkey)))
      {
        *zk = *privkey;
        return GNUNET_OK;
      }
    }
  }
  else
  {
    for (ego_entry = ego_head; NULL != ego_entry; ego_entry = ego_entry->next)
    {
      /** FIXME: Check for zTLD? **/
      if (0 != strcmp (str, ego_entry->identifier))
        continue;
      *zk = *GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
      return GNUNET_OK;
    }
  }
  return GNUNET_NO;
}


static void
process_command_stdin (void)
{
  char buf[MAX_LINE_LEN];
  static struct GNUNET_CRYPTO_PrivateKey next_zone_key;
  static char next_name[GNUNET_DNSPARSER_MAX_NAME_LENGTH];
  static int finished = GNUNET_NO;
  static int have_next_recordline = GNUNET_NO;
  int zonekey_set = GNUNET_NO;
  char *tmp;
  char *current_name = NULL;


  if (GNUNET_YES == have_next_recordline)
  {
    zone_pkey = next_zone_key;
    if (NULL != current_name)
      GNUNET_free (current_name);
    current_name = GNUNET_strdup (next_name);
    zonekey_set = GNUNET_YES;
  }
  while (NULL != fgets (buf, sizeof (buf), stdin))
  {
    if (1 >= strlen (buf))
      continue;
    if (buf[strlen (buf) - 1] == '\n')
      buf[strlen (buf) - 1] = '\0';
    /**
     * Check if this is a new name. If yes, and we have records, store them.
     */
    if (buf[strlen (buf) - 1] == ':')
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Switching to %s\n", buf);
      memset (next_name, 0, sizeof (next_name));
      strncpy (next_name, buf, strlen (buf) - 1);
      tmp = strchr (next_name, '.');
      if (NULL == tmp)
      {
        fprintf (stderr, "Error parsing name `%s'\n", next_name);
        GNUNET_SCHEDULER_shutdown ();
        ret = 1;
        return;
      }
      if (GNUNET_OK != get_identity_for_string (tmp + 1, &next_zone_key))
      {
        fprintf (stderr, "Error parsing zone name `%s'\n", tmp + 1);
        ret = 1;
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      *tmp = '\0';
      have_next_recordline = GNUNET_YES;
      /* Run a command for the previous record set */
      if (NULL != recordset)
      {
        if (ri_count >= record_info_capacity)
        {
          GNUNET_array_grow (record_info,
                             record_info_capacity,
                             record_info_capacity + max_batch_size);
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Recordinfo array grown to %u bytes!\n",
                      record_info_capacity);
        }
        record_info[ri_count].a_label = GNUNET_strdup (current_name);
        {
          int rd_count = 0;
          for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
            rd_count++;
          record_info[ri_count].a_rd = GNUNET_new_array (rd_count,
                                                         struct
                                                         GNUNET_GNSRECORD_Data);
          rd_count = 0;
          for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
          {
            record_info[ri_count].a_rd[rd_count] = e->record;
            record_info[ri_count].a_rd[rd_count].data = GNUNET_malloc (e->
                                                                       record.
                                                                       data_size);
            record_info[ri_count].a_rd[rd_count].data_size = e->record.
                                                             data_size;
            memcpy ((void*) record_info[ri_count].a_rd[rd_count].data,
                    e->record.data, e->record.data_size);
            rd_count++;
          }
          record_info[ri_count].a_rd_count = rd_count;
          ri_count++;
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Added %d records to record info\n", rd_count);
          clear_recordset ();
        }
        /* If the zone has changed, insert */
        /* If we have reached batch size, insert */
        if (0 != GNUNET_memcmp (&next_zone_key, &zone_pkey) ||
            (ri_count >= max_batch_size))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Batch inserting %d RI\n",
                      ri_count);
          batch_insert_recordinfo (cfg);
          return;
        }
      }
      zone_pkey = next_zone_key;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Switching from %s to %s\n",
                  current_name, next_name);
      if (NULL != current_name)
        GNUNET_free (current_name);
      current_name = GNUNET_strdup (next_name);
      zonekey_set = GNUNET_YES;
      continue;
    }
    if (GNUNET_NO == zonekey_set)
    {
      fprintf (stderr, "Warning, encountered recordline without zone\n");
      continue;
    }
    parse_recordline (buf);
  }
  if (GNUNET_NO == finished)
  {
    if (NULL != recordset)
    {
      if (GNUNET_YES == zonekey_set)
      {
        record_info[ri_count].a_label = GNUNET_strdup (current_name);
        {
          int rd_count = 0;
          for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
            rd_count++;
          record_info[ri_count].a_rd = GNUNET_new_array (rd_count,
                                                         struct
                                                         GNUNET_GNSRECORD_Data);
          rd_count = 0;
          for (struct RecordSetEntry *e = recordset; NULL != e; e = e->next)
          {
            record_info[ri_count].a_rd[rd_count] = e->record;
            record_info[ri_count].a_rd[rd_count].data = GNUNET_malloc (e->record
                                                                       .
                                                                       data_size);
            record_info[ri_count].a_rd[rd_count].data_size = e->record.data_size
            ;
            memcpy ((void*) record_info[ri_count].a_rd[rd_count].data,
                    e->record.data, e->record.data_size);
            rd_count++;
          }
          record_info[ri_count].a_rd_count = rd_count;
        }
        ri_count++;
        batch_insert_recordinfo (cfg);   /** One last time **/
        finished = GNUNET_YES;
        return;
      }
      fprintf (stderr, "Warning, encountered recordline without zone\n");
    }
  }
  if (ri_sent < ri_count)
  {
    batch_insert_recordinfo (cfg);
    return;
  }
  GNUNET_SCHEDULER_shutdown ();
  return;
}


/**
 * Function called with ALL of the egos known to the
 * identity service, used on startup if the user did
 * not specify a zone on the command-line.
 * Once the iteration is done (@a ego is NULL), we
 * ask for the default ego for "namestore".
 *
 * @param cls a `struct GNUNET_CONFIGURATION_Handle`
 * @param ego an ego, NULL for end of iteration
 * @param ctx NULL
 * @param name name associated with @a ego
 */
static void
id_connect_cb (void *cls,
               struct GNUNET_IDENTITY_Ego *ego,
               void **ctx,
               const char *ego_name_tmp)
{
  struct GNUNET_CRYPTO_PublicKey pk;
  struct EgoEntry *ego_entry;

  (void) ctx;
  (void) ego_name_tmp;
  if ((NULL != ego_name_tmp) && (NULL != ego))
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (ego_name_tmp);
    GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                      ego_tail,
                                      ego_entry);
    if ((NULL != ego_name) && (NULL != ego_name_tmp) &&
        (0 == strcmp (ego_name, ego_name_tmp)))
      zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
    return;
  }
  if (NULL != ego)
    return;
  if (read_from_stdin)
  {
    process_command_stdin ();
    return;
  }
  run_with_zone_pkey (cfg);
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
     const struct GNUNET_CONFIGURATION_Handle *_cfg)
{
  (void) cls;
  (void) args;
  (void) cfgfile;
  cfg = _cfg;
  if (NULL != args[0])
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ ("Superfluous command line arguments (starting with `%s') ignored\n"),
      args[0]);

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, (void *) cfg);
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    fprintf (stderr, _ ("Failed to connect to namestore\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  idh = GNUNET_IDENTITY_connect (cfg, &id_connect_cb, (void *) cfg);
  if (NULL == idh)
  {
    ret = -1;
    fprintf (stderr, _ ("Cannot connect to identity service\n"));
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * The main function for gnunet-namestore.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int lret;
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_flag ('a', "add", gettext_noop ("add record"), &add),
    GNUNET_GETOPT_option_flag ('d',
                               "delete",
                               gettext_noop ("delete record"),
                               &del),
    GNUNET_GETOPT_option_flag ('D',
                               "display",
                               gettext_noop ("display records"),
                               &list),
    GNUNET_GETOPT_option_flag ('S',
                               "from-stdin",
                               gettext_noop ("read commands from stdin"),
                               &read_from_stdin),
    GNUNET_GETOPT_option_string (
      'e',
      "expiration",
      "TIME",
      gettext_noop (
        "expiration time for record to use (for adding only), \"never\" is possible"),
      &expirationstring),
    GNUNET_GETOPT_option_string ('i',
                                 "nick",
                                 "NICKNAME",
                                 gettext_noop (
                                   "set the desired nick name for the zone"),
                                 &nickstring),
    GNUNET_GETOPT_option_flag ('m',
                               "monitor",
                               gettext_noop (
                                 "monitor changes in the namestore"),
                               &monitor),
    GNUNET_GETOPT_option_string ('n',
                                 "name",
                                 "NAME",
                                 gettext_noop (
                                   "name of the record to add/delete/display"),
                                 &name),
    GNUNET_GETOPT_option_flag ('r',
                               "recordline",
                               gettext_noop ("Output in recordline format"),
                               &output_recordline),
    GNUNET_GETOPT_option_string ('Z',
                                 "zone-to-name",
                                 "KEY",
                                 gettext_noop (
                                   "determine our name for the given KEY"),
                                 &reverse_pkey),
    GNUNET_GETOPT_option_string ('t',
                                 "type",
                                 "TYPE",
                                 gettext_noop (
                                   "type of the record to add/delete/display"),
                                 &typestring),
    GNUNET_GETOPT_option_string ('u',
                                 "uri",
                                 "URI",
                                 gettext_noop ("URI to import into our zone"),
                                 &uri),
    GNUNET_GETOPT_option_string ('V',
                                 "value",
                                 "VALUE",
                                 gettext_noop (
                                   "value of the record to add/delete"),
                                 &value),
    GNUNET_GETOPT_option_flag ('p',
                               "public",
                               gettext_noop ("create or list public record"),
                               &is_public),
    GNUNET_GETOPT_option_flag ('o',
                               "omit-private",
                               gettext_noop ("omit private records"),
                               &omit_private),
    GNUNET_GETOPT_option_flag ('T',
                               "include-maintenance",
                               gettext_noop (
                                 "do not filter maintenance records"),
                               &include_maintenance),
    GNUNET_GETOPT_option_flag ('P',
                               "purge-orphans",
                               gettext_noop (
                                 "purge namestore of all orphans"),
                               &purge_orphaned),
    GNUNET_GETOPT_option_flag ('O',
                               "list-orphans",
                               gettext_noop (
                                 "show private key for orphaned records for recovery using `gnunet-identity -C -P <key>'. Use in combination with --display"),
                               &list_orphaned),
    GNUNET_GETOPT_option_flag ('X',
                               "purge-zone-records",
                               gettext_noop (
                                 "delete all records in specified zone"),
                               &purge_zone),
    GNUNET_GETOPT_option_uint ('B',
                               "batch-size",
                               "NUMBER",
                               gettext_noop (
                                 "number of records to buffer and send as batch (for use with --from-stdin)"),
                               &max_batch_size),
    GNUNET_GETOPT_option_flag (
      's',
      "shadow",
      gettext_noop (
        "create shadow record (only valid if all other records of the same type have expired)"),
      &is_shadow),
    GNUNET_GETOPT_option_flag (
      'M',
      "maintenance",
      gettext_noop (
        "create maintenance record (e.g TOMBSTONEs)"),
      &is_maintenance),
    GNUNET_GETOPT_option_string ('z',
                                 "zone",
                                 "EGO",
                                 gettext_noop (
                                   "name of the ego controlling the zone"),
                                 &ego_name),
    GNUNET_GETOPT_OPTION_END };


  is_public = -1;
  is_shadow = -1;
  is_maintenance = -1;
  GNUNET_log_setup ("gnunet-namestore", "WARNING", NULL);
  if (GNUNET_OK !=
      (lret = GNUNET_PROGRAM_run (argc,
                                  argv,
                                  "gnunet-namestore",
                                  _ ("GNUnet zone manipulation tool"),
                                  options,
                                  &run,
                                  NULL)))
  {
    // FIXME
    // GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
    return lret;
  }
  // FIXME
  // GNUNET_CRYPTO_ecdsa_key_clear (&zone_pkey);
  return ret;
}


/* end of gnunet-namestore.c */
