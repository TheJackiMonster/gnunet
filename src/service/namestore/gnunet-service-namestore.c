/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2014, 2018 GNUnet e.V.

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "gnunet_error_codes.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_statistics_service.h"
#include "namestore.h"

#define LOG_STRERROR_FILE(kind, syscall, filename) \
        GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * If a monitor takes more than 1 minute to process an event, print a warning.
 */
#define MONITOR_STALL_WARN_DELAY GNUNET_TIME_UNIT_MINUTES

/**
 * Size of the cache used by #get_nick_record()
 */
#define NC_SIZE 16

/**
 * A namestore client
 */
struct NamestoreClient;


/**
 * A namestore iteration operation.
 */
struct ZoneIteration
{
  /**
   * Next element in the DLL
   */
  struct ZoneIteration *next;

  /**
   * Previous element in the DLL
   */
  struct ZoneIteration *prev;

  /**
   * Namestore client which intiated this zone iteration
   */
  struct NamestoreClient *nc;

  /**
   * The nick to add to the records
   */
  struct GNUNET_GNSRECORD_Data *nick;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_PrivateKey zone;

  /**
   * The record set filter
   */
  enum GNUNET_GNSRECORD_Filter filter;

  /**
   * Last sequence number in the zone iteration used to address next
   * result of the zone iteration in the store
   *
   * Initially set to 0.
   * Updated in #zone_iterate_proc()
   */
  uint64_t seq;

  /**
   * The operation id for the zone iteration in the response for the client
   */
  uint32_t request_id;

  /**
   * Offset of the zone iteration used to address next result of the zone
   * iteration in the store
   *
   * Initially set to 0 in #handle_iteration_start
   * Incremented with by every call to #handle_iteration_next
   */
  uint32_t offset;

  /**
   * Set to #GNUNET_YES if the last iteration exhausted the limit set by the
   * client and we should send the #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END
   * message and free the data structure.
   */
  int send_end;
};

/**
 * A namestore client
 */
struct NamestoreClient
{
  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Database handle for client
   */
  struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

  /**
   * Name of loaded plugin (neeed for cleanup)
   */
  char *db_lib_name;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct ZoneIteration *op_head;

  /**
   * Tail of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct ZoneIteration *op_tail;
};


/**
 * A namestore monitor.
 */
struct ZoneMonitor
{
  /**
   * Next element in the DLL
   */
  struct ZoneMonitor *next;

  /**
   * Previous element in the DLL
   */
  struct ZoneMonitor *prev;

  /**
   * Namestore client which intiated this zone monitor
   */
  struct NamestoreClient *nc;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_PrivateKey zone;

  /**
   * The record set filter
   */
  enum GNUNET_GNSRECORD_Filter filter;

  /**
   * Task active during initial iteration.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Task to warn about slow monitors.
   */
  struct GNUNET_SCHEDULER_Task *sa_wait_warning;

  /**
   * Since when are we blocked on this monitor?
   */
  struct GNUNET_TIME_Absolute sa_waiting_start;

  /**
   * Last sequence number in the zone iteration used to address next
   * result of the zone iteration in the store
   *
   * Initially set to 0.
   * Updated in #monitor_iterate_cb()
   */
  uint64_t seq;

  /**
   * Current limit of how many more messages we are allowed
   * to queue to this monitor.
   */
  uint64_t limit;

  /**
   * How many more requests may we receive from the iterator
   * before it is at the limit we gave it?  Will be below or
   * equal to @e limit.  The effective limit for monitor
   * events is thus @e iteration_cnt - @e limit!
   */
  uint64_t iteration_cnt;

  /**
   * Are we (still) in the initial iteration pass?
   */
  int in_first_iteration;

  /**
   * Run again because we skipped an orphan
   */
  int run_again;

  /**
   * Is there a store activity waiting for this monitor?  We only raise the
   * flag when it happens and search the DLL for the store activity when we
   * had a limit increase.  If we cannot find any waiting store activity at
   * that time, we clear the flag again.
   */
  int sa_waiting;
};


/**
 * Information for an ongoing #handle_record_store() operation.
 * Needed as we may wait for monitors to be ready for the notification.
 */
struct StoreActivity
{
  /**
   * Kept in a DLL.
   */
  struct StoreActivity *next;

  /**
   * Kept in a DLL.
   */
  struct StoreActivity *prev;

  /**
   * Which client triggered the store activity?
   */
  struct NamestoreClient *nc;

  /**
   * The request ID
   */
  uint32_t rid;

  /**
   * The currently processed record
   */
  uint16_t rd_set_pos;

  /**
   * The number of records in this activity
   */
  uint16_t rd_set_count;

  /**
   * The zone private key
   */
  struct GNUNET_CRYPTO_PrivateKey private_key;

  /**
   * Copy of the original record set (as data fields in @e rd will
   * point into it!).
   */
  const struct RecordSet *rs;

  /**
   * Next zone monitor that still needs to be notified about this PUT.
   */
  struct ZoneMonitor *zm_pos;

};


/**
 * Entry in list of cached nick resolutions.
 */
struct NickCache
{
  /**
   * Zone the cache entry is for.
   */
  struct GNUNET_CRYPTO_PrivateKey zone;

  /**
   * Cached record data.
   */
  struct GNUNET_GNSRECORD_Data *rd;

  /**
   * Timestamp when this cache entry was used last.
   */
  struct GNUNET_TIME_Absolute last_used;
};

/**
 * We cache nick records to reduce DB load.
 */
static struct NickCache nick_cache[NC_SIZE];

/**
 * Public key of all zeros.
 */
static const struct GNUNET_CRYPTO_PrivateKey zero;

/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;

/**
 * Name of the database plugin
 */
static char *db_lib_name;

/**
 * Database handle for service
 */
struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;


/**
 * First active zone monitor.
 */
static struct ZoneMonitor *monitor_head;

/**
 * Last active zone monitor.
 */
static struct ZoneMonitor *monitor_tail;

/**
 * Head of DLL of monitor-blocked store activities.
 */
static struct StoreActivity *sa_head;

/**
 * Tail of DLL of monitor-blocked store activities.
 */
static struct StoreActivity *sa_tail;

/**
 * Notification context shared by all monitors.
 */
static struct GNUNET_NotificationContext *monitor_nc;

/**
 * Returned orphaned records?
 */
static int return_orphaned;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
cleanup_task (void *cls)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping namestore service\n");
  if (NULL != monitor_nc)
  {
    GNUNET_notification_context_destroy (monitor_nc);
    monitor_nc = NULL;
  }
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics, GNUNET_NO);
    statistics = NULL;
  }
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
}


/**
 * Release memory used by @a sa.
 *
 * @param sa activity to free
 */
static void
free_store_activity (struct StoreActivity *sa)
{
  GNUNET_CONTAINER_DLL_remove (sa_head, sa_tail, sa);
  GNUNET_free (sa);
}


/**
 * Function called with the records for the #GNUNET_GNS_EMPTY_LABEL_AT
 * label in the zone.  Used to locate the #GNUNET_GNSRECORD_TYPE_NICK
 * record, which (if found) is then copied to @a cls for future use.
 *
 * @param cls a `struct GNUNET_GNSRECORD_Data **` for storing the nick (if found)
 * @param seq sequence number of the record, MUST NOT BE ZERO
 * @param private_key the private key of the zone (unused)
 * @param label should be #GNUNET_GNS_EMPTY_LABEL_AT
 * @param rd_count number of records in @a rd
 * @param rd records stored under @a label in the zone
 */
static void
lookup_nick_it (void *cls,
                uint64_t seq,
                const char *editor_hint,
                const struct GNUNET_CRYPTO_PrivateKey *private_key,
                const char *label,
                unsigned int rd_count,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_GNSRECORD_Data **res = cls;

  (void) private_key;
  GNUNET_assert (0 != seq);
  if (0 != strcmp (label, GNUNET_GNS_EMPTY_LABEL_AT))
  {
    GNUNET_break (0);
    return;
  }
  for (unsigned int c = 0; c < rd_count; c++)
  {
    if (GNUNET_GNSRECORD_TYPE_NICK == rd[c].record_type)
    {
      (*res) =
        GNUNET_malloc (rd[c].data_size + sizeof(struct GNUNET_GNSRECORD_Data));
      (*res)->data = &(*res)[1];
      GNUNET_memcpy ((void *) (*res)->data, rd[c].data, rd[c].data_size);
      (*res)->data_size = rd[c].data_size;
      (*res)->expiration_time = rd[c].expiration_time;
      (*res)->flags = rd[c].flags;
      (*res)->record_type = GNUNET_GNSRECORD_TYPE_NICK;
      return;
    }
  }
  (*res) = NULL;
}


/**
 * Add entry to the cache for @a zone and @a nick
 *
 * @param zone zone key to cache under
 * @param nick nick entry to cache
 */
static void
cache_nick (const struct GNUNET_CRYPTO_PrivateKey *zone,
            const struct GNUNET_GNSRECORD_Data *nick)
{
  struct NickCache *oldest;

  oldest = NULL;
  for (unsigned int i = 0; i < NC_SIZE; i++)
  {
    struct NickCache *pos = &nick_cache[i];

    if ((NULL == oldest) ||
        (oldest->last_used.abs_value_us > pos->last_used.abs_value_us))
      oldest = pos;
    if (0 == GNUNET_memcmp (zone, &pos->zone))
    {
      oldest = pos;
      break;
    }
  }
  GNUNET_free (oldest->rd);
  oldest->zone = *zone;
  if (NULL != nick)
  {
    oldest->rd = GNUNET_malloc (sizeof(*nick) + nick->data_size);
    *oldest->rd = *nick;
    oldest->rd->data = &oldest->rd[1];
    memcpy (&oldest->rd[1], nick->data, nick->data_size);
  }
  else
  {
    oldest->rd = NULL;
  }
  oldest->last_used = GNUNET_TIME_absolute_get ();
}


/**
 * Return the NICK record for the zone (if it exists).
 *
 * @param nc the namestore client
 * @param zone private key for the zone to look for nick
 * @return NULL if no NICK record was found
 */
static struct GNUNET_GNSRECORD_Data *
get_nick_record (const struct GNUNET_CRYPTO_PrivateKey *zone)
{
  struct GNUNET_CRYPTO_PublicKey pub;
  struct GNUNET_GNSRECORD_Data *nick;
  int res;

  /* check cache first */
  for (unsigned int i = 0; i < NC_SIZE; i++)
  {
    struct NickCache *pos = &nick_cache[i];
    if ((NULL != pos->rd) && (0 == GNUNET_memcmp (zone, &pos->zone)))
    {
      if (NULL == pos->rd)
        return NULL;
      nick = GNUNET_malloc (sizeof(*nick) + pos->rd->data_size);
      *nick = *pos->rd;
      nick->data = &nick[1];
      memcpy (&nick[1], pos->rd->data, pos->rd->data_size);
      pos->last_used = GNUNET_TIME_absolute_get ();
      return nick;
    }
  }

  nick = NULL;
  res = GSN_database->lookup_records (GSN_database->cls,
                                      zone,
                                      GNUNET_GNS_EMPTY_LABEL_AT,
                                      &lookup_nick_it,
                                      &nick);
  if ((GNUNET_OK != res) || (NULL == nick))
  {
#if ! defined(GNUNET_CULL_LOGGING)
    static int do_log = GNUNET_LOG_CALL_STATUS;

    if (0 == do_log)
      do_log = GNUNET_get_log_call_status (GNUNET_ERROR_TYPE_DEBUG,
                                           "namestore",
                                           __FILE__,
                                           __FUNCTION__,
                                           __LINE__);
    if (1 == do_log)
    {
      GNUNET_CRYPTO_key_get_public (zone, &pub);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "No nick name set for zone `%s'\n",
                  GNUNET_GNSRECORD_z2s (&pub));
    }
#endif
    /* update cache */
    cache_nick (zone, NULL);
    return NULL;
  }

  /* update cache */
  cache_nick (zone, nick);
  return nick;
}


/**
 * Merge the nick record @a nick_rd with the rest of the
 * record set given in @a rd2.  Store the result in @a rdc_res
 * and @a rd_res.  The @a nick_rd's expiration time is set to
 * the maximum expiration time of all of the records in @a rd2.
 *
 * @param nick_rd the nick record to integrate
 * @param rd2_length length of the @a rd2 array
 * @param rd2 array of records
 * @param[out] rdc_res length of the resulting @a rd_res array
 * @param[out] rd_res set to an array of records,
 *                    including @a nick_rd and @a rd2;
 *           all of the variable-size 'data' fields in @a rd2 are
 *           allocated in the same chunk of memory!
 */
static void
merge_with_nick_records (const struct GNUNET_GNSRECORD_Data *nick_rd,
                         unsigned int rd2_length,
                         const struct GNUNET_GNSRECORD_Data *rd2,
                         unsigned int *rdc_res,
                         struct GNUNET_GNSRECORD_Data **rd_res)
{
  uint64_t latest_expiration;
  size_t req;
  char *data;
  size_t data_offset;
  struct GNUNET_GNSRECORD_Data *target;

  (*rdc_res) = 1 + rd2_length;
  if (0 == 1 + rd2_length)
  {
    GNUNET_break (0);
    (*rd_res) = NULL;
    return;
  }
  req = sizeof(struct GNUNET_GNSRECORD_Data) + nick_rd->data_size;
  for (unsigned int i = 0; i < rd2_length; i++)
  {
    const struct GNUNET_GNSRECORD_Data *orig = &rd2[i];

    if (req + sizeof(struct GNUNET_GNSRECORD_Data) + orig->data_size < req)
    {
      GNUNET_break (0);
      (*rd_res) = NULL;
      return;
    }
    req += sizeof(struct GNUNET_GNSRECORD_Data) + orig->data_size;
  }
  target = GNUNET_malloc (req);
  (*rd_res) = target;
  data = (char *) &target[1 + rd2_length];
  data_offset = 0;
  latest_expiration = 0;
  for (unsigned int i = 0; i < rd2_length; i++)
  {
    const struct GNUNET_GNSRECORD_Data *orig = &rd2[i];

    if (0 != (orig->flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      if ((GNUNET_TIME_absolute_get ().abs_value_us + orig->expiration_time) >
          latest_expiration)
        latest_expiration = orig->expiration_time;
    }
    else if (orig->expiration_time > latest_expiration)
      latest_expiration = orig->expiration_time;
    target[i] = *orig;
    target[i].data = (void *) &data[data_offset];
    GNUNET_memcpy (&data[data_offset], orig->data, orig->data_size);
    data_offset += orig->data_size;
  }
  /* append nick */
  target[rd2_length] = *nick_rd;
  /* Mark as supplemental */
  target[rd2_length].flags = nick_rd->flags | GNUNET_GNSRECORD_RF_SUPPLEMENTAL;
  target[rd2_length].expiration_time = latest_expiration;
  target[rd2_length].data = (void *) &data[data_offset];
  GNUNET_memcpy (&data[data_offset], nick_rd->data, nick_rd->data_size);
  data_offset += nick_rd->data_size;
  GNUNET_assert (req == (sizeof(struct GNUNET_GNSRECORD_Data)) * (*rdc_res)
                 + data_offset);
}


/**
 * Generate a `struct LookupNameResponseMessage` and send it to the
 * given client using the given notification context.
 *
 * @param nc client to unicast to
 * @param request_id request ID to use
 * @param zone_key zone key of the zone
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd array of records
 * @param filter record set filter
 */
static int
send_lookup_response_with_filter (struct NamestoreClient *nc,
                                  uint32_t request_id,
                                  const struct
                                  GNUNET_CRYPTO_PrivateKey *zone_key,
                                  const char *name,
                                  unsigned int rd_count,
                                  const struct GNUNET_GNSRECORD_Data *rd,
                                  enum GNUNET_GNSRECORD_Filter filter)
{
  struct GNUNET_MQ_Envelope *env;
  struct RecordResultMessage *zir_msg;
  struct GNUNET_GNSRECORD_Data *nick;
  struct GNUNET_GNSRECORD_Data *res;
  struct GNUNET_GNSRECORD_Data rd_nf[rd_count];
  struct GNUNET_TIME_Absolute block_exp = GNUNET_TIME_UNIT_ZERO_ABS;;
  unsigned int res_count;
  unsigned int rd_nf_count;
  size_t name_len;
  size_t key_len;
  ssize_t rd_ser_len;
  char *name_tmp;
  char *rd_ser;
  char *emsg;

  nick = get_nick_record (zone_key);
  GNUNET_assert (-1 != GNUNET_GNSRECORD_records_get_size (rd_count, rd));

  if (GNUNET_OK != GNUNET_GNSRECORD_normalize_record_set (name,
                                                          rd,
                                                          rd_count,
                                                          rd_nf,
                                                          &rd_nf_count,
                                                          &block_exp,
                                                          filter,
                                                          &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GNUNET_free (emsg);
    GNUNET_assert (0);
  }

  /**
   * FIXME if we ever support GNUNET_NAMESTORE_OMIT_PUBLIC,
   * we need to omit adding this public record here
   */
  if ((NULL != nick) && (0 != strcmp (name, GNUNET_GNS_EMPTY_LABEL_AT)))
  {
    nick->flags =
      (nick->flags | GNUNET_GNSRECORD_RF_PRIVATE) ^ GNUNET_GNSRECORD_RF_PRIVATE;
    merge_with_nick_records (nick, rd_nf_count, rd_nf, &res_count, &res);
  }
  else
  {
    res_count = rd_nf_count;
    res = (struct GNUNET_GNSRECORD_Data *) rd_nf;
  }
  if (NULL != nick)
    GNUNET_free (nick);

  if (0 == res_count)
  {
    if (rd_nf != res)
      GNUNET_free (res);
    return 0;
  }
  GNUNET_assert (-1 != GNUNET_GNSRECORD_records_get_size (res_count, res));


  name_len = strlen (name) + 1;
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (res_count, res);
  if (rd_ser_len < 0)
  {
    if (rd_nf != res)
      GNUNET_free (res);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return 0;
  }
  if (((size_t) rd_ser_len) >= UINT16_MAX - name_len - sizeof(*zir_msg))
  {
    if (rd_nf != res)
      GNUNET_free (res);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return 0;
  }
  key_len = GNUNET_CRYPTO_private_key_get_length (zone_key);
  env = GNUNET_MQ_msg_extra (zir_msg,
                             name_len + rd_ser_len + key_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT);
  zir_msg->gns_header.r_id = htonl (request_id);
  zir_msg->name_len = htons (name_len);
  zir_msg->rd_count = htons (res_count);
  zir_msg->rd_len = htons ((uint16_t) rd_ser_len);
  zir_msg->key_len = htons (key_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (zone_key,
                                             &zir_msg[1],
                                             key_len);
  zir_msg->expire = GNUNET_TIME_absolute_hton (block_exp);
  name_tmp = (char *) &zir_msg[1] + key_len;
  GNUNET_memcpy (name_tmp, name, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_assert (
    rd_ser_len ==
    GNUNET_GNSRECORD_records_serialize (res_count, res, rd_ser_len, rd_ser));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RECORD_RESULT message with %u records\n",
              res_count);
  GNUNET_STATISTICS_update (statistics,
                            "Record sets sent to clients",
                            1,
                            GNUNET_NO);
  GNUNET_MQ_send (nc->mq, env);
  if (rd_nf != res)
    GNUNET_free (res);
  return res_count;
}


/**
 * Send response to the store request to the client.
 *
 * @param nc client to talk to
 * @param ec status of the operation
 * @param rid client's request ID
 */
static void
send_store_response (struct NamestoreClient *nc,
                     enum GNUNET_ErrorCode ec,
                     uint32_t rid)
{
  struct GNUNET_MQ_Envelope *env;
  struct NamestoreResponseMessage *rcr_msg;

  GNUNET_assert (NULL != nc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending GENERIC_RESPONSE message\n");
  GNUNET_STATISTICS_update (statistics,
                            "Store requests completed",
                            1,
                            GNUNET_NO);
  env = GNUNET_MQ_msg (rcr_msg,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE);
  rcr_msg->gns_header.r_id = htonl (rid);
  rcr_msg->ec = htonl (ec);
  GNUNET_MQ_send (nc->mq, env);
}


/**
 * Function called once we are done with the zone iteration and
 * allow the zone iteration client to send us more messages.
 *
 * @param zi zone iteration we are processing
 */
static void
zone_iteration_done_client_continue (struct ZoneIteration *zi)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAMESTORE_Header *em;

  GNUNET_SERVICE_client_continue (zi->nc->client);
  if (! zi->send_end)
    return;
  /* send empty response to indicate end of list */
  env = GNUNET_MQ_msg (em, GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END);
  em->r_id = htonl (zi->request_id);
  GNUNET_MQ_send (zi->nc->mq, env);

  GNUNET_CONTAINER_DLL_remove (zi->nc->op_head, zi->nc->op_tail, zi);
  GNUNET_free (zi);
}


/**
 * Print a warning that one of our monitors is no longer reacting.
 *
 * @param cls a `struct ZoneMonitor` to warn about
 */
static void
warn_monitor_slow (void *cls)
{
  struct ZoneMonitor *zm = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "No response from monitor since %s\n",
              GNUNET_STRINGS_absolute_time_to_string (zm->sa_waiting_start));
  zm->sa_wait_warning = GNUNET_SCHEDULER_add_delayed (MONITOR_STALL_WARN_DELAY,
                                                      &warn_monitor_slow,
                                                      zm);
}


/**
 * Continue processing the @a sa.
 *
 * @param sa store activity to process
 */
static int
continue_store_activity (struct StoreActivity *sa,
                         int call_continue)
{
  const struct RecordSet *rd_set = sa->rs;
  unsigned int rd_count;
  size_t name_len;
  size_t rd_ser_len;
  const char *name_tmp;
  const char *rd_ser;
  const char *buf;
  char *conv_name;

  buf = (const char *) &sa[1];
  for (int i = sa->rd_set_pos; i < sa->rd_set_count; i++)
  {
    rd_set = (struct RecordSet *) buf;
    name_len = ntohs (rd_set->name_len);
    rd_count = ntohs (rd_set->rd_count);
    rd_ser_len = ntohs (rd_set->rd_len);
    name_tmp = (const char *) &rd_set[1];
    rd_ser = &name_tmp[name_len];
    conv_name = GNUNET_GNSRECORD_string_normalize (name_tmp);
    GNUNET_assert (NULL != conv_name);
    {
      struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL (rd_count)];

      /* We did this before, must succeed again */
      GNUNET_assert (
        GNUNET_OK ==
        GNUNET_GNSRECORD_records_deserialize (rd_ser_len, rd_ser, rd_count,
                                              rd));

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Checking monitors watching for `%s'\n",
                  conv_name);
      for (struct ZoneMonitor *zm = sa->zm_pos; NULL != zm; zm = sa->zm_pos)
      {
        if ((0 != GNUNET_memcmp (&sa->private_key, &zm->zone)) &&
            (0 != GNUNET_memcmp (&zm->zone, &zero)))
        {
          sa->zm_pos = zm->next;   /* not interesting to this monitor */
          continue;
        }
        if (zm->limit == zm->iteration_cnt)
        {
          zm->sa_waiting = GNUNET_YES;
          zm->sa_waiting_start = GNUNET_TIME_absolute_get ();
          if (NULL != zm->sa_wait_warning)
            GNUNET_SCHEDULER_cancel (zm->sa_wait_warning);
          zm->sa_wait_warning =
            GNUNET_SCHEDULER_add_delayed (MONITOR_STALL_WARN_DELAY,
                                          &warn_monitor_slow,
                                          zm);
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Monitor is blocking client for `%s'\n",
                      conv_name);
          GNUNET_free (conv_name);
          return GNUNET_NO;    /* blocked on zone monitor */
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Notifying monitor about changes under label `%s'\n",
                    conv_name);
        if (0 < send_lookup_response_with_filter (zm->nc,
                                                  0,
                                                  &sa->private_key,
                                                  conv_name,
                                                  rd_count,
                                                  rd,
                                                  zm->filter))
          zm->limit--;
        sa->zm_pos = zm->next;
      }
      sa->rd_set_pos++;
      GNUNET_free (conv_name);
    }
  }
  if (GNUNET_YES == call_continue)
    GNUNET_SERVICE_client_continue (sa->nc->client);
  send_store_response (sa->nc, GNUNET_EC_NONE, sa->rid);
  free_store_activity (sa);
  return GNUNET_OK;
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx the `struct NamestoreClient` of @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct NamestoreClient *nc = app_ctx;
  struct ZoneIteration *no;
  struct StoreActivity *sa = sa_head;
  struct StoreActivity *sn;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected\n", client);
  for (struct ZoneMonitor *zm = monitor_head; NULL != zm; zm = zm->next)
  {
    if (nc != zm->nc)
      continue;
    GNUNET_CONTAINER_DLL_remove (monitor_head, monitor_tail, zm);
    if (NULL != zm->task)
    {
      GNUNET_SCHEDULER_cancel (zm->task);
      zm->task = NULL;
    }
    if (NULL != zm->sa_wait_warning)
    {
      GNUNET_SCHEDULER_cancel (zm->sa_wait_warning);
      zm->sa_wait_warning = NULL;
    }
    for (sa = sa_head; NULL != sa; sa = sn)
    {
      sn = sa->next;
      if (zm == sa->zm_pos)
      {
        sa->zm_pos = zm->next;
        /* this may free sa */
        continue_store_activity (sa, GNUNET_YES);
      }
    }
    GNUNET_free (zm);
    break;
  }
  sa = sa_head;
  while (NULL != sa)
  {
    if (nc != sa->nc)
    {
      sa = sa->next;
      continue;
    }
    sn = sa->next;
    free_store_activity (sa);
    sa = sn;
  }
  while (NULL != (no = nc->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
  }
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (nc->db_lib_name,
                                              nc->GSN_database));
  GNUNET_free (nc->db_lib_name);
  GNUNET_free (nc);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct NamestoreClient *nc;
  char *database;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", client);
  nc = GNUNET_new (struct NamestoreClient);
  nc->client = client;
  nc->mq = mq;
  /* Loading database plugin */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (GSN_cfg,
                                                          "namestore",
                                                          "database",
                                                          &database))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");
    GNUNET_free (nc);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loading %s\n", db_lib_name);
  nc->GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  GNUNET_free (database);
  if (NULL == nc->GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load database backend `%s'\n",
                db_lib_name);
    GNUNET_free (nc);
    return NULL;
  }
  nc->db_lib_name = GNUNET_strdup (db_lib_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loaded %s\n", db_lib_name);
  return nc;
}


/**
 * Closure for #lookup_it().
 */
struct RecordLookupContext
{
  /**
   * The label to look up.
   */
  const char *label;

  /**
   * The editor hint for set
   */
  const char *editor_hint;

  /**
   * The record result.
   */
  char *res_rd;

  /**
   * The nick for the zone.
   */
  struct GNUNET_GNSRECORD_Data *nick;

  /**
   * If a record set was found or not.
   */
  int found;

  /**
   * The record filter
   */
  enum GNUNET_GNSRECORD_Filter filter;

  /**
   * The number of found records.
   */
  unsigned int res_rd_count;

  /**
   * The length of the serialized records.
   */
  ssize_t rd_ser_len;
};


/**
 * Function called by the namestore plugin when we are trying to lookup
 * a record as part of #handle_record_lookup().  Merges all results into
 * the context.
 *
 * @param cls closure with a `struct RecordLookupContext`
 * @param seq unique serial number of the record, MUST NOT BE ZERO
 * @param private_key private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
lookup_it (void *cls,
           uint64_t seq,
           const char *editor_hint,
           const struct GNUNET_CRYPTO_PrivateKey *private_key,
           const char *label,
           unsigned int rd_count_nf,
           const struct GNUNET_GNSRECORD_Data *rd_nf)
{
  struct RecordLookupContext *rlc = cls;
  struct GNUNET_GNSRECORD_Data rd[rd_count_nf];
  struct GNUNET_TIME_Absolute block_exp;
  unsigned int rd_count = 0;
  char *emsg;

  (void) private_key;
  GNUNET_assert (0 != seq);
  if (0 != strcmp (label, rlc->label))
    return;
  rlc->found = GNUNET_YES;
  rlc->editor_hint = editor_hint;
  if (GNUNET_OK != GNUNET_GNSRECORD_normalize_record_set (rlc->label,
                                                          rd_nf,
                                                          rd_count_nf,
                                                          rd,
                                                          &rd_count,
                                                          &block_exp,
                                                          rlc->filter,
                                                          &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GNUNET_free (emsg);
    GNUNET_assert (0);
  }

  if (0 == rd_count)
  {
    rlc->rd_ser_len = 0;
    rlc->res_rd_count = 0;
    rlc->res_rd = NULL;
    return;
  }
  if ((NULL != rlc->nick) && (0 != strcmp (label, GNUNET_GNS_EMPTY_LABEL_AT)))
  {
    /* Merge */
    struct GNUNET_GNSRECORD_Data *rd_res;
    unsigned int rdc_res;

    rd_res = NULL;
    rdc_res = 0;
    rlc->nick->flags = (rlc->nick->flags | GNUNET_GNSRECORD_RF_PRIVATE)
                       ^ GNUNET_GNSRECORD_RF_PRIVATE;
    merge_with_nick_records (rlc->nick, rd_count, rd, &rdc_res, &rd_res);
    rlc->rd_ser_len = GNUNET_GNSRECORD_records_get_size (rdc_res, rd_res);
    if (rlc->rd_ser_len < 0)
    {
      GNUNET_break (0);
      GNUNET_free (rd_res);
      rlc->found = GNUNET_NO;
      rlc->rd_ser_len = 0;
      return;
    }
    rlc->res_rd_count = rdc_res;
    rlc->res_rd = GNUNET_malloc (rlc->rd_ser_len);
    if (rlc->rd_ser_len != GNUNET_GNSRECORD_records_serialize (rdc_res,
                                                               rd_res,
                                                               rlc->rd_ser_len,
                                                               rlc->res_rd))
    {
      GNUNET_break (0);
      GNUNET_free (rlc->res_rd);
      rlc->res_rd = NULL;
      rlc->res_rd_count = 0;
      rlc->rd_ser_len = 0;
      GNUNET_free (rd_res);
      rlc->found = GNUNET_NO;
      return;
    }
    GNUNET_free (rd_res);
    GNUNET_free (rlc->nick);
    rlc->nick = NULL;
  }
  else
  {
    rlc->rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
    if (rlc->rd_ser_len < 0)
    {
      GNUNET_break (0);
      rlc->found = GNUNET_NO;
      rlc->rd_ser_len = 0;
      return;
    }
    rlc->res_rd_count = rd_count;
    rlc->res_rd = GNUNET_malloc (rlc->rd_ser_len);
    if (rlc->rd_ser_len != GNUNET_GNSRECORD_records_serialize (rd_count,
                                                               rd,
                                                               rlc->rd_ser_len,
                                                               rlc->res_rd))
    {
      GNUNET_break (0);
      GNUNET_free (rlc->res_rd);
      rlc->res_rd = NULL;
      rlc->res_rd_count = 0;
      rlc->rd_ser_len = 0;
      rlc->found = GNUNET_NO;
      return;
    }
  }
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT message
 *
 * @param cls client sending the message
 * @param er_msg message of type `struct EditRecordSetMessage`
 * @return #GNUNET_OK if @a er_msg is well-formed
 */
static int
check_edit_record_set (void *cls, const struct EditRecordSetMessage *er_msg)
{
  uint16_t name_len;
  uint16_t editor_hint_len;
  size_t src_size;
  size_t key_len;

  (void) cls;
  name_len = ntohs (er_msg->label_len);
  editor_hint_len = ntohs (er_msg->editor_hint_len);
  key_len = ntohs (er_msg->key_len);
  src_size = ntohs (er_msg->gns_header.header.size);
  if (name_len + editor_hint_len + key_len != src_size - sizeof(struct
                                                                EditRecordSetMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct EditRecordSetMessage`
 */
static void
handle_edit_record_set (void *cls, const struct EditRecordSetMessage *er_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct EditRecordSetResponseMessage *rer_msg;
  struct RecordLookupContext rlc;
  const char *name_tmp;
  const char *editor_hint;
  char *conv_name;
  uint16_t name_len;
  uint16_t old_editor_hint_len;
  int res;
  size_t key_len;
  size_t kb_read;

  key_len = ntohs (er_msg->key_len);
  name_len = ntohs (er_msg->label_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&er_msg[1],
                                                   key_len,
                                                   &zone,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error reading private key\n");
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_tmp = (const char *) &er_msg[1] + key_len;
  editor_hint = (const char *) name_tmp + name_len;
  GNUNET_SERVICE_client_continue (nc->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received NAMESTORE_RECORD_SET_EDIT message for name `%s'\n",
              name_tmp);

  conv_name = GNUNET_GNSRECORD_string_normalize (name_tmp);
  if (NULL == conv_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error converting name `%s'\n",
                name_tmp);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_len = strlen (conv_name) + 1;
  rlc.label = conv_name;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up without filter\n");
  rlc.filter = GNUNET_GNSRECORD_FILTER_NONE;
  rlc.found = GNUNET_NO;
  rlc.res_rd_count = 0;
  rlc.res_rd = NULL;
  rlc.rd_ser_len = 0;
  rlc.nick = get_nick_record (&zone);
  res = nc->GSN_database->edit_records (nc->GSN_database->cls,
                                        editor_hint,
                                        &zone,
                                        conv_name,
                                        &lookup_it,
                                        &rlc);

  old_editor_hint_len = 0;
  if (NULL != rlc.editor_hint)
    old_editor_hint_len = strlen (rlc.editor_hint) + 1;
  env =
    GNUNET_MQ_msg_extra (rer_msg,
                         rlc.rd_ser_len + old_editor_hint_len,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE)
  ;
  rer_msg->editor_hint_len = htons (old_editor_hint_len);
  rer_msg->gns_header.r_id = er_msg->gns_header.r_id;
  rer_msg->rd_count = htons (rlc.res_rd_count);
  rer_msg->rd_len = htons (rlc.rd_ser_len);
  if (GNUNET_YES == rlc.found)
    rer_msg->ec = htons (GNUNET_EC_NONE);
  else if (GNUNET_SYSERR == res)
    rer_msg->ec = htons (GNUNET_EC_NAMESTORE_UNKNOWN);
  else
    rer_msg->ec = htons (GNUNET_EC_NAMESTORE_NO_RESULTS);
  GNUNET_memcpy (&rer_msg[1], rlc.editor_hint, old_editor_hint_len);
  GNUNET_memcpy ((char*) &rer_msg[1] + old_editor_hint_len, rlc.res_rd,
                 rlc.rd_ser_len);
  GNUNET_MQ_send (nc->mq, env);
  GNUNET_free (rlc.res_rd);
  GNUNET_free (conv_name);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_CANCEL message
 *
 * @param cls client sending the message
 * @param er_msg message of type `struct EditRecordSetMessage`
 * @return #GNUNET_OK if @a er_msg is well-formed
 */
static int
check_edit_record_set_cancel (void *cls, const struct
                              EditRecordSetCancelMessage *er_msg)
{
  uint16_t name_len;
  uint16_t editor_hint_len;
  uint16_t editor_hint_repl_len;
  size_t src_size;
  size_t key_len;

  (void) cls;
  name_len = ntohs (er_msg->label_len);
  editor_hint_len = ntohs (er_msg->editor_hint_len);
  editor_hint_repl_len = ntohs (er_msg->editor_hint_len);
  key_len = ntohs (er_msg->key_len);
  src_size = ntohs (er_msg->gns_header.header.size);
  if (name_len + editor_hint_len + editor_hint_repl_len + key_len != src_size
      - sizeof(struct
               EditRecordSetCancelMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_CANCEL message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct EditRecordSetCancelMessage`
 */
static void
handle_edit_record_set_cancel (void *cls, const struct
                               EditRecordSetCancelMessage *er_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct NamestoreResponseMessage *rer_msg;
  const char *name_tmp;
  const char *editor_hint;
  const char *editor_hint_repl;
  char *conv_name;
  uint16_t name_len;
  uint16_t editor_hint_len;
  int res;
  size_t key_len;
  size_t kb_read;

  key_len = ntohs (er_msg->key_len);
  name_len = ntohs (er_msg->label_len);
  editor_hint_len = ntohs (er_msg->editor_hint_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&er_msg[1],
                                                   key_len,
                                                   &zone,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error reading private key\n");
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_tmp = (const char *) &er_msg[1] + key_len;
  editor_hint = (const char *) name_tmp + name_len;
  editor_hint_repl = (const char *) name_tmp + name_len + editor_hint_len;
  GNUNET_SERVICE_client_continue (nc->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received NAMESTORE_RECORD_SET_EDIT message for name `%s'\n",
              name_tmp);

  conv_name = GNUNET_GNSRECORD_string_normalize (name_tmp);
  if (NULL == conv_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error converting name `%s'\n",
                name_tmp);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_len = strlen (conv_name) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Clearing editor hint\n");
  res = nc->GSN_database->clear_editor_hint (nc->GSN_database->cls,
                                             editor_hint,
                                             editor_hint_repl,
                                             &zone,
                                             conv_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Clearing editor hint %s\n", (GNUNET_SYSERR == res) ? "failed." :
              "successful.");

  env =
    GNUNET_MQ_msg (rer_msg,
                   GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE);
  rer_msg->gns_header.r_id = er_msg->gns_header.r_id;
  rer_msg->ec = htons ((GNUNET_OK == res) ? GNUNET_EC_NONE :
                       GNUNET_EC_NAMESTORE_BACKEND_FAILED);
  GNUNET_MQ_send (nc->mq, env);
  GNUNET_free (conv_name);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct LabelLookupMessage`
 * @return #GNUNET_OK if @a ll_msg is well-formed
 */
static int
check_record_lookup (void *cls, const struct LabelLookupMessage *ll_msg)
{
  uint32_t name_len;
  size_t src_size;
  size_t key_len;

  (void) cls;
  name_len = ntohs (ll_msg->label_len);
  key_len = ntohs (ll_msg->key_len);
  src_size = ntohs (ll_msg->gns_header.header.size);
  if (name_len + key_len != src_size - sizeof(struct LabelLookupMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP message
 *
 * @param cls client sending the message
 * @param ll_msg message of type `struct LabelLookupMessage`
 */
static void
handle_record_lookup (void *cls, const struct LabelLookupMessage *ll_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct LabelLookupResponseMessage *llr_msg;
  struct RecordLookupContext rlc;
  const char *name_tmp;
  char *res_name;
  char *conv_name;
  uint32_t name_len;
  int res;
  size_t key_len;
  size_t kb_read;

  key_len = ntohs (ll_msg->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&ll_msg[1],
                                                   key_len,
                                                   &zone,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error reading private key\n");
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_tmp = (const char *) &ll_msg[1] + key_len;
  GNUNET_SERVICE_client_continue (nc->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received NAMESTORE_RECORD_LOOKUP message for name `%s'\n",
              name_tmp);

  conv_name = GNUNET_GNSRECORD_string_normalize (name_tmp);
  if (NULL == conv_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error converting name `%s'\n",
                name_tmp);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  name_len = strlen (conv_name) + 1;
  rlc.label = conv_name;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up with filter %u\n", ntohs (ll_msg->filter));
  rlc.filter = ntohs (ll_msg->filter);
  rlc.found = GNUNET_NO;
  rlc.res_rd_count = 0;
  rlc.res_rd = NULL;
  rlc.rd_ser_len = 0;
  rlc.nick = get_nick_record (&zone);
  res = nc->GSN_database->lookup_records (nc->GSN_database->cls,
                                          &zone,
                                          conv_name,
                                          &lookup_it,
                                          &rlc);
  env =
    GNUNET_MQ_msg_extra (llr_msg,
                         key_len + name_len + rlc.rd_ser_len,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE);
  llr_msg->gns_header.r_id = ll_msg->gns_header.r_id;
  GNUNET_memcpy (&llr_msg[1], &ll_msg[1], key_len);
  llr_msg->key_len = ll_msg->key_len;
  llr_msg->name_len = htons (name_len);
  llr_msg->rd_count = htons (rlc.res_rd_count);
  llr_msg->rd_len = htons (rlc.rd_ser_len);
  llr_msg->reserved = htons (0);
  res_name = ((char *) &llr_msg[1]) + key_len;
  if (GNUNET_YES == rlc.found)
    llr_msg->found = htons (GNUNET_YES);
  else if (GNUNET_SYSERR == res)
    llr_msg->found = htons (GNUNET_SYSERR);
  else
    llr_msg->found = htons (GNUNET_NO);
  GNUNET_memcpy (res_name, conv_name, name_len);
  GNUNET_memcpy (&res_name[name_len], rlc.res_rd, rlc.rd_ser_len);
  GNUNET_MQ_send (nc->mq, env);
  GNUNET_free (rlc.res_rd);
  GNUNET_free (conv_name);
}


/**
 * Checks a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE message
 *
 * @param cls client sending the message
 * @param rp_msg message of type `struct RecordStoreMessage`
 * @return #GNUNET_OK if @a rp_msg is well-formed
 */
static int
check_record_store (void *cls, const struct RecordStoreMessage *rp_msg)
{
  size_t msg_size;
  size_t min_size_exp;
  size_t rd_set_count;
  size_t key_len;

  (void) cls;
  msg_size = ntohs (rp_msg->gns_header.header.size);
  rd_set_count = ntohs (rp_msg->rd_set_count);
  key_len = ntohs (rp_msg->key_len);

  min_size_exp = sizeof(*rp_msg) + key_len + sizeof (struct RecordSet)
                 * rd_set_count;
  if (msg_size < min_size_exp)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


struct LookupExistingRecordsContext
{

  /**
   * The expiration of the existing records or tombstone
   */
  struct GNUNET_TIME_Absolute exp;

  /**
   * Whether the existing record set consists only of a tombstone
   * (e.g. is "empty")
   */
  int only_tombstone;

};


/**
 * Check if set contains a tombstone, store if necessary
 *
 * @param cls a `struct GNUNET_GNSRECORD_Data **` for storing the nick (if found)
 * @param seq sequence number of the record, MUST NOT BE ZERO
 * @param private_key the private key of the zone (unused)
 * @param label should be #GNUNET_GNS_EMPTY_LABEL_AT
 * @param rd_count number of records in @a rd
 * @param rd records stored under @a label in the zone
 */
static void
get_existing_rd_exp (void *cls,
                     uint64_t seq,
                     const char *editor_hint,
                     const struct
                     GNUNET_CRYPTO_PrivateKey *private_key,
                     const char *label,
                     unsigned int rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct LookupExistingRecordsContext *lctx = cls;
  struct GNUNET_GNSRECORD_Data rd_pub[rd_count];
  unsigned int rd_pub_count;
  char *emsg;

  if ((1 == rd_count) &&
      (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd[0].record_type))
  {
    /* This record set contains only a tombstone! */
    lctx->only_tombstone = GNUNET_YES;
  }
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_normalize_record_set (label,
                                             rd,
                                             rd_count,
                                             rd_pub,
                                             &rd_pub_count,
                                             &lctx->exp,
                                             GNUNET_GNSRECORD_FILTER_OMIT_PRIVATE,
                                             &emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s\n", emsg);
    GNUNET_free (emsg);
  }
}


static enum GNUNET_ErrorCode
store_record_set (struct NamestoreClient *nc,
                  const struct GNUNET_CRYPTO_PrivateKey *private_key,
                  const struct RecordSet *rd_set,
                  ssize_t *len)
{
  size_t name_len;
  size_t rd_ser_len;
  const char *name_tmp;
  const char *rd_ser;
  char *conv_name;
  char *emsg;
  unsigned int rd_count;
  int res;
  enum GNUNET_ErrorCode ec;
  struct GNUNET_TIME_Absolute new_block_exp;
  struct LookupExistingRecordsContext lctx;
  *len = sizeof (struct RecordSet);

  ec = GNUNET_EC_NONE;
  lctx.only_tombstone = GNUNET_NO;
  lctx.exp = GNUNET_TIME_UNIT_ZERO_ABS;
  new_block_exp = GNUNET_TIME_UNIT_ZERO_ABS;
  name_len = ntohs (rd_set->name_len);
  *len += name_len;
  rd_count = ntohs (rd_set->rd_count);
  rd_ser_len = ntohs (rd_set->rd_len);
  *len += rd_ser_len;
  name_tmp = (const char *) &rd_set[1];
  rd_ser = &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL (rd_count)];

    /* Extracting and converting private key */
    conv_name = GNUNET_GNSRECORD_string_normalize (name_tmp);
    if (NULL == conv_name)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error normalizing name `%s'\n",
                  name_tmp);
      return GNUNET_EC_NAMESTORE_LABEL_INVALID;
    }

    /* Check name for validity */
    if (GNUNET_OK != GNUNET_GNSRECORD_label_check (conv_name, &emsg))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Label invalid: `%s'\n",
                  emsg);
      GNUNET_free (emsg);
      GNUNET_free (conv_name);
      return GNUNET_EC_NAMESTORE_LABEL_INVALID;
    }

    if (GNUNET_OK !=
        GNUNET_GNSRECORD_records_deserialize (rd_ser_len, rd_ser, rd_count,
                                              rd))
    {
      GNUNET_free (conv_name);
      return GNUNET_EC_NAMESTORE_RECORD_DATA_INVALID;
    }

    GNUNET_STATISTICS_update (statistics,
                              "Well-formed store requests received",
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating %u records for name `%s'\n",
                (unsigned int) rd_count,
                conv_name);
    if ((GNUNET_NO == nc->GSN_database->lookup_records (nc->GSN_database->cls,
                                                        private_key,
                                                        conv_name,
                                                        &get_existing_rd_exp,
                                                        &lctx))
        &&
        (rd_count == 0))
    {
      /* This name does not exist, so cannot be removed */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Name `%s' does not exist, no deletion required\n",
                  conv_name);
      res = GNUNET_NO;
      ec = GNUNET_EC_NAMESTORE_RECORD_NOT_FOUND;
    }
    else
    {
      /* remove "NICK" records, unless this is for the
       #GNUNET_GNS_EMPTY_LABEL_AT label
       We may need one additional record later for tombstone.
       FIXME: Since we must normalize the record set (check for
       consistency etc) we have to iterate the set twice.
       May be inefficient.
       We cannot really move the nick caching into GNSRECORD.
       */
      struct GNUNET_GNSRECORD_Data rd_clean[GNUNET_NZL (rd_count)];
      struct GNUNET_GNSRECORD_Data rd_nf[GNUNET_NZL (rd_count) + 1];
      unsigned int rd_clean_off;
      unsigned int rd_nf_count;
      int have_nick;

      rd_clean_off = 0;
      have_nick = GNUNET_NO;
      for (unsigned int i = 0; i < rd_count; i++)
      {
        rd_clean[rd_clean_off] = rd[i];

        if ((0 == strcmp (GNUNET_GNS_EMPTY_LABEL_AT, conv_name)) ||
            (GNUNET_GNSRECORD_TYPE_NICK != rd[i].record_type))
          rd_clean_off++;

        if ((0 == strcmp (GNUNET_GNS_EMPTY_LABEL_AT, conv_name)) &&
            (GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type))
        {
          cache_nick (private_key, &rd[i]);
          have_nick = GNUNET_YES;
        }
      }
      if (GNUNET_OK !=
          GNUNET_GNSRECORD_normalize_record_set (conv_name,
                                                 rd_clean,
                                                 rd_clean_off,
                                                 rd_nf,
                                                 &rd_nf_count,
                                                 &new_block_exp,
                                                 GNUNET_GNSRECORD_FILTER_INCLUDE_MAINTENANCE,
                                                 &emsg))
      {
        GNUNET_free (conv_name);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Error normalizing record set: `%s'\n",
                    emsg);
        GNUNET_free (emsg);
        return GNUNET_EC_NAMESTORE_RECORD_DATA_INVALID;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%u/%u records before tombstone\n", rd_nf_count,
                  rd_clean_off);
      /*
       * If existing_block_exp is 0, then there was no record set
       * and no tombstone.
       * Otherwise, if the existing block expiration is after the
       * new block expiration would be, we need to add a tombstone
       * or update it.
       */
      if (GNUNET_TIME_absolute_cmp (new_block_exp, <=, lctx.exp))
      {
        rd_nf[rd_nf_count].record_type = GNUNET_GNSRECORD_TYPE_TOMBSTONE;
        rd_nf[rd_nf_count].expiration_time =
          lctx.exp.abs_value_us;
        rd_nf[rd_nf_count].data = NULL;
        rd_nf[rd_nf_count].data_size = 0;
        rd_nf[rd_nf_count].flags = GNUNET_GNSRECORD_RF_PRIVATE
                                   | GNUNET_GNSRECORD_RF_MAINTENANCE;
        rd_nf_count++;
      }
      if ((0 == strcmp (GNUNET_GNS_EMPTY_LABEL_AT, conv_name)) &&
          (GNUNET_NO == have_nick))
      {
        cache_nick (private_key, NULL);
      }
      res = nc->GSN_database->store_records (nc->GSN_database->cls,
                                             private_key,
                                             conv_name,
                                             rd_nf_count,
                                             rd_nf);
      /* If after a store there is only a TOMBSTONE left, and
       * there was >1 record under this label found (the tombstone; indicated
       * through res != GNUNET_NO) then we should return "NOT FOUND" == GNUNET_NO
       */
      if ((GNUNET_SYSERR != res) &&
          (0 == rd_count) &&
          (1 == rd_nf_count) &&
          (GNUNET_GNSRECORD_TYPE_TOMBSTONE == rd_nf[0].record_type) &&
          (GNUNET_YES == lctx.only_tombstone))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Client tried to remove non-existant record\n");
        ec = GNUNET_EC_NAMESTORE_RECORD_NOT_FOUND;
      }
    }

    if (GNUNET_SYSERR == res)
    {
      /* store not successful, no need to tell monitors */
      GNUNET_free (conv_name);
      return GNUNET_EC_NAMESTORE_STORE_FAILED;
    }
  }
  GNUNET_free (conv_name);
  return ec;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE message
 *
 * @param cls client sending the message
 * @param rp_msg message of type `struct RecordStoreMessage`
 */
static void
handle_record_store (void *cls, const struct RecordStoreMessage *rp_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  uint32_t rid;
  uint16_t rd_set_count;
  const char *buf;
  ssize_t read;
  size_t key_len;
  size_t kb_read;
  size_t rp_msg_len;
  size_t rs_len;
  size_t rs_off;
  struct StoreActivity *sa;
  struct RecordSet *rs;
  enum GNUNET_ErrorCode res;

  key_len = ntohs (rp_msg->key_len);
  rp_msg_len = ntohs (rp_msg->gns_header.header.size);
  rs_off = sizeof (*rp_msg) + key_len;
  rs_len = rp_msg_len - rs_off;
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&rp_msg[1],
                                                   key_len,
                                                   &zone,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error reading private key\n");
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received NAMESTORE_RECORD_STORE message\n");
  rid = ntohl (rp_msg->gns_header.r_id);
  rd_set_count = ntohs (rp_msg->rd_set_count);
  buf = (const char *) rp_msg + rs_off;
  for (int i = 0; i < rd_set_count; i++)
  {
    rs = (struct RecordSet *) buf;
    res = store_record_set (nc, &zone,
                            rs, &read);
    if (GNUNET_EC_NONE != res)
    {
      send_store_response (nc, res, rid);
      GNUNET_SERVICE_client_continue (nc->client);
      return;
    }
    buf += read;
  }
  sa = GNUNET_malloc (sizeof(struct StoreActivity) + rs_len);
  GNUNET_CONTAINER_DLL_insert (sa_head, sa_tail, sa);
  sa->nc = nc;
  sa->rs = (struct RecordSet *) &sa[1];
  sa->rd_set_count = rd_set_count;
  GNUNET_memcpy (&sa[1], (char *) rp_msg + rs_off, rs_len);
  sa->rid = rid;
  sa->rd_set_pos = 0;
  sa->private_key = zone;
  sa->zm_pos = monitor_head;
  continue_store_activity (sa, GNUNET_YES);
}


/**
 * Context for record remove operations passed from #handle_zone_to_name to
 * #handle_zone_to_name_it as closure
 */
struct ZoneToNameCtx
{
  /**
   * Namestore client
   */
  struct NamestoreClient *nc;

  /**
   * Request id (to be used in the response to the client).
   */
  uint32_t rid;

  /**
   * Set to #GNUNET_OK on success, #GNUNET_SYSERR on error.  Note that
   * not finding a name for the zone still counts as a 'success' here,
   * as this field is about the success of executing the IPC protocol.
   */
  enum GNUNET_ErrorCode ec;
};


/**
 * Zone to name iterator
 *
 * @param cls struct ZoneToNameCtx *
 * @param seq sequence number of the record, MUST NOT BE ZERO
 * @param zone_key the zone key
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd record data
 */
static void
handle_zone_to_name_it (void *cls,
                        uint64_t seq,
                        const char *editor_hint,
                        const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                        const char *name,
                        unsigned int rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneToNameCtx *ztn_ctx = cls;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneToNameResponseMessage *ztnr_msg;
  size_t name_len;
  size_t key_len;
  ssize_t rd_ser_len;
  size_t msg_size;
  char *name_tmp;
  char *rd_tmp;

  GNUNET_assert (0 != seq);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found result for zone-to-name lookup: `%s'\n",
              name);
  ztn_ctx->ec = GNUNET_EC_NONE;
  name_len = (NULL == name) ? 0 : strlen (name) + 1;
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (rd_ser_len < 0)
  {
    GNUNET_break (0);
    ztn_ctx->ec = htonl (GNUNET_EC_NAMESTORE_UNKNOWN);
    return;
  }
  key_len = GNUNET_CRYPTO_private_key_get_length (zone_key);
  msg_size = sizeof(struct ZoneToNameResponseMessage)
             + name_len + rd_ser_len + key_len;
  if (msg_size >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    ztn_ctx->ec = GNUNET_EC_NAMESTORE_RECORD_TOO_BIG;
    return;
  }
  env =
    GNUNET_MQ_msg_extra (ztnr_msg,
                         key_len + name_len + rd_ser_len,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
  ztnr_msg->gns_header.header.size = htons (msg_size);
  ztnr_msg->gns_header.r_id = htonl (ztn_ctx->rid);
  ztnr_msg->ec = htonl (ztn_ctx->ec);
  ztnr_msg->rd_len = htons (rd_ser_len);
  ztnr_msg->rd_count = htons (rd_count);
  ztnr_msg->name_len = htons (name_len);
  ztnr_msg->key_len = htons (key_len);
  GNUNET_CRYPTO_write_private_key_to_buffer (zone_key,
                                             &ztnr_msg[1],
                                             key_len);
  name_tmp = (char *) &ztnr_msg[1] + key_len;
  GNUNET_memcpy (name_tmp, name, name_len);
  rd_tmp = &name_tmp[name_len];
  GNUNET_assert (
    rd_ser_len ==
    GNUNET_GNSRECORD_records_serialize (rd_count, rd, rd_ser_len, rd_tmp));
  ztn_ctx->ec = GNUNET_EC_NONE;
  GNUNET_MQ_send (ztn_ctx->nc->mq, env);
}


static enum GNUNET_GenericReturnValue
check_zone_to_name (void *cls,
                    const struct ZoneToNameMessage *zis_msg)
{
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME message
 *
 * @param cls client client sending the message
 * @param ztn_msg message of type 'struct ZoneToNameMessage'
 */
static void
handle_zone_to_name (void *cls, const struct ZoneToNameMessage *ztn_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct GNUNET_CRYPTO_PublicKey value_zone;
  struct NamestoreClient *nc = cls;
  struct ZoneToNameCtx ztn_ctx;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneToNameResponseMessage *ztnr_msg;
  size_t key_len;
  size_t pkey_len;
  size_t kb_read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ZONE_TO_NAME message\n");
  ztn_ctx.rid = ntohl (ztn_msg->gns_header.r_id);
  ztn_ctx.nc = nc;
  ztn_ctx.ec = GNUNET_EC_NAMESTORE_ZONE_NOT_FOUND;
  key_len = ntohs (ztn_msg->key_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_private_key_from_buffer (&ztn_msg[1],
                                                   key_len,
                                                   &zone,
                                                   &kb_read)) ||
      (kb_read != key_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error parsing private key.\n");
    GNUNET_SERVICE_client_drop (nc->client);
    GNUNET_break (0);
    return;
  }
  pkey_len = ntohs (ztn_msg->pkey_len);
  if ((GNUNET_SYSERR ==
       GNUNET_CRYPTO_read_public_key_from_buffer ((char*) &ztn_msg[1]
                                                  + key_len,
                                                  pkey_len,
                                                  &value_zone,
                                                  &kb_read)) ||
      (kb_read != pkey_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error parsing public key.\n");
    GNUNET_SERVICE_client_drop (nc->client);
    GNUNET_break (0);
    return;
  }
  if (GNUNET_SYSERR == nc->GSN_database->zone_to_name (nc->GSN_database->cls,
                                                       &zone,
                                                       &value_zone,
                                                       &handle_zone_to_name_it,
                                                       &ztn_ctx))
  {
    /* internal error, hang up instead of signalling something
       that might be wrong */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  if (GNUNET_EC_NAMESTORE_ZONE_NOT_FOUND == ztn_ctx.ec)
  {
    /* no result found, send empty response */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found no result for zone-to-name lookup.\n");
    env = GNUNET_MQ_msg (ztnr_msg,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
    ztnr_msg->gns_header.r_id = ztn_msg->gns_header.r_id;
    ztnr_msg->ec = htonl (GNUNET_EC_NAMESTORE_ZONE_NOT_FOUND);
    GNUNET_MQ_send (nc->mq, env);
  }
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Context for record remove operations passed from
 * #run_zone_iteration_round to #zone_iterate_proc as closure
 */
struct ZoneIterationProcResult
{
  /**
   * The zone iteration handle
   */
  struct ZoneIteration *zi;

  /**
   * Number of results left to be returned in this iteration.
   */
  uint64_t limit;

  /**
   * Skip a result and run again unless GNUNET_NO
   */
  int run_again;
};


/**
 * Process results for zone iteration from database
 *
 * @param cls struct ZoneIterationProcResult
 * @param seq sequence number of the record, MUST NOT BE ZERO
 * @param zone_key the zone key
 * @param name name
 * @param rd_count number of records for this name
 * @param rd record data
 */
static void
zone_iterate_proc (void *cls,
                   uint64_t seq,
                   const char *editor_hint,
                   const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                   const char *name,
                   unsigned int rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneIterationProcResult *proc = cls;

  GNUNET_assert (0 != seq);
  if ((NULL == zone_key) && (NULL == name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration done\n");
    return;
  }
  if ((NULL == zone_key) || (NULL == name))
  {
    /* what is this!? should never happen */
    GNUNET_break (0);
    return;
  }
  if (0 == proc->limit)
  {
    /* what is this!? should never happen */
    GNUNET_break (0);
    return;
  }
  proc->zi->seq = seq;
  if (0 < send_lookup_response_with_filter (proc->zi->nc,
                                            proc->zi->request_id,
                                            zone_key,
                                            name,
                                            rd_count,
                                            rd,
                                            proc->zi->filter))
    proc->limit--;
  else
    proc->run_again = GNUNET_YES;
}


/**
 * Perform the next round of the zone iteration.
 *
 * @param zi zone iterator to process
 * @param limit number of results to return in one pass
 */
static void
run_zone_iteration_round (struct ZoneIteration *zi, uint64_t limit)
{
  struct ZoneIterationProcResult proc;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative duration;
  struct NamestoreClient *nc = zi->nc;

  memset (&proc, 0, sizeof(proc));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to return up to %llu records at position %llu\n",
              (unsigned long long) limit,
              (unsigned long long) zi->seq);
  proc.zi = zi;
  proc.limit = limit;
  proc.run_again = GNUNET_YES;
  start = GNUNET_TIME_absolute_get ();
  while (GNUNET_YES == proc.run_again)
  {
    proc.run_again = GNUNET_NO;
    GNUNET_break (GNUNET_SYSERR !=
                  nc->GSN_database->iterate_records (nc->GSN_database->cls,
                                                     (GNUNET_YES ==
                                                      GNUNET_is_zero (
                                                        &zi->zone))
                                               ? NULL
                                               : &zi->zone,
                                                     zi->seq,
                                                     proc.limit,
                                                     &zone_iterate_proc,
                                                     &proc));
  }
  duration = GNUNET_TIME_absolute_get_duration (start);
  duration = GNUNET_TIME_relative_divide (duration, limit - proc.limit);
  GNUNET_STATISTICS_set (statistics,
                         "NAMESTORE iteration delay (μs/record)",
                         duration.rel_value_us,
                         GNUNET_NO);
  if (0 == proc.limit)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returned %llu results, more results available\n",
                (unsigned long long) limit);
  zi->send_end = (0 != proc.limit);
  zone_iteration_done_client_continue (zi);
}


static enum GNUNET_GenericReturnValue
check_iteration_start (void *cls,
                       const struct ZoneIterationStartMessage *zis_msg)
{
  uint16_t size;
  size_t key_len;

  size = ntohs (zis_msg->gns_header.header.size);
  key_len = ntohs (zis_msg->key_len);

  if (size < key_len + sizeof(*zis_msg))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_start (void *cls,
                        const struct ZoneIterationStartMessage *zis_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;
  size_t key_len;
  size_t kb_read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_ITERATION_START message\n");
  key_len = ntohs (zis_msg->key_len);
  zi = GNUNET_new (struct ZoneIteration);
  if (0 < key_len)
  {
    if ((GNUNET_SYSERR ==
         GNUNET_CRYPTO_read_private_key_from_buffer (&zis_msg[1],
                                                     key_len,
                                                     &zone,
                                                     &kb_read)) ||
        (kb_read != key_len))
    {
      GNUNET_SERVICE_client_drop (nc->client);
      GNUNET_free (zi);
      return;
    }
    zi->zone = zone;
  }
  zi->request_id = ntohl (zis_msg->gns_header.r_id);
  zi->filter = ntohs (zis_msg->filter);
  zi->offset = 0;
  zi->nc = nc;
  GNUNET_CONTAINER_DLL_insert (nc->op_head, nc->op_tail, zi);
  run_zone_iteration_round (zi, 1);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_stop (void *cls,
                       const struct ZoneIterationStopMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_ITERATION_STOP message\n");
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, zi);
  GNUNET_free (zi);
  GNUNET_SERVICE_client_continue (nc->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_next (void *cls,
                       const struct ZoneIterationNextMessage *zis_msg)
{
  struct NamestoreClient *nc = cls;
  struct ZoneIteration *zi;
  uint32_t rid;
  uint64_t limit;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_ITERATION_NEXT message\n");
  GNUNET_STATISTICS_update (statistics,
                            "Iteration NEXT messages received",
                            1,
                            GNUNET_NO);
  rid = ntohl (zis_msg->gns_header.r_id);
  limit = GNUNET_ntohll (zis_msg->limit);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  run_zone_iteration_round (zi, limit);
}


/**
 * Function called when the monitor is ready for more data, and we
 * should thus unblock PUT operations that were blocked on the
 * monitor not being ready.
 */
static void
monitor_unblock (struct ZoneMonitor *zm)
{
  struct StoreActivity *sa = sa_head;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Unblocking zone monitor %p\n", zm);
  while ((NULL != sa) && (zm->limit > zm->iteration_cnt))
  {
    struct StoreActivity *sn = sa->next;

    if (sa->zm_pos == zm)
      continue_store_activity (sa, GNUNET_YES);
    sa = sn;
  }
  if (zm->limit > zm->iteration_cnt)
  {
    zm->sa_waiting = GNUNET_NO;
    if (NULL != zm->sa_wait_warning)
    {
      GNUNET_SCHEDULER_cancel (zm->sa_wait_warning);
      zm->sa_wait_warning = NULL;
    }
  }
  else if (GNUNET_YES == zm->sa_waiting)
  {
    zm->sa_waiting_start = GNUNET_TIME_absolute_get ();
    if (NULL != zm->sa_wait_warning)
      GNUNET_SCHEDULER_cancel (zm->sa_wait_warning);
    zm->sa_wait_warning =
      GNUNET_SCHEDULER_add_delayed (MONITOR_STALL_WARN_DELAY,
                                    &warn_monitor_slow,
                                    zm);
  }
}


/**
 * Send 'sync' message to zone monitor, we're now in sync.
 *
 * @param zm monitor that is now in sync
 */
static void
monitor_sync (struct ZoneMonitor *zm)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *sync;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Synching zone monitor %p\n", zm);

  env = GNUNET_MQ_msg (sync, GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC);
  GNUNET_MQ_send (zm->nc->mq, env);
  /* mark iteration done */
  zm->in_first_iteration = GNUNET_NO;
  zm->iteration_cnt = 0;
  if ((zm->limit > 0) && (zm->sa_waiting))
    monitor_unblock (zm);
}


/**
 * Obtain the next datum during the zone monitor's zone initial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 */
static void
monitor_iteration_next (void *cls);


/**
 * A #GNUNET_NAMESTORE_RecordIterator for monitors.
 *
 * @param cls a 'struct ZoneMonitor *' with information about the monitor
 * @param seq sequence number of the record, MUST NOT BE ZERO
 * @param zone_key zone key of the zone
 * @param name name
 * @param rd_count number of records in @a rd
 * @param rd array of records
 */
static void
monitor_iterate_cb (void *cls,
                    uint64_t seq,
                    const char *editor_hint,
                    const struct GNUNET_CRYPTO_PrivateKey *zone_key,
                    const char *name,
                    unsigned int rd_count,
                    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneMonitor *zm = cls;

  GNUNET_assert (0 != seq);
  zm->seq = seq;
  GNUNET_assert (NULL != name);
  GNUNET_STATISTICS_update (statistics,
                            "Monitor notifications sent",
                            1,
                            GNUNET_NO);
  if (0 < send_lookup_response_with_filter (zm->nc, 0, zone_key, name,
                                            rd_count, rd, zm->filter))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sent records.\n");
    zm->limit--;
    zm->iteration_cnt--;
  }
  else
    zm->run_again = GNUNET_YES;
  if ((0 == zm->iteration_cnt) && (0 != zm->limit))
  {
    /* We are done with the current iteration batch, AND the
       client would right now accept more, so go again! */
    GNUNET_assert (NULL == zm->task);
    zm->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, zm);
  }
}


static enum GNUNET_GenericReturnValue
check_monitor_start (void *cls,
                     const struct ZoneMonitorStartMessage *zis_msg)
{
  uint16_t size;
  size_t key_len;

  size = ntohs (zis_msg->header.size);
  key_len = ntohs (zis_msg->key_len);

  if (size < key_len + sizeof(*zis_msg))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_monitor_start (void *cls, const struct
                      ZoneMonitorStartMessage *zis_msg)
{
  struct GNUNET_CRYPTO_PrivateKey zone;
  struct NamestoreClient *nc = cls;
  struct ZoneMonitor *zm;
  size_t key_len;
  size_t kb_read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_MONITOR_START message\n");
  zm = GNUNET_new (struct ZoneMonitor);
  zm->nc = nc;
  key_len = ntohs (zis_msg->key_len);
  if (0 < key_len)
  {
    if ((GNUNET_SYSERR ==
         GNUNET_CRYPTO_read_private_key_from_buffer (&zis_msg[1],
                                                     key_len,
                                                     &zone,
                                                     &kb_read)) ||
        (kb_read != key_len))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error reading private key\n");
      GNUNET_SERVICE_client_drop (nc->client);
      GNUNET_free (zm);
      return;
    }
    zm->zone = zone;
  }
  zm->limit = 1;
  zm->filter = ntohs (zis_msg->filter);
  zm->in_first_iteration = (GNUNET_YES == ntohl (zis_msg->iterate_first));
  GNUNET_CONTAINER_DLL_insert (monitor_head, monitor_tail, zm);
  GNUNET_SERVICE_client_mark_monitor (nc->client);
  GNUNET_SERVICE_client_continue (nc->client);
  GNUNET_notification_context_add (monitor_nc, nc->mq);
  if (zm->in_first_iteration)
    zm->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, zm);
  else
    monitor_sync (zm);
}


/**
 * Obtain the next datum during the zone monitor's zone initial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 */
static void
monitor_iteration_next (void *cls)
{
  struct ZoneMonitor *zm = cls;
  struct NamestoreClient *nc = zm->nc;
  int ret;

  zm->task = NULL;
  GNUNET_assert (0 == zm->iteration_cnt);
  if (zm->limit > 16)
    zm->iteration_cnt = zm->limit / 2;   /* leave half for monitor events */
  else
    zm->iteration_cnt = zm->limit;   /* use it all */
  zm->run_again = GNUNET_YES;
  while (GNUNET_YES == zm->run_again)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running iteration\n");
    zm->run_again = GNUNET_NO;
    ret = nc->GSN_database->iterate_records (nc->GSN_database->cls,
                                             (GNUNET_YES == GNUNET_is_zero (
                                                &zm->zone)) ? NULL : &zm->zone,
                                             zm->seq,
                                             zm->iteration_cnt,
                                             &monitor_iterate_cb,
                                             zm);
  }
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_SERVICE_client_drop (zm->nc->client);
    return;
  }
  if (GNUNET_NO == ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Zone empty... syncing\n");
    /* empty zone */
    monitor_sync (zm);
    return;
  }
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT message
 *
 * @param cls the client sending the message
 * @param nm message from the client
 */
static void
handle_monitor_next (void *cls, const struct ZoneMonitorNextMessage *nm)
{
  struct NamestoreClient *nc = cls;
  struct ZoneMonitor *zm;
  uint64_t inc;

  inc = GNUNET_ntohll (nm->limit);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ZONE_MONITOR_NEXT message with limit %llu\n",
              (unsigned long long) inc);
  for (zm = monitor_head; NULL != zm; zm = zm->next)
    if (zm->nc == nc)
      break;
  if (NULL == zm)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  GNUNET_SERVICE_client_continue (nc->client);
  if (zm->limit + inc < zm->limit)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (nc->client);
    return;
  }
  zm->limit += inc;
  if ((zm->in_first_iteration) && (zm->limit == inc))
  {
    /* We are still iterating, and the previous iteration must
       have stopped due to the client's limit, so continue it! */
    GNUNET_assert (NULL == zm->task);
    zm->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, zm);
  }
  GNUNET_assert (zm->iteration_cnt <= zm->limit);
  if ((zm->limit > zm->iteration_cnt) && (zm->sa_waiting))
  {
    monitor_unblock (zm);
  }
  else if (GNUNET_YES == zm->sa_waiting)
  {
    if (NULL != zm->sa_wait_warning)
      GNUNET_SCHEDULER_cancel (zm->sa_wait_warning);
    zm->sa_waiting_start = GNUNET_TIME_absolute_get ();
    zm->sa_wait_warning =
      GNUNET_SCHEDULER_add_delayed (MONITOR_STALL_WARN_DELAY,
                                    &warn_monitor_slow,
                                    zm);
  }
}


/**
 * Process namestore requests.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  char *database;
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");
  return_orphaned = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                          "namestore",
                                                          "RETURN_ORPHANED");
  GSN_cfg = cfg;
  monitor_nc = GNUNET_notification_context_create (1);
  statistics = GNUNET_STATISTICS_create ("namestore", cfg);
  /* Loading database plugin */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "namestore",
                                                          "database",
                                                          &database))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }
  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Loading %s\n", db_lib_name);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
  GNUNET_free (database);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load database backend `%s'\n",
                db_lib_name);
    GNUNET_free (db_lib_name);
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&cleanup_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "namestore",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (record_store,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE,
                         struct RecordStoreMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (edit_record_set,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT,
                         struct EditRecordSetMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (edit_record_set_cancel,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_CANCEL,
                         struct EditRecordSetCancelMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (record_lookup,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP,
                         struct LabelLookupMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (zone_to_name,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME,
                         struct ZoneToNameMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (iteration_start,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START,
                         struct ZoneIterationStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (iteration_next,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT,
                           struct ZoneIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (iteration_stop,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP,
                           struct ZoneIterationStopMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (monitor_start,
                         GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START,
                         struct ZoneMonitorStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (monitor_next,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT,
                           struct ZoneMonitorNextMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-namestore.c */
