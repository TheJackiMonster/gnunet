/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file peerstore/gnunet-service-peerstore.c
 * @brief peerstore service implementation
 * @author Omar Tarabai
 */
#include "gnunet_peerstore_service.h"
#include "gnunet_protocols.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "peerstore.h"
#include "gnunet_peerstore_plugin.h"
#include "peerstore_common.h"
#include "gnunet_hello_uri_lib.h"


/**
 * Interval for expired records cleanup (in seconds)
 */
#define EXPIRED_RECORDS_CLEANUP_INTERVAL 300 /* 5mins */


/**
 * A namestore client
 */
struct PeerstoreClient;

/**
 * A peerstore monitor.
 */
struct Monitor
{
  /**
   * Next element in the DLL
   */
  struct Monitor *next;

  /**
   * Previous element in the DLL
   */
  struct Monitor *prev;

  /**
   * Namestore client which intiated this zone monitor
   */
  struct PeerstoreClient *pc;

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
   * result of the iteration in the store
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
   * Is the peer set?
   */
  int peer_set;

  /**
   * Responsible sub system string
   */
  char *sub_system;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Record key string
   */
  char *key;
};

/**
 * A peerstore iteration operation.
 */
struct Iteration
{
  /**
   * Next element in the DLL
   */
  struct Iteration *next;

  /**
   * Previous element in the DLL
   */
  struct Iteration *prev;

  /**
   * Namestore client which intiated this zone iteration
   */
  struct PeerstoreClient *pc;

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
   * client and we should send the #GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD_RESULT_END
   * message and free the data structure.
   */
  int send_end;

  /**
   * Responsible sub system string
   */
  char *sub_system;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Record key string
   */
  char *key;

  /**
   * Peer is set?
   */
  int peer_set;
};

/**
 * A peerstore client
 */
struct PeerstoreClient
{
  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct Iteration *op_head;

  /**
   * Tail of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct Iteration *op_tail;
};


struct StoreRecordContext
{
  /**
   * The record that was stored.
   */
  struct GNUNET_PEERSTORE_Record *record;

  /**
   * The request ID
   */
  uint32_t rid;

  /**
   * The client
   */
  struct PeerstoreClient *pc;
};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Database plugin library name
 */
static char *db_lib_name;

/**
 * Database handle
 */
static struct GNUNET_PEERSTORE_PluginFunctions *db;

/**
 * Task run to clean up expired records.
 */
static struct GNUNET_SCHEDULER_Task *expire_task;

/**
 * Monitor DLL
 */
static struct Monitor *monitors_head;

/**
 * Monitor DLL
 */
static struct Monitor *monitors_tail;

/**
 * Notification context shared by all monitors.
 */
static struct GNUNET_NotificationContext *monitor_nc;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down peerstore, bye.\n");
  if (NULL != db_lib_name)
  {
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, db));
    GNUNET_free (db_lib_name);
    db_lib_name = NULL;
  }
  if (NULL != expire_task)
  {
    GNUNET_SCHEDULER_cancel (expire_task);
    expire_task = NULL;
  }
  if (NULL != monitor_nc)
  {
    GNUNET_notification_context_destroy (monitor_nc);
    monitor_nc = NULL;
  }
}


/* Forward declaration */
static void
expire_records_continuation (void *cls, int success);


/**
 * Deletes any expired records from storage
 */
static void
cleanup_expired_records (void *cls)
{
  int ret;

  expire_task = NULL;
  GNUNET_assert (NULL != db);
  ret = db->expire_records (db->cls,
                            GNUNET_TIME_absolute_get (),
                            &expire_records_continuation,
                            NULL);
  if (GNUNET_OK != ret)
  {
    GNUNET_assert (NULL == expire_task);
    expire_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     EXPIRED_RECORDS_CLEANUP_INTERVAL),
      &cleanup_expired_records,
      NULL);
  }
}


/**
 * Continuation to expire_records called by the peerstore plugin
 *
 * @param cls unused
 * @param success count of records deleted or #GNUNET_SYSERR
 */
static void
expire_records_continuation (void *cls, int success)
{
  if (success > 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d records expired.\n", success);
  GNUNET_assert (NULL == expire_task);
  expire_task = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                   EXPIRED_RECORDS_CLEANUP_INTERVAL),
    &cleanup_expired_records,
    NULL);
}


/**
 * Send 'sync' message to zone monitor, we're now in sync.
 *
 * @param zm monitor that is now in sync
 */
static void
monitor_sync (struct Monitor *mc)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *sync;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Synching zone monitor %p\n", mc);

  env = GNUNET_MQ_msg (sync, GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_SYNC);
  GNUNET_MQ_send (mc->pc->mq, env);
  /* mark iteration done */
  mc->in_first_iteration = GNUNET_NO;
  mc->iteration_cnt = 0;
}


/**
 * Given a new record, notifies watchers
 *
 * @param record changed record to update watchers with
 */
static void
watch_notifier (struct GNUNET_PEERSTORE_Record *record)
{
  struct GNUNET_MQ_Envelope *env;
  struct Monitor *mc;

  // FIXME this is very inefficient, we may want to use a hash
  // map again.
  for (mc = monitors_head; NULL != mc; mc = mc->next)
  {
    if ((GNUNET_YES == mc->peer_set) &&
        (0 != memcmp (&mc->peer, &record->peer, sizeof (record->peer))))
      continue;
    if ((NULL != mc->sub_system) &&
        (0 != strcmp (mc->sub_system, record->sub_system)))
      continue;
    if ((NULL != mc->key) &&
        (0 != strcmp (mc->key, record->key)))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found watcher %p to update.\n", mc);
    env = PEERSTORE_create_record_mq_envelope (
      0,
      record->sub_system,
      &record->peer,
      record->key,
      record->value,
      record->value_size,
      record->expiry,
      0,
      GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD);
    GNUNET_MQ_send (mc->pc->mq, env);
  }
}


/**
 * Context for iteration operations passed from
 * #run_iteration_round to #iterate_proc as closure
 */
struct IterationProcResult
{
  /**
   * The zone iteration handle
   */
  struct Iteration *ic;

  /**
   * Number of results left to be returned in this iteration.
   */
  uint64_t limit;

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
iterate_proc (void *cls,
              uint64_t seq,
              const struct GNUNET_PEERSTORE_Record *record,
              const char *emsg)
{
  struct IterationProcResult *proc = cls;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error iterating over peerstore: `%s'", emsg);
    return;
  }
  if (NULL == record)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration done\n");
    return;
  }
  if (0 == proc->limit)
  {
    /* what is this!? should never happen */
    GNUNET_break (0);
    return;
  }
  proc->ic->seq = seq;
  env = PEERSTORE_create_record_mq_envelope (
    proc->ic->request_id,
    record->sub_system,
    &record->peer,
    record->key,
    record->value,
    record->value_size,
    record->expiry,
    0,
    GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD);
  GNUNET_MQ_send (proc->ic->pc->mq, env);
  proc->limit--;
}

/**
 * Function called once we are done with the iteration and
 * allow the zone iteration client to send us more messages.
 *
 * @param zi zone iteration we are processing
 */
static void
iteration_done_client_continue (struct Iteration *ic)
{
  struct GNUNET_MQ_Envelope *env;
  struct PeerstoreResultMessage *endmsg;

  GNUNET_SERVICE_client_continue (ic->pc->client);
  if (! ic->send_end)
    return;
  /* No more records */

  env = GNUNET_MQ_msg (endmsg, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END);
  endmsg->rid = htons (ic->request_id);
  endmsg->result = htonl (GNUNET_OK);
  GNUNET_MQ_send (ic->pc->mq, env);
  GNUNET_free (ic->key);
  GNUNET_free (ic->sub_system);
  GNUNET_CONTAINER_DLL_remove (ic->pc->op_head, ic->pc->op_tail, ic);
  GNUNET_free (ic);
  return;
}



/**
 * Perform the next round of the zone iteration.
 *
 * @param ic iterator to process
 * @param limit number of results to return in one pass
 */
static void
run_iteration_round (struct Iteration *ic, uint64_t limit)
{
  struct IterationProcResult proc;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative duration;

  memset (&proc, 0, sizeof(proc));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to return up to %llu records at position %llu\n",
              (unsigned long long) limit,
              (unsigned long long) ic->seq);
  proc.ic = ic;
  proc.limit = limit;
  start = GNUNET_TIME_absolute_get ();
  GNUNET_break (GNUNET_SYSERR !=
                db->iterate_records (db->cls,
                                     ic->sub_system,
                                     (GNUNET_YES == ic->peer_set) ? &ic->peer :
                                     NULL,
                                     ic->key,
                                     ic->seq,
                                     proc.limit,
                                     &iterate_proc,
                                     &proc));
  duration = GNUNET_TIME_absolute_get_duration (start);
  duration = GNUNET_TIME_relative_divide (duration, limit - proc.limit);
  if (0 == proc.limit)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returned %llu results, more results available\n",
                (unsigned long long) limit);
  ic->send_end = (0 != proc.limit);
  iteration_done_client_continue (ic);
}


/**
 * Check an iterate request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 * @return #GNUNET_OK if @a srm is well-formed
 */
static int
check_iterate_start (void *cls, const struct
                     PeerstoreIterationStartMessage *srm)
{
  uint16_t ss_size;
  uint16_t key_size;
  uint16_t size;

  ss_size = ntohs (srm->sub_system_size);
  key_size = ntohs (srm->key_size);
  size = ntohs (srm->header.size);

  if (size < key_size + ss_size + sizeof(*srm))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an iterate request from client
 *
 * @param cls identification of the client
 * @param srm the actual message
 */
static void
handle_iterate_start (void *cls, const struct PeerstoreIterationStartMessage *
                      srm)
{
  struct Iteration *ic = GNUNET_new (struct Iteration);
  uint16_t ss_size;
  char *ptr;

  ss_size = ntohs (srm->sub_system_size);

  ic->pc = cls;
  ic->request_id = ntohs (srm->rid);
  ic->offset = 0;
  ic->peer_set = (ntohs (srm->peer_set)) ? GNUNET_YES : GNUNET_NO;
  if (GNUNET_YES == ic->peer_set)
    ic->peer = srm->peer;
  ptr = (char*) &srm[1];
  ic->sub_system = GNUNET_strdup (ptr);
  ptr += ss_size;
  if (0 < ntohs (srm->key_size))
    ic->key = GNUNET_strdup (ptr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Iterate request: ss `%s', peer `%s', key `%s'\n",
              ic->sub_system,
              GNUNET_i2s (&ic->peer),
              (NULL == ic->key) ? "NULL" : ic->key);
  GNUNET_CONTAINER_DLL_insert (ic->pc->op_head,
                               ic->pc->op_tail,
                               ic);
  run_iteration_round (ic, 1);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATION_STOP message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iterate_stop (void *cls,
                     const struct PeerstoreIterationStopMessage *zis_msg)
{
  struct PeerstoreClient *pc = cls;
  struct Iteration *ic;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ITERATION_STOP message\n");
  rid = ntohl (zis_msg->rid);
  for (ic = pc->op_head; NULL != ic; ic = ic->next)
    if (ic->request_id == rid)
      break;
  if (NULL == ic)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (pc->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (pc->op_head, pc->op_tail, ic);
  GNUNET_free (ic);
  GNUNET_SERVICE_client_continue (pc->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATION_NEXT message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iterate_next (void *cls,
                     const struct PeerstoreIterationNextMessage *is_msg)
{
  struct PeerstoreClient *pc = cls;
  struct Iteration *ic;
  uint32_t rid;
  uint64_t limit;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ITERATION_NEXT message\n");
  rid = ntohs (is_msg->rid);
  limit = GNUNET_ntohll (is_msg->limit);
  for (ic = pc->op_head; NULL != ic; ic = ic->next)
    if (ic->request_id == rid)
      break;
  if (NULL == ic)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not in iteration...\n");
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (pc->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found iteration...\n");
  run_iteration_round (ic, limit);
}


/**
 * Obtain the next datum during the monitor's initial iteration.
 *
 * @param cls monitor that does its initial iteration
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
                    const struct GNUNET_PEERSTORE_Record *record,
                    const char *emsg)
{
  struct Monitor *mc = cls;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert (0 != seq);
  mc->seq = seq;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error iterating over peerstore: `%s'", emsg);
    return;
  }
  if (NULL == record)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration done\n");
    return;
  }
  if (0 == mc->limit)
  {
    /* what is this!? should never happen */
    GNUNET_break (0);
    return;
  }
  env = PEERSTORE_create_record_mq_envelope (
    0,
    record->sub_system,
    &record->peer,
    record->key,
    record->value,
    record->value_size,
    record->expiry,
    0,
    GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD);
  GNUNET_MQ_send (mc->pc->mq, env);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent records.\n");
  mc->limit--;
  mc->iteration_cnt--;
  if ((0 == mc->iteration_cnt) && (0 != mc->limit))
  {
    /* We are done with the current iteration batch, AND the
       client would right now accept more, so go again! */
    GNUNET_assert (NULL == mc->task);
    mc->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, mc);
  }
}


/**
 * Obtain the next datum during the zone monitor's zone initial iteration.
 *
 * @param cls zone monitor that does its initial iteration
 */
static void
monitor_iteration_next (void *cls)
{
  struct Monitor *mc = cls;
  int ret;

  mc->task = NULL;
  GNUNET_assert (0 == mc->iteration_cnt);
  if (mc->limit > 16)
    mc->iteration_cnt = mc->limit / 2;   /* leave half for monitor events */
  else
    mc->iteration_cnt = mc->limit;   /* use it all */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running iteration\n");
  ret = db->iterate_records (db->cls,
                             mc->sub_system,
                             (GNUNET_YES == mc->peer_set) ? &mc->peer : NULL,
                             mc->key,
                             mc->seq,
                             mc->iteration_cnt,
                             &monitor_iterate_cb,
                             mc);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_free (mc->key);
    GNUNET_free (mc->sub_system);
    GNUNET_free (mc);
    GNUNET_SERVICE_client_drop (mc->pc->client);
    return;
  }
  if (GNUNET_NO == ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Zone empty... syncing\n");
    /* empty zone */
    monitor_sync (mc);
    return;
  }
}


/**
 * Check a monitor request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 * @return #GNUNET_OK if @a srm is well-formed
 */
static int
check_monitor_start (void *cls, const struct PeerstoreMonitorStartMessage *srm)
{
  uint16_t ss_size;
  uint16_t key_size;
  uint16_t size;

  ss_size = ntohs (srm->sub_system_size);
  key_size = ntohs (srm->key_size);
  size = ntohs (srm->header.size);

  if (size < key_size + ss_size + sizeof(*srm))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an iterate request from client
 *
 * @param cls identification of the client
 * @param srm the actual message
 */
static void
handle_monitor_start (void *cls, const struct PeerstoreMonitorStartMessage *msm)
{
  struct Monitor *mc = GNUNET_new (struct Monitor);

  uint16_t ss_size;
  char *ptr;

  ss_size = ntohs (msm->sub_system_size);

  mc->pc = cls;
  mc->peer_set = (ntohs (msm->peer_set)) ? GNUNET_YES : GNUNET_NO;
  if (GNUNET_YES == mc->peer_set)
    mc->peer = msm->peer;
  ptr = (char*) &msm[1];
  if (0 < ss_size)
    mc->sub_system = GNUNET_strdup (ptr);
  ptr += ss_size;
  if (0 < ntohs (msm->key_size))
    mc->key = GNUNET_strdup (ptr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Monitor request: ss `%s', peer `%s', key `%s'\n",
              mc->sub_system,
              GNUNET_i2s (&mc->peer),
              (NULL == mc->key) ? "NULL" : mc->key);
  mc->in_first_iteration = (GNUNET_YES == ntohs (msm->iterate_first));
  mc->limit = 1;
  mc->peer_set = (ntohs (msm->peer_set)) ? GNUNET_YES : GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (monitors_head,
                               monitors_tail,
                               mc);
  GNUNET_SERVICE_client_mark_monitor (mc->pc->client);
  GNUNET_SERVICE_client_continue (mc->pc->client);
  GNUNET_notification_context_add (monitor_nc, mc->pc->mq);
  if (mc->in_first_iteration)
    mc->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, mc);
  else
    monitor_sync (mc);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_NEXT message
 *
 * @param cls the client sending the message
 * @param nm message from the client
 */
static void
handle_monitor_next (void *cls, const struct PeerstoreMonitorNextMessage *nm)
{
  struct PeerstoreClient *pc = cls;
  struct Monitor *mc;
  uint64_t inc;

  inc = GNUNET_ntohll (nm->limit);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received MONITOR_NEXT message with limit %llu\n",
              (unsigned long long) inc);
  for (mc = monitors_head; NULL != mc; mc = mc->next)
    if (mc->pc == pc)
      break;
  if (NULL == mc)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (pc->client);
    return;
  }
  GNUNET_SERVICE_client_continue (pc->client);
  if (mc->limit + inc < mc->limit)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (pc->client);
    return;
  }
  mc->limit += inc;
  if ((mc->in_first_iteration) && (mc->limit == inc))
  {
    /* We are still iterating, and the previous iteration must
       have stopped due to the client's limit, so continue it! */
    GNUNET_assert (NULL == mc->task);
    mc->task = GNUNET_SCHEDULER_add_now (&monitor_iteration_next, mc);
  }
  GNUNET_assert (mc->iteration_cnt <= mc->limit);
}


/**
 * Continuation of store_record called by the peerstore plugin
 *
 * @param cls closure
 * @param success result
 */
static void
store_record_continuation (void *cls, int success)
{
  struct StoreRecordContext *src = cls;
  struct PeerstoreResultMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT);
  msg->rid = src->rid;
  msg->result = htonl (success);
  GNUNET_MQ_send (src->pc->mq, env);
  watch_notifier (src->record);
  GNUNET_SERVICE_client_continue (src->pc->client);
  PEERSTORE_destroy_record (src->record);
  GNUNET_free (src);
}


/**
 * Check a store request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 * @return #GNUNET_OK if @a srm is well-formed
 */
static int
check_store (void *cls, const struct PeerstoreRecordMessage *srm)
{
  struct GNUNET_PEERSTORE_Record *record;

  record = PEERSTORE_parse_record_message (srm);
  if (NULL == record)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ((NULL == record->sub_system) || (NULL == record->key))
  {
    GNUNET_break (0);
    PEERSTORE_destroy_record (record);
    return GNUNET_SYSERR;
  }
  PEERSTORE_destroy_record (record);
  return GNUNET_OK;
}


/**
 * Handle a store request from client
 *
 * @param cls client identification of the client
 * @param srm the actual message
 */
static void
handle_store (void *cls, const struct PeerstoreRecordMessage *srm)
{
  struct PeerstoreClient *pc = cls;
  struct StoreRecordContext *src = GNUNET_new (struct StoreRecordContext);
  src->record = PEERSTORE_parse_record_message (srm);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Received a store request. Sub system `%s' Peer `%s Key `%s' Options: %u.\n",
    src->record->sub_system,
    GNUNET_i2s (&src->record->peer),
    src->record->key,
    (uint32_t) ntohl (srm->options));
  src->rid = srm->rid;
  src->pc = pc;
  if (GNUNET_OK != db->store_record (db->cls,
                                     src->record->sub_system,
                                     &src->record->peer,
                                     src->record->key,
                                     src->record->value,
                                     src->record->value_size,
                                     src->record->expiry,
                                     ntohl (srm->options),
                                     &store_record_continuation,
                                     src))
  {
    GNUNET_break (0);
    PEERSTORE_destroy_record (src->record);
    GNUNET_free (src);
    GNUNET_SERVICE_client_drop (pc->client);
    GNUNET_free (pc);
    return;
  }
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 * @param mq the message queue
 * @return
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct PeerstoreClient *pc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "A client %p connected\n", client);
  pc = GNUNET_new (struct PeerstoreClient);
  pc->client = client;
  pc->mq = mq;
  return pc;
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_cls)
{
  struct PeerstoreClient *pc = app_cls;
  struct Iteration *iter;
  struct Monitor *mo;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected.\n",
              client);
  for (mo = monitors_head; NULL != mo; mo = mo->next)
  {
    if (pc != mo->pc)
      continue;
    GNUNET_CONTAINER_DLL_remove (monitors_head, monitors_tail, mo);
    if (NULL != mo->task)
    {
      GNUNET_SCHEDULER_cancel (mo->task);
      mo->task = NULL;
    }
    if (NULL != mo->sa_wait_warning)
    {
      GNUNET_SCHEDULER_cancel (mo->sa_wait_warning);
      mo->sa_wait_warning = NULL;
    }
    GNUNET_free (mo);
    break;
  }
  while (NULL != (iter = pc->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (pc->op_head, pc->op_tail, iter);
    GNUNET_free (iter);
  }
  GNUNET_free (pc);
}


static void
store_hello_continuation (void *cls, int success)
{
  (void) cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error storing bootstrap hello!\n");
    GNUNET_break (0);
  }
}


static int
hosts_directory_scan_callback (void *cls, const char *fullname)
{
  (void) cls;
  ssize_t size_total;
  char buffer[GNUNET_MAX_MESSAGE_SIZE - 1] GNUNET_ALIGN;
  const struct GNUNET_MessageHeader *hello;
  struct GNUNET_HELLO_Builder *builder;
  const struct GNUNET_PeerIdentity *pid;

  if (GNUNET_YES != GNUNET_DISK_file_test (fullname))
    return GNUNET_OK; /* ignore non-files */

  size_total = GNUNET_DISK_fn_read (fullname, buffer, sizeof(buffer));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Read %d bytes from `%s'\n",
              (int) size_total,
              fullname);
  if ((size_total < 0) ||
      (((size_t) size_total) < sizeof(struct GNUNET_MessageHeader)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to parse HELLO in file `%s': %s\n"),
                fullname,
                "File has invalid size");
    return GNUNET_OK;
  }
  hello = (const struct GNUNET_MessageHeader *) &buffer[0];
  builder = GNUNET_HELLO_builder_from_msg (hello);
  if (NULL == builder)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse HELLO message\n");
    return GNUNET_OK;
  }
  pid = GNUNET_HELLO_builder_get_id (builder);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "store contrib hello for peer %s\n",
              GNUNET_i2s (pid));

  if (GNUNET_OK != db->store_record (db->cls,
                                     "peerstore",
                                     pid,
                                     GNUNET_PEERSTORE_HELLO_KEY,
                                     hello,
                                     size_total,
                                     GNUNET_TIME_UNIT_FOREVER_ABS,
                                     GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
                                     &store_hello_continuation,
                                     NULL))
  {
    GNUNET_break (0);
  }
  GNUNET_HELLO_builder_free (builder);
  return GNUNET_OK;
}


/**
 * Peerstore service runner.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  char *database;
  int use_included;
  char *ip;
  char *peerdir;

  cfg = c;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "peerstore",
                                                          "DATABASE",
                                                          &database))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "peerstore",
                               "DATABASE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_peerstore_%s", database);
  db = GNUNET_PLUGIN_load (db_lib_name, (void *) cfg);
  GNUNET_free (database);
  if (NULL == db)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not load database backend `%s'\n"),
                db_lib_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  expire_task = GNUNET_SCHEDULER_add_now (&cleanup_expired_records, NULL);

  use_included = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                       "peerstore",
                                                       "USE_INCLUDED_HELLOS");
  if (GNUNET_SYSERR == use_included)
    use_included = GNUNET_NO;
  if (GNUNET_YES == use_included)
  {
    ip = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
    GNUNET_asprintf (&peerdir, "%shellos", ip);
    GNUNET_free (ip);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Importing HELLOs from `%s'\n"),
                peerdir);

    GNUNET_DISK_directory_scan (peerdir,
                                &hosts_directory_scan_callback,
                                NULL);
    GNUNET_free (peerdir);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Skipping import of included HELLOs\n"));
  }
  monitor_nc = GNUNET_notification_context_create (1);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "peerstore", GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN, &run, &client_connect_cb,
  &client_disconnect_cb, NULL,
  GNUNET_MQ_hd_var_size (store, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE,
                         struct PeerstoreRecordMessage, NULL),
  GNUNET_MQ_hd_var_size (iterate_start,
                         GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_START,
                         struct PeerstoreIterationStartMessage, NULL),
  GNUNET_MQ_hd_fixed_size (iterate_stop,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_STOP,
                           struct PeerstoreIterationStopMessage, NULL),
  GNUNET_MQ_hd_fixed_size (iterate_next,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_NEXT,
                           struct PeerstoreIterationNextMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (monitor_start,
                         GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_START,
                         struct PeerstoreMonitorStartMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (monitor_next,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_NEXT,
                           struct PeerstoreMonitorNextMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-peerstore.c */
