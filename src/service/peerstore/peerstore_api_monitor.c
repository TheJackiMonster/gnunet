/*
     This file is part of GNUnet.
     Copyright (C) 2013-2024, 2019 GNUnet e.V.

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
 * @file service/peerstore/peerstore_api.c
 * @brief API for peerstore
 * @author Martin Schanzenbach
 */
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "peerstore.h"
#include "peerstore_common.h"
#include "gnunet_peerstore_service.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "peerstore-monitor-api", \
                                        __VA_ARGS__)
/**
 * Context for a monitor
 */
struct GNUNET_PEERSTORE_Monitor
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_Monitor *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_Monitor *prev;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Callback with each record received
   */
  GNUNET_PEERSTORE_Processor callback;

  /**
   * Closure for @e callback
   */
  void *callback_cls;

  /**
   * Hash of the combined key
   */
  struct GNUNET_HashCode keyhash;

  /**
   * The peer we are watching for values.
   */
  const struct GNUNET_PeerIdentity *peer;

  /**
   * The key we like to watch for values.
   */
  const char *key;

  /**
   * The sub system requested the watch.
   */
  const char *sub_system;

  /**
   * Request ID
   */
  uint32_t rid;

  /**
   * CFG
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Sync CB
   */
  GNUNET_SCHEDULER_TaskCallback sync_cb;

  /**
   * Sync CB cls
   */
  void *sync_cb_cls;

  /**
   * MQ
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Iterate first flag
   */
  int iterate_first;
};

static void
handle_sync (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Monitor *mc = cls;

  if (NULL != mc->sync_cb)
    mc->sync_cb (mc->sync_cb_cls);
}


/**
 * When a response for iterate request is received, check the
 * message is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_result (void *cls, const struct PeerstoreRecordMessage *msg)
{
  /* we defer validation to #handle_result */
  return GNUNET_OK;
}


/**
 * When a response to monitor is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_result (void *cls, const struct PeerstoreRecordMessage *msg)
{
  struct GNUNET_PEERSTORE_Monitor *mc = cls;
  struct GNUNET_PEERSTORE_Record *record;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Monitor received RecordMessage\n");
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    mc->callback (mc->callback_cls,
                  NULL,
                  _ ("Received a malformed response from service."));
  }
  else
  {
    mc->callback (mc->callback_cls, record, NULL);
    PEERSTORE_destroy_record (record);
  }
}


static void reconnect (struct GNUNET_PEERSTORE_Monitor *mc);

static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error err)
{
  struct GNUNET_PEERSTORE_Monitor *mc = cls;

  reconnect (mc);
}


static void
reconnect (struct GNUNET_PEERSTORE_Monitor *mc)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (sync,
                             GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_SYNC,
                             struct GNUNET_MessageHeader,
                             mc),
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD,
                           struct PeerstoreRecordMessage, mc),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct PeerstoreMonitorStartMessage *sm;
  size_t key_len = 0;

  if (NULL != mc->mq)
  {
    GNUNET_MQ_destroy (mc->mq);
    mc->error_cb (mc->error_cb_cls);
  }
  mc->mq = GNUNET_CLIENT_connect (mc->cfg,
                                  "peerstore",
                                  handlers,
                                  &mq_error_handler,
                                  mc);
  if (NULL == mc->mq)
    return;
  if (NULL != mc->key)
    key_len = strlen (mc->key) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending MONITOR_START\n");
  env = GNUNET_MQ_msg_extra (sm,
                             htons (key_len),
                             GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_START);
  sm->iterate_first = htons (mc->iterate_first);
  if (NULL != mc->peer)
  {
    sm->peer = *mc->peer;
    sm->peer_set = htons (GNUNET_YES);
  }
  if (NULL != mc->key)
    GNUNET_memcpy (&sm[1], mc->key, key_len);
  sm->key_size = htons (key_len);
  GNUNET_MQ_send (mc->mq, env);
}


struct GNUNET_PEERSTORE_Monitor *
GNUNET_PEERSTORE_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                int iterate_first,
                                const char *sub_system,
                                const struct GNUNET_PeerIdentity *peer,
                                const char *key,
                                GNUNET_SCHEDULER_TaskCallback error_cb,
                                void *error_cb_cls,
                                GNUNET_SCHEDULER_TaskCallback sync_cb,
                                void *sync_cb_cls,
                                GNUNET_PEERSTORE_Processor callback,
                                void *callback_cls)
{
  struct GNUNET_PEERSTORE_Monitor *mc;

  mc = GNUNET_new (struct GNUNET_PEERSTORE_Monitor);
  mc->callback = callback;
  mc->callback_cls = callback_cls;
  mc->sync_cb = sync_cb;
  mc->sync_cb_cls = sync_cb_cls;
  mc->error_cb = error_cb;
  mc->error_cb_cls = error_cb_cls;
  mc->key = key;
  mc->peer = peer;
  mc->iterate_first = iterate_first;
  mc->sub_system = sub_system;
  mc->cfg = cfg;
  reconnect (mc);
  if (NULL == mc->mq)
  {
    GNUNET_free (mc);
    return NULL;
  }
  return mc;
}


/**
 * Stop monitoring.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_PEERSTORE_monitor_stop (struct GNUNET_PEERSTORE_Monitor *zm)
{
  if (NULL != zm->mq)
  {
    GNUNET_MQ_destroy (zm->mq);
    zm->mq = NULL;
  }
  GNUNET_free (zm);
}


void
GNUNET_PEERSTORE_monitor_next (struct GNUNET_PEERSTORE_Monitor *zm,
                               uint64_t limit)
{
  struct GNUNET_MQ_Envelope *env;
  struct PeerstoreMonitorNextMessage *nm;

  env = GNUNET_MQ_msg (nm, GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_NEXT);
  nm->limit = GNUNET_htonll (limit);
  GNUNET_MQ_send (zm->mq, env);
}
