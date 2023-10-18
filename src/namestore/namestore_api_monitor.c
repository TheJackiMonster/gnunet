/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016, 2018 GNUnet e.V.

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
 * @file namestore/namestore_api_monitor.c
 * @brief API to monitor changes in the NAMESTORE
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"


/**
 * Handle for a monitoring activity.
 */
struct GNUNET_NAMESTORE_ZoneMonitor
{
  /**
   * Configuration (to reconnect).
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle to namestore service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Function to call on events.
   */
  GNUNET_NAMESTORE_RecordMonitor monitor;

  /**
   * Function to call on events.
   */
  GNUNET_NAMESTORE_RecordSetMonitor monitor2;

  /**
   * Record set filter for this monitor
   */
  enum GNUNET_GNSRECORD_Filter filter;

  /**
   * Closure for @e monitor.
   */
  void *monitor_cls;

  /**
   * Function called when we've synchronized.
   */
  GNUNET_SCHEDULER_TaskCallback sync_cb;

  /**
   * Closure for @e sync_cb.
   */
  void *sync_cb_cls;

  /**
   * Monitored zone.
   */
  struct GNUNET_CRYPTO_PrivateKey zone;

  /**
   * Do we first iterate over all existing records?
   */
  int iterate_first;

  /**
   * Zone key length
   */
  uint32_t key_len;
};


/**
 * Reconnect to the namestore service.
 *
 * @param zm monitor to reconnect
 */
static void
reconnect (struct GNUNET_NAMESTORE_ZoneMonitor *zm);


/**
 * Handle SYNC message from the namestore service.
 *
 * @param cls the monitor
 * @param msg the sync message
 */
static void
handle_sync (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;

  (void) cls;
  (void) msg;
  if (NULL != zm->sync_cb)
    zm->sync_cb (zm->sync_cb_cls);
}


/**
 * We've received a notification about a change to our zone.
 * Check that it is well-formed.
 *
 * @param cls the zone monitor handle
 * @param lrm the message from the service.
 */
static int
check_result (void *cls, const struct RecordResultMessage *lrm)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;
  size_t lrm_len;
  size_t exp_lrm_len;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;
  size_t key_len;

  (void) zm;
  key_len = ntohs (lrm->key_len);
  (void) cls;
  if (0 == key_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  lrm_len = ntohs (lrm->gns_header.header.size);
  rd_len = ntohs (lrm->rd_len);
  rd_count = ntohs (lrm->rd_count);
  name_len = ntohs (lrm->name_len);
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  exp_lrm_len = sizeof(struct RecordResultMessage) + name_len + rd_len + key_len;
  if (lrm_len != exp_lrm_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (0 == name_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_tmp = (const char *) &lrm[1] + key_len;
  if (name_tmp[name_len - 1] != '\0')
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK !=
        GNUNET_GNSRECORD_records_deserialize (rd_len, rd_ser_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/**
 * We've received a notification about a change to our zone.
 * Forward to monitor callback.
 *
 * @param cls the zone monitor handle
 * @param lrm the message from the service.
 */
static void
handle_result (void *cls, const struct RecordResultMessage *lrm)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;
  struct GNUNET_CRYPTO_PrivateKey private_key;
  size_t name_len;
  size_t rd_len;
  size_t key_len;
  size_t kbytes_read;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;

  key_len = ntohs (lrm->key_len);
  rd_len = ntohs (lrm->rd_len);
  rd_count = ntohs (lrm->rd_count);
  name_len = ntohs (lrm->name_len);
  name_tmp = (const char *) &lrm[1] + key_len;
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CRYPTO_read_private_key_from_buffer (&lrm[1],
                                                               key_len,
                                                               &private_key,
                                                               &kbytes_read));
  GNUNET_assert (kbytes_read == key_len);
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (
      GNUNET_OK ==
      GNUNET_GNSRECORD_records_deserialize (rd_len, rd_ser_tmp, rd_count, rd));
    if (NULL != zm->monitor2)
      zm->monitor2 (zm->monitor_cls, &private_key, name_tmp,
                    rd_count, rd, GNUNET_TIME_absolute_ntoh (lrm->expire));
    else
      zm->monitor (zm->monitor_cls, &private_key, name_tmp, rd_count, rd);
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NAMESTORE_ZoneMonitor *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm = cls;

  (void) error;
  reconnect (zm);
}


/**
 * Reconnect to the namestore service.
 *
 * @param zm monitor to reconnect
 */
static void
reconnect (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_fixed_size (sync,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC,
                             struct GNUNET_MessageHeader,
                             zm),
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT,
                           struct RecordResultMessage,
                           zm),
    GNUNET_MQ_handler_end () };
  struct GNUNET_MQ_Envelope *env;
  struct ZoneMonitorStartMessage *sm;

  if (NULL != zm->mq)
  {
    GNUNET_MQ_destroy (zm->mq);
    zm->error_cb (zm->error_cb_cls);
  }
  zm->mq = GNUNET_CLIENT_connect (zm->cfg,
                                  "namestore",
                                  handlers,
                                  &mq_error_handler,
                                  zm);
  if (NULL == zm->mq)
    return;
  env = GNUNET_MQ_msg_extra (sm,
                             zm->key_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START);
  sm->iterate_first = htonl (zm->iterate_first);
  if (0 < zm->key_len)
    GNUNET_CRYPTO_write_private_key_to_buffer (&zm->zone,
                                               &sm[1],
                                               zm->key_len);
  sm->key_len = htons (zm->key_len);
  sm->filter = htons (zm->filter);
  GNUNET_MQ_send (zm->mq, env);
}


struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const struct GNUNET_CRYPTO_PrivateKey *zone,
  int iterate_first,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordMonitor monitor,
  void *monitor_cls,
  GNUNET_SCHEDULER_TaskCallback sync_cb,
  void *sync_cb_cls)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm;

  zm = GNUNET_new (struct GNUNET_NAMESTORE_ZoneMonitor);
  if (NULL != zone)
  {
    zm->key_len = GNUNET_CRYPTO_private_key_get_length (zone);
    zm->zone = *zone;
  }
  zm->iterate_first = iterate_first;
  zm->error_cb = error_cb;
  zm->error_cb_cls = error_cb_cls;
  zm->monitor = monitor;
  zm->monitor_cls = monitor_cls;
  zm->sync_cb = sync_cb;
  zm->sync_cb_cls = sync_cb_cls;
  zm->cfg = cfg;
  reconnect (zm);
  if (NULL == zm->mq)
  {
    GNUNET_free (zm);
    return NULL;
  }
  return zm;
}

struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start2 (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const struct GNUNET_CRYPTO_PrivateKey *zone,
  int iterate_first,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_NAMESTORE_RecordSetMonitor monitor,
  void *monitor_cls,
  GNUNET_SCHEDULER_TaskCallback sync_cb,
  void *sync_cb_cls,
  enum GNUNET_GNSRECORD_Filter filter)
{
  struct GNUNET_NAMESTORE_ZoneMonitor *zm;

  zm = GNUNET_new (struct GNUNET_NAMESTORE_ZoneMonitor);
  if (NULL != zone)
  {
    zm->key_len = GNUNET_CRYPTO_private_key_get_length (zone);
    zm->zone = *zone;
  }
  zm->iterate_first = iterate_first;
  zm->error_cb = error_cb;
  zm->error_cb_cls = error_cb_cls;
  zm->monitor2 = monitor;
  zm->monitor_cls = monitor_cls;
  zm->sync_cb = sync_cb;
  zm->sync_cb_cls = sync_cb_cls;
  zm->cfg = cfg;
  zm->filter = filter;
  reconnect (zm);
  if (NULL == zm->mq)
  {
    GNUNET_free (zm);
    return NULL;
  }
  return zm;
}


/**
 * Calls the monitor processor specified in #GNUNET_NAMESTORE_zone_monitor_start
 * for the next record(s).  This function is used to allow clients that merely
 * monitor the NAMESTORE to still throttle namestore operations, so we can be
 * sure that the monitors can keep up.
 *
 * Note that #GNUNET_NAMESTORE_records_store() only waits for this
 * call if the previous limit set by the client was already reached.
 * Thus, by using a @a limit greater than 1, monitors basically enable
 * a queue of notifications to be processed asynchronously with some
 * delay.  Note that even with a limit of 1 the
 * #GNUNET_NAMESTORE_records_store() function will run asynchronously
 * and the continuation may be invoked before the monitors completed
 * (or even started) processing the notification.  Thus, monitors will
 * only closely track the current state of the namestore, but not
 * be involved in the transactions.
 *
 * @param zm the monitor
 * @param limit number of records to return to the iterator in one shot
 *        (before #GNUNET_NAMESTORE_zone_monitor_next is to be called again)
 */
void
GNUNET_NAMESTORE_zone_monitor_next (struct GNUNET_NAMESTORE_ZoneMonitor *zm,
                                    uint64_t limit)
{
  struct GNUNET_MQ_Envelope *env;
  struct ZoneMonitorNextMessage *nm;

  env = GNUNET_MQ_msg (nm, GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT);
  nm->limit = GNUNET_htonll (limit);
  GNUNET_MQ_send (zm->mq, env);
}


/**
 * Stop monitoring a zone for changes.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_NAMESTORE_zone_monitor_stop (struct GNUNET_NAMESTORE_ZoneMonitor *zm)
{
  if (NULL != zm->mq)
  {
    GNUNET_MQ_destroy (zm->mq);
    zm->mq = NULL;
  }
  GNUNET_free (zm);
}


/* end of namestore_api_monitor.c */
