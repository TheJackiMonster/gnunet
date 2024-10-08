/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013, 2018 GNUnet e.V.

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
 * @addtogroup GNS
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * API that can be used to store naming information on a GNUnet node;
 *
 * @defgroup namestore  Name Store service
 * Store naming information on a GNUnet node.
 *
 * Naming information can either be records for which this peer/user is
 * authoritative, or blocks which are cached, encrypted naming data from other
 * peers.
 *
 * @see [Documentation](https://gnunet.org/namestore-subsystem)
 *
 * @{
 */
#ifndef GNUNET_NAMESTORE_SERVICE_H
#define GNUNET_NAMESTORE_SERVICE_H


#include "gnunet_error_codes.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Entry in the queue.
 */
struct GNUNET_NAMESTORE_QueueEntry;

/**
 * Handle to the namestore service.
 */
struct GNUNET_NAMESTORE_Handle;

/**
 * Handle to the namestore zone iterator.
 */
struct GNUNET_NAMESTORE_ZoneIterator;

/**
 * Transaction control types.
 * They roughly correspond to DB transaction controls
 */
enum GNUNET_NAMESTORE_TxControl
{
  GNUNET_NAMESTORE_TX_BEGIN = 0,
  GNUNET_NAMESTORE_TX_COMMIT = 1,
  GNUNET_NAMESTORE_TX_ROLLBACK = 2,
};

/**
 * A struct for record bulk import.
 * The fields are arrays pointing to individual GNS records and names.
 */
struct GNUNET_NAMESTORE_RecordInfo
{
  const char *a_label;
  unsigned int a_rd_count;
  struct GNUNET_GNSRECORD_Data *a_rd;
};


/**
 * Connect to the namestore service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_NAMESTORE_Handle *
GNUNET_NAMESTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the namestore service (and free associated
 * resources).  Must not be called from within operation callbacks of
 * the API.
 *
 * @param h handle to the namestore
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param ec the #GNUNET_ErrorCode, #GNUNET_EC_NONE on success.
 */
typedef void
(*GNUNET_NAMESTORE_ContinuationWithStatus) (void *cls,
                                            enum GNUNET_ErrorCode ec);


/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * The continuation is called after the value has been stored in the
 * database. Monitors may be notified asynchronously (basically with
 * a buffer). However, if any monitor is consistently too slow to
 * keep up with the changes, calling @a cont will be delayed until the
 * monitors do keep up.
 *
 * This always overwrites the record set and unsets any advisory
 * lock inrrespective of the currently set editor hint/advisory lock value.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped
 * @param rd_count number of records in the 'rd' array
 * @param rd array of records with data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_store (struct GNUNET_NAMESTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_PrivateKey *pkey,
                                   const char *label,
                                   unsigned int rd_count,
                                   const struct GNUNET_GNSRECORD_Data *rd,
                                   GNUNET_NAMESTORE_ContinuationWithStatus cont,
                                   void *cont_cls);

/**
 * Store one or more record sets in the namestore. If any item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * The continuation is called after the records have been stored in the
 * database. They may not yet have been committed. Monitors may be notified
 * asynchronously (basically with a buffer when committed).
 * However, if any monitor is consistently too slow to
 * keep up with the changes, calling @a cont will be delayed until the
 * monitors do keep up.
 * Uncommitted store requests within a transaction (GNUNET_NAMESTORE_transaction_begin)
 * cause @a cont to be called immediately before the commit and before
 * notification of monitors.
 *
 * This always overwrites the record set and unsets any advisory
 * lock inrrespective of the currently set editor hint/advisory lock value.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param rd_set_count the number of record sets
 * @param record_info the records to add containing @a rd_set_count records
 * @param cont continuation to call when done
 * @param rds_sent set to how many record sets could actually be sent
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_store (
  struct GNUNET_NAMESTORE_Handle *h,
  const struct GNUNET_CRYPTO_PrivateKey *pkey,
  unsigned int rd_set_count,
  const struct GNUNET_NAMESTORE_RecordInfo *record_info,
  unsigned int *rds_sent,
  GNUNET_NAMESTORE_ContinuationWithStatus cont,
  void *cont_cls);

/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * The continuation is called after the value has been stored in the
 * database. Monitors may be notified asynchronously (basically with
 * a buffer). However, if any monitor is consistently too slow to
 * keep up with the changes, calling @a cont will be delayed until the
 * monitors do keep up.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped
 * @param rd_count number of records in the 'rd' array
 * @param rd array of records with data to store
 * @param is_zonemaster update tombstones, do not process monitors
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_store_ (struct GNUNET_NAMESTORE_Handle *h,
                                    const struct GNUNET_CRYPTO_PrivateKey *pkey,
                                    const char *label,
                                    unsigned int rd_count,
                                    const struct GNUNET_GNSRECORD_Data *rd,
                                    int is_zonemaster,
                                    GNUNET_NAMESTORE_ContinuationWithStatus cont,
                                    void *cont_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone private key of the zone
 * @param label label of the records
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
typedef void
(*GNUNET_NAMESTORE_RecordMonitor) (void *cls,
                                   const struct
                                   GNUNET_CRYPTO_PrivateKey *zone,
                                   const char *label,
                                   unsigned int rd_count,
                                   const struct GNUNET_GNSRECORD_Data *rd);
/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param ec the error code. #GNUNET_EC_NONE on success.
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 * @param editor_hint the advisory lock value that was replaced. NULL of not advisory lock
                      was set or if lock was equal to provided editor hint.
 */
typedef void
(*GNUNET_NAMESTORE_EditRecordSetBeginCallback) (void *cls,
                                                enum GNUNET_ErrorCode ec,
                                                unsigned int rd_count,
                                                const struct
                                                GNUNET_GNSRECORD_Data *rd,
                                                const char *editor_hint);

/**
 * Process a record set that was stored in the namestore.
 * The record set expiration value takes existing TOMBSTONE records
 * into account even if those are not returned.
 *
 * @param cls closure
 * @param zone private key of the zone
 * @param label label of the records
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 * @param expiry the expiration of this record set.
 */
typedef void
(*GNUNET_NAMESTORE_RecordSetMonitor) (void *cls,
                                      const struct
                                      GNUNET_CRYPTO_PrivateKey *zone,
                                      const char *label,
                                      unsigned int rd_count,
                                      const struct GNUNET_GNSRECORD_Data *rd,
                                      struct GNUNET_TIME_Absolute expiry);


/**
 * Lookup an item in the namestore.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped
 * @param error_cb function to call on error (i.e. disconnect)
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param rm function to call with the result (with 0 records if we don't have that label);
 *        the handle is afterwards invalid
 * @param rm_cls closure for @a rm
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup (struct GNUNET_NAMESTORE_Handle *h,
                                 const struct
                                 GNUNET_CRYPTO_PrivateKey *pkey,
                                 const char *label,
                                 GNUNET_SCHEDULER_TaskCallback error_cb,
                                 void *error_cb_cls,
                                 GNUNET_NAMESTORE_RecordMonitor rm,
                                 void *rm_cls);

/**
 * Lookup an item in the namestore with GNSRECORD filter.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped
 * @param error_cb function to call on error (i.e. disconnect)
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param rm function to call with the result (with 0 records if we don't have that label);
 *        the handle is afterwards invalid
 * @param rm_cls closure for @a rm
 *  @param filter the record set filter to use
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup2 (struct GNUNET_NAMESTORE_Handle *h,
                                  const struct
                                  GNUNET_CRYPTO_PrivateKey *pkey,
                                  const char *label,
                                  GNUNET_SCHEDULER_TaskCallback error_cb,
                                  void *error_cb_cls,
                                  GNUNET_NAMESTORE_RecordMonitor rm,
                                  void *rm_cls,
                                  enum GNUNET_GNSRECORD_Filter filter);


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone private key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param error_cb function to call on error (i.e. disconnect)
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records;
 *        the handle is afterwards invalid
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (struct GNUNET_NAMESTORE_Handle *h,
                               const struct GNUNET_CRYPTO_PrivateKey *zone,
                               const struct
                               GNUNET_CRYPTO_PublicKey *value_zone,
                               GNUNET_SCHEDULER_TaskCallback error_cb,
                               void *error_cb_cls,
                               GNUNET_NAMESTORE_RecordMonitor proc,
                               void *proc_cls);


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.  Must be called on any
 * namestore operation that has not yet completed prior to calling
 * #GNUNET_NAMESTORE_disconnect.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe);


/**
 * @deprecated since 0.16.7 will be replaced in 0.18
 * @see GNUNET_NAMESTORE_zone_iteration_start2()
 *
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). This MUST lock the `struct GNUNET_NAMESTORE_Handle`
 * for any other calls than #GNUNET_NAMESTORE_zone_iterator_next() and
 * #GNUNET_NAMESTORE_zone_iteration_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_NAMESTORE_zone_iterator_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
                                       const struct
                                       GNUNET_CRYPTO_PrivateKey *zone,
                                       GNUNET_SCHEDULER_TaskCallback error_cb,
                                       void *error_cb_cls,
                                       GNUNET_NAMESTORE_RecordMonitor proc,
                                       void *proc_cls,
                                       GNUNET_SCHEDULER_TaskCallback finish_cb,
                                       void *finish_cb_cls);

/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). This MUST lock the `struct GNUNET_NAMESTORE_Handle`
 * for any other calls than #GNUNET_NAMESTORE_zone_iterator_next() and
 * #GNUNET_NAMESTORE_zone_iteration_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_NAMESTORE_zone_iterator_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @param filter the record set filter to use
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start2 (struct GNUNET_NAMESTORE_Handle *h,
                                        const struct
                                        GNUNET_CRYPTO_PrivateKey *zone,
                                        GNUNET_SCHEDULER_TaskCallback error_cb,
                                        void *error_cb_cls,
                                        GNUNET_NAMESTORE_RecordSetMonitor proc,
                                        void *proc_cls,
                                        GNUNET_SCHEDULER_TaskCallback finish_cb,
                                        void *finish_cb_cls,
                                        enum GNUNET_GNSRECORD_Filter filter);


/**
 * Calls the record processor specified in #GNUNET_NAMESTORE_zone_iteration_start
 * for the next record.
 *
 * @param it the iterator
 * @param limit number of records to return to the iterator in one shot
 *         (before #GNUNET_NAMESTORE_zone_iterator_next is to be called again)
 */
void
GNUNET_NAMESTORE_zone_iterator_next (struct GNUNET_NAMESTORE_ZoneIterator *it,
                                     uint64_t limit);


/**
 * Stops iteration and releases the namestore handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_NAMESTORE_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Handle for a monitoring activity.
 */
struct GNUNET_NAMESTORE_ZoneMonitor;


/**
 * @deprecated since 0.16.7 will be replaced in 0.18
 * @see GNUNET_NAMESTORE_zone_monitor_start2()
 *
 * Begin monitoring a zone for changes.  Will first call the @a
 * monitor function on all existing records in the selected zone(s) if
 * @a iterate_first is #GNUNET_YES.  In any case, we will then call @a
 * sync_cb, and then afterwards call the @a monitor whenever a record
 * changes.  If the namestore disconnects, the @a error_cb function is
 * called with a disconnect event. Once the connection is
 * re-established, the process begins from the start (depending on @a
 * iterate_first, we will again first do all existing records, then @a
 * sync, then updates).
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor, NULL for all zones
 * @param iterate_first #GNUNET_YES to first iterate over all existing records,
 *                      #GNUNET_NO to only return changes that happen from now on
 * @param error_cb function to call on error (i.e. disconnect); note that
 *         unlike the other error callbacks in this API, a call to this
 *         function does NOT destroy the monitor handle, it merely signals
 *         that monitoring is down. You need to still explicitly call
 *         #GNUNET_NAMESTORE_zone_monitor_stop().
 * @param error_cb_cls closure for @a error_cb
 * @param monitor function to call on zone changes, with an initial limit of 1
 * @param monitor_cls closure for @a monitor
 * @param sync_cb function called when we're in sync with the namestore
 * @param sync_cb_cls closure for @a sync_cb
 * @return handle to stop monitoring
 */
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
  void *sync_cb_cls);

/**
 * Begin monitoring a zone for changes.  Will first call the @a
 * monitor function on all existing records in the selected zone(s) if
 * @a iterate_first is #GNUNET_YES.  In any case, we will then call @a
 * sync_cb, and then afterwards call the @a monitor whenever a record
 * changes.  If the namestore disconnects, the @a error_cb function is
 * called with a disconnect event. Once the connection is
 * re-established, the process begins from the start (depending on @a
 * iterate_first, we will again first do all existing records, then @a
 * sync, then updates).
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor, NULL for all zones
 * @param iterate_first #GNUNET_YES to first iterate over all existing records,
 *                      #GNUNET_NO to only return changes that happen from now on
 * @param error_cb function to call on error (i.e. disconnect); note that
 *         unlike the other error callbacks in this API, a call to this
 *         function does NOT destroy the monitor handle, it merely signals
 *         that monitoring is down. You need to still explicitly call
 *         #GNUNET_NAMESTORE_zone_monitor_stop().
 * @param error_cb_cls closure for @a error_cb
 * @param monitor function to call on zone changes, with an initial limit of 1
 * @param monitor_cls closure for @a monitor
 * @param sync_cb function called when we're in sync with the namestore
 * @param sync_cb_cls closure for @a sync_cb
 * @param filter the record set filter to use
 * @return handle to stop monitoring
 */
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
  enum GNUNET_GNSRECORD_Filter filter);


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
                                    uint64_t limit);


/**
 * Stop monitoring a zone for changes.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_NAMESTORE_zone_monitor_stop (struct GNUNET_NAMESTORE_ZoneMonitor *zm);


/**
 * New API draft. Experimental
 */

/**
 * This function is used to initiate the editing
 * of a record set under #label.
 * It will set the editor hint of the record set to #editor_hint.
 * The editor hint serves as an advisory lock that is used in
 * #GNUNET_NAMESTORE_EdtirRecordSetBeginCallback if #editor_hint
 * differs from the currently set advisory lock in the database.
 *
 * @param h handle to the namestore
 * @param pkey the private key of the zone to edit
 * @param label the label of the record set to edit
 * @param editor_hint the editor hint to set as advisory lock
 * @param error_cb the error callback
 * @param error_cb_cls closure to #error_cb
 * @param edit_cb the #GNUNET_NAMESTORE_EditRecordSetBeginCallback
 * @param edit_cb_cls closure to #edit_cb
 * @return handle to the operation
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_edit_begin (struct GNUNET_NAMESTORE_Handle *h,
                                        const struct
                                        GNUNET_CRYPTO_PrivateKey *pkey,
                                        const char *label,
                                        const char *editor_hint,
                                        GNUNET_NAMESTORE_EditRecordSetBeginCallback
                                        edit_cb,
                                        void *edit_cb_cls);

/**
 * If the current advisory lock is set to the provided editor hint,
 * this API cancels the editing of a record set and unsets the advisory lock in database.
 * Optionally, a new editor hint can be provided: For example,
 * the value that was returned in in the callback to
 * #GNUNET_NAMESTORE_record_set_edit_begin.
 *
 * If provided editor hint does not match the current advisory lock,
 * this function is not doing anything (NOP).
 *
 * @param h handle to the namestore
 * @param pkey the private key of the zone to edit
 * @param label the label of the record set to edit
 * @param editor_hint the editor hint to set as advisory lock
 * @param editor_hint_replacement the editor hint to set as advisory lock instead of clearing it
 * @param finished_cb the callback called when cancelled
 * @param finished_cb_cls closure to #finished_cb
 * @return handle to the operation
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_set_edit_cancel (struct GNUNET_NAMESTORE_Handle *h,
                                         const struct
                                         GNUNET_CRYPTO_PrivateKey *pkey,
                                         const char *label,
                                         const char *editor_hint,
                                         const char *editor_hint_replacement,
                                         GNUNET_NAMESTORE_ContinuationWithStatus
                                         finished_cb,
                                         void *finished_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

/** @} */ /* end of group addition */
