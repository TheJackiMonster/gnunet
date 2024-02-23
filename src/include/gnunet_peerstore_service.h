/*
      This file is part of GNUnet
      Copyright (C) GNUnet e.V. 2004--2019

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
 * @addtogroup Backbone
 * @{
 *
 * @author Omar Tarabai
 *
 * @file
 * API to the peerstore service
 *
 * @defgroup peerstore  Peer Store service
 *
 * @see [Documentation](https://gnunet.org/gnunets-peerstore-subsystem)
 *
 * @{
 */
#ifndef GNUNET_PEERSTORE_SERVICE_H
#define GNUNET_PEERSTORE_SERVICE_H


#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Key used for storing HELLO in the peerstore
 */
#define GNUNET_PEERSTORE_HELLO_KEY "peerstore-peer-hello-uri"

/**
 * Key used for storing addresses in URL format in the peerstore
 */
#define GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY "transport-communicator-url"

/**
 * Key used for storing HELLOs in the peerstore
 */
#define GNUNET_PEERSTORE_TRANSPORT_HELLO_KEY "transport-peer-hello"

/**
 * Key used to store sender's monotonic time from backchannel
 * messages.
 */
#define GNUNET_PEERSTORE_TRANSPORT_BACKCHANNEL_MONOTIME \
        "transport-backchannel-monotonic-time"

/**
 * Key used to store sender's monotonic time from DV learn
 * messages.
 */
#define GNUNET_PEERSTORE_TRANSPORT_DVLEARN_MONOTIME \
        "transport-dv-learn-monotonic-time"

/**
 * Key used to store sender's monotonic time from handshake message.
 */
#define GNUNET_PEERSTORE_TRANSPORT_TCP_COMMUNICATOR_HANDSHAKE \
        "transport-tcp-communicator-handshake"

/**
 * Key used to store sender's monotonic time from handshake ack message.
 */
#define GNUNET_PEERSTORE_TRANSPORT_TCP_COMMUNICATOR_HANDSHAKE_ACK \
        "transport-tcp-communicator-handshake-ack"

/**
 * Key used to store sender's monotonic time from rekey message.
 */
#define GNUNET_PEERSTORE_TRANSPORT_TCP_COMMUNICATOR_REKEY \
        "transport-tcp-communicator-rekey"


/**
 * Options for storing values in PEERSTORE
 */
enum GNUNET_PEERSTORE_StoreOption
{
  /**
   * Possibly store multiple values under given key.
   */
  GNUNET_PEERSTORE_STOREOPTION_MULTIPLE = 0,

  /**
   * Delete any previous values for the given key before
   * storing the given value.
   */
  GNUNET_PEERSTORE_STOREOPTION_REPLACE = 1,

  /**
   * Upserts values. Replaces if expiry is later than existing.
   */
  GNUNET_PEERSTORE_STOREOPTION_UPSERT_LATER_EXPIRY = 2
};

/**
 * Handle to the peerstore service.
 */
struct GNUNET_PEERSTORE_Handle;

/**
 * Context for a store request
 */
struct GNUNET_PEERSTORE_StoreContext;

/**
 * Context for the info handler.
 */
struct GNUNET_PEERSTORE_NotifyContext;

/**
 * Single PEERSTORE record
 */
struct GNUNET_PEERSTORE_Record
{
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
   * Record value BLOB
   */
  void *value;

  /**
   * Size of @e value BLOB
   */
  size_t value_size;

  /**
   * Expiry time of entry
   */
  struct GNUNET_TIME_Absolute expiry;

};


/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param success #GNUNET_OK or #GNUNET_SYSERR
 */
typedef void (*GNUNET_PEERSTORE_Continuation) (void *cls, int success);


/**
 * Context for a add hello uri request.
 */
struct GNUNET_PEERSTORE_StoreHelloContext
{
  /**
   * Kept (also) in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *prev;

  /**
   * Kept (also) in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *next;

  /**
   * Peerstore handle.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Function to call with information.
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for @e callback.
   */
  void *cont_cls;

  /**
   * Hello uri which was request for storing.
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * The peer id for the hello.
   */
  struct GNUNET_PeerIdentity *pid;

  /**
   * The iteration for the merge
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

};

/**
 * Closure to hold a GNUNET_PEERSTORE_StoreHelloContext.
 */
struct GNUNET_PEERSTORE_StoreHelloContextClosure
{
  /**
   * The GNUNET_PEERSTORE_StoreHelloContext to hold.
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *shc;
};

/**
 * Function called by PEERSTORE for each matching record.
 *
 * @param cls closure
 * @param seq sequence in interation
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 */
typedef void (*GNUNET_PEERSTORE_Processor) (
  void *cls,
  const struct GNUNET_PEERSTORE_Record *record,
  const char *emsg);

/**
 * Function called by PEERSTORE when notifying a client about a changed hello.
 *
 * @param cls closure
 * @param hello_uri Hello uri.
 */
typedef void (*GNUNET_PEERSTORE_hello_notify_cb) (
  void *cls,
  const struct GNUNET_PeerIdentity *peer,
  const struct GNUNET_MessageHeader *hello,
  const char *err_msg);

/**
 * Add hello to peerstore.
 *
 * @param h handle for peerstore.
 * @param msg The hello to add.
 * @param cont The continuation function to execute after storing.
 * @param cont_cls The continuation function closure.
 * @return The context for storing.
 */
struct GNUNET_PEERSTORE_StoreHelloContext *
GNUNET_PEERSTORE_hello_add (struct GNUNET_PEERSTORE_Handle *h,
                            const struct GNUNET_MessageHeader *msg,
                            GNUNET_PEERSTORE_Continuation cont,
                            void *cont_cls);


/**
 * Cancel the request to add a hello.
 *
 * @param huc The context for storing a hello.
 */
void
GNUNET_PEERSTORE_hello_add_cancel (struct
                                   GNUNET_PEERSTORE_StoreHelloContext *huc);


/**
 * Connect to the PEERSTORE service.
 *
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the PEERSTORE service. Any pending ITERATE and WATCH and
 * STORE requests will be canceled.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERSTORE_disconnect (struct GNUNET_PEERSTORE_Handle *h);


/**
 * Store a new entry in the PEERSTORE.
 * Note that stored entries can be lost in some cases
 * such as power failure.
 *
 * @param h Handle to the PEERSTORE service
 * @param sub_system name of the sub system
 * @param peer Peer Identity
 * @param key entry key
 * @param value entry value BLOB
 * @param size size of @e value
 * @param expiry absolute time after which the entry is (possibly) deleted
 * @param options options specific to the storage operation
 * @param cont Continuation function after the store request is sent
 * @param cont_cls Closure for @a cont
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        const void *value,
                        size_t size,
                        struct GNUNET_TIME_Absolute expiry,
                        enum GNUNET_PEERSTORE_StoreOption options,
                        GNUNET_PEERSTORE_Continuation cont,
                        void *cont_cls);


/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc);


/**
 * Iterate over peerstore entries.
 * The iteration can be filtered to contain only records
 * matching @a peer and/or @a key.
 * The @a sub_system to match must be provided.
 * @a callback will be called with (each) matching record.
 * #GNUNET_PEERSTORE_iteration_next() must be invoked
 * to continue processing until the end of the iteration is
 * reached.
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @param callback function called with each matching record. The record will be NULL to indicate end.
 * @param callback_cls closure for @a callback
 * @return Handle to iteration request
 */
struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iteration_start (struct GNUNET_PEERSTORE_Handle *h,
                                  const char *sub_system,
                                  const struct GNUNET_PeerIdentity *peer,
                                  const char *key,
                                  GNUNET_PEERSTORE_Processor callback,
                                  void *callback_cls);


/**
 * Continue an iteration.
 * Do NOT call after the iterate request is done.
 *
 * @param ic Iterate request context as returned by #GNUNET_PEERSTORE_iteration_start()
 * @param limit how many records to return max until #GNUNET_PEERSTORE_iterate_next() needs to be called again.
 */
void
GNUNET_PEERSTORE_iteration_next (struct GNUNET_PEERSTORE_IterateContext *ic,
                                 uint64_t limit);


/**
 * Cancel an iteration.
 * Do NOT call after the iterate request is done
 *
 * @param ic Iterate request context as returned by #GNUNET_PEERSTORE_iteration_start()
 */
void
GNUNET_PEERSTORE_iteration_stop (struct GNUNET_PEERSTORE_IterateContext *ic);

/**
 * Request watching a given key
 * The monitoring can be filtered to contain only records
 * matching @a peer and/or @a key.
 * The @a sub_system to match must be provided.
 * @a callback will be called with (each) matching new record.
 * #GNUNET_PEERSTORE_monitor_next() must be invoked
 * to continue processing until @a sync_cb is
 * called, indicating that the caller should be up-to-date.
 * The caller will be notified with any new values added to key
 * through @a callback.
 * If @a iterate_first is set to GNUNET_YES, the monitor will first
 * iterate over all existing, matching records. In any case,
 * after @a sync_cb is called the first time monitoring starts.
 *
 * @param h handle to the PEERSTORE service
 * @param iterate_first first iterated of all results if GNUNET_YES
 * @param sub_system name of sub system
 * @param peer Peer identity
 * @param key entry key string
 * @param error_cb function to call on error (i.e. disconnect); note that
 *         unlike the other error callbacks in this API, a call to this
 *         function does NOT destroy the monitor handle, it merely signals
 *         that monitoring is down. You need to still explicitly call
 *         #GNUNET_PEERSTORE_monitor_stop().
 * @param error_cb_cls closure for @a error_cb
 * @param sync_cb function called when we're in sync with the peerstore
 * @param sync_cb_cls closure for @a sync_cb
 * @param callback function called with each new value
 * @param callback_cls closure for @a callback
 * @return Handle to watch request
 */
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
                                void *callback_cls);

/**
 * Calls the monitor processor specified in #GNUNET_PEERSTORE_monitor_start
 * for the next record(s).  This function is used to allow clients that merely
 * monitor the NAMESTORE to still throttle namestore operations, so we can be
 * sure that the monitors can keep up.
 *
 * Note that #GNUNET_PEERSTORE_store() only waits for this
 * call if the previous limit set by the client was already reached.
 * Thus, by using a @a limit greater than 1, monitors basically enable
 * a queue of notifications to be processed asynchronously with some
 * delay.  Note that even with a limit of 1 the
 * #GNUNET_PEERSTORE_store() function will run asynchronously
 * and the continuation may be invoked before the monitors completed
 * (or even started) processing the notification.  Thus, monitors will
 * only closely track the current state of the peerstore, but not
 * be involved in the transactions.
 *
 * @param zm the monitor
 * @param limit number of records to return to the iterator in one shot
 *        (before #GNUNET_PEERSTORE_monitor_next is to be called again)
 */
void
GNUNET_PEERSTORE_monitor_next (struct GNUNET_PEERSTORE_Monitor *zm,
                               uint64_t limit);

/**
 * Stop monitoring.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_PEERSTORE_monitor_stop (struct GNUNET_PEERSTORE_Monitor *zm);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */

/** @} */ /* end of group addition */
