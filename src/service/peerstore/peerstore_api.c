/*
     This file is part of GNUnet.
     Copyright (C) 2013-2016, 2019 GNUnet e.V.

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
 * @file peerstore/peerstore_api.c
 * @brief API for peerstore
 * @author Omar Tarabai
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"
#include "peerstore.h"
#include "peerstore_common.h"
#include "gnunet_peerstore_service.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "peerstore-api", __VA_ARGS__)

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Handle to the PEERSTORE service.
 */
struct GNUNET_PEERSTORE_Handle
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Message queue
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of active STORE requests.
   */
  struct GNUNET_PEERSTORE_StoreContext *store_head;

  /**
   * Tail of active STORE requests.
   */
  struct GNUNET_PEERSTORE_StoreContext *store_tail;

  /**
   * Head of active ITERATE requests.
   */
  struct GNUNET_PEERSTORE_IterateContext *iterate_head;

  /**
   * Tail of active ITERATE requests.
   */
  struct GNUNET_PEERSTORE_IterateContext *iterate_tail;

  /**
   * Hashmap of watch requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *watches;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

};

/**
 * Context for a store request
 */
struct GNUNET_PEERSTORE_StoreContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Continuation called with service response
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for @e cont
   */
  void *cont_cls;

  /**
   * Which subsystem does the store?
   */
  char *sub_system;

  /**
   * Key for the store operation.
   */
  char *key;

  /**
   * Contains @e size bytes.
   */
  void *value;

  /**
   * Peer the store is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Number of bytes in @e value.
   */
  size_t size;

  /**
   * When does the value expire?
   */
  struct GNUNET_TIME_Absolute expiry;

  /**
   * Options for the store operation.
   */
  enum GNUNET_PEERSTORE_StoreOption options;
};

/**
 * Closure for store callback when storing hello uris.
 */
struct StoreHelloCls
{
  /**
   * The corresponding store context.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * The corresponding hello uri add request.
   */
  struct GNUNET_PEERSTORE_StoreHelloContext *huc;
};

/**
 * Context for a iterate request
 */
struct GNUNET_PEERSTORE_IterateContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_IterateContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_IterateContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Which subsystem does the store?
   */
  char *sub_system;

  /**
   * Peer the store is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Key for the store operation.
   */
  char *key;

  /**
   * Callback with each matching record
   */
  GNUNET_PEERSTORE_Processor callback;

  /**
   * Closure for @e callback
   */
  void *callback_cls;

  /**
   * #GNUNET_YES if we are currently processing records.
   */
  int iterating;
};

/**
 * Context for a watch request
 */
struct GNUNET_PEERSTORE_WatchContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_WatchContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_WatchContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

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
   * The iteration context to deliver the actual values for the key.
   */
  struct GNUNET_PEERSTORE_IterateContext *ic;

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
};

/**
 * Context for the info handler.
 */
struct GNUNET_PEERSTORE_NotifyContext
{
  /**
   * Peerstore handle.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Function to call with information.
   */
  GNUNET_PEERSTORE_hello_notify_cb callback;

  /**
   * Closure for @e callback.
   */
  void *callback_cls;

  /**
   * The watch for this context.
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * Is this request canceled.
   */
  unsigned int canceled;
};

/******************************************************************************/
/*******************             DECLARATIONS             *********************/
/******************************************************************************/

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *h`
 */
static void
reconnect (void *cls);


/**
 * Disconnect from the peerstore service.
 *
 * @param h peerstore handle to disconnect
 */
static void
disconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  struct GNUNET_PEERSTORE_IterateContext *next;

  for (struct GNUNET_PEERSTORE_IterateContext *ic = h->iterate_head; NULL != ic;
       ic = next)
  {
    next = ic->next;
    if (GNUNET_YES == ic->iterating)
    {
      GNUNET_PEERSTORE_Processor icb;
      void *icb_cls;

      icb = ic->callback;
      icb_cls = ic->callback_cls;
      GNUNET_PEERSTORE_iterate_cancel (ic);
      if (NULL != icb)
        icb (icb_cls, NULL, "Iteration canceled due to reconnection");
    }
  }

  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h peerstore to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  disconnect (h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to PEERSTORE service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay, GNUNET_YES));
  h->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Callback after MQ envelope is sent
 *
 * @param cls a `struct GNUNET_PEERSTORE_StoreContext *`
 */
static void
store_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;
  GNUNET_PEERSTORE_Continuation cont;
  void *cont_cls;

  if (NULL != sc)
  {
    cont = sc->cont;
    cont_cls = sc->cont_cls;
    GNUNET_PEERSTORE_store_cancel (sc);
    if (NULL != cont)
      cont (cont_cls, GNUNET_OK);
  }
}


/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/


/**
 * Function called when we had trouble talking to the service.
 */
static void
handle_client_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Received an error notification from MQ of type: %d\n",
       error);
  disconnect_and_schedule_reconnect (h);
}


/**
 * Iterator over previous watches to resend them
 *
 * @param cls the `struct GNUNET_PEERSTORE_Handle`
 * @param key key for the watch
 * @param value the `struct GNUNET_PEERSTORE_WatchContext *`
 * @return #GNUNET_YES (continue to iterate)
 */
static int
rewatch_it (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_WatchContext *wc = value;
  struct StoreKeyHashMessage *hm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
  hm->keyhash = wc->keyhash;
  GNUNET_MQ_send (h->mq, ev);
  return GNUNET_YES;
}


/**
 * Iterator over watch requests to cancel them.
 *
 * @param cls unused
 * @param key key to the watch request
 * @param value watch context
 * @return #GNUNET_YES to continue iteration
 */
static int
destroy_watch (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_PEERSTORE_WatchContext *wc = value;

  GNUNET_PEERSTORE_watch_cancel (wc);
  return GNUNET_YES;
}


/**
 * Connect to the PEERSTORE service.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PEERSTORE_Handle *h;

  h = GNUNET_new (struct GNUNET_PEERSTORE_Handle);
  h->cfg = cfg;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the PEERSTORE service. Any pending ITERATE and WATCH requests
 * will be canceled.
 * Any pending STORE requests will depend on @e snyc_first flag.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERSTORE_disconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting.\n");
  if (NULL != h->watches)
  {
    GNUNET_CONTAINER_multihashmap_iterate (h->watches, &destroy_watch, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (h->watches);
    h->watches = NULL;
  }
  while (NULL != (ic = h->iterate_head))
  {
    GNUNET_break (0);
    GNUNET_PEERSTORE_iterate_cancel (ic);
  }
  while (NULL != (sc = h->store_head))
  {
    GNUNET_break (0);
    GNUNET_PEERSTORE_store_cancel (sc);
  }
  disconnect (h);
}


/******************************************************************************/
/*******************            STORE FUNCTIONS           *********************/
/******************************************************************************/


/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "store cancel with sc %p \n",
              sc);
  GNUNET_CONTAINER_DLL_remove (sc->h->store_head, sc->h->store_tail, sc);
  GNUNET_free (sc->sub_system);
  GNUNET_free (sc->value);
  GNUNET_free (sc->key);
  GNUNET_free (sc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "store cancel with sc %p is null\n",
              sc);
}


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
                        void *cont_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Storing value (size: %lu) for subsystem `%s', peer `%s', key `%s'\n",
       size,
       sub_system,
       GNUNET_i2s (peer),
       key);
  ev =
    PEERSTORE_create_record_mq_envelope (sub_system,
                                         peer,
                                         key,
                                         value,
                                         size,
                                         expiry,
                                         options,
                                         GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
  sc = GNUNET_new (struct GNUNET_PEERSTORE_StoreContext);

  sc->sub_system = GNUNET_strdup (sub_system);
  sc->peer = *peer;
  sc->key = GNUNET_strdup (key);
  sc->value = GNUNET_memdup (value, size);
  sc->size = size;
  sc->expiry = expiry;
  sc->options = options;
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;

  GNUNET_CONTAINER_DLL_insert_tail (h->store_head, h->store_tail, sc);
  GNUNET_MQ_notify_sent (ev, &store_request_sent, sc);
  GNUNET_MQ_send (h->mq, ev);
  return sc;
}


/******************************************************************************/
/*******************           ITERATE FUNCTIONS          *********************/
/******************************************************************************/


/**
 * When a response for iterate request is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_iterate_end (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;

  ic = h->iterate_head;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Unexpected iteration response, this should not happen.\n"));
    disconnect_and_schedule_reconnect (h);
    return;
  }
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  ic->iterating = GNUNET_NO;
  GNUNET_PEERSTORE_iterate_cancel (ic);
  /* NOTE: set this here and not after callback because callback may free h */
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  if (NULL != callback)
    callback (callback_cls, NULL, NULL);
}


/**
 * When a response for iterate request is received, check the
 * message is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_iterate_result (void *cls, const struct StoreRecordMessage *msg)
{
  /* we defer validation to #handle_iterate_result */
  return GNUNET_OK;
}


/**
 * When a response for iterate request is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_iterate_result (void *cls, const struct StoreRecordMessage *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;
  struct GNUNET_PEERSTORE_Record *record;

  ic = h->iterate_head;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Unexpected iteration response, this should not happen.\n"));
    disconnect_and_schedule_reconnect (h);
    return;
  }
  ic->iterating = GNUNET_YES;
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  if (NULL == callback)
    return;
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    callback (callback_cls,
              NULL,
              _ ("Received a malformed response from service."));
  }
  else
  {
    callback (callback_cls, record, NULL);
    PEERSTORE_destroy_record (record);
  }
}


/**
 * Cancel an iterate request
 * Please do not call after the iterate request is done
 *
 * @param ic Iterate request context as returned by GNUNET_PEERSTORE_iterate()
 */
void
GNUNET_PEERSTORE_iterate_cancel (struct GNUNET_PEERSTORE_IterateContext *ic)
{
  if (GNUNET_YES == ic->iterating)
  {
    if (NULL != ic->callback)
      ic->callback (ic->callback_cls, NULL, "Iteration canceled due to reconnection");
  }
  GNUNET_CONTAINER_DLL_remove (ic->h->iterate_head, ic->h->iterate_tail, ic);
  GNUNET_free (ic->sub_system);
  GNUNET_free (ic->key);
  GNUNET_free (ic);
}


struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iterate (struct GNUNET_PEERSTORE_Handle *h,
                          const char *sub_system,
                          const struct GNUNET_PeerIdentity *peer,
                          const char *key,
                          GNUNET_PEERSTORE_Processor callback,
                          void *callback_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PEERSTORE_IterateContext *ic;

  ev =
    PEERSTORE_create_record_mq_envelope (sub_system,
                                         peer,
                                         key,
                                         NULL,
                                         0,
                                         GNUNET_TIME_UNIT_FOREVER_ABS,
                                         0,
                                         GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE);
  ic = GNUNET_new (struct GNUNET_PEERSTORE_IterateContext);
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->h = h;
  ic->sub_system = GNUNET_strdup (sub_system);
  if (NULL != peer)
    ic->peer = *peer;
  if (NULL != key)
    ic->key = GNUNET_strdup (key);
  GNUNET_CONTAINER_DLL_insert_tail (h->iterate_head, h->iterate_tail, ic);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending an iterate request for sub system `%s'\n",
       sub_system);
  GNUNET_MQ_send (h->mq, ev);
  return ic;
}


/******************************************************************************/
/*******************            WATCH FUNCTIONS           *********************/
/******************************************************************************/

/**
 * When a watch record is received, validate it is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_watch_record (void *cls, const struct StoreRecordMessage *msg)
{
  /* we defer validation to #handle_watch_result */
  return GNUNET_OK;
}


/**
 * When a watch record is received, process it.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_watch_record (void *cls, const struct StoreRecordMessage *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_Record *record;
  struct GNUNET_HashCode keyhash;
  struct GNUNET_PEERSTORE_WatchContext *wc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received a watch record from service.\n");
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    disconnect_and_schedule_reconnect (h);
    return;
  }
  PEERSTORE_hash_key (record->sub_system, &record->peer, record->key, &keyhash);
  // FIXME: what if there are multiple watches for the same key?
  wc = GNUNET_CONTAINER_multihashmap_get (h->watches, &keyhash);
  if (NULL == wc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Received a watch result for a non existing watch.\n"));
    PEERSTORE_destroy_record (record);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  if (NULL != wc->callback)
    wc->callback (wc->callback_cls, record, NULL);
  PEERSTORE_destroy_record (record);
}


/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 */
static void
reconnect (void *cls)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler mq_handlers[] =
  { GNUNET_MQ_hd_fixed_size (iterate_end,
                             GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END,
                             struct GNUNET_MessageHeader,
                             h),
    GNUNET_MQ_hd_var_size (iterate_result,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD,
                           struct StoreRecordMessage,
                           h),
    GNUNET_MQ_hd_var_size (watch_record,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD,
                           struct StoreRecordMessage,
                           h),
    GNUNET_MQ_handler_end () };
  struct GNUNET_MQ_Envelope *ev;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting...\n");
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "peerstore",
                                 mq_handlers,
                                 &handle_client_error,
                                 h);
  if (NULL == h->mq)
  {
    h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
    h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resending pending requests after reconnect.\n");
  if (NULL != h->watches)
    GNUNET_CONTAINER_multihashmap_iterate (h->watches, &rewatch_it, h);
  for (struct GNUNET_PEERSTORE_IterateContext *ic = h->iterate_head; NULL != ic;
       ic = ic->next)
  {
    ev =
      PEERSTORE_create_record_mq_envelope (ic->sub_system,
                                           &ic->peer,
                                           ic->key,
                                           NULL,
                                           0,
                                           GNUNET_TIME_UNIT_FOREVER_ABS,
                                           0,
                                           GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE);
    GNUNET_MQ_send (h->mq, ev);
  }
  for (struct GNUNET_PEERSTORE_StoreContext *sc = h->store_head; NULL != sc;
       sc = sc->next)
  {
    ev =
      PEERSTORE_create_record_mq_envelope (sc->sub_system,
                                           &sc->peer,
                                           sc->key,
                                           sc->value,
                                           sc->size,
                                           sc->expiry,
                                           sc->options,
                                           GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
    GNUNET_MQ_notify_sent (ev, &store_request_sent, sc);
    GNUNET_MQ_send (h->mq, ev);
  }
}


/**
 * Cancel a watch request
 *
 * @param wc handle to the watch request
 */
void
GNUNET_PEERSTORE_watch_cancel (struct GNUNET_PEERSTORE_WatchContext *wc)
{
  struct GNUNET_PEERSTORE_Handle *h = wc->h;
  struct GNUNET_MQ_Envelope *ev;
  struct StoreKeyHashMessage *hm;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Canceling watch.\n");
  if (NULL != wc->ic)
  {
    GNUNET_PEERSTORE_iterate_cancel (wc->ic);
    GNUNET_free (wc);
    return;
  }

  ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL);
  hm->keyhash = wc->keyhash;
  GNUNET_MQ_send (h->mq, ev);
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multihashmap_remove (h->watches, &wc->keyhash, wc));
  GNUNET_free (wc);
}


static void
watch_iterate (void *cls,
               const struct GNUNET_PEERSTORE_Record *record,
               const char *emsg)
{
  struct GNUNET_PEERSTORE_WatchContext *wc = cls;
  struct GNUNET_PEERSTORE_Handle *h = wc->h;
  struct StoreKeyHashMessage *hm;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Got failure from PEERSTORE: %s\n",
                emsg);
    wc->callback (wc->callback_cls, NULL, emsg);
    return;
  }
  if (NULL == record)
  {
    struct GNUNET_MQ_Envelope *ev;
    const struct GNUNET_PeerIdentity *peer;

    if (NULL == wc->peer)
      peer = GNUNET_new (struct GNUNET_PeerIdentity);
    else
      peer = wc->peer;
    ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
    PEERSTORE_hash_key (wc->sub_system, peer, wc->key, &hm->keyhash);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Hash key we watch for %s\n",
         GNUNET_h2s_full (&hm->keyhash));
    wc->keyhash = hm->keyhash;
    if (NULL == h->watches)
      h->watches = GNUNET_CONTAINER_multihashmap_create (5, GNUNET_NO);
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (
                     h->watches,
                     &wc->keyhash,
                     wc,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending a watch request for subsystem `%s', peer `%s', key `%s'.\n",
         wc->sub_system,
         GNUNET_i2s (peer),
         wc->key);
    GNUNET_MQ_send (h->mq, ev);
    wc->ic = NULL;
    if (NULL != wc->callback)
      wc->callback (wc->callback_cls, record, NULL);
    if (NULL == wc->peer)
      GNUNET_free_nz ((void *) peer);
    return;
  }

  if (NULL != wc->callback)
    wc->callback (wc->callback_cls, record, NULL);
}


/**
 * Request watching a given key
 * User will be notified with any new values added to key,
 * all existing entries are supplied beforehand.
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity
 * @param key entry key string
 * @param callback function called with each new value
 * @param callback_cls closure for @a callback
 * @return Handle to watch request
 */
struct GNUNET_PEERSTORE_WatchContext *
GNUNET_PEERSTORE_watch (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        GNUNET_PEERSTORE_Processor callback,
                        void *callback_cls)
{
  struct GNUNET_PEERSTORE_WatchContext *wc;

  wc = GNUNET_new (struct GNUNET_PEERSTORE_WatchContext);
  wc->callback = callback;
  wc->callback_cls = callback_cls;
  wc->h = h;
  wc->key = key;
  wc->peer = peer;
  wc->sub_system = sub_system;

  wc->ic = GNUNET_PEERSTORE_iterate (h,
                                     sub_system,
                                     peer,
                                     key,
                                     &watch_iterate,
                                     wc);

  return wc;
}


/******************************************************************************/
/*******************            HELLO FUNCTIONS           *********************/
/******************************************************************************/


static void
hello_updated (void *cls,
               const struct GNUNET_PEERSTORE_Record *record,
               const char *emsg)
{
  struct GNUNET_PEERSTORE_NotifyContext *nc = cls;
  const struct GNUNET_MessageHeader *hello;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "hello_updated\n");
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Got failure from PEERSTORE: %s\n",
                emsg);
    nc->callback (nc->callback_cls, NULL, NULL, emsg);
    return;
  }
  if (NULL == record)
    return;
  hello = record->value;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "hello_updated with expired %s and size %u for peer %s\n",
              GNUNET_STRINGS_absolute_time_to_string (
                GNUNET_HELLO_builder_get_expiration_time (hello)),
              ntohs (hello->size),
              GNUNET_i2s (&record->peer));
  if ((0 == record->value_size))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "hello_updated call callback\n");
  nc->callback (nc->callback_cls, &record->peer, hello, NULL);
}


struct GNUNET_PEERSTORE_NotifyContext *
GNUNET_PEERSTORE_hello_changed_notify (struct GNUNET_PEERSTORE_Handle *h,
                                       int include_friend_only,
                                       GNUNET_PEERSTORE_hello_notify_cb callback,
                                       void *callback_cls)
{
  struct GNUNET_PEERSTORE_NotifyContext *nc;

  nc = GNUNET_new (struct GNUNET_PEERSTORE_NotifyContext);
  nc->callback = callback;
  nc->callback_cls = callback_cls;
  nc->h = h;

  nc->wc = GNUNET_PEERSTORE_watch (h,
                                   "peerstore",
                                   NULL,
                                   GNUNET_PEERSTORE_HELLO_KEY,
                                   &hello_updated,
                                   nc);

  return nc;
}


/**
 * Stop notifying about changes.
 *
 * @param nc context to stop notifying
 */
void
GNUNET_PEERSTORE_hello_changed_notify_cancel (struct
                                              GNUNET_PEERSTORE_NotifyContext *nc)
{
  if (NULL != nc->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (nc->wc);
    nc->wc = NULL;
  }
}


static void
merge_success (void *cls, int success)
{
  struct StoreHelloCls *shu_cls = cls;
  struct GNUNET_PEERSTORE_StoreHelloContext *huc = shu_cls->huc;

  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_remove (huc->store_context_map,
                                                         huc->pid, shu_cls->sc))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "There was no store context to be removed after storing hello for peer %s\n",
                GNUNET_i2s (huc->pid));
  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Storing hello uri failed\n");
    huc->cont (huc->cont_cls, success);
    GNUNET_free (huc->hello);
    GNUNET_free (huc->pid);
    GNUNET_free (huc);
    GNUNET_free (shu_cls);
    return;
  }
  if (0 == GNUNET_CONTAINER_multipeermap_size (huc->store_context_map))
  {
    GNUNET_PEERSTORE_watch_cancel (huc->wc);
    huc->wc = NULL;
    huc->cont (huc->cont_cls, GNUNET_OK);
    huc->success = GNUNET_OK;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Storing hello uri succeeded for peer %s!\n",
                GNUNET_i2s (huc->pid));
    GNUNET_free (huc->hello);
    GNUNET_free (huc->pid);
    GNUNET_free (huc);
    GNUNET_free (shu_cls);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got notified during storing hello uri for peer %s!\n",
              GNUNET_i2s (huc->pid));
  GNUNET_free (shu_cls);
}


static void
store_hello (struct GNUNET_PEERSTORE_StoreHelloContext *huc,
             const struct GNUNET_MessageHeader *hello)
{
  struct GNUNET_PEERSTORE_Handle *h = huc->h;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  struct StoreHelloCls *shu_cls = GNUNET_new (struct StoreHelloCls);
  struct GNUNET_TIME_Absolute hello_exp;

  shu_cls->huc = huc;
  hello_exp = GNUNET_HELLO_builder_get_expiration_time (hello);
  sc = GNUNET_PEERSTORE_store (h,
                               "peerstore",
                               huc->pid,
                               GNUNET_PEERSTORE_HELLO_KEY,
                               hello,
                               ntohs (hello->size),
                               hello_exp,
                               GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                               merge_success,
                               shu_cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "store_hello with expiration %s\n",
              GNUNET_STRINGS_absolute_time_to_string (hello_exp));
  GNUNET_assert (GNUNET_SYSERR != GNUNET_CONTAINER_multipeermap_put (
                   huc->store_context_map,
                   huc->pid,
                   sc,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  shu_cls->sc = sc;
}


// TODO Find a better name for the function. We do not merge, but replace, if there is a storing process
//     during another store process with a newer hello.
static void
merge_uri  (void *cls,
            const struct GNUNET_PEERSTORE_Record *record,
            const char *emsg)
{
  struct GNUNET_PEERSTORE_StoreHelloContext *huc = cls;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_TIME_Absolute huc_hello_exp_time;
  struct GNUNET_TIME_Absolute record_hello_exp_time;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Got failure from PEERSTORE: %s\n",
                emsg);
    return;
  }

  if (NULL == record && GNUNET_NO == huc->success)
  {
    huc_hello_exp_time = GNUNET_HELLO_builder_get_expiration_time (huc->hello);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "merge_uri just store for peer %s with expiration %s\n",
                GNUNET_i2s (huc->pid),
                GNUNET_STRINGS_absolute_time_to_string (huc_hello_exp_time));
    store_hello (huc, huc->hello);
  }
  else if (GNUNET_NO == huc->success && 0 == GNUNET_memcmp (huc->pid,
                                                            &record->peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "merge_uri record for peer %s\n",
                GNUNET_i2s (&record->peer));
    hello = record->value;
    if ((0 == record->value_size))
    {
      GNUNET_break (0);
      return;
    }

    huc_hello_exp_time = GNUNET_HELLO_builder_get_expiration_time (huc->hello);
    record_hello_exp_time = GNUNET_HELLO_builder_get_expiration_time (hello);

    if (GNUNET_TIME_absolute_cmp (huc_hello_exp_time, >, record_hello_exp_time))
      store_hello (huc, huc->hello);
  }
}


struct GNUNET_PEERSTORE_StoreHelloContext *
GNUNET_PEERSTORE_hello_add (struct GNUNET_PEERSTORE_Handle *h,
                            const struct GNUNET_MessageHeader *msg,
                            GNUNET_PEERSTORE_Continuation cont,
                            void *cont_cls)
{
  struct GNUNET_HELLO_Builder *builder = GNUNET_HELLO_builder_from_msg (msg);
  struct GNUNET_PEERSTORE_StoreHelloContext *huc;
  const struct GNUNET_PeerIdentity *pid;
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute hello_exp =
    GNUNET_HELLO_builder_get_expiration_time (msg);
  struct GNUNET_TIME_Absolute huc_exp;
  uint16_t pid_size;
  uint16_t size_msg = ntohs (msg->size);

  if (NULL == builder)
    return NULL;
  if (GNUNET_TIME_absolute_cmp (hello_exp, <, now))
    return NULL;

  huc = GNUNET_new (struct GNUNET_PEERSTORE_StoreHelloContext);
  huc->store_context_map = GNUNET_CONTAINER_multipeermap_create (1, GNUNET_NO);
  huc->h = h;
  huc->cont = cont;
  huc->cont_cls = cont_cls;
  huc->hello = GNUNET_malloc (size_msg);
  GNUNET_memcpy (huc->hello, msg, size_msg);
  huc_exp =
    GNUNET_HELLO_builder_get_expiration_time (huc->hello);
  pid = GNUNET_HELLO_builder_get_id (builder);
  pid_size = sizeof (struct GNUNET_PeerIdentity);
  huc->pid = GNUNET_malloc (pid_size);
  GNUNET_memcpy (huc->pid, pid, pid_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding hello for peer %s with expiration %s msg size %u\n",
       GNUNET_i2s (huc->pid),
       GNUNET_STRINGS_absolute_time_to_string (huc_exp),
       size_msg);
  huc->wc = GNUNET_PEERSTORE_watch (h,
                                    "peerstore",
                                    NULL,
                                    GNUNET_PEERSTORE_HELLO_KEY,
                                    &merge_uri,
                                    huc);
  GNUNET_HELLO_builder_free (builder);

  return huc;
}


static enum GNUNET_GenericReturnValue
free_store_context (void *cls,
                    const struct GNUNET_PeerIdentity *key,
                    void *value)
{
  (void) cls;

  GNUNET_PEERSTORE_store_cancel ((struct
                                  GNUNET_PEERSTORE_StoreContext *) value);
  return GNUNET_YES; // FIXME why is this a map anyway
}


void
GNUNET_PEERSTORE_hello_add_cancel (struct
                                   GNUNET_PEERSTORE_StoreHelloContext *huc)
{
  GNUNET_PEERSTORE_watch_cancel (huc->wc);
  GNUNET_CONTAINER_multipeermap_iterate (huc->store_context_map,
                                         free_store_context,
                                         NULL);
  GNUNET_free (huc->hello);
  GNUNET_free (huc->pid);
  GNUNET_free (huc);
}


/* end of peerstore_api.c */
