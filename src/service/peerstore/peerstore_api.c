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
#include "gnunet_time_lib.h"
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
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

  /**
   *
   */
  uint32_t last_op_id;

};

/**
* Context for a add hello uri request.
*/
struct GNUNET_PEERSTORE_StoreHelloContext
{
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
  struct GNUNET_PeerIdentity pid;

  /**
   * Store operation for the merge
   */
  struct GNUNET_PEERSTORE_StoreContext *sc;

  /**
   * The iteration for the merge
   */
  struct GNUNET_PEERSTORE_IterateContext *ic;
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
   * Request ID
   */
  uint32_t rid;

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

  /**
   * Temporary envelope
   */
  struct GNUNET_MQ_Envelope *env;
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
   * Request ID
   */
  uint32_t rid;

  /**
   * Temporary envelope
   */
  struct GNUNET_MQ_Envelope *env;
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
  struct GNUNET_PEERSTORE_Monitor *wc;

  /**
   * Is this request canceled.
   */
  unsigned int canceled;

  /**
   * Request ID
   */
  uint32_t rid;

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
 * Get a fresh operation id to distinguish between namestore requests
 *
 * @param h the namestore handle
 * @return next operation id to use
 */
static uint32_t
get_op_id (struct GNUNET_PEERSTORE_Handle *h)
{
  return h->last_op_id++;
}


/**
 * Disconnect from the peerstore service.
 *
 * @param h peerstore handle to disconnect
 */
static void
disconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  if (NULL != h->watches)
  {
    GNUNET_assert (0 != GNUNET_CONTAINER_multihashmap_size (h->watches));
    GNUNET_CONTAINER_multihashmap_destroy (h->watches);
  }
  GNUNET_assert (NULL == h->iterate_head);
  GNUNET_assert (NULL == h->store_head);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnect initiated from client.\n");
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "store cancel with sc %p \n",
       sc);
  GNUNET_CONTAINER_DLL_remove (sc->h->store_head, sc->h->store_tail, sc);
  GNUNET_free (sc->sub_system);
  GNUNET_free (sc->value);
  GNUNET_free (sc->key);
  GNUNET_free (sc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
       "Storing value (size: %llu) for subsystem `%s', peer `%s', key `%s'\n",
       (unsigned long long) size,
       sub_system,
       GNUNET_i2s (peer),
       key);
  sc = GNUNET_new (struct GNUNET_PEERSTORE_StoreContext);
  sc->rid = get_op_id (h);
  sc->sub_system = GNUNET_strdup (sub_system);
  GNUNET_assert (NULL != peer);
  sc->peer = *peer;
  sc->key = GNUNET_strdup (key);
  sc->value = GNUNET_memdup (value, size);
  sc->size = size;
  sc->expiry = expiry;
  sc->options = options;
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;
  ev =
    PEERSTORE_create_record_mq_envelope (sc->rid,
                                         sub_system,
                                         peer,
                                         key,
                                         value,
                                         size,
                                         expiry,
                                         options,
                                         GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);

  GNUNET_CONTAINER_DLL_insert_tail (h->store_head, h->store_tail, sc);
  if (NULL == h->mq)
  {
    sc->env = ev;
  }
  else
  {
    GNUNET_MQ_send (h->mq, ev);
  }
  return sc;
}


/**
 * When a response for store request is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_store_result (void *cls, const struct PeerstoreResultMessage *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_StoreContext *sc = h->store_head;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got PeerstoreResultMessage\n");
  for (sc = h->store_head; NULL != sc; sc = sc->next)
  {
    if (sc->rid == ntohs (msg->rid))
      break;
  }
  if (NULL == sc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Unexpected store response.\n"));
    return;
  }
  if (NULL != sc->cont)
    sc->cont (sc->cont_cls, ntohl (msg->result));
  GNUNET_CONTAINER_DLL_remove (h->store_head, h->store_tail, sc);
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
handle_iterate_end (void *cls, const struct PeerstoreResultMessage *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic = h->iterate_head;

  for (ic = h->iterate_head; NULL != ic; ic = ic->next)
    if (ic->rid == ntohs (msg->rid))
      break;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Unexpected iteration response.\n"));
    return;
  }
  if (NULL != ic->callback)
    ic->callback (ic->callback_cls, NULL, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up iteration with rid %u\n", ic->rid);
  GNUNET_CONTAINER_DLL_remove (h->iterate_head, h->iterate_tail, ic);
}


/**
 * When a response for iterate request is received, check the
 * message is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_iterate_result (void *cls, const struct PeerstoreRecordMessage *msg)
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
handle_iterate_result (void *cls, const struct PeerstoreRecordMessage *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_Record *record;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received RecordMessage\n");
  for (ic = h->iterate_head; NULL != ic; ic = ic->next)
    if (ic->rid == ntohs (msg->rid))
      break;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ (
           "Unexpected iteration response, no iterating client found, discarding message.\n"));
    return;
  }
  if (NULL == ic->callback)
    return;
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    ic->callback (ic->callback_cls,
                  NULL,
                  _ ("Received a malformed response from service."));
  }
  else
  {
    ic->callback (ic->callback_cls, record, NULL);
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
GNUNET_PEERSTORE_iteration_next (struct GNUNET_PEERSTORE_IterateContext *ic,
                                 uint64_t limit)
{
  struct GNUNET_MQ_Envelope *ev;
  struct PeerstoreIterationNextMessage *inm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending PEERSTORE_ITERATION_NEXT message\n");
  ev = GNUNET_MQ_msg (inm, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_NEXT);
  inm->rid = htons (ic->rid);
  inm->limit = GNUNET_htonll (limit);
  if (NULL == ic->h->mq)
  {
    ic->env = ev;
  }
  else
  {
    GNUNET_MQ_send (ic->h->mq, ev);
  }
}


/**
 * Cancel an iterate request
 * Please do not call after the iterate request is done
 *
 * @param ic Iterate request context as returned by GNUNET_PEERSTORE_iterate()
 */
void
GNUNET_PEERSTORE_iteration_stop (struct GNUNET_PEERSTORE_IterateContext *ic)
{
  struct GNUNET_MQ_Envelope *ev;
  struct PeerstoreIterationStopMessage *ism;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending PEERSTORE_ITERATION_STOP message\n");
  if (NULL != ic->h->mq)
  {
    ev = GNUNET_MQ_msg (ism, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_STOP);
    ism->rid = htons (ic->rid);
    if (NULL != ic->h->mq)
      GNUNET_MQ_send (ic->h->mq, ev);
  }
  GNUNET_CONTAINER_DLL_remove (ic->h->iterate_head, ic->h->iterate_tail, ic);
  GNUNET_free (ic->sub_system);
  GNUNET_free (ic->key);
  GNUNET_free (ic);
}


struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iteration_start (struct GNUNET_PEERSTORE_Handle *h,
                                  const char *sub_system,
                                  const struct GNUNET_PeerIdentity *peer,
                                  const char *key,
                                  GNUNET_PEERSTORE_Processor callback,
                                  void *callback_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct PeerstoreIterationStartMessage *srm;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  size_t ss_size;
  size_t key_size;
  size_t msg_size;
  void *dummy;

  ic = GNUNET_new (struct GNUNET_PEERSTORE_IterateContext);
  ic->rid = get_op_id (h);

  GNUNET_assert (NULL != sub_system);
  ss_size = strlen (sub_system) + 1;
  if (NULL == key)
    key_size = 0;
  else
    key_size = strlen (key) + 1;
  msg_size = ss_size + key_size;
  ev = GNUNET_MQ_msg_extra (srm, msg_size,
                            GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_START);
  srm->key_size = htons (key_size);
  srm->rid = htons (ic->rid);
  srm->sub_system_size = htons (ss_size);
  dummy = &srm[1];
  GNUNET_memcpy (dummy, sub_system, ss_size);
  dummy += ss_size;
  GNUNET_memcpy (dummy, key, key_size);
  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->h = h;
  ic->sub_system = GNUNET_strdup (sub_system);
  if (NULL != peer)
  {
    ic->peer = *peer;
    srm->peer_set = htons (GNUNET_YES);
    srm->peer = *peer;
  }
  if (NULL != key)
    ic->key = GNUNET_strdup (key);
  GNUNET_CONTAINER_DLL_insert_tail (h->iterate_head, h->iterate_tail, ic);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending an iterate request for sub system `%s'\n",
       sub_system);
  GNUNET_MQ_send (h->mq, ev);
  return ic;
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
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_fixed_size (iterate_end,
                             GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END,
                             struct PeerstoreResultMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (store_result,
                             GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT,
                             struct PeerstoreResultMessage,
                             h),
    GNUNET_MQ_hd_var_size (iterate_result,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD,
                           struct PeerstoreRecordMessage,
                           h),
    GNUNET_MQ_handler_end ()
  };

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
  for (struct GNUNET_PEERSTORE_IterateContext *ic = h->iterate_head; NULL != ic;
       ic = ic->next)
  {
    GNUNET_MQ_send (h->mq, ic->env);
  }
  for (struct GNUNET_PEERSTORE_StoreContext *sc = h->store_head; NULL != sc;
       sc = sc->next)
  {
    GNUNET_MQ_send (h->mq, sc->env);
  }
}


static void
hello_store_success (void *cls, int success)
{
  struct GNUNET_PEERSTORE_StoreHelloContext *huc = cls;

  huc->sc = NULL;
  if (GNUNET_OK != success)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Storing hello uri failed\n");
    huc->cont (huc->cont_cls, success);
    GNUNET_free (huc->hello);
    GNUNET_free (huc);
    return;
  }
  huc->cont (huc->cont_cls, GNUNET_OK);
  GNUNET_free (huc->hello);
  GNUNET_free (huc);
}


static void
hello_add_iter (void *cls, const struct GNUNET_PEERSTORE_Record *record,
                const char *emsg)
{
  struct GNUNET_PEERSTORE_StoreHelloContext *huc = cls;
  struct GNUNET_TIME_Absolute hello_exp =
    GNUNET_HELLO_builder_get_expiration_time (huc->hello);
  if ((NULL == record) && (NULL == emsg))
  {
    /** If we ever get here, we are newer than the existing record
     *  or the only/first record.
     */
    huc->sc = GNUNET_PEERSTORE_store (huc->h,
                                      "peerstore",
                                      &huc->pid,
                                      GNUNET_PEERSTORE_HELLO_KEY,
                                      huc->hello,
                                      ntohs (huc->hello->size),
                                      hello_exp,
                                      GNUNET_PEERSTORE_STOREOPTION_REPLACE,
                                      &hello_store_success,
                                      huc);
    return;
  }
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GNUNET_PEERSTORE_iteration_next (huc->ic, 1);
    return;
  }
  if (GNUNET_TIME_absolute_cmp (record->expiry, >, hello_exp))
  {
    huc->cont (huc->cont_cls, GNUNET_OK);
    GNUNET_PEERSTORE_iteration_stop (huc->ic);
    GNUNET_free (huc->hello);
    GNUNET_free (huc);
    return;
  }
  GNUNET_PEERSTORE_iteration_next (huc->ic, 1);
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
  uint16_t size_msg = ntohs (msg->size);

  if (NULL == builder)
    return NULL;
  if (GNUNET_TIME_absolute_cmp (hello_exp, <, now))
    return NULL;

  huc = GNUNET_new (struct GNUNET_PEERSTORE_StoreHelloContext);
  huc->h = h;
  huc->cont = cont;
  huc->cont_cls = cont_cls;
  huc->hello = GNUNET_malloc (size_msg);
  GNUNET_memcpy (huc->hello, msg, size_msg);
  huc_exp =
    GNUNET_HELLO_builder_get_expiration_time (huc->hello);
  pid = GNUNET_HELLO_builder_get_id (builder);
  huc->pid = *pid;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding hello for peer %s with expiration %s msg size %u\n",
       GNUNET_i2s (&huc->pid),
       GNUNET_STRINGS_absolute_time_to_string (huc_exp),
       size_msg);

  huc->ic = GNUNET_PEERSTORE_iteration_start (h, "peerstore", &huc->pid,
                                              GNUNET_PEERSTORE_HELLO_KEY,
                                              &hello_add_iter,
                                              huc);
  GNUNET_HELLO_builder_free (builder);
  return huc;
}


void
GNUNET_PEERSTORE_hello_add_cancel (struct
                                   GNUNET_PEERSTORE_StoreHelloContext *huc)
{
  if (NULL != huc->sc)
    GNUNET_PEERSTORE_store_cancel (huc->sc);
  if (NULL != huc->ic)
    GNUNET_PEERSTORE_iteration_stop (huc->ic);
  GNUNET_free (huc->hello);
  GNUNET_free (huc);
}


/* end of peerstore_api.c */
