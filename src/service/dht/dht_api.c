/*
     This file is part of GNUnet.
     Copyright (C) 2009-2012, 2016, 2018, 2022 GNUnet e.V.

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
 * @file dht/dht_api.c
 * @brief library to access the DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "dht.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "dht-api", __VA_ARGS__)


/**
 * Handle to a PUT request.
 */
struct GNUNET_DHT_PutHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHT_PutHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHT_PutHandle *prev;

  /**
   * Continuation to call when done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Envelope from the PUT operation.
   */
  struct GNUNET_MQ_Envelope *env;
};

/**
 * Handle to a GET request
 */
struct GNUNET_DHT_GetHandle
{
  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_GetIterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Array of hash codes over the results that we have already
   * seen.
   */
  struct GNUNET_HashCode *seen_results;

  /**
   * Key that this get request is for
   */
  struct GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint64_t unique_id;

  /**
   * Size of the extended query, allocated at the end of this struct.
   */
  size_t xquery_size;

  /**
   * Desired replication level.
   */
  uint32_t desired_replication_level;

  /**
   * Type of the block we are looking for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Routing options.
   */
  enum GNUNET_DHT_RouteOption options;

  /**
   * Size of the @e seen_results array.  Note that not
   * all positions might be used (as we over-allocate).
   */
  unsigned int seen_results_size;

  /**
   * Offset into the @e seen_results array marking the
   * end of the positions that are actually used.
   */
  unsigned int seen_results_end;
};


/**
 * Handle to a monitoring request.
 */
struct GNUNET_DHT_MonitorHandle
{
  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *next;

  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *prev;

  /**
   * Main handle to this DHT api.
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Type of block looked for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Key being looked for, NULL == all.
   */
  struct GNUNET_HashCode *key;

  /**
   * Callback for each received message of type get.
   */
  GNUNET_DHT_MonitorGetCB get_cb;

  /**
   * Callback for each received message of type get response.
   */
  GNUNET_DHT_MonitorGetRespCB get_resp_cb;

  /**
   * Callback for each received message of type put.
   */
  GNUNET_DHT_MonitorPutCB put_cb;

  /**
   * Closure for @e get_cb, @e put_cb and @e get_resp_cb.
   */
  void *cb_cls;
};


/**
 * Handle to get a HELLO URL from the DHT for manual bootstrapping.
 */
struct GNUNET_DHT_HelloGetHandle
{

  /**
   * DLL.
   */
  struct GNUNET_DHT_HelloGetHandle *next;

  /**
   * DLL.
   */
  struct GNUNET_DHT_HelloGetHandle *prev;

  /**
   * Function to call with the result.
   */
  GNUNET_DHT_HelloGetCallback cb;

  /**
   * Closure for @a cb.
   */
  void *cb_cls;

  /**
   * Connection to the DHT service.
   */
  struct GNUNET_DHT_Handle *dht_handle;

};


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to DHT service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of linked list of messages we would like to monitor.
   */
  struct GNUNET_DHT_MonitorHandle *monitor_head;

  /**
   * Tail of linked list of messages we would like to monitor.
   */
  struct GNUNET_DHT_MonitorHandle *monitor_tail;

  /**
   * Head of active PUT requests.
   */
  struct GNUNET_DHT_PutHandle *put_head;

  /**
   * Tail of active PUT requests.
   */
  struct GNUNET_DHT_PutHandle *put_tail;

  /**
   * DLL.
   */
  struct GNUNET_DHT_HelloGetHandle *hgh_head;

  /**
   * DLL.
   */
  struct GNUNET_DHT_HelloGetHandle *hgh_tail;

  /**
   * Hash map containing the current outstanding unique GET requests
   * (values are of type `struct GNUNET_DHT_GetHandle`).
   */
  struct GNUNET_CONTAINER_MultiHashMap *active_requests;

  /**
   * Task for trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How quickly should we retry?  Used for exponential back-off on
   * connect-errors.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Generator for unique ids.
   */
  uint64_t uid_gen;
};


/**
 * Try to (re)connect to the DHT service.
 *
 * @param h DHT handle to reconnect
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
static enum GNUNET_GenericReturnValue
try_connect (struct GNUNET_DHT_Handle *h);


/**
 * Send GET message for a @a get_handle to DHT.
 *
 * @param gh GET to generate messages for.
 */
static void
send_get (struct GNUNET_DHT_GetHandle *gh)
{
  struct GNUNET_DHT_Handle *h = gh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientGetMessage *get_msg;

  env = GNUNET_MQ_msg_extra (get_msg,
                             gh->xquery_size,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET);
  get_msg->options = htonl ((uint32_t) gh->options);
  get_msg->desired_replication_level = htonl (gh->desired_replication_level);
  get_msg->type = htonl (gh->type);
  get_msg->key = gh->key;
  get_msg->unique_id = gh->unique_id;
  GNUNET_memcpy (&get_msg[1],
                 &gh[1],
                 gh->xquery_size);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Send GET message(s) for indicating which results are already known
 * for a @a get_handle to DHT.  Complex as we need to send the list of
 * known results, which means we may need multiple messages to block
 * known results from the result set.
 *
 * @param gh GET to generate messages for
 * @param transmission_offset_start at which offset should we start?
 */
static void
send_get_known_results (struct GNUNET_DHT_GetHandle *gh,
                        unsigned int transmission_offset_start)
{
  struct GNUNET_DHT_Handle *h = gh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientGetResultSeenMessage *msg;
  unsigned int delta;
  unsigned int max;
  unsigned int transmission_offset;

  max = (GNUNET_MAX_MESSAGE_SIZE - sizeof(*msg))
        / sizeof(struct GNUNET_HashCode);
  transmission_offset = transmission_offset_start;
  while (transmission_offset < gh->seen_results_end)
  {
    delta = gh->seen_results_end - transmission_offset;
    if (delta > max)
      delta = max;
    env = GNUNET_MQ_msg_extra (msg,
                               delta * sizeof(struct GNUNET_HashCode),
                               GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN);
    msg->key = gh->key;
    msg->unique_id = gh->unique_id;
    GNUNET_memcpy (&msg[1],
                   &gh->seen_results[transmission_offset],
                   sizeof(struct GNUNET_HashCode) * delta);
    GNUNET_MQ_send (h->mq,
                    env);
    transmission_offset += delta;
  }
}


/**
 * Add the GET request corresponding to the given route handle
 * to the pending queue (if it is not already in there).
 *
 * @param cls the `struct GNUNET_DHT_Handle *`
 * @param key key for the request (not used)
 * @param value the `struct GNUNET_DHT_GetHandle *`
 * @return #GNUNET_YES (always)
 */
static enum GNUNET_GenericReturnValue
add_get_request_to_pending (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_GetHandle *gh = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Retransmitting request related to %s to DHT %p\n",
       GNUNET_h2s (key),
       handle);
  send_get (gh);
  send_get_known_results (gh, 0);
  return GNUNET_YES;
}


/**
 * Send #GNUNET_MESSAGE_TYPE_DHT_MONITOR_START message.
 *
 * @param mh monitor handle to generate start message for
 */
static void
send_monitor_start (struct GNUNET_DHT_MonitorHandle *mh)
{
  struct GNUNET_DHT_Handle *h = mh->dht_handle;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_MonitorStartStopMessage *m;

  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DHT_MONITOR_START);
  m->type = htonl (mh->type);
  m->get = htons (NULL != mh->get_cb);
  m->get_resp = htons (NULL != mh->get_resp_cb);
  m->put = htons (NULL != mh->put_cb);
  if (NULL != mh->key)
  {
    m->filter_key = htons (1);
    m->key = *mh->key;
  }
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Try reconnecting to the dht service.
 *
 * @param cls a `struct GNUNET_DHT_Handle`
 */
static void
try_reconnect (void *cls)
{
  struct GNUNET_DHT_Handle *h = cls;
  struct GNUNET_DHT_MonitorHandle *mh;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reconnecting with DHT %p\n",
       h);
  h->retry_time = GNUNET_TIME_STD_BACKOFF (h->retry_time);
  h->reconnect_task = NULL;
  if (GNUNET_YES != try_connect (h))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "DHT reconnect failed!\n");
    h->reconnect_task
      = GNUNET_SCHEDULER_add_delayed (h->retry_time,
                                      &try_reconnect,
                                      h);
    return;
  }
  GNUNET_CONTAINER_multihashmap_iterate (h->active_requests,
                                         &add_get_request_to_pending,
                                         h);
  for (mh = h->monitor_head; NULL != mh; mh = mh->next)
    send_monitor_start (mh);
}


/**
 * Try reconnecting to the DHT service.
 *
 * @param h handle to dht to (possibly) disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_DHT_Handle *h)
{
  struct GNUNET_DHT_PutHandle *ph;
  GNUNET_SCHEDULER_TaskCallback cont;
  void *cont_cls;

  if (NULL == h->mq)
    return;
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from DHT service, will try to reconnect in %s\n",
              GNUNET_STRINGS_relative_time_to_string (h->retry_time,
                                                      GNUNET_YES));
  /* notify client about all PUTs that (may) have failed due to disconnect */
  while (NULL != (ph = h->put_head))
  {
    cont = ph->cont;
    cont_cls = ph->cont_cls;
    ph->env = NULL;
    GNUNET_DHT_put_cancel (ph);
    if (NULL != cont)
      cont (cont_cls);
  }
  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->retry_time,
                                    &try_reconnect,
                                    h);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_DHT_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_DHT_Handle *h = cls;

  do_disconnect (h);
}


/**
 * Process a get monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor get message from the service.
 */
static void
handle_monitor_get (void *cls,
                    const struct GNUNET_DHT_MonitorGetMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);

  for (struct GNUNET_DHT_MonitorHandle *mh = handle->monitor_head;
       NULL != mh;
       mh = mh->next)
  {
    if (NULL == mh->get_cb)
      continue;
    if ( (GNUNET_BLOCK_TYPE_ANY != mh->type) &&
         (mh->type != ntohl (msg->type)))
      continue;
    if ( (NULL != mh->key) &&
         (0 != GNUNET_memcmp (mh->key,
                              &msg->key)) )
      continue;
    mh->get_cb (mh->cb_cls,
                ro,
                ntohl (msg->type),
                ntohl (msg->hop_count),
                ntohl (msg->desired_replication_level),
                &msg->key);
  }
}


/**
 * Validate a get response monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg monitor get response message from the service
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static enum GNUNET_GenericReturnValue
check_monitor_get_resp (void *cls,
                        const struct GNUNET_DHT_MonitorGetRespMessage *msg)
{
  size_t msize = ntohs (msg->header.size) - sizeof(*msg);
  uint32_t getl = ntohl (msg->get_path_length);
  uint32_t putl = ntohl (msg->put_path_length);
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));

  if (truncated)
  {
    if (msize < sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    msize -= sizeof (struct GNUNET_PeerIdentity);
  }
  if ((getl + putl < getl) ||
      ((msize / sizeof(struct GNUNET_DHT_PathElement)) < getl + putl))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a get response monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg monitor get response message from the service
 */
static void
handle_monitor_get_resp (void *cls,
                         const struct GNUNET_DHT_MonitorGetRespMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t msize = ntohs (msg->header.size) - sizeof(*msg);
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);
  uint32_t getl = ntohl (msg->get_path_length);
  uint32_t putl = ntohl (msg->put_path_length);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? (const struct GNUNET_PeerIdentity *) &msg[1]
    : NULL;
  const struct GNUNET_DHT_PathElement *path
    = truncated
    ? (const struct GNUNET_DHT_PathElement *) &trunc_peer[1]
    : (const struct GNUNET_DHT_PathElement *) &msg[1];

  if (truncated)
    msize -= sizeof (struct GNUNET_PeerIdentity);
  msize -= sizeof(struct GNUNET_DHT_PathElement) * (putl + getl);
  for (struct GNUNET_DHT_MonitorHandle *mh = handle->monitor_head;
       NULL != mh;
       mh = mh->next)
  {
    if (NULL == mh->get_resp_cb)
      continue;
    if ( (GNUNET_BLOCK_TYPE_ANY != mh->type) &&
         (mh->type != ntohl (msg->type)) )
      continue;
    if ( (NULL != mh->key) &&
         (0 != GNUNET_memcmp (mh->key,
                              &msg->key)) )
      continue;
    mh->get_resp_cb (mh->cb_cls,
                     ntohl (msg->type),
                     trunc_peer,
                     &path[putl],
                     getl,
                     path,
                     putl,
                     GNUNET_TIME_absolute_ntoh (msg->expiration_time),
                     &msg->key,
                     (const void *) &path[getl + putl],
                     msize);
  }
}


/**
 * Check validity of a put monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static enum GNUNET_GenericReturnValue
check_monitor_put (void *cls,
                   const struct GNUNET_DHT_MonitorPutMessage *msg)
{
  size_t msize = ntohs (msg->header.size) - sizeof(*msg);
  uint32_t putl = ntohl (msg->put_path_length);
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));

  if (truncated)
  {
    if (msize < sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    msize -= sizeof (struct GNUNET_PeerIdentity);
  }
  if ((msize / sizeof(struct GNUNET_DHT_PathElement)) < putl)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a put monitor message from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 */
static void
handle_monitor_put (void *cls,
                    const struct GNUNET_DHT_MonitorPutMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t msize = ntohs (msg->header.size) - sizeof(*msg);
  uint32_t putl = ntohl (msg->put_path_length);
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? (const struct GNUNET_PeerIdentity *) &msg[1]
    : NULL;
  const struct GNUNET_DHT_PathElement *path
    = truncated
    ? (const struct GNUNET_DHT_PathElement *) &trunc_peer[1]
    : (const struct GNUNET_DHT_PathElement *) &msg[1];

  if (truncated)
    msize -= sizeof (struct GNUNET_PeerIdentity);
  msize -= sizeof(struct GNUNET_DHT_PathElement) * putl;
  for (struct GNUNET_DHT_MonitorHandle *mh = handle->monitor_head;
       NULL != mh;
       mh = mh->next)
  {
    if (NULL == mh->put_cb)
      continue;
    if ( (GNUNET_BLOCK_TYPE_ANY != mh->type) &&
         (mh->type != ntohl (msg->type)) )
      continue;
    if ( (NULL != mh->key) &&
         (0 != GNUNET_memcmp (mh->key,
                              &msg->key)) )
      continue;
    mh->put_cb (mh->cb_cls,
                ro,
                ntohl (msg->type),
                ntohl (msg->hop_count),
                ntohl (msg->desired_replication_level),
                trunc_peer,
                putl,
                path,
                GNUNET_TIME_absolute_ntoh (msg->expiration_time),
                &msg->key,
                (const void *) &path[putl],
                msize);
  }
}


/**
 * Verify that client result  message received from the service is well-formed.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 * @return #GNUNET_OK if everything went fine,
 *         #GNUNET_SYSERR if the message is malformed.
 */
static enum GNUNET_GenericReturnValue
check_client_result (void *cls,
                     const struct GNUNET_DHT_ClientResultMessage *msg)
{
  size_t msize = ntohs (msg->header.size) - sizeof(*msg);
  uint32_t put_path_length = ntohl (msg->put_path_length);
  uint32_t get_path_length = ntohl (msg->get_path_length);
  enum GNUNET_DHT_RouteOption ro = ntohl (msg->options);
  bool truncated = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  size_t meta_length;

  if (truncated)
  {
    if (msize < sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    msize -= sizeof (struct GNUNET_PeerIdentity);
  }
  meta_length = msize / sizeof(struct GNUNET_DHT_PathElement);
  if ( (get_path_length + put_path_length >
        meta_length) ||
       (get_path_length + put_path_length <
        get_path_length) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a given reply that might match the given request.
 *
 * @param cls the `struct GNUNET_DHT_ClientResultMessage`
 * @param key query of the request
 * @param value the `struct GNUNET_DHT_GetHandle` of a request matching the same key
 * @return #GNUNET_YES to continue to iterate over all results
 */
static enum GNUNET_GenericReturnValue
process_client_result (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  const struct GNUNET_DHT_ClientResultMessage *crm = cls;
  struct GNUNET_DHT_GetHandle *get_handle = value;
  size_t msize = ntohs (crm->header.size) - sizeof(*crm);
  uint16_t type = ntohl (crm->type);
  enum GNUNET_DHT_RouteOption ro = ntohl (crm->options);
  bool truncated
    = (0 != (ro & GNUNET_DHT_RO_TRUNCATED));
  uint32_t put_path_length
    = ntohl (crm->put_path_length);
  uint32_t get_path_length
    = ntohl (crm->get_path_length);
  const struct GNUNET_PeerIdentity *trunc_peer
    = truncated
    ? (const struct GNUNET_PeerIdentity *) &crm[1]
    : NULL;
  const struct GNUNET_DHT_PathElement *put_path
    = truncated
    ? (const struct GNUNET_DHT_PathElement *) &trunc_peer[1]
    : (const struct GNUNET_DHT_PathElement *) &crm[1];
  const struct GNUNET_DHT_PathElement *get_path
    = &put_path[put_path_length];
  const void *data
    = &get_path[get_path_length];
  size_t meta_length
    = sizeof(struct GNUNET_DHT_PathElement)
      * (get_path_length + put_path_length);
  size_t data_length
    = msize - meta_length;
  struct GNUNET_HashCode hc;

  if (truncated)
    data_length -= sizeof (struct GNUNET_PeerIdentity);
  if (crm->unique_id != get_handle->unique_id)
  {
    /* UID mismatch */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring reply for %s: UID mismatch: %llu/%llu\n",
         GNUNET_h2s (key),
         (unsigned long long) crm->unique_id,
         (unsigned long long) get_handle->unique_id);
    return GNUNET_YES;
  }
  if ( (get_handle->type != GNUNET_BLOCK_TYPE_ANY) &&
       (get_handle->type != type) )
  {
    /* type mismatch */
    GNUNET_break (0);
    return GNUNET_YES;
  }

  {
    char *pp;
    char *gp;

    gp = GNUNET_DHT_pp2s (get_path,
                          get_path_length);
    pp = GNUNET_DHT_pp2s (put_path,
                          put_path_length);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Giving %u byte reply for %s to application (GP: %s, PP: %s)\n",
         (unsigned int) data_length,
         GNUNET_h2s (key),
         gp,
         pp);
    GNUNET_free (gp);
    GNUNET_free (pp);
  }
  /* remember that we've seen this result */
  GNUNET_CRYPTO_hash (data,
                      data_length,
                      &hc);
  if (get_handle->seen_results_size == get_handle->seen_results_end)
    GNUNET_array_grow (get_handle->seen_results,
                       get_handle->seen_results_size,
                       get_handle->seen_results_size * 2 + 1);
  get_handle->seen_results[get_handle->seen_results_end++] = hc;
  /* no need to block it explicitly, service already knows about it! */
  get_handle->iter (get_handle->iter_cls,
                    GNUNET_TIME_absolute_ntoh (crm->expiration),
                    key,
                    trunc_peer,
                    get_path,
                    get_path_length,
                    put_path,
                    put_path_length,
                    type,
                    data_length,
                    data);
  return GNUNET_YES;
}


/**
 * Process a client result  message received from the service.
 *
 * @param cls The DHT handle.
 * @param msg Monitor put message from the service.
 */
static void
handle_client_result (void *cls,
                      const struct GNUNET_DHT_ClientResultMessage *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->active_requests,
                                              &msg->key,
                                              &process_client_result,
                                              (void *) msg);
}


/**
 * Process a client HELLO message received from the service.
 *
 * @param cls The DHT handle.
 * @param hdr HELLO URL message from the service.
 * @return #GNUNET_OK if @a hdr is well-formed
 */
static enum GNUNET_GenericReturnValue
check_client_hello (void *cls,
                    const struct GNUNET_MessageHeader *hdr)
{
  uint16_t len = ntohs (hdr->size);
  const char *buf = (const char *) &hdr[1];

  (void) cls;
  if ('\0' != buf[len - sizeof (*hdr) - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a client HELLO message received from the service.
 *
 * @param cls The DHT handle.
 * @param hdr HELLO URL message from the service.
 */
static void
handle_client_hello (void *cls,
                     const struct GNUNET_MessageHeader *hdr)
{
  struct GNUNET_DHT_Handle *handle = cls;
  const char *url = (const char *) &hdr[1];
  struct GNUNET_DHT_HelloGetHandle *hgh;

  while (NULL != (hgh = handle->hgh_head))
  {
    hgh->cb (hgh->cb_cls,
             url);
    GNUNET_DHT_hello_get_cancel (hgh);
  }
}


/**
 * Process a MQ PUT transmission notification.
 *
 * @param cls The DHT handle.
 */
static void
handle_put_cont (void *cls)
{
  struct GNUNET_DHT_PutHandle *ph = cls;
  GNUNET_SCHEDULER_TaskCallback cont;
  void *cont_cls;

  cont = ph->cont;
  cont_cls = ph->cont_cls;
  ph->env = NULL;
  GNUNET_DHT_put_cancel (ph);
  if (NULL != cont)
    cont (cont_cls);
}


/**
 * Try to (re)connect to the DHT service.
 *
 * @param h DHT handle to reconnect
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
static enum GNUNET_GenericReturnValue
try_connect (struct GNUNET_DHT_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (monitor_get,
                             GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET,
                             struct GNUNET_DHT_MonitorGetMessage,
                             h),
    GNUNET_MQ_hd_var_size (monitor_get_resp,
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP,
                           struct GNUNET_DHT_MonitorGetRespMessage,
                           h),
    GNUNET_MQ_hd_var_size (monitor_put,
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT,
                           struct GNUNET_DHT_MonitorPutMessage,
                           h),
    GNUNET_MQ_hd_var_size (client_result,
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT,
                           struct GNUNET_DHT_ClientResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (client_hello,
                           GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_URL,
                           struct GNUNET_MessageHeader,
                           h),
    GNUNET_MQ_handler_end ()
  };

  if (NULL != h->mq)
    return GNUNET_OK;
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "dht",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to connect to the DHT service!\n");
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_DHT_Handle *handle;

  handle = GNUNET_new (struct GNUNET_DHT_Handle);
  handle->cfg = cfg;
  handle->uid_gen
    = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                UINT64_MAX);
  handle->active_requests
    = GNUNET_CONTAINER_multihashmap_create (ht_len,
                                            GNUNET_YES);
  if (GNUNET_NO == try_connect (handle))
  {
    GNUNET_DHT_disconnect (handle);
    return NULL;
  }
  return handle;
}


void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle)
{
  struct GNUNET_DHT_PutHandle *ph;

  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (handle->active_requests));
  while (NULL != (ph = handle->put_head))
  {
    if (NULL != ph->cont)
      ph->cont (ph->cont_cls);
    GNUNET_DHT_put_cancel (ph);
  }
  if (NULL != handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_CONTAINER_multihashmap_destroy (handle->active_requests);
  GNUNET_free (handle);
}


struct GNUNET_DHT_PutHandle *
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const struct GNUNET_HashCode *key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const void *data,
                struct GNUNET_TIME_Absolute exp,
                GNUNET_SCHEDULER_TaskCallback cont,
                void *cont_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientPutMessage *put_msg;
  size_t msize;
  struct GNUNET_DHT_PutHandle *ph;

  if (0 == size)
  {
    GNUNET_break (0);
    return NULL;
  }
  msize = sizeof(struct GNUNET_DHT_ClientPutMessage) + size;
  if ((msize >= GNUNET_MAX_MESSAGE_SIZE) ||
      (size >= GNUNET_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (NULL == handle->mq)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending PUT for %s to DHT via %p\n",
       GNUNET_h2s (key),
       handle);
  ph = GNUNET_new (struct GNUNET_DHT_PutHandle);
  ph->dht_handle = handle;
  ph->cont = cont;
  ph->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (handle->put_head,
                                    handle->put_tail,
                                    ph);
  env = GNUNET_MQ_msg_extra (put_msg,
                             size,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT);
  GNUNET_MQ_notify_sent (env,
                         &handle_put_cont,
                         ph);
  ph->env = env;
  put_msg->type = htonl ((uint32_t) type);
  put_msg->options = htonl ((uint32_t) options);
  put_msg->desired_replication_level = htonl (desired_replication_level);
  put_msg->expiration = GNUNET_TIME_absolute_hton (exp);
  put_msg->key = *key;
  GNUNET_memcpy (&put_msg[1],
                 data,
                 size);
  GNUNET_MQ_send (handle->mq,
                  env);
  return ph;
}


void
GNUNET_DHT_put_cancel (struct GNUNET_DHT_PutHandle *ph)
{
  struct GNUNET_DHT_Handle *handle = ph->dht_handle;

  if (NULL != ph->env)
    GNUNET_MQ_notify_sent (ph->env,
                           NULL,
                           NULL);
  GNUNET_CONTAINER_DLL_remove (handle->put_head,
                               handle->put_tail,
                               ph);
  GNUNET_free (ph);
}


struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      enum GNUNET_BLOCK_Type type,
                      const struct GNUNET_HashCode *key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const void *xquery,
                      size_t xquery_size,
                      GNUNET_DHT_GetIterator iter,
                      void *iter_cls)
{
  struct GNUNET_DHT_GetHandle *gh;
  size_t msize;

  msize = sizeof(struct GNUNET_DHT_ClientGetMessage) + xquery_size;
  if ((msize >= GNUNET_MAX_MESSAGE_SIZE) ||
      (xquery_size >= GNUNET_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending query for %s to DHT %p\n",
       GNUNET_h2s (key),
       handle);
  gh = GNUNET_malloc (sizeof(struct GNUNET_DHT_GetHandle)
                      + xquery_size);
  gh->iter = iter;
  gh->iter_cls = iter_cls;
  gh->dht_handle = handle;
  gh->key = *key;
  gh->unique_id = ++handle->uid_gen;
  gh->xquery_size = xquery_size;
  gh->desired_replication_level = desired_replication_level;
  gh->type = type;
  gh->options = options;
  GNUNET_memcpy (&gh[1],
                 xquery,
                 xquery_size);
  GNUNET_CONTAINER_multihashmap_put (handle->active_requests,
                                     &gh->key,
                                     gh,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (NULL != handle->mq)
    send_get (gh);
  return gh;
}


void
GNUNET_DHT_get_filter_known_results (struct GNUNET_DHT_GetHandle *get_handle,
                                     unsigned int num_results,
                                     const struct GNUNET_HashCode *results)
{
  unsigned int needed;
  unsigned int had;

  had = get_handle->seen_results_end;
  needed = had + num_results;
  if (needed > get_handle->seen_results_size)
    GNUNET_array_grow (get_handle->seen_results,
                       get_handle->seen_results_size,
                       needed);
  GNUNET_memcpy (&get_handle->seen_results[get_handle->seen_results_end],
                 results,
                 num_results * sizeof(struct GNUNET_HashCode));
  get_handle->seen_results_end += num_results;
  if (NULL != get_handle->dht_handle->mq)
    send_get_known_results (get_handle,
                            had);
}


void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle)
{
  struct GNUNET_DHT_Handle *handle = get_handle->dht_handle;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending STOP for %s to DHT via %p\n",
       GNUNET_h2s (&get_handle->key),
       handle);
  if (NULL != handle->mq)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_DHT_ClientGetStopMessage *stop_msg;

    env = GNUNET_MQ_msg (stop_msg,
                         GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP);
    stop_msg->reserved = htonl (0);
    stop_msg->unique_id = get_handle->unique_id;
    stop_msg->key = get_handle->key;
    GNUNET_MQ_send (handle->mq,
                    env);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (handle->active_requests,
                                                       &get_handle->key,
                                                       get_handle));
  GNUNET_array_grow (get_handle->seen_results,
                     get_handle->seen_results_end,
                     0);
  GNUNET_free (get_handle);
}


struct GNUNET_DHT_MonitorHandle *
GNUNET_DHT_monitor_start (struct GNUNET_DHT_Handle *handle,
                          enum GNUNET_BLOCK_Type type,
                          const struct GNUNET_HashCode *key,
                          GNUNET_DHT_MonitorGetCB get_cb,
                          GNUNET_DHT_MonitorGetRespCB get_resp_cb,
                          GNUNET_DHT_MonitorPutCB put_cb,
                          void *cb_cls)
{
  struct GNUNET_DHT_MonitorHandle *mh;

  mh = GNUNET_new (struct GNUNET_DHT_MonitorHandle);
  mh->get_cb = get_cb;
  mh->get_resp_cb = get_resp_cb;
  mh->put_cb = put_cb;
  mh->cb_cls = cb_cls;
  mh->type = type;
  mh->dht_handle = handle;
  if (NULL != key)
  {
    mh->key = GNUNET_new (struct GNUNET_HashCode);
    *mh->key = *key;
  }
  GNUNET_CONTAINER_DLL_insert (handle->monitor_head,
                               handle->monitor_tail,
                               mh);
  if (NULL != handle->mq)
    send_monitor_start (mh);
  return mh;
}


void
GNUNET_DHT_monitor_stop (struct GNUNET_DHT_MonitorHandle *mh)
{
  struct GNUNET_DHT_Handle *handle = mh->dht_handle;
  struct GNUNET_DHT_MonitorStartStopMessage *m;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_CONTAINER_DLL_remove (handle->monitor_head,
                               handle->monitor_tail,
                               mh);
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP);
  m->type = htonl (mh->type);
  m->get = htons (NULL != mh->get_cb);
  m->get_resp = htons (NULL != mh->get_resp_cb);
  m->put = htons (NULL != mh->put_cb);
  if (NULL != mh->key)
  {
    m->filter_key = htons (1);
    m->key = *mh->key;
  }
  GNUNET_MQ_send (handle->mq,
                  env);
  GNUNET_free (mh->key);
  GNUNET_free (mh);
}


char *
GNUNET_DHT_pp2s (const struct GNUNET_DHT_PathElement *path,
                 unsigned int path_len)
{
  char *buf;
  size_t off;
  size_t plen = path_len * 5 + 1;

  GNUNET_assert (path_len < UINT32_MAX / 5);
  off = 0;
  buf = GNUNET_malloc (plen);
  for (unsigned int i = 0; i < path_len; i++)
  {
    off += GNUNET_snprintf (&buf[off],
                            plen - off,
                            "%s%s",
                            GNUNET_i2s (&path[i].pred),
                            (i == path_len - 1) ? "" : "-");
  }
  return buf;
}


unsigned int
GNUNET_DHT_verify_path (const void *data,
                        size_t data_size,
                        struct GNUNET_TIME_Absolute exp_time,
                        const struct GNUNET_PeerIdentity *bpid,
                        const struct GNUNET_DHT_PathElement *put_path,
                        unsigned int put_path_len,
                        const struct GNUNET_DHT_PathElement *get_path,
                        unsigned int get_path_len,
                        const struct GNUNET_PeerIdentity *me)
{
  static struct GNUNET_PeerIdentity zero;
  struct GNUNET_DHT_HopSignature hs = {
    .purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DHT_HOP),
    .purpose.size = htonl (sizeof (hs)),
    .expiration_time = GNUNET_TIME_absolute_hton (exp_time)
  };
  unsigned int i;

  if (0 == get_path_len + put_path_len)
    return 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s is verifying signatures with GPL: %u PPL: %u!\n",
              GNUNET_i2s (me),
              get_path_len,
              put_path_len);
  for (unsigned int j = 0; j<put_path_len; j++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "PP%u=%s\n",
                j,
                GNUNET_i2s (&put_path[j].pred));
  for (unsigned int j = 0; j<get_path_len; j++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GP%u=%s\n",
                j,
                GNUNET_i2s (&get_path[j].pred));
  GNUNET_CRYPTO_hash (data,
                      data_size,
                      &hs.h_data);
  i = put_path_len + get_path_len;
  while (i > 0)
  {
    const struct GNUNET_PeerIdentity *pred;
    const struct GNUNET_PeerIdentity *succ;
    const struct GNUNET_DHT_PathElement *pe;

    i--;
    if (0 == i)
    {
      pred = (NULL == bpid) ? &zero : bpid;
    }
    else
    {
      unsigned int off = i - 1;

      pred = (off >= put_path_len)
        ? &get_path[off - put_path_len].pred
        : &put_path[off].pred;
    }
    if (i == get_path_len + put_path_len - 1)
    {
      succ = me;
    }
    else
    {
      unsigned int off = i + 1;

      succ = (off >= put_path_len)
        ? &get_path[off - put_path_len].pred
        : &put_path[off].pred;
    }
    hs.pred = *pred;
    hs.succ = *succ;
    pe = (i >= put_path_len)
      ? &get_path[i - put_path_len]
      : &put_path[i];
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_verify (
          GNUNET_SIGNATURE_PURPOSE_DHT_HOP,
          &hs,
          &pe->sig,
          &pe->pred.public_key))
    {
      GNUNET_break_op (0);
      return i + 1;
    }
  }
  return i;
}


struct GNUNET_DHT_HelloGetHandle *
GNUNET_DHT_hello_get (struct GNUNET_DHT_Handle *dht_handle,
                      GNUNET_DHT_HelloGetCallback cb,
                      void *cb_cls)
{
  struct GNUNET_DHT_HelloGetHandle *hgh;
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_MQ_Envelope *env;

  hgh = GNUNET_new (struct GNUNET_DHT_HelloGetHandle);
  hgh->cb = cb;
  hgh->cb_cls = cb_cls;
  hgh->dht_handle = dht_handle;
  GNUNET_CONTAINER_DLL_insert (dht_handle->hgh_head,
                               dht_handle->hgh_tail,
                               hgh);
  env = GNUNET_MQ_msg (hdr,
                       GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_GET);
  GNUNET_MQ_send (dht_handle->mq,
                  env);
  return hgh;
}


void
GNUNET_DHT_hello_get_cancel (struct GNUNET_DHT_HelloGetHandle *hgh)
{
  struct GNUNET_DHT_Handle *dht_handle = hgh->dht_handle;

  GNUNET_CONTAINER_DLL_remove (dht_handle->hgh_head,
                               dht_handle->hgh_tail,
                               hgh);
  GNUNET_free (hgh);
}


void
GNUNET_DHT_hello_offer (struct GNUNET_DHT_Handle *dht_handle,
                        const char *url,
                        GNUNET_SCHEDULER_TaskCallback cb,
                        void *cb_cls)
{
  struct GNUNET_MessageHeader *hdr;
  size_t slen = strlen (url) + 1;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra (hdr,
                             slen,
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_URL);
  memcpy (&hdr[1],
          url,
          slen);
  GNUNET_MQ_notify_sent (env,
                         cb,
                         cb_cls);
  GNUNET_MQ_send (dht_handle->mq,
                  env);
}


/* end of dht_api.c */
