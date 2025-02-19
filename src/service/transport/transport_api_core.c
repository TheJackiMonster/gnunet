/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2018 GNUnet e.V.

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
 * @file transport/transport_api_core.c
 * @brief library to access the transport service for message exchange
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_core_service.h"
#include "transport.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "transport-api-core", __VA_ARGS__)

/**
 * How large to start with for the hashmap of neighbours.
 */
#define STARTING_NEIGHBOURS_SIZE 16

/**
 * Window size. How many messages to the same target do we pass
 * to TRANSPORT without a SEND_OK in between? Small values limit
 * throughput, large values will increase latency.
 *
 * FIXME-OPTIMIZE: find out what good values are experimentally,
 * maybe set adaptively (i.e. to observed available bandwidth).
 */
#define SEND_WINDOW_SIZE 4


/**
 * Entry in hash table of all of our current (connected) neighbours.
 */
struct Neighbour
{
  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Overall transport handle.
   */
  struct GNUNET_TRANSPORT_CoreHandle *h;

  /**
   * Active message queue for the peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Envelope with the message we are currently transmitting (or NULL).
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Closure for @e mq handlers.
   */
  void *handlers_cls;

  /**
   * How many messages can we still send to this peer before we should
   * throttle?
   */
  unsigned int ready_window;

  /**
   * Used to indicate our status if @e env is non-NULL.  Set to
   * #GNUNET_YES if we did pass a message to the MQ and are waiting
   * for the call to #notify_send_done(). Set to #GNUNET_NO if the @e
   * ready_window is 0 and @e env is waiting for a
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK?
   */
  int16_t awaiting_done;

  /**
   * Size of the message in @e env.
   */
  uint16_t env_size;
};


/**
 * Handle for the transport service (includes all of the
 * state for the transport service).
 */
struct GNUNET_TRANSPORT_CoreHandle
{
  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Functions to call for received data (template for
   * new message queues).
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * function to call on connect events
   */
  GNUNET_TRANSPORT_NotifyConnect nc_cb;

  /**
   * function to call on disconnect events
   */
  GNUNET_TRANSPORT_NotifyDisconnect nd_cb;

  /**
   * My client connection to the transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * My configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Hash map of the current connected neighbours of this peer.
   * Maps peer identities to `struct Neighbour` entries.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *neighbours;

  /**
   * Peer identity as assumed by this process, or all zeros.
   */
  struct GNUNET_PeerIdentity self;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Transport connection started at.
   */
  struct GNUNET_TIME_Absolute restarted_at;

  /**
   * Should we check that @e self matches what the service thinks?
   * (if #GNUNET_NO, then @e self is all zeros!).
   */
  int check_self;
};


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_CoreHandle *h);


/**
 * Get the neighbour list entry for the given peer
 *
 * @param h our context
 * @param peer peer to look up
 * @return NULL if no such peer entry exists
 */
static struct Neighbour *
neighbour_find (struct GNUNET_TRANSPORT_CoreHandle *h,
                const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_get (h->neighbours, peer);
}


/**
 * Iterator over hash map entries, for deleting state of a neighbour.
 *
 * @param cls the `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param key peer identity
 * @param value value in the hash map, the neighbour entry to delete
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
neighbour_delete (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct GNUNET_TRANSPORT_CoreHandle *handle = cls;
  struct Neighbour *n = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dropping entry for neighbour `%s'.\n",
       GNUNET_i2s (key));
  if (NULL != handle->nd_cb)
    handle->nd_cb (handle->cls, &n->id, n->handlers_cls);
  if (NULL != n->env)
  {
    GNUNET_MQ_send_cancel (n->env);
    n->env = NULL;
  }
  GNUNET_MQ_destroy (n->mq);
  GNUNET_assert (NULL == n->mq);
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multipeermap_remove (handle->neighbours, key, n));
  GNUNET_free (n);
  return GNUNET_YES;
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Error %u received from transport service, disconnecting temporarily.\n",
       error);
  disconnect_and_schedule_reconnect (h);
}


/**
 * A message from the handler's message queue to a neighbour was
 * transmitted.  Now trigger (possibly delayed) notification of the
 * neighbour's message queue that we are done and thus ready for
 * the next message.  Note that the MQ being ready is independent
 * of the send window, as we may queue many messages and simply
 * not pass them to TRANSPORT if the send window is insufficient.
 *
 * @param cls the `struct Neighbour` where the message was sent
 */
static void
notify_send_done (void *cls)
{
  struct Neighbour *n = cls;

  n->awaiting_done = GNUNET_NO;
  n->env = NULL;
  if (0 < n->ready_window)
    GNUNET_MQ_impl_send_continue (n->mq);
}


/**
 * We have an envelope waiting for transmission at @a n, and
 * our transmission window is positive. Perform the transmission.
 *
 * @param n neighbour to perform transmission for
 */
static void
do_send (struct Neighbour *n)
{
  GNUNET_assert (0 < n->ready_window);
  GNUNET_assert (NULL != n->env);
  n->ready_window--;
  n->awaiting_done = GNUNET_YES;
  GNUNET_MQ_notify_sent (n->env, &notify_send_done, n);
  GNUNET_MQ_send (n->h->mq, n->env);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Passed message of type %u for neighbour `%s' to TRANSPORT. ready_window %u\n",
       ntohs (GNUNET_MQ_env_get_msg (n->env)->type),
       GNUNET_i2s (&n->id),
       n->ready_window);
}


/**
 * Implement sending functionality of a message queue.
 * Called one message at a time. Should send the @a msg
 * to the transport service and then notify the queue
 * once we are ready for the next one.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
mq_send_impl (struct GNUNET_MQ_Handle *mq,
              const struct GNUNET_MessageHeader *msg,
              void *impl_state)
{
  struct Neighbour *n = impl_state;
  struct OutboundMessage *obm;
  uint16_t msize;

  msize = ntohs (msg->size);
  if (msize >= GNUNET_MAX_MESSAGE_SIZE - sizeof(*obm))
  {
    GNUNET_break (0);
    GNUNET_MQ_impl_send_continue (mq);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "CORE requested transmission of message of type %u to neighbour `%s'.\n",
       ntohs (msg->type),
       GNUNET_i2s (&n->id));

  GNUNET_assert (NULL == n->env);
  n->env =
    GNUNET_MQ_msg_nested_mh (obm, GNUNET_MESSAGE_TYPE_TRANSPORT_SEND, msg);
  n->env_size = ntohs (msg->size);
  {
    struct GNUNET_MQ_Envelope *env;
    enum GNUNET_MQ_PriorityPreferences prio;

    env = GNUNET_MQ_get_current_envelope (mq);
    prio = GNUNET_MQ_env_get_options (env);
    obm->priority = htonl ((uint32_t) prio);
  }
  obm->peer = n->id;
  if (0 == n->ready_window)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Flow control delays transmission to CORE until we see SEND_OK.\n");
    return;   /* can't send yet, need to wait for SEND_OK */
  }
  do_send (n);
}


/**
 * Handle destruction of a message queue.  Implementations must not
 * free @a mq, but should take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
mq_destroy_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Neighbour *n = impl_state;

  GNUNET_assert (mq == n->mq);
  n->mq = NULL;
}


/**
 * Implementation function that cancels the currently sent message.
 * Should basically undo whatever #mq_send_impl() did.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
mq_cancel_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Neighbour *n = impl_state;

  n->ready_window++;
  if (GNUNET_YES == n->awaiting_done)
  {
    GNUNET_MQ_send_cancel (n->env);
    n->env = NULL;
    n->awaiting_done = GNUNET_NO;
  }
  else
  {
    GNUNET_assert (0 == n->ready_window);
    n->env = NULL;
  }
}


/**
 * We had an error processing a message we forwarded from a peer to
 * the CORE service.  We should just complain about it but otherwise
 * continue processing.
 *
 * @param cls closure
 * @param error error code
 */
static void
peer_mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct Neighbour *n = cls;

  if (GNUNET_MQ_ERROR_MALFORMED == error)
    GNUNET_break_op (0);
  //TODO Look into bug #7887

  GNUNET_TRANSPORT_core_receive_continue (n->h, &n->id);
}


/**
 * Function we use for handling incoming connect messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_Handle *`
 * @param cim message received
 */
static void
handle_connect (void *cls, const struct ConnectInfoMessage *cim)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving CONNECT message for `%s'\n",
       GNUNET_i2s (&cim->id));
  n = neighbour_find (h, &cim->id);
  if (NULL != n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  n = GNUNET_new (struct Neighbour);
  n->id = cim->id;
  n->h = h;
  n->ready_window = SEND_WINDOW_SIZE;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (
                   h->neighbours,
                   &n->id,
                   n,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  n->mq = GNUNET_MQ_queue_for_callbacks (&mq_send_impl,
                                         &mq_destroy_impl,
                                         &mq_cancel_impl,
                                         n,
                                         h->handlers,
                                         &peer_mq_error_handler,
                                         n);
  if (NULL != h->nc_cb)
  {
    n->handlers_cls = h->nc_cb (h->cls, &n->id, n->mq);
    GNUNET_MQ_set_handlers_closure (n->mq, n->handlers_cls);
  }
}


/**
 * Function we use for handling incoming disconnect messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param dim message received
 */
static void
handle_disconnect (void *cls, const struct DisconnectInfoMessage *dim)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  GNUNET_break (ntohl (dim->reserved) == 0);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving DISCONNECT message for `%s'.\n",
       GNUNET_i2s (&dim->peer));
  n = neighbour_find (h, &dim->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  GNUNET_assert (GNUNET_YES == neighbour_delete (h, &dim->peer, n));
}


/**
 * Function we use for handling incoming send-ok messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param okm message received
 */
static void
handle_send_ok (void *cls, const struct SendOkMessage *okm)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receiving SEND_OK message for transmission to %s\n",
       GNUNET_i2s (&okm->peer));

  n = neighbour_find (h, &okm->peer);

  if (NULL == n)
  {
    /* We should never get a 'SEND_OK' for a peer that we are not
       connected to */
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }

  if ((GNUNET_NO == n->awaiting_done) &&
      (NULL != n->env) &&
      (0 == n->ready_window))
  {
    n->ready_window++;
    do_send (n);
    return;
  }
  else if ((GNUNET_NO == n->awaiting_done) &&
           (0 == n->ready_window))
  {
    n->ready_window++;
    GNUNET_MQ_impl_send_continue (n->mq);
    return;
  }
  n->ready_window++;
}


/**
 * Function we use for checking incoming "inbound" messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param im message received
 */
static int
check_recv (void *cls, const struct InboundMessage *im)
{
  const struct GNUNET_MessageHeader *imm;
  uint16_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "check_recv\n");
  size = ntohs (im->header.size) - sizeof(*im);
  if (size < sizeof(struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  imm = (const struct GNUNET_MessageHeader *) &im[1];
  if (ntohs (imm->size) != size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function we use for handling incoming messages.
 *
 * @param cls closure, a `struct GNUNET_TRANSPORT_CoreHandle *`
 * @param im message received
 */
static void
handle_recv (void *cls, const struct InboundMessage *im)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  const struct GNUNET_MessageHeader *imm =
    (const struct GNUNET_MessageHeader *) &im[1];
  struct Neighbour *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u with %u bytes from `%s'.\n",
       (unsigned int) ntohs (imm->type),
       (unsigned int) ntohs (imm->size),
       GNUNET_i2s (&im->peer));
  n = neighbour_find (h, &im->peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    disconnect_and_schedule_reconnect (h);
    return;
  }
  GNUNET_MQ_inject_message (n->mq, imm);
}


/**
 * Try again to connect to transport service.
 *
 * @param cls the handle to the transport service
 */
static void
reconnect (void *cls)
{
  struct GNUNET_TRANSPORT_CoreHandle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_fixed_size (connect,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT,
                             struct ConnectInfoMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (disconnect,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT,
                             struct DisconnectInfoMessage,
                             h),
    GNUNET_MQ_hd_fixed_size (send_ok,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK,
                             struct SendOkMessage,
                             h),
    GNUNET_MQ_hd_var_size (recv,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_RECV,
                           struct InboundMessage,
                           h),
    GNUNET_MQ_handler_end () };
  struct GNUNET_MQ_Envelope *env;
  struct StartMessage *s;
  uint32_t options;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to transport service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq =
    GNUNET_CLIENT_connect (h->cfg, "transport", handlers, &mq_error_handler, h);
  h->restarted_at = GNUNET_TIME_absolute_get ();
  if (NULL == h->mq)
    return;
  env = GNUNET_MQ_msg (s, GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  options = 0;
  if (h->check_self)
    options |= 1;
  if (NULL != h->handlers)
    options |= 2;
  s->options = htonl (options);
  s->self = h->self;
  GNUNET_MQ_send (h->mq, env);
}


/**
 * Disconnect from the transport service.
 *
 * @param h transport service to reconnect
 */
static void
disconnect (struct GNUNET_TRANSPORT_CoreHandle *h)
{
  GNUNET_CONTAINER_multipeermap_iterate (h->neighbours, &neighbour_delete, h);
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
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_CoreHandle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  disconnect (h);
  {
    /* Reduce delay based on runtime of the connection,
       so that there is a cool-down if a connection is up
       for a while. */
    struct GNUNET_TIME_Relative runtime;
    unsigned int minutes;

    runtime = GNUNET_TIME_absolute_get_duration (h->restarted_at);
    minutes = runtime.rel_value_us / GNUNET_TIME_UNIT_MINUTES.rel_value_us;
    if (minutes > 31)
      h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
    else
      h->reconnect_delay.rel_value_us >>= minutes;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to transport service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay, GNUNET_YES));
  h->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Checks if a given peer is connected to us and get the message queue.
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return NULL if disconnected, otherwise message queue for @a peer
 */
struct GNUNET_MQ_Handle *
GNUNET_TRANSPORT_core_get_mq (struct GNUNET_TRANSPORT_CoreHandle *handle,
                              const struct GNUNET_PeerIdentity *peer)
{
  struct Neighbour *n;

  n = neighbour_find (handle, peer);
  if (NULL == n)
    return NULL;
  return n->mq;
}


/**
 * Notification from the CORE service to the TRANSPORT service
 * that the CORE service has finished processing a message from
 * TRANSPORT (via the @code{handlers} of #GNUNET_TRANSPORT_core_connect())
 * and that it is thus now OK for TRANSPORT to send more messages
 * for @a pid.
 *
 * Used to provide flow control, this is our equivalent to
 * #GNUNET_SERVICE_client_continue() of an ordinary service.
 *
 * Note that due to the use of a window, TRANSPORT may send multiple
 * messages destined for the same peer even without an intermediate
 * call to this function. However, CORE must still call this function
 * once per message received, as otherwise eventually the window will
 * be full and TRANSPORT will stop providing messages to CORE for @a
 * pid.
 *
 * @param ch core handle
 * @param pid which peer was the message from that was fully processed by CORE
 */
void
GNUNET_TRANSPORT_core_receive_continue (struct GNUNET_TRANSPORT_CoreHandle *ch,
                                        const struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_MQ_Envelope *env;
  struct RecvOkMessage *rok;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Message for %s finished CORE processing, sending RECV_OK.\n",
       GNUNET_i2s (pid));
  if (NULL == ch->mq)
    return;
  env = GNUNET_MQ_msg (rok, GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK);
  rok->increase_window_delta = htonl (1);
  rok->peer = *pid;
  GNUNET_MQ_send (ch->mq, env);
}


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param nd function to call on disconnect events
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CoreHandle *
GNUNET_TRANSPORT_core_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_PeerIdentity *self,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               void *cls,
                               GNUNET_TRANSPORT_NotifyConnect nc,
                               GNUNET_TRANSPORT_NotifyDisconnect nd)
{
  struct GNUNET_TRANSPORT_CoreHandle *h;
  unsigned int i;

  h = GNUNET_new (struct GNUNET_TRANSPORT_CoreHandle);
  if (NULL != self)
  {
    h->self = *self;
    h->check_self = GNUNET_YES;
  }
  h->cfg = cfg;
  h->cls = cls;
  h->nc_cb = nc;
  h->nd_cb = nd;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  if (NULL != handlers)
  {
    for (i = 0; NULL != handlers[i].cb; i++)
      ;
    h->handlers = GNUNET_new_array (i + 1, struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (h->handlers,
                   handlers,
                   i * sizeof(struct GNUNET_MQ_MessageHandler));
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to transport service\n");
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h->handlers);
    GNUNET_free (h);
    return NULL;
  }
  h->neighbours =
    GNUNET_CONTAINER_multipeermap_create (STARTING_NEIGHBOURS_SIZE, GNUNET_YES);
  return h;
}


/**
 * Disconnect from the transport service.
 *
 * @param handle handle to the service as returned from
 * #GNUNET_TRANSPORT_core_connect()
 */
void
GNUNET_TRANSPORT_core_disconnect (struct GNUNET_TRANSPORT_CoreHandle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transport disconnect called!\n");
  /* this disconnects all neighbours... */
  disconnect (handle);
  /* and now we stop trying to connect again... */
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_destroy (handle->neighbours);
  handle->neighbours = NULL;
  GNUNET_free (handle->handlers);
  handle->handlers = NULL;
  GNUNET_free (handle);
}


/* end of transport_api_core.c */
