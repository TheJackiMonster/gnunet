/*
     This file is part of GNUnet.
     Copyright (C) 2023 GNUnet e.V.

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
 * @addtogroup Core
 * @{
 *
 * @author Julius Bünger
 *
 * @file
 * Implementation of the dummy core underlay that uses unix domain sockets
 *
 * @defgroup CORE
 * Secure Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/core-service) TODO
 *
 * @{
 */

// TODO actually implement rate-limiting

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include "gnunet_core_underlay_dummy.h"
#include "gnunet_util_lib.h"
#include "gnunet_scheduler_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "core-underlay-dummy", __VA_ARGS__)

#define SOCK_NAME_BASE "/tmp/gnunet-core-underlay-dummy-socket"
#define SOCK_EXTENSION ".sock"
#define BUFF_SIZE 8192
#define BACKLOG 10


/**
 * @brief Closure used for the #peer_connect_task
 */
struct PeerConnectCls
{
  /**
   * @brief Linked list next
   */
  struct PeerConnectCls *next;

  /**
   * @brief Linked list previous
   */
  struct PeerConnectCls *prev;

  /**
   * @brief The handle for the service
   */
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;

  /**
   * @brief The file name to connect to
   */
  char *sock_name;

  /**
   * Task to connect to another peer.
   */
  struct GNUNET_SCHEDULER_Task *peer_connect_task;
};


struct QueuedMessage
{
  struct QueuedMessage *next;
  struct QueuedMessage *prev;

  struct GNUNET_MessageHeader *msg;
};


enum ConnectionStatus
{
  /* Created, but neither received, nor sent anything over it */
  CONNECTION_INITIALIZING,

  /* Created and successfully sent something (probably init) */
  CONNECTION_INITIALIZING_SEND,

  /* Created and successfully received something (probably init) */
  CONNECTION_INITIALIZING_RECV,

  /* Live - usable - successfully received and sent something (probably init) */
  CONNECTION_LIVE,

  /* In the process of destruction */
  CONNECTION_DESTROY,
};


/**
 * @brief Used to keep track of context of peer
 */
struct Connection
{
  /**
   * @brief Linked list next
   */
  struct Connection *next;

  /**
   * @brief Linked list previous
   */
  struct Connection *prev;

  /**
   * Message queue towards the connected peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Handlers for mq
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for the mq towards the client.
   *
   * Connection-specific, given to handlers and disconnect_cb/notify_disconnect
   */
  void *cls_mq;

  /**
   * Socket for the connected peer.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Address of the connected peer.
   */
  char *peer_addr;

  /**
   * Task waiting for incoming messages.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Task waiting until the socket becomes ready to be written to.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Task to notify the client about an open connection
   */
  struct GNUNET_SCHEDULER_Task *notify_connect_task;

  /**
   * Task to pass the message to the client's handlers
   */
  struct GNUNET_SCHEDULER_Task *handle_message_task;

  /**
   * Whether notify_connect was called already
   * It is used to check whether to call notify_disconnect or not.
   */
  enum GNUNET_GenericReturnValue notify_connect_called;

  /**
   * Indicating whether the client is ready to receive new messages.
   * This is set to #GNUNET_YES after the client called
   * #GNUNET_CORE_UNDERLAY_DUMMY_receive_continue() and to
   * #GNUNET_NO after #GNUNET_MQ_handle_message() was called.
   * TODO might be a duplicate to handle_message_task being NULL or not
   */
  enum GNUNET_GenericReturnValue client_ready_to_receive;

  /**
   * Status of the connection: Initializing, Live, Destroy
   */
  enum ConnectionStatus status;

  /**
   * Message about to be sent, given by the message queue, waiting for the
   * socket to be ready.
   */
  const struct GNUNET_MessageHeader *message_to_send;

  /**
   * Queued received messages in a DLL
   * TODO implement cleanup
   * TODO replace with a performant queue
   */
  struct QueuedMessage *queued_recv_messages_head;
  struct QueuedMessage *queued_recv_messages_tail;

  /**
   * @brief Handle to the service
   */
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *handle;
};


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle
{
  /**
   * Callback (from/to client) to call when another peer connects.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect notify_connect;

  /**
   * Callback (from/to client) to call when a peer disconnects.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect notify_disconnect;

  /**
   * Callback (from/to client) to call when our address changes.
   */
  GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange notify_address_change;

  /**
   * Array of message handlers given by the client. Don't use for handling of
   * messages - this discards the per-mq-cls;
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for handlers given by the client - connection-independant
   * (#notify_connect, #notify_disconnect, #notify_address_change)
   * TODO what's the doxygen way of linking to other members of this struct?
   */
  void *cls;

  /**
   * Name of the listening socket.
   */
  char *sock_name;

  // TODO
  uint64_t sock_name_index_start;
  // TODO
  uint64_t sock_name_index;

  /**
   * Socket on which we listen for incoming connections.
   */
  struct GNUNET_NETWORK_Handle *sock_listen;

  /**
   * Task that waits for incoming connections
   */
  struct GNUNET_SCHEDULER_Task *listen_task;

  /**
   * Task to notify core about address changes.
   */
  struct GNUNET_SCHEDULER_Task *notify_address_change_task;

  /**
   * Task to discover other peers.
   */
  struct GNUNET_SCHEDULER_Task *peer_discovery_task;

  // TODO
  struct GNUNET_SCHEDULER_Task *address_change_task;

  /**
   * @brief Head of linked list with peer connect closures
   */
  struct PeerConnectCls *peer_connect_cls_head;

  /**
   * @brief Tail of linked list with peer connect closures
   */
  struct PeerConnectCls *peer_connect_cls_tail;

  /**
   * @brief Head of linked list with peer connect closures
   */
  struct Connection *connections_head;

  /**
   * @brief Tail of linked list with peer connect closures
   */
  struct Connection *connections_tail;
};


static const char *
status2string (enum ConnectionStatus status)
{
  switch (status)
  {
    case CONNECTION_INITIALIZING:
      return "C_INITIALIZING";
      break;
    case CONNECTION_INITIALIZING_SEND:
      return "C_INITIALIZING_SEND";
      break;
    case CONNECTION_INITIALIZING_RECV:
      return "C_INITIALIZING_RECV";
      break;
    case CONNECTION_LIVE:
      return "C_LIVE";
      break;
    case CONNECTION_DESTROY:
      return "C_DESTROY";
      break;
  }
  return ""; /* Make compiler happy */
}


/**
 * @brief Callback scheduled to run when there is something to read from the
 * socket. Reads the data from the socket and passes it to the message queue.
 *
 * @param cls Closure: Information for this socket
 */
static void
do_read (void *cls);


/*****************************************************************************
 * Connection-related functions                                              *
 ****************************************************************************/

/**
 * @brief Destroy a connection
 *
 * cancel all tasks, remove its memory,
 * close sockets, remove it from the DLL, ...
 *
 * @param connection The #Connection to destroy
 */
static void
connection_destroy (struct Connection *connection)
{
  /* The mq should already be cleaned as this function is called from within
   * mq_destroy_impl. */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_destroy\n");
  if ((NULL != connection->handle->notify_disconnect) &&
      (GNUNET_YES == connection->notify_connect_called))
  {
    /* Call the notify disconnect only if the notify_connect_task has been
     * executed and the client was actually notified about the connection */
    connection->handle->notify_disconnect (connection->handle->cls, /* connection-independant cls */
                                           connection->cls_mq); /* connection-specific cls */
  }
  if (NULL != connection->notify_connect_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling notify connect task\n");
    GNUNET_SCHEDULER_cancel (connection->notify_connect_task);
  }
  if (NULL != connection->handle_message_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling handle message task\n");
    GNUNET_SCHEDULER_cancel (connection->handle_message_task);
  }
  if (NULL != connection->write_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling write task\n");
    GNUNET_SCHEDULER_cancel (connection->write_task);
  }
  if (NULL != connection->recv_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling recv task\n");
    GNUNET_SCHEDULER_cancel (connection->recv_task);
  }
  if (NULL != connection->sock)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "closing socket\n");
    GNUNET_NETWORK_socket_close (connection->sock);
  }
  GNUNET_free (connection->peer_addr);
  if (NULL != connection->handlers) GNUNET_free (connection->handlers);
  /* Don't free the cls_mq - we don't own it! */
  GNUNET_CONTAINER_DLL_remove (connection->handle->connections_head,
                               connection->handle->connections_tail,
                               connection);
  GNUNET_free (connection);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_destroy - end\n");
}

/*****************************************************************************
 * Connection-related functions (end)                                        *
 ****************************************************************************/


/**
 * @brief Set the closures for mq handlers
 *
 * This is a utility function that sets the closures of the given mq handlers
 * to a given closure
 *
 * @param handlers the list of handlers
 * @param handlers_cls the new closure for the handlers
 */
static void
set_handlers_closure (struct GNUNET_MQ_MessageHandler *handlers,
                      void *handlers_cls)
{
  GNUNET_assert (NULL != handlers);

  for (unsigned int i = 0; NULL != handlers[i].cb; i++)
    handlers[i].cls = handlers_cls;
}


static void
do_handle_message (void *cls)
{
  struct Connection *connection = cls;
  struct QueuedMessage *q_msg = connection->queued_recv_messages_head;
  struct GNUNET_MessageHeader *msg = q_msg->msg;

  connection->handle_message_task = NULL;
  connection->client_ready_to_receive = GNUNET_NO;
  GNUNET_CONTAINER_DLL_remove (
      connection->queued_recv_messages_head,
      connection->queued_recv_messages_tail,
      q_msg);
  GNUNET_free (q_msg);
  // FIXME check return value!!!
  GNUNET_MQ_handle_message (
      connection->handlers,
      msg);
  //GNUNET_free (msg); // TODO what do we do with this pointer? Who owns it?
                       //      Who cleans it?
}


static void
check_for_messages (struct Connection *connection)
{
  if (NULL != connection->queued_recv_messages_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "got messages in the queue - handle those\n");
    GNUNET_assert (NULL == connection->handle_message_task);
    connection->handle_message_task =
      GNUNET_SCHEDULER_add_now (do_handle_message, connection);
  }
  else if (NULL == connection->recv_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "no messages in the queue - receive more from socket\n");
    connection->recv_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     connection->sock,
                                     do_read,
                                     connection);
  }
}


/**
 * @brief Notify the api caller about a new connection.
 *
 * This connection could either be initiated by us or the connecting peer.
 * The function is supposed to be called through the scheduler.
 *
 * @param cls
 */
static void
do_notify_connect (void *cls)
{
  struct Connection *connection = cls;
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = connection->handle;
  void *cls_mq;

  connection->notify_connect_task = NULL;
  connection->notify_connect_called = GNUNET_YES;
  connection->client_ready_to_receive = GNUNET_YES;
  /* The global, connection-independant closure is given to notify_connect,
   * notify_disconnect and notify_address_change, whereas the
   * connection-specific cls is the return value of notify_connect and given to
   * the handlers. */
  cls_mq =
    h->notify_connect(h->cls,
                      1,
                      (const char **) &connection->peer_addr,
                      connection->mq,
                      NULL); /* peer_id */
  /* The handlers are copied because the connection-specific closures can be
   * set. The global handlers remain the same - they are just called with the
   * connection specific closures. */
  connection->handlers = GNUNET_MQ_copy_handlers (h->handlers);
  set_handlers_closure (connection->handlers, h->cls); /* in case there's no connection-specific closure */
  if (NULL != cls_mq)
  {
    connection->cls_mq = cls_mq;
    //GNUNET_MQ_set_handlers_closure (connection->mq, connection->cls_mq);
    /* Overwrite the closure set above with the cls_mq */
    set_handlers_closure (connection->handlers, connection->cls_mq);
  }

  /* Handle already enqueued messages */
  check_for_messages (connection);
}


static void
try_notify_connect (struct Connection *connection)
{
  if ((NULL != connection->peer_addr) &&
      (CONNECTION_LIVE == connection->status) &&
      (NULL != connection->handle->notify_connect) &&
      (NULL == connection->notify_connect_task))
  {
    connection->notify_connect_task =
      GNUNET_SCHEDULER_add_now (do_notify_connect, connection);
  }
}


static void
cancel_initiating_connections (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
                               struct Connection *connection)
{
  struct Connection *c_iter_next;
  char *peer_addr = connection->peer_addr;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to cancel all initializing connections to %s\n",
      peer_addr);
  if (NULL == peer_addr) return; /* No sense in comparing to unknown address */
  for (struct Connection *c_iter = h->connections_head;
       NULL != c_iter;
       c_iter = c_iter_next)
  {
    c_iter_next = c_iter->next;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  %s :%s\n",
        c_iter->peer_addr,
        status2string (c_iter->status));
    if ((c_iter != connection) && /* Don't shut down current connection */
        (NULL != c_iter->peer_addr) && /* No address - can't compare */
        (0 == strcmp (c_iter->peer_addr, peer_addr)) &&
        (
          (CONNECTION_INITIALIZING == c_iter->status) ||
          (CONNECTION_INITIALIZING_SEND == c_iter->status) ||
          (CONNECTION_INITIALIZING_RECV == c_iter->status)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "    -> Cancelling connection - MQ_destroy()\n");
      GNUNET_MQ_destroy (c_iter->mq);
    }
  }
}


/**
 * @brief Callback scheduled to run when there is something to read from the
 * socket. Reads the data from the socket and passes it to the message queue.
 *
 * @param cls Closure: Information for this socket
 */
static void
do_read (void *cls)
{
  struct Connection *connection = cls;

  char buf[65536] GNUNET_ALIGN;
  ssize_t ret;
  struct GNUNET_MessageHeader *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "do_read(): receiving bytes from %s :%s\n",
      connection->peer_addr,
      status2string (connection->status));
  connection->recv_task = NULL;
  GNUNET_assert (NULL != connection->sock);
  ret = GNUNET_NETWORK_socket_recv (connection->sock,
                                    &buf,
                                    sizeof(buf));
  if (0 > ret)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Error reading from socket - MQ_destroy()\n");
    connection->status = CONNECTION_DESTROY;
    GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
    return;
  }
  if (0 == ret)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Other peer closed connection - MQ_destroy()\n");
    connection->status = CONNECTION_DESTROY;
    GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Read %d bytes\n", (int) ret);
  GNUNET_assert (2 <= ret); /* has to have returned enough for one full msg_hdr */

  /* Handle the message itself */
  {
    ssize_t ret_remain;
    char *buf_iter;
    struct GNUNET_MessageHeader *msg_iter;

    msg = (struct GNUNET_MessageHeader *) buf;
    ret_remain = ret;
    buf_iter = buf;
    /* Just debug logging */
    while (0 < ret_remain)
    {
      msg_iter = (struct GNUNET_MessageHeader *) buf_iter;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Length of message: %d bytes\n", ntohs (msg_iter->size));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Remaining bytes of buffer: %ld\n", ret_remain);

      {
        // XXX only for debugging purposes
        // this shows everything works as expected

        struct GNUNET_UNDERLAY_DUMMY_Message
        {
          struct GNUNET_MessageHeader header;
          // The following will be used for debugging
          uint64_t id; // id of the message
          uint64_t batch; // first batch of that peer (for this test 0 or 1)
          //uint64_t peer; // number of sending peer (for this test 0 or 1)
        };



        struct GNUNET_UNDERLAY_DUMMY_Message *msg_dbg =
          (struct GNUNET_UNDERLAY_DUMMY_Message *) msg_iter;
        //LOG (GNUNET_ERROR_TYPE_DEBUG, "do_read - id: %u, batch: %u, peer: %u\n",
        LOG (GNUNET_ERROR_TYPE_DEBUG, "do_read - id: %" PRIu64 ", batch: %" PRIu64 "\n",
             GNUNET_ntohll (msg_dbg->id),
             GNUNET_ntohll (msg_dbg->batch));
        //LOG (GNUNET_ERROR_TYPE_DEBUG, "do_read - size: %u\n",
        //     ntohs (msg_dbg->size));
        //LOG (GNUNET_ERROR_TYPE_DEBUG, "do_read - (sanity) size msghdr: %u\n",
        //     sizeof (struct GNUNET_MessageHeader));
        //LOG (GNUNET_ERROR_TYPE_DEBUG, "do_read - (sanity) size msg field: %u\n",
        //     sizeof (msg_dbg->id));
      }
      buf_iter = buf_iter + ntohs (msg_iter->size);
      ret_remain = ret_remain - ntohs (msg_iter->size);
    }

    /* Enqueue the following messages */
    /* skip the first message */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Enqueueing messages\n");
    buf_iter = buf + ntohs (msg->size);
    ret_remain = ret - ntohs (msg->size);
    /* iterate over the rest */
    while (0 < ret_remain)
    {
      struct QueuedMessage *q_msg = GNUNET_new (struct QueuedMessage);

      LOG (GNUNET_ERROR_TYPE_DEBUG, "Enqueueing message\n");
      msg_iter = (struct GNUNET_MessageHeader *) buf_iter;
      q_msg->msg = GNUNET_malloc (ntohs (msg_iter->size));
      GNUNET_memcpy (q_msg->msg, msg_iter, ntohs (msg_iter->size));
      GNUNET_CONTAINER_DLL_insert_tail (connection->queued_recv_messages_head,
                                        connection->queued_recv_messages_tail,
                                        q_msg);

      buf_iter = buf_iter + ntohs (msg_iter->size);
      ret_remain = ret_remain - ntohs (msg_iter->size);
    }
  }

  /* check for and handle init */
  if ((0 == ntohs (msg->type)) && /* 0 = GNUNET_MESSAGE_TYPE_TEST is deprecated - usage for this dummy should be fine */
      (CONNECTION_LIVE != connection->status)) /* ignore if current connection is already live */
  {
    char *peer_addr_sent = (char *) &msg[1];
    // FIXME is it really meaningful to send multiple addresses? probably just
    //       send the address that's used to open the connection
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Init-message: %s\n",
        peer_addr_sent);
    if ((NULL != connection->peer_addr) &&
        (0 != strcmp (peer_addr_sent, connection->peer_addr)))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
          "Peer sent us an Init-message with an address different from the one we already know. -> MQ_destroy()\n");
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "sent address: %s\n",
          peer_addr_sent);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "old address: %s\n",
          connection->peer_addr);
      GNUNET_MQ_destroy (connection->mq);
      GNUNET_break_op (0);
      return;
    }
    switch (connection->status)
    {
      case CONNECTION_INITIALIZING_SEND:
        connection->status = CONNECTION_LIVE;
        break;
      case CONNECTION_INITIALIZING:
        connection->status = CONNECTION_INITIALIZING_RECV;
        break;
      case CONNECTION_DESTROY:
        return;
      default:
        break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Connection to %s is now %s\n",
        connection->peer_addr,
        status2string (connection->status));
    // else: we could skip ahead to end of if - we do already know the peer_addr
    /* Check whether we already got a connection to that address/peer */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Init - checking other connections\n");
    for (struct Connection *c_iter = connection->handle->connections_head;
         NULL != c_iter;
         c_iter = c_iter->next)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "  %s (%s)\n",
          c_iter->peer_addr,
          status2string (c_iter->status));
      if ((NULL != c_iter->peer_addr) && /* we can't compare the addr */
          (0 == strcmp (peer_addr_sent, c_iter->peer_addr)) && /* same peer */
          (CONNECTION_LIVE == c_iter->status) && /* other connection is live*/
          (connection != c_iter)) /* discovered the currently handled connection - skip */
      {
        /* We already got a connection with this peer - tear the current one
         * down. */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "Init from other peer - already connected: %s - MQ_destroy()\n",
            peer_addr_sent);
        connection->status = CONNECTION_DESTROY;
        GNUNET_MQ_destroy (connection->mq);
        return;
      }
    }
    connection->peer_addr = strdup (peer_addr_sent);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Init-Message - notifying caller (%s :%s)\n",
        connection->peer_addr,
        status2string (connection->status));

    try_notify_connect (connection);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Finished initializing - going to cancel all still initializing connections to this address\n");
    cancel_initiating_connections (connection->handle, connection);

    /* We need to schedule the recv_task here because this is not a message
     * passed to the caller an thus the caller will not call
     * GNUNET_CORE_UNDERLAY_DUMMY_receive_continue () which usually schedules
     * the recv_task */
    connection->recv_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     connection->sock,
                                     do_read,
                                     connection);
    return;
  }
  else if ((0 == ntohs (msg->type)) && /* 0 = GNUNET_MESSAGE_TYPE_TEST is deprecated - usage for this dummy should be fine */
           (CONNECTION_LIVE == connection->status))
  {
    /* We need to schedule the recv_task here because this is not a message
     * passed to the caller an thus the caller will not call
     * GNUNET_CORE_UNDERLAY_DUMMY_receive_continue () which usually schedules
     * the recv_task */
    connection->recv_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     connection->sock,
                                     do_read,
                                     connection);
    return;
  }

  if (GNUNET_NO == connection->notify_connect_called)
  {
    /* Notify connect has not been called yet - the caller doesn't know about
     * this connection. Enqueue the first message, too; instead of handling it.
     */
    struct QueuedMessage *q_msg = GNUNET_new (struct QueuedMessage);

    q_msg->msg = GNUNET_malloc (ntohs (msg->size));
    GNUNET_memcpy (q_msg->msg, msg, ntohs (msg->size));
    GNUNET_CONTAINER_DLL_insert (connection->queued_recv_messages_head,
                                 connection->queued_recv_messages_tail,
                                 q_msg);
    return;
  }

  if (GNUNET_YES == connection->client_ready_to_receive)
  {
    // TODO maybe just call check_for_messages() instead?
    //check_for_messages (connection);
    // FIXME for now the above gives only an unsuccessful test - check why
    connection->client_ready_to_receive = GNUNET_NO;
    // FIXME check return value!!!
    GNUNET_MQ_handle_message (connection->handlers, msg);
  }
  // else TODO
}


/**
 * @brief Callback scheduled to run once the socket is ready for writing.
 * Writes the message to the socket.
 *
 * @param cls Closure: The handle of the underlay dummy
 */
static void
write_cb (void *cls)
{
  ssize_t sent;
  struct Connection *connection = cls;

  connection->write_task = NULL;
  GNUNET_assert (NULL != connection->sock);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "write_cb(): sending bytes to %s :%s\n",
      connection->peer_addr,
      status2string (connection->status));
  {
    // XXX only for debugging purposes
    // this shows everything works as expected

    struct GNUNET_UNDERLAY_DUMMY_Message
    {
      struct GNUNET_MessageHeader header;
      // The following will be used for debugging
      uint64_t id; // id of the message
      uint64_t batch; // first batch of that peer (for this test 0 or 1)
      //uint64_t peer; // number of sending peer (for this test 0 or 1)
    };



    struct GNUNET_UNDERLAY_DUMMY_Message *msg_dbg =
      (struct GNUNET_UNDERLAY_DUMMY_Message *) connection->message_to_send;
    //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - id: %u, batch: %u, peer: %u\n",
    LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - id: %" PRIu64 ", batch: %" PRIu64"\n",
         GNUNET_ntohll (msg_dbg->id),
         GNUNET_ntohll (msg_dbg->batch));
    //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - size: %u\n",
    //     ntohs (msg_dbg->size));
    //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - (sanity) size msghdr: %u\n",
    //     sizeof (struct GNUNET_MessageHeader));
    //LOG (GNUNET_ERROR_TYPE_DEBUG, "write_cb - (sanity) size msg field: %u\n",
    //     sizeof (msg_dbg->id));
  }
  GNUNET_assert (NULL != connection->message_to_send);
  sent = GNUNET_NETWORK_socket_send (
      connection->sock,
      connection->message_to_send,
      ntohs (connection->message_to_send->size));
  if (GNUNET_SYSERR == sent)
  {
    //LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to send message\n");
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to send message: %s\n", strerror(errno));
    if (EPIPE == errno)
    {
      /* Tear down the connection */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "MQ_destroy() (Failed to send message)\n");
      connection->status = CONNECTION_DESTROY;
      GNUNET_MQ_destroy (connection->mq); // This triggers mq_destroy_impl()
      return;
    }
    LOG (GNUNET_ERROR_TYPE_ERROR, "Retrying (due to failure)\n");
    /* retry */
    connection->write_task =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      connection->sock,
                                      &write_cb,
                                      connection);
    return; // TODO proper handling - don't try to resend on certain errors
            // (e.g. EPIPE as above)
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Successfully sent message\n");
  connection->message_to_send = NULL;
  switch (connection->status)
  {
    case CONNECTION_INITIALIZING_RECV:
      connection->status = CONNECTION_LIVE;
      try_notify_connect (connection);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Finished initializing - going to cancel all still initializing connections to this address\n");
      cancel_initiating_connections (connection->handle, connection);
      break;
    case CONNECTION_INITIALIZING:
      connection->status = CONNECTION_INITIALIZING_SEND;
      break;
    case CONNECTION_DESTROY:
      return;
    default:
      break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Connection to %s is now %s\n",
      connection->peer_addr,
      status2string (connection->status));
  GNUNET_MQ_impl_send_continue (connection->mq);
}


static void
send_init (struct Connection *connection)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  uint32_t peer_addr_len;

  GNUNET_assert (NULL != connection->handle->sock_name);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Sending init: %s\n",
      connection->handle->sock_name);
  peer_addr_len = strnlen (connection->handle->sock_name, 128) + 1;
  env = GNUNET_MQ_msg_header_extra (msg, // usually we wanted to keep the
      peer_addr_len,                     // envelopes to potentially cancel the
      0);                                // message
  GNUNET_memcpy (&msg[1], connection->handle->sock_name, peer_addr_len);
  GNUNET_MQ_send (connection->mq, env);
}


/**
 * @brief Callback called from the MQ to send a message over a socket.
 * Schedules the sending of the message once the socket is ready.
 *
 * @param mq The message queue
 * @param msg The message to send
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_send_impl (struct GNUNET_MQ_Handle *mq,
              const struct GNUNET_MessageHeader *msg,
              void *impl_state)
{
  struct Connection *connection = impl_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "from mq_send_impl\n");
  {
    // XXX only for debugging purposes
    // this shows everything works as expected

    struct GNUNET_UNDERLAY_DUMMY_Message
    {
      struct GNUNET_MessageHeader header;
      // The following will be used for debugging
      uint64_t id; // id of the message
      uint64_t batch; // first batch of that peer (for this test 0 or 1)
      //uint64_t peer; // number of sending peer (for this test 0 or 1)
    };

    struct GNUNET_UNDERLAY_DUMMY_Message *msg_dbg =
      (struct GNUNET_UNDERLAY_DUMMY_Message *) msg;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "id: %" PRIu64 ", batch: %" PRIu64 "\n",
         GNUNET_ntohll (msg_dbg->id),
         GNUNET_ntohll (msg_dbg->batch));
  }
  connection->message_to_send = msg;
  GNUNET_assert (NULL == connection->write_task);
  connection->write_task =
    GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                    connection->sock,
                                    &write_cb,
                                    connection);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduled sending of message\n");
}


/**
 * @brief Callback to destroy the message queue
 *
 * @param mq message queue to destroy
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_destroy_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Connection *connection = impl_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "mq_destroy_impl\n");
  connection_destroy (connection);
}


/**
 * @brief Callback to cancel sending a message.
 *
 * @param mq The message queue the message was supposed to be sent over.
 * @param impl_state The handle of the underlay dummy
 */
static void
mq_cancel_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct Connection *connection = impl_state;

  if (NULL != connection->write_task)
  {
    GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = NULL;
  }
}


/**
 * @brief Handle mq errors
 *
 * This is currently a stub that only logs.
 *
 * @param cls closure is unused
 * @param error the kind of error
 */
static void
mq_error_handler_impl (void *cls, enum GNUNET_MQ_Error error)
{
  LOG (GNUNET_ERROR_TYPE_ERROR,
      "mq_error_handler_impl: %u\n",
      error);
}


/**
 * Accept a connection on the dummy's socket
 *
 * @param cls the handle to the dummy passed as closure
 */
static void
do_accept (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  struct Connection *connection;
  struct GNUNET_NETWORK_Handle *sock;
  struct sockaddr_un addr_other;
  socklen_t addr_other_len = sizeof(addr_other);
  memset (&addr_other, 0, sizeof (addr_other));

  h->listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  h->sock_listen,
                                                  do_accept,
                                                  h);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Handling incoming connection\n");

  GNUNET_assert (NULL != h->sock_listen);

  LOG (GNUNET_ERROR_TYPE_INFO, "Accepting incoming connection\n");
  sock = GNUNET_NETWORK_socket_accept (h->sock_listen,
                                       (struct sockaddr *) &addr_other,
                                       &addr_other_len);
  if (NULL == sock)
  {
    //LOG(GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection, %s", strerror(errno));
    LOG (GNUNET_ERROR_TYPE_ERROR, "Error accepting incoming connection\n");
    return;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_set_blocking (sock, GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "Failed setting socket of incoming connection to non-blocking\n");
    return;
  }
  connection = GNUNET_new (struct Connection);
  connection->sock = sock;
  connection->peer_addr = NULL; // GNUNET_strdup (addr_other.sun_path); should
                                // be empty
  connection->handle = h;
  connection->notify_connect_called = GNUNET_NO;
  connection->client_ready_to_receive = GNUNET_NO;
  connection->status = CONNECTION_INITIALIZING;
  LOG (GNUNET_ERROR_TYPE_INFO, "Peer connected\n");
  GNUNET_CONTAINER_DLL_insert (h->connections_head,
                               h->connections_tail,
                               connection);
  connection->mq =
    GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                   mq_destroy_impl,
                                   mq_cancel_impl,
                                   connection, // impl_state - gets passed to _impls
                                   h->handlers,
                                   mq_error_handler_impl,
                                   connection->cls_mq);
  connection->recv_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   connection->sock,
                                   do_read,
                                   connection);
  send_init (connection);
}


/**
 * @brief Connect to another peer
 *
 * This function is scheduled and pays attention that it's not called
 * unnecessarily.
 *
 * @param cls
 */
static void
do_connect_to_peer (void *cls)
{
  struct PeerConnectCls *pcc = cls;

  pcc->peer_connect_task = NULL;
  GNUNET_CONTAINER_DLL_remove (pcc->h->peer_connect_cls_head,
                               pcc->h->peer_connect_cls_tail,
                               pcc);
  {
    struct Connection *connection;
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = pcc->h;
    struct sockaddr_un addr_other;
    memset (&addr_other, 0, sizeof (addr_other));

    connection = GNUNET_new (struct Connection);
    connection->handle = pcc->h;
    connection->sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
    connection->peer_addr = pcc->sock_name;
    connection->notify_connect_called = GNUNET_NO;
    connection->client_ready_to_receive = GNUNET_NO;
    connection->status = CONNECTION_INITIALIZING;
    if (NULL == connection->sock)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Socket does not open\n");
      GNUNET_free (connection);
      return;
    }
    if (GNUNET_OK !=
        GNUNET_NETWORK_socket_set_blocking (connection->sock, GNUNET_NO))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Failed setting socket to non-blocking\n");
      GNUNET_free (connection);
      return;
    }

    addr_other.sun_family = AF_UNIX;
    //strcpy (addr_other.sun_path, pcc->sock_name);
    GNUNET_memcpy (addr_other.sun_path, pcc->sock_name, strlen (pcc->sock_name));
    if (GNUNET_OK != GNUNET_NETWORK_socket_connect (connection->sock,
                                                    (struct sockaddr *) &addr_other,
                                                    sizeof(addr_other)))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
          "failed to connect to the socket: %u %s (closing socket)\n",
          errno, strerror(errno));
      GNUNET_NETWORK_socket_close (connection->sock);
      GNUNET_free (connection);
      //LOG (GNUNET_ERROR_TYPE_INFO, "Sanity check: %s\n", addr_other.sun_path);
      return;
    }
    connection->peer_addr = GNUNET_strdup (pcc->sock_name);
    LOG (GNUNET_ERROR_TYPE_INFO, "Successfully connected to socket\n");
    connection->recv_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     connection->sock,
                                     do_read,
                                     connection);
    connection->mq =
      GNUNET_MQ_queue_for_callbacks (mq_send_impl,
                                     mq_destroy_impl,
                                     mq_cancel_impl,
                                     connection, // impl_state - gets passed to _impls
                                     h->handlers,
                                     mq_error_handler_impl,
                                     connection->cls_mq);
    GNUNET_CONTAINER_DLL_insert (h->connections_head,
                                 h->connections_tail,
                                 connection);
    send_init (connection);

    //  FIXME: proper array
    //  FIXME: proper address format ("dummy:<sock_name>")
  }
  GNUNET_free (pcc->sock_name);
  GNUNET_free (pcc);
}


/**
 * @brief Notify core about address change.
 *
 * This is in an extra function so the callback gets called after the
 * GNUNET_CORE_UNDERLAY_DUMMY_connect() finishes.
 *
 * @param cls Closure: The handle of the dummy underlay.
 */
static void
do_notify_address_change (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  const char *addresses[1] = {h->sock_name}; // The dummy will only ever know
                                             // about this one address

  h->notify_address_change_task = NULL;
  h->notify_address_change (h->cls, 1, addresses);
}


static void
try_connect (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h, const char *address)
{
  GNUNET_assert (0 != strcmp (address, ""));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect to socket: `%s'\n", address);
  if (0 == strcmp (address, h->sock_name))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not going to connect to own address\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO,
      "Discovered another peer with address `%s'\n",
      address);

  /**
   * Check whether we are already connected to this peer
   *
   * This is limited as we don't always have the socket name of the other peer
   */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "checking other connections:\n");
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  %s (%s)\n",
        conn_iter->peer_addr,
        status2string (conn_iter->status));
    if ((NULL != conn_iter->peer_addr) &&
        (0 == strcmp (address, conn_iter->peer_addr)) &&
        (CONNECTION_LIVE == conn_iter->status))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already connected to this peer - don't try to open another connection\n");
      return;
    }
  }
  for (struct PeerConnectCls *pcc_iter = h->peer_connect_cls_head;
       NULL != pcc_iter;
       pcc_iter = pcc_iter->next)
  {
    if (0 == strcmp (address,
                     pcc_iter->sock_name))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Already waiting to connect to this peer\n");
      return;
    }
  }

  {
    struct PeerConnectCls *peer_connect_cls;
    peer_connect_cls = GNUNET_new (struct PeerConnectCls);
    peer_connect_cls->h = h;
    peer_connect_cls->sock_name = GNUNET_strdup (address);
    peer_connect_cls->peer_connect_task =
      GNUNET_SCHEDULER_add_now (do_connect_to_peer,
                                peer_connect_cls);
    GNUNET_CONTAINER_DLL_insert (h->peer_connect_cls_head,
                                 h->peer_connect_cls_tail,
                                 peer_connect_cls);
  }
}


/**
 * @brief Handle the discovery of a certain socket.
 *
 * This is called from within the discovery of file names with the correct
 * pattern.
 * It checks whether we are already connected to this socket, are waiting for a
 * reply, it's our own socket.
 * Issue a connection if the conditions are given.
 *
 * @param cls handle to the dummy service
 * @param filename the discovered filename
 *
 * @return #GNUNET_OK indicating that the iteration through filenames is
 * supposed to continue
 */
static enum GNUNET_GenericReturnValue
discovered_socket_cb (void *cls,
                      const char *filename)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;

  try_connect (h, filename);

  return GNUNET_OK;
}


/**
 * @brief Discover sockets of other peers
 *
 * Sockets with a certain file name pattern are treated as candidates.
 *
 * @param cls
 */
static void
do_discover_peers (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  int ret;

  ret = GNUNET_DISK_glob (SOCK_NAME_BASE "*" SOCK_EXTENSION,
                          discovered_socket_cb,
                          h);
  if (0 > ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Scanning for unix domain sockets failed\n");
  }

  h->peer_discovery_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100),
      do_discover_peers,
      h);
}


static enum GNUNET_GenericReturnValue
try_open_listening_socket (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
                           char *sock_name)
{
  struct sockaddr_un *addr_un;
  socklen_t addr_un_len;
  uint8_t ret = GNUNET_NO;

  h->sock_listen = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  GNUNET_assert (NULL != h->sock_listen);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Opened socket, going to bind to address\n");

  addr_un = GNUNET_new (struct sockaddr_un);
  addr_un->sun_family = AF_UNIX;
  // TODO check that the string is not too long
  GNUNET_memcpy (&addr_un->sun_path, sock_name, strlen (sock_name));
  addr_un_len = sizeof (struct sockaddr_un);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Trying to bind to `%s'\n", addr_un->sun_path);
  ret = GNUNET_NETWORK_socket_bind (h->sock_listen,
                                   (struct sockaddr *) addr_un,
                                   addr_un_len);
  if ((GNUNET_OK != ret) && (98 != errno))
  {
    /* Error different from Address already in use - cancel */
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "Failed binding to socket: %u %s (closing socket)\n",
        errno, strerror(errno));
    GNUNET_NETWORK_socket_close (h->sock_listen);
    h->sock_listen = NULL;
    GNUNET_free (addr_un);
    return GNUNET_SYSERR;
  }
  else if (GNUNET_OK != ret)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  -> something went wrong (address is probably in use)\n");
    GNUNET_NETWORK_socket_close (h->sock_listen);
    h->sock_listen = NULL;
    GNUNET_free (addr_un);
  }
  else if (GNUNET_OK == ret)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  -> succeeded! (binding to socket)\n");
    h->sock_name = GNUNET_strdup (sock_name);
  }
  GNUNET_free (addr_un);
  return ret;
}



/**
 * Opens UNIX domain socket.
 *
 * It start trying with a default name and successively increases a number
 * within it, when it encounters already used sockets.
 *
 * @param cls Closure: The handle of the dummy underlay.
 * @param sock_name_ctr TODO Append to the socket name to avoid collisions
 * TODO
 */
static void
do_open_listening_socket (void *cls,
                          uint64_t sock_name_ctr_start)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  char *sock_name;
  uint64_t sock_name_ctr = sock_name_ctr_start; // Append to the socket name to avoid collisions
  uint8_t ret = GNUNET_NO;

  /* Open a socket that's not occupied by another 'peer' yet:
   * Try opening sockets with an increasing counter in the socket name. */
  // TODO we might want to change this loop to schedule a new task
  do {
    GNUNET_asprintf (&sock_name,
                    SOCK_NAME_BASE "%" PRIu64 "" SOCK_EXTENSION "\0", sock_name_ctr++);
    ret = try_open_listening_socket (h, sock_name);
    GNUNET_free (sock_name);
    if (GNUNET_SYSERR == ret) return;
  } while (GNUNET_YES != ret);
  LOG (GNUNET_ERROR_TYPE_INFO, "Bound to `%s'\n", h->sock_name);
  h->sock_name_index_start = sock_name_ctr_start;
  h->sock_name_index = sock_name_ctr;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Mark socket as accepting connections\n");
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (h->sock_listen, BACKLOG))
  {
    //LOG (GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket: %s", strerror(errno));
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed listening to socket (closing socket)\n");
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h->sock_listen));
    h->sock_listen = NULL;
    GNUNET_free (h->sock_name);
    return;
  }

  if (NULL != h->notify_address_change)
  {
    // TODO cancel and cleanup task on run and shutdown
    LOG (GNUNET_ERROR_TYPE_DEBUG, "schedlue do_notify_address_change()\n");
    h->notify_address_change_task =
      GNUNET_SCHEDULER_add_now (do_notify_address_change, h);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "scheudle do_discover_peers()\n");
  h->peer_discovery_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100),
      do_discover_peers,
      h);

  LOG (GNUNET_ERROR_TYPE_INFO, "Going to listen for connections\n");
  h->listen_task = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  h->sock_listen,
                                                  do_accept,
                                                  h);
}


// TODO
static void
do_close_listening_socket (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  struct PeerConnectCls *pcc_next;
  struct Connection *conn_next;

  if (NULL != h->notify_address_change_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling notify address change task\n");
    GNUNET_SCHEDULER_cancel (h->notify_address_change_task);
    h->notify_address_change_task = NULL;
  }
  if (NULL != h->peer_discovery_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling peer discovery task\n");
    GNUNET_SCHEDULER_cancel (h->peer_discovery_task);
    h->peer_discovery_task = NULL;
  }
  for (struct PeerConnectCls *pcc = h->peer_connect_cls_head;
       NULL != pcc;
       pcc = pcc_next)
  {
    pcc_next = pcc->next;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling peer connect task\n");
    GNUNET_SCHEDULER_cancel (pcc->peer_connect_task);
    GNUNET_CONTAINER_DLL_remove (h->peer_connect_cls_head,
                                 h->peer_connect_cls_tail,
                                 pcc);
    GNUNET_free (pcc->sock_name);
    GNUNET_free (pcc);
  }
  if (NULL != h->listen_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancelling listen task\n");
    GNUNET_SCHEDULER_cancel (h->listen_task);
    h->listen_task = NULL;
  }
  if (NULL != h->sock_listen)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "closing socket\n");
    GNUNET_NETWORK_socket_close (h->sock_listen);
    h->sock_listen = NULL;
  }
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_next)
  {
    // TODO consider moving MQ_destroy() into connection_destroy(), but keep in
    // mind that connection_destroy() is also called from within
    // mq_destroy_impl()
    conn_next = conn_iter->next;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying a connection - MQ_destroy()\n");
    conn_iter->status = CONNECTION_DESTROY;
    GNUNET_MQ_destroy (conn_iter->mq); // This triggers mq_destroy_impl()
  }
}


static void
do_change_address (void *cls)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h = cls;
  GNUNET_CORE_UNDERLAY_DUMMY_change_address (h);
  h->address_change_task = GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1),
      do_change_address,
      h);
}


/**
 * Connect to the core underlay dummy service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param handlers array of message handlers or NULL; note that the closures
 *                 provided will be ignored and replaced with the respective
 *                 return value from @a nc
 * @param cls closure for the @a nc, @a nd and @a na callbacks
 * @param nc function to call on connect events, or NULL. Returns the closure
 *           for message handlers for this opened connection.
 * @param nd function to call on disconnect events, or NULL
 * @param na function to call on address changes, or NULL
 * @return NULL on error
 */
struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *
GNUNET_CORE_UNDERLAY_DUMMY_connect (
    const struct GNUNET_CONFIGURATION_Handle *cfg,
    const struct GNUNET_MQ_MessageHandler *handlers,
    void *cls,
    GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect nc,
    GNUNET_CORE_UNDERLAY_DUMMY_NotifyDisconnect nd,
    GNUNET_CORE_UNDERLAY_DUMMY_NotifyAddressChange na)
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_CORE_UNDERLAY_DUMMY_Handle));
  h->notify_connect = nc;
  h->notify_disconnect = nd;
  h->notify_address_change = na;
  if (NULL != handlers) h->handlers = GNUNET_MQ_copy_handlers (handlers);
  h->cls = cls;

  do_open_listening_socket (h, 0);

  //h->address_change_task = GNUNET_SCHEDULER_add_delayed (
  //    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
  //    do_change_address,
  //    h);

  LOG (GNUNET_ERROR_TYPE_INFO, "Core connected\n");

  return h;
}


/**
 * Disconnect from the core underlay dummy service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_disconnect
(struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *handle)
{
  LOG (GNUNET_ERROR_TYPE_INFO, "Core disconnects\n");
  // TODO delete, free and close everything
  if (NULL != handle->address_change_task)
    GNUNET_SCHEDULER_cancel (handle->address_change_task);
  do_close_listening_socket (handle);
  if (NULL != handle->handlers) GNUNET_free (handle->handlers);
  GNUNET_free (handle->sock_name);
  GNUNET_free (handle);
  LOG (GNUNET_ERROR_TYPE_INFO, "  -> Disconnected\n");
}


/**
 * Notification from the CORE service to the CORE UNDERLAY DUMMY service
 * that the CORE service has finished processing a message from
 * CORE UNDERLAY DUMMY (via the @code{handlers} of
 * #GNUNET_CORE_UNDERLAY_DUMMY_connect()) and that it is thus now OK for CORE
 * UNDERLAY DUMMY to send more messages for the peer with @a mq.
 *
 * Used to provide flow control, this is our equivalent to
 * #GNUNET_SERVICE_client_continue() of an ordinary service.
 *
 * Note that due to the use of a window, CORE UNDERLAY DUMMY may send multiple
 * messages destined for the same peer even without an intermediate
 * call to this function. However, CORE must still call this function
 * once per message received, as otherwise eventually the window will
 * be full and CORE UNDERLAY DUMMY will stop providing messages to CORE on @a
 * mq.
 *
 * @param ch core underlay dummy handle
 * @param mq continue receiving on this message queue
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
    struct GNUNET_MQ_Handle *mq)
{
  struct Connection *connection;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "from _receive_continue()\n");

  /* Find the connection belonging to the mq */
  for (struct Connection *conn_iter = h->connections_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    if (mq == conn_iter->mq)
    {
      connection = conn_iter;
    }
  }
  GNUNET_assert (NULL != connection);
  connection->recv_task = NULL;
  connection->client_ready_to_receive = GNUNET_YES;
  check_for_messages (connection);
}


/**
 * Instruct the underlay dummy to try to connect to another peer.
 *
 * Once the connection was successful, the
 * #GNUNET_CORE_UNDERLAY_DUMMY_NotifyConnect
 * will be called with a mq towards the peer.
 *
 * @param ch core underlay dummy handle
 * @param peer_address URI of the peer to connect to
 * @param pp what kind of priority will the application require (can be
 *           #GNUNET_MQ_PRIO_BACKGROUND, we will still try to connect)
 * @param bw desired bandwidth, can be zero (we will still try to connect)
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h,
    const char *peer_address,
    enum GNUNET_MQ_PriorityPreferences pp,
    struct GNUNET_BANDWIDTH_Value32NBO bw)
{
  // TODO PriorityPreferences
  // TODO BANDWIDTH_Value
  try_connect (h, peer_address);
}


/**
 * FOR TESTING PURPOSES ONLY
 */
void
GNUNET_CORE_UNDERLAY_DUMMY_change_address (
    struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing address!\n");
  do_close_listening_socket (h);
  if (0 == h->sock_name_index_start)
  {
    do_open_listening_socket (h, 10);
  }
  else
  {
    do_open_listening_socket (h, 0);
  }
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of gnunet_core_underlay_dummy.c */
