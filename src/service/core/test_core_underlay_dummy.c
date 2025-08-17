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
 * @author ch3
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

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_core_underlay_dummy.h"
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "core", __VA_ARGS__)

#define SOCK_NAME_BASE "/tmp/gnunet-core-underlay-dummy-socket"
#define SOCK_EXTENSION ".sock"

#define MTYPE 12345
#define NUMBER_MESSAGES 10
/* Number of open queues per peer - currently only 1 or 2 make sense */
#define NUMBER_CONNECTIONS 1 // FIXME - not needed anymore, simplify test!
#define NUMBER_SENDING_PEERS 2

// TODO we could implement checks for early success and tear everything down

/**
 * @brief This struct represents a 'peer' and most notably links to the service
 * handle
 */
struct DummyContext;


/**
 * @brief This struct keeps relevant information to a connection
 */
struct Connection
{
  /** DLL */
  struct Connection *next;
  struct Connection *prev;

  /* The message queue */
  struct GNUNET_MQ_Handle *mq;

  /* Address of the connected peer */
  char *address;

  /* Context to the 'peer' to which the connection belongs */
  struct DummyContext *dc;

 /* counter of replies/highest index */
  uint32_t result_replies;
};


/**
 * @brief Context for the scheduled destruction of an MQ.
 *
 * This is needed in case an undesired channel opens and we want to tear it
 * down immediately - this cannot be done from within the handler/callback that
 * provides us with the new connection.
 */
struct DestroyMQTask
{
  struct DestroyMQTask *next;
  struct DestroyMQTask *prev;
  struct GNUNET_SCHEDULER_Task *destroy_mq_task;
  struct DummyContext *dc;
  struct GNUNET_MQ_Handle *mq;
};


/**
 * @brief This struct represents a 'peer' and most notably links to the service
 * handle
 */
struct DummyContext
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  struct Connection *conn_head;
  struct Connection *conn_tail;
  uint32_t num_open_connections;
  struct DestroyMQTask *destroy_mq_task_head;
  struct DestroyMQTask *destroy_mq_task_tail;
} dc0, dc1;


/**
 * @brief A dummy message to be sent from one peer to another.
 */
struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  uint64_t peer; // number of sending peer (for this test 0 or 1)
};


/* Flag indicating whether #address_change_cb was called */
uint8_t result_address_callback = GNUNET_NO;

/* Flag indicating whether #notify_connect_cb was called once */
uint8_t result_connect_cb_0 = GNUNET_NO;

/* Flag indicating whether #notify_connect_cb was called a second time */
uint8_t result_connect_cb_1 = GNUNET_NO;

/* Number of replies that peer0 received */
uint32_t result_replies_0 = 0;

/* Number of replies that peer1 received */
uint32_t result_replies_1 = 0;

/**
 * @brief Task of the schutdown task that is triggert after a timeout
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;


/**
 * @brief Scheduled function to destroy an mq.
 *
 * This is needed in case the test is informed about an undesired connection
 * that it likes to terminate right away.
 *
 * @param cls The #DestroyMQTask
 */
static void
do_destroy_mq (void *cls)
{
  struct DestroyMQTask *destroy_mq_task = cls;

  GNUNET_MQ_destroy (destroy_mq_task->mq);
  GNUNET_CONTAINER_DLL_remove (destroy_mq_task->dc->destroy_mq_task_head,
                               destroy_mq_task->dc->destroy_mq_task_tail,
                               destroy_mq_task);
  GNUNET_free (destroy_mq_task);
}


static void
print_connections (struct DummyContext *dc)
{
  uint32_t count = 0;

  for (struct Connection *c_iter = dc->conn_head;
      NULL != c_iter;
      c_iter = c_iter->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  %" PRIu32 ": %s\n",
        count,
        c_iter->address);
    count++;
  }
}


/**
 * @brief Notify about an established connection.
 *
 * @param cls the closure given to the 'service' on
 *            #GNUNET_CORE_UNDERLAY_DUMMY_connect
 * @param num_addresses number of addresses connected to the incoming
 *                      connection
 * @param addresses string representation of the @a num_addresses addresses
 *                  connected to the incoming connection
 * @param mq The mq to the newly established connection
 *
 * @return The returned value overwrites the cls set in the handlers for this
 * mq. If NULL, the cls from the original handlers array is used.
 */
static void *notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq,
  const struct GNUNET_PeerIdentity *peer_id)
{
  struct DummyContext *dc = (struct DummyContext *) cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;
  struct Connection *connection;
  (void) peer_id; /* unused - the underlay dummy doesn't know abot peer ids */

  if (0 == num_addresses)
  {
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got notified about successful connection to peer with %u address\n",
      dc == &dc0 ? 0 : 1,
      num_addresses);
  }
  else
  {
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got notified about successful connection to peer with %u address: `%s'\n",
      dc == &dc0 ? 0 : 1,
      num_addresses,
      addresses[num_addresses - 1]);
  }
  /* Note test result */
  if (GNUNET_NO == result_connect_cb_0)
  {
    result_connect_cb_0 = GNUNET_YES;
  }
  else if (GNUNET_YES == result_connect_cb_0 &&
             GNUNET_NO == result_connect_cb_1)
  {
    result_connect_cb_1 = GNUNET_YES;
  }
  /* If we knew whether this connection is the one that's used to send/recv, we
   * could close it right now: */
  //if ()
  //{
  //  /* Don't accept further connections */
  //  struct DestroyMQTask *destroy_mq_task;
  //  destroy_mq_task = GNUNET_new (struct DestroyMQTask);
  //  destroy_mq_task->destroy_mq_task =
  //    GNUNET_SCHEDULER_add_now (do_destroy_mq, destroy_mq_task);
  //  destroy_mq_task->dc = dc;
  //  destroy_mq_task->mq = mq;
  //  GNUNET_CONTAINER_DLL_insert (dc->destroy_mq_task_head,
  //                               dc->destroy_mq_task_tail,
  //                               destroy_mq_task);
  //  return NULL;
  //}
  connection = GNUNET_new (struct Connection);
  connection->mq = mq;
  connection->address = GNUNET_strdup (addresses[0]);
  connection->dc = dc;
  connection->result_replies = 0;
  GNUNET_MQ_set_handlers_closure (mq, connection);
  GNUNET_CONTAINER_DLL_insert (dc->conn_head,
                               dc->conn_tail,
                               connection);
  dc->num_open_connections++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%u) Current connections:\n",
      dc == &dc0 ? 0 : 1);
  print_connections(dc);
  // FIXME get it in sync: number of messages sent (per connection) vs. number
  // of messages received (per peer)
  if (NUMBER_SENDING_PEERS == 1 &&
      &dc1 == dc)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Not going to send messages - only one peer is supposed to\n",
        dc == &dc0 ? 0 : 1);
    return connection;
  }
  for (uint64_t i = 0; i < NUMBER_MESSAGES; i++)
  {
    env = GNUNET_MQ_msg (msg, MTYPE); // usually we wanted to keep the
                                      // envelopes to potentially cancel the
                                      // message
    // a real implementation would set message fields here
    msg->id = GNUNET_htonll (i);
    msg->batch = GNUNET_htonll (dc->num_open_connections - 1);
    msg->peer = GNUNET_htonll (&dc0 == dc ? 0 : 1);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Going to send message %" PRIu64 " through message queue %" PRIu32 "\n",
        &dc0 == dc ? 0 : 1,
        i,
        dc->num_open_connections - 1);
    GNUNET_MQ_send (mq, env);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "(%u) Sent message %" PRIu64 " through message queue %" PRIu32 "\n",
        &dc0 == dc ? 0 : 1,
        i,
        dc->num_open_connections - 1);
  }

  return connection;
}


static void
notify_disconnect_cb (
  void *cls, /* dc */
  void *handler_cls) /* connection */
{
  struct Connection *connection = handler_cls;
  struct DummyContext *dc = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%u) Connection disconnected.\n",
      &dc0 == dc ? 0 : 1);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%u) Adding result replies: %" PRIu32 ".\n",
      &dc0 == dc ? 0 : 1,
      connection->result_replies);
  if (&dc0 == dc)
    result_replies_0 = result_replies_0 + connection->result_replies;
  else if (&dc1 == dc)
    result_replies_1 = result_replies_1 + connection->result_replies;
  else
    LOG (GNUNET_ERROR_TYPE_ERROR, "Unknown dummy context\n");
  GNUNET_CONTAINER_DLL_remove (dc->conn_head,
                               dc->conn_tail,
                               connection);
  GNUNET_free (connection->address);
  GNUNET_free (connection);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%u) Connections:\n",
      &dc0 == dc ? 0 : 1);
  print_connections (dc);
  // TODO cancel test
  if ((NUMBER_MESSAGES * NUMBER_CONNECTIONS == result_replies_0) &&
      (NUMBER_MESSAGES * NUMBER_CONNECTIONS == result_replies_1))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Test finished early, shutting down\n");
    if (NULL != timeout_task) GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * @brief Callback called when our address changes
 *
 * TODO document or link to network location hash and network generation id
 *
 * @param cls Closure: The #DummyContext
 * @param network_location_hash The network location hash for the new address
 * @param network_generation_id The network generation id for the new address
 */
static void
address_change_cb (void *cls,
                   uint32_t num_addresses,
                   const char *addresses[static num_addresses])
{
  struct DummyContext *dc = cls;

  result_address_callback = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
      "(%u) Got informed of address change\n",
      dc == &dc0 ? 0 : 1);
  LOG (GNUNET_ERROR_TYPE_INFO,
      "%" PRIu32 " new addresses:\n",
      num_addresses);
  for (uint32_t i = 0; i < num_addresses; i++)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
        "  %" PRIu32 ": %s\n",
        i,
        addresses[i]);
  }
  if (&dc0 == dc)
  {
    /* We cannot know which peer has which socket - try both */
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "0" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "1" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
  }
  else if (NUMBER_SENDING_PEERS == 2 &&
           &dc1 == dc)
  {
    /* We cannot know which peer has which socket - try both */
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "0" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
    GNUNET_CORE_UNDERLAY_DUMMY_connect_to_peer (dc->h,
                                                SOCK_NAME_BASE "1" SOCK_EXTENSION,
                                                GNUNET_MQ_PRIO_BEST_EFFORT,
                                                GNUNET_BANDWIDTH_VALUE_MAX);
  }
}


/**
 * @brief Shutdown task
 *
 * Scheduled and then called to shut the test down
 *
 * @param cls closure - unused
 */
static void
do_shutdown (void *cls)
{
  struct DestroyMQTask *dmt_iter_next;

  for (struct Connection *conn_iter = dc0.conn_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    result_replies_0 = result_replies_0 + conn_iter->result_replies;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "added %u replies for this connection\n",
         conn_iter->result_replies);
  }
  for (struct Connection *conn_iter = dc1.conn_head;
       NULL != conn_iter;
       conn_iter = conn_iter->next)
  {
    result_replies_1 = result_replies_1 + conn_iter->result_replies;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "added %u replies for this connection\n",
         conn_iter->result_replies);
  }

  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc0.h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (dc1.h);
  for (struct DestroyMQTask *dmt_iter = dc0.destroy_mq_task_head;
       NULL != dmt_iter;
       dmt_iter = dmt_iter_next)
  {
    dmt_iter_next = dmt_iter->next;
    GNUNET_SCHEDULER_cancel (dmt_iter->destroy_mq_task);
    do_destroy_mq (dmt_iter);
  }
  for (struct DestroyMQTask *dmt_iter = dc1.destroy_mq_task_head;
       NULL != dmt_iter;
       dmt_iter = dmt_iter_next)
  {
    dmt_iter_next = dmt_iter->next;
    GNUNET_SCHEDULER_cancel (dmt_iter->destroy_mq_task);
    do_destroy_mq (dmt_iter);
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnected from underlay dummy\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "counted %u replies for peer 0\n",
       result_replies_0);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "counted %u replies for peer 1\n",
       result_replies_1);
}


/**
 * @brief Scheduled task to trigger shutdown
 *
 * @param cls Closure - unused
 */
static void
do_timeout (void *cls)
{
  timeout_task = NULL;

  LOG(GNUNET_ERROR_TYPE_INFO, "Disconnecting from underlay dummy\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * @brief Handle a test message
 *
 * @param cls Closure - the #Connection struct containing all relevant info to
 *            the connection
 * @param msg the #GNUNET_UNDERLAY_DUMMY_Message
 */
static void
handle_test (void *cls, const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct Connection *connection = cls;
  uint32_t peer_id;

  GNUNET_assert (NULL != cls);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "received test message %" PRIu64 " (%" PRIu64 ", %" PRIu64 ")\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch),
       GNUNET_ntohll (msg->peer));
  if (connection->dc->conn_head == connection)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "on connection 0\n");
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "on connection 1\n");
  }
  GNUNET_assert (GNUNET_ntohll (msg->id) == connection->result_replies);

  connection->result_replies++;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(%u messages on this channel now)\n",
       connection->result_replies);
  peer_id = &dc0 == connection->dc ? 0 : 1;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(peer %u)\n", peer_id);
  GNUNET_assert (GNUNET_ntohll (msg->peer) != peer_id);
  GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (connection->dc->h,
                                               connection->mq);
}


/**
 * @brief Run the test
 *
 * This mainly connects to the services - everything else is then triggered by
 * callbacks
 *
 * @param cls Closure - unused
 */
static void run_test (void *cls)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_UNDERLAY_DUMMY_Message, NULL),
    GNUNET_MQ_handler_end ()
  };
  GNUNET_log_setup ("test-core-underlay-dummy", "DEBUG", NULL);
  dc0.num_open_connections = 0;
  dc1.num_open_connections = 0;

  LOG(GNUNET_ERROR_TYPE_INFO, "Connecting to underlay dummy\n");
  dc0.h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                              handlers,
                                              &dc0, // cls
                                              notify_connect_cb,
                                              notify_disconnect_cb, // nd
                                              address_change_cb);
  LOG(GNUNET_ERROR_TYPE_INFO, "(0) Connected to underlay dummy\n");
  dc1.h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, //cfg
                                              handlers,
                                              &dc1, // cls
                                              notify_connect_cb,
                                              notify_disconnect_cb, // nd
                                              address_change_cb);
  LOG(GNUNET_ERROR_TYPE_INFO, "(1) Connected to underlay dummy 2\n");
  GNUNET_SCHEDULER_add_shutdown (do_shutdown, NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               do_timeout,
                                               NULL);
}


/**
 * @brief Main function of the test
 *
 * Runs the test via starting the scheduler and checks the results after
 * scheduler shuts down.
 *
 * @return Indicate success or failure
 */
int main (void)
{
  GNUNET_SCHEDULER_run (run_test, NULL);

  if (GNUNET_YES != result_address_callback) return -1;
  if (GNUNET_YES != result_connect_cb_0) return -1;
  if (GNUNET_YES != result_connect_cb_1) return -1;
  if ((NUMBER_SENDING_PEERS > 1) &&
      (NUMBER_MESSAGES * NUMBER_CONNECTIONS != result_replies_0))
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 0 received %u of %u messages\n",
        result_replies_0,
        NUMBER_MESSAGES * NUMBER_CONNECTIONS);
    // XXX:
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 1 received %u of %u messages\n",
        result_replies_1,
        NUMBER_MESSAGES * NUMBER_CONNECTIONS);
    return -1;
  }
  if (NUMBER_MESSAGES * NUMBER_CONNECTIONS != result_replies_1)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
        "Peer 1 received %u of %u messages\n",
        result_replies_1,
        NUMBER_MESSAGES * NUMBER_CONNECTIONS);
    return -1;
  }
  return 0;
}


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/** @} */ /* end of group */

/** @} */ /* end of group addition */

/* end of test_gnunet_core_underlay_dummy.c */
