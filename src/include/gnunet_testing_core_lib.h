/*
      This file is part of GNUnet
      Copyright (C) 2021-2023 GNUnet e.V.

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
 * @brief API for cmds working with core sub system provided by libgnunetcoretesting
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_CORE_LIB_H
#define GNUNET_TESTING_CORE_LIB_H


#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


#define MTYPE 12345

#define NODE_ID_LEN 16


/**
 * Struct to store information needed in callbacks.
 */
// FIXME: breaks naming conventions
struct GNUNET_TESTING_ConnectPeersState
{
  /**
   * Receive callback
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * A map with struct GNUNET_MQ_Handle values for each peer this peer
   * is connected to.
   */
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  /**
   * Handle for transport.
   */
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;

  /**
   * Core handle.
   */
  struct GNUNET_TRANSPORT_CoreHandle *th;

  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The testing system of this node.
   */
  const struct GNUNET_TESTBED_System *tl_system;

  // Label of the cmd which started the test system.
  const char *create_label;

  /**
   * Number globally identifying the node.
   *
   */
  uint32_t num;

  /**
   * Label of the cmd to start a peer.
   *
   */
  const char *start_peer_label;

  /**
   * The topology of the test setup.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * Connections to other peers.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_head;

  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Number of connections.
   */
  unsigned int con_num;

  /**
   * Number of additional connects this cmd will wait for not triggered by this cmd.
   */
  unsigned int additional_connects;

  /**
 * Number of connections we already have a notification for.
 */
  unsigned int con_num_notified;

  /**
   * Number of additional connects this cmd will wait for not triggered by this cmd we already have a notification for.
   */
  unsigned int additional_connects_notified;

  /**
   * Flag indicating, whether the command is waiting for peers to connect that are configured to connect.
   */
  unsigned int wait_for_connect;
};


struct GNUNET_TESTING_CORE_ConnectState;


struct GNUNET_TESTING_CORE_Channel
{
  struct GNUNET_TESTING_CORE_Channel *next;
  struct GNUNET_TESTING_CORE_Channel *prev;
  struct GNUNET_TESTING_CORE_ConnectState *connect_state;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_PeerIdentity peer_id;
};


struct GNUNET_TESTING_CORE_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  // uint64_t peer; // number of sending peer (for this test 0 or 1)
  char node_id[NODE_ID_LEN];
};


typedef void *
(*GNUNET_TESTING_CORE_connect_cb) (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  struct GNUNET_MQ_Handle *mq);


struct GNUNET_TESTING_CORE_ConnectCb
{
  GNUNET_TESTING_CORE_connect_cb callback;
  void *cls;
};


typedef void
(*GNUNET_TESTING_CORE_handle_msg)(
  void *cls,
  struct GNUNET_TESTING_CORE_Channel *channel,
  const struct GNUNET_TESTING_CORE_Message *msg);


struct GNUNET_TESTING_CORE_ConnectState
{
  struct GNUNET_CORE_Handle *h;

  // FIXME why is this const? Borrowed pointer?!
  const char*node_id;
  struct GNUNET_PeerIdentity peer_id;
  char *arm_service_label;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  enum GNUNET_GenericReturnValue finished;

  /**
   * Receive callback
   */
  GNUNET_TESTING_CORE_handle_msg *recv_handlers;
  uint32_t recv_handlers_len;
  void *recv_handlers_cls;

  /**
   * Connect callback
   * TODO we probably only need a single one.
   */
  struct GNUNET_TESTING_CORE_ConnectCb *connect_cbs;
  uint32_t connect_cbs_len;

  struct GNUNET_TESTING_CORE_Channel *channels_head;
  struct GNUNET_TESTING_CORE_Channel *channels_tail;

  struct GNUNET_TESTING_AsyncContext ac;
};


/**
 * FIXME: document properly!
 * Create command
 *
 * @param label name for command
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param topology The topology for the test setup.
 * @param additional_connects Number of additional connects this cmd will wait for not triggered by this cmd.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect_peers (
  const char *label,
  const char *start_peer_label,
  const char *create_label,
  uint32_t num,
  struct GNUNET_TESTING_NetjailTopology *topology,
  unsigned int additional_connects,
  unsigned int wait_for_connect,
  struct GNUNET_MQ_MessageHandler *handlers);

const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_connect (
  const char *label,
  const char*node_id,
  char *arm_service_label);


const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_recv (
  const char *label,
  uint64_t num_messages);


const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_send (
  const char *label,
  uint64_t num_messages,
  enum GNUNET_GenericReturnValue await_new_connection);


/**
 * Call #op on all simple traits.
 */
#define GNUNET_CORE_TESTING_SIMPLE_TRAITS(op, prefix)   \
        op (prefix, connect_peer_state, const struct \
            GNUNET_TESTING_ConnectPeersState) \
        op (prefix, connect, struct \
            GNUNET_TESTING_CORE_ConnectState)

GNUNET_CORE_TESTING_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                   GNUNET_CORE_TESTING)


#endif
