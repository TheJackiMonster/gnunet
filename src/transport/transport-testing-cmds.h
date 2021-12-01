/*
     This file is part of GNUnet.
     Copyright (C) 2021 GNUnet e.V.

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
 * @file transport-testing.h
 * @brief testing lib for transport service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef TRANSPORT_TESTING_CMDS_H
#define TRANSPORT_TESTING_CMDS_H
#include "gnunet_testing_lib.h"


typedef void *
(*GNUNET_TRANSPORT_notify_connect_cb) (struct GNUNET_TESTING_Interpreter *is,
                                       const struct GNUNET_PeerIdentity *peer);

/**
 * Struct to store information needed in callbacks.
 *
 */
struct ConnectPeersState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  GNUNET_TRANSPORT_notify_connect_cb notify_connect;

  /**
   * The testing system of this node.
   */
  const struct GNUNET_TESTING_System *tl_system;

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
};

struct StartPeerState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The ip of a node.
   */
  char *node_ip;

  /**
   * Receive callback
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  const char *cfgname;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_TESTING_Peer *peer;

  /**
   * Peer identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Peer's transport service handle
   */
  struct GNUNET_TRANSPORT_CoreHandle *th;

  /**
   * Application handle
   */
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;

  /**
   * Peer's PEERSTORE Handle
   */
  struct GNUNET_PEERSTORE_Handle *ph;

  /**
   * Hello get task
   */
  struct GNUNET_SCHEDULER_Task *rh_task;

  /**
   * Peer's transport get hello handle to retrieve peer's HELLO message
   */
  struct GNUNET_PEERSTORE_IterateContext *pic;

  /**
   * Hello
   */
  char *hello;

  /**
   * Hello size
   */
  size_t hello_size;

  char *m;

  char *n;

  char *local_m;

  const char *system_label;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  const struct GNUNET_TESTING_System *tl_system;

  GNUNET_TRANSPORT_notify_connect_cb notify_connect;

  /**
   * Flag indicating, if udp broadcast should be switched on.
   */
  unsigned int broadcast;
};


/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param m The number of the local node of the actual network namespace.
 * @param n The number of the actual namespace.
 * @param local_m Number of local nodes in each namespace.
 * @param handlers Handler for messages received by this peer.
 * @param cfgname Configuration file name for this peer.
 * @param notify_connect Method which will be called, when a peer connects.
 * @param broadcast Flag indicating, if broadcast should be switched on.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer (const char *label,
                                 const char *system_label,
                                 uint32_t no,
                                 char *node_ip,
                                 struct GNUNET_MQ_MessageHandler *handlers,
                                 const char *cfgname,
                                 GNUNET_TRANSPORT_notify_connect_cb
                                 notify_connect,
                                 unsigned int broadcast);


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_stop_peer (const char *label,
                                const char *start_label);


/**
 * Create command
 *
 * @param label name for command
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_peer_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param The topology for the test setup.
 * @param additional_connects Number of additional connects this cmd will wait for not triggered by this cmd.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers (
  const char *label,
  const char *start_peer_label,
  const char *create_label,
  uint32_t num,
  struct GNUNET_TESTING_NetjailTopology *topology,
  unsigned int additional_connects);


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_peer_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple (const char *label,
                                  const char *start_peer_label,
                                  const char *create_label,
                                  uint32_t num,
                                  struct GNUNET_TESTING_NetjailTopology *
                                  topology);


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd to create the testing system.
 * @param num Number globally identifying the node.
 * @param node_n The number of the node in a network namespace.
 * @param namespace_n The number of the network namespace.
 * @param The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_backchannel_check (const char *label,
                                        const char *start_peer_label,
                                        const char *create_label,
                                        uint32_t num,
                                        unsigned int node_n,
                                        unsigned int namespace_n,
                                        struct GNUNET_TESTING_NetjailTopology *
                                        topology);


/**
 * Create headers for a trait with name @a name for
 * statically allocated data of type @a type.
 */
#define GNUNET_TRANSPORT_MAKE_DECL_SIMPLE_TRAIT(name,type)   \
  enum GNUNET_GenericReturnValue                          \
    GNUNET_TRANSPORT_get_trait_ ## name (                    \
    const struct GNUNET_TESTING_Command *cmd,              \
    type **ret);                                          \
  struct GNUNET_TESTING_Trait                              \
    GNUNET_TRANSPORT_make_trait_ ## name (                   \
    type * value);


/**
 * Create C implementation for a trait with name @a name for statically
 * allocated data of type @a type.
 */
#define GNUNET_TRANSPORT_MAKE_IMPL_SIMPLE_TRAIT(name,type)  \
  enum GNUNET_GenericReturnValue                         \
    GNUNET_TRANSPORT_get_trait_ ## name (                   \
    const struct GNUNET_TESTING_Command *cmd,             \
    type **ret)                                          \
  {                                                      \
    if (NULL == cmd->traits) return GNUNET_SYSERR;       \
    return cmd->traits (cmd->cls,                        \
                        (const void **) ret,             \
                        GNUNET_S (name),                  \
                        0);                              \
  }                                                      \
  struct GNUNET_TESTING_Trait                             \
    GNUNET_TRANSPORT_make_trait_ ## name (                  \
    type * value)                                        \
  {                                                      \
    struct GNUNET_TESTING_Trait ret = {                   \
      .trait_name = GNUNET_S (name),                      \
      .ptr = (const void *) value                        \
    };                                                   \
    return ret;                                          \
  }


/**
 * Call #op on all simple traits.
 */
#define GNUNET_TRANSPORT_SIMPLE_TRAITS(op) \
  op (peer_id, const struct GNUNET_PeerIdentity) \
  op (connected_peers_map, const struct GNUNET_CONTAINER_MultiShortmap) \
  op (hello_size, const size_t) \
  op (hello, const char) \
  op (application_handle, const struct GNUNET_TRANSPORT_ApplicationHandle) \
  op (connect_peer_state, const struct ConnectPeersState) \
  op (state, const struct StartPeerState)

GNUNET_TRANSPORT_SIMPLE_TRAITS (GNUNET_TRANSPORT_MAKE_DECL_SIMPLE_TRAIT)


#endif
/* end of transport_testing.h */
