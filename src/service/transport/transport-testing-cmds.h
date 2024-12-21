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
#include "gnunet_testing_transport_lib.h"


/**
 * Struct to store information needed in callbacks.
 *
 */
// FIXME: breaks naming conventions! Needed public?
struct ConnectPeersState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  GNUNET_TESTING_notify_connect_cb notify_connect;

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


typedef void *
(*GNUNET_TRANSPORT_notify_connect_cb) (struct GNUNET_TESTING_Interpreter *is,
                                       const struct GNUNET_PeerIdentity *peer);


struct TestState
{
  /**
   * The name for a specific test environment directory.
   *
   */
  char *testdir;

  /**
   * The name for the configuration file of the specific node.
   *
   */
  char *cfgname;

  /**
   * The complete topology information.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;
};


/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param no Decimal number representing the last byte of the IP address of this peer.
 * @param node_ip The IP address of this node.
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
                                 const char *node_ip,
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
 * @param create_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param topology The topology for the test setup.
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
  unsigned int additional_connects,
  unsigned int wait_for_connect);


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param topology The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple (const char *label,
                                  const char *start_peer_label,
                                  const char *create_label,
                                  uint32_t num);

/**
 *
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param size The size of the test message to send.
 * @param max_send The number of messages to send.
 * @param topology The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple_performance (const char *label,
                                              const char *start_peer_label,
                                              const char *create_label,
                                              uint32_t num,
                                              int size,
                                              int max_send,
                                              struct
                                              GNUNET_TESTING_NetjailTopology *
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
 * @param topology The topology for the test setup.
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
 * Call #op on all simple traits.
 */
#define GNUNET_TRANSPORT_SIMPLE_TRAITS(op, prefix)                 \
        op (prefix, connect_peer_state, const struct ConnectPeersState)

GNUNET_TRANSPORT_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                GNUNET_TRANSPORT_TESTING)


#endif
/* end of transport_testing.h */
