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
 * @brief API for cmds working with transport sub system.
 * @author t3sserakt
 */
#ifndef GNUNET_TRANSPORT_TESTING_NG_LIB_H
#define GNUNET_TRANSPORT_TESTING_NG_LIB_H


#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

/**
 * Application handle; FIXME: what exactly is this?
 */
struct GNUNET_TRANSPORT_ApplicationHandle;

/**
 * FIXME: what is this?
 */
struct GNUNET_TESTING_StartPeerState;


// FIXME: breaks naming conventions
typedef void *
(*GNUNET_TESTING_notify_connect_cb) (struct GNUNET_TESTING_Interpreter *is,
                                     const struct GNUNET_PeerIdentity *peer);



// FIXME: breaks naming conventions! Needed public?
struct GNUNET_TESTING_StartPeerState
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

  /**
   * GNUnet configuration file used to start a peer.
   */
  char *cfgname;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * struct GNUNET_TESTING_Peer returned by GNUNET_TESTING_peer_configure.
   */
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

  /**
   * The label of the command which was started by calling GNUNET_TESTING_cmd_system_create.
   */
  char *system_label;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  /**
   * A map with struct GNUNET_MQ_Handle values for each peer this peer
   * is connected to.
   */
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  /**
   * Test setup for this peer.
   */
  const struct GNUNET_TESTING_System *tl_system;

  /**
   * Callback which is called on neighbour connect events.
   */
  GNUNET_TESTING_notify_connect_cb notify_connect;

  /**
   * Flag indicating, if udp broadcast should be switched on.
   */
  enum GNUNET_GenericReturnValue broadcast;
};



/**
 * Create command.
 *
 * @param label name for command.
 * @param system_label Label of the cmd to setup a test environment.
 * @param no Decimal number representing the last byte of the IP address of this peer.
 * @param node_ip The IP address of this node.
 * @param cfgname Configuration file name for this peer.
 * @param broadcast Flag indicating, if broadcast should be switched on.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_start_peer (const char *label,
                               const char *system_label,
                               uint32_t no,
                               const char *node_ip,
                               const char *cfgname,
                               unsigned int broadcast);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_peer (const char *label,
                              const char *start_label);


/**
 * Retrieve peer identity from the test system with the unique node id.
 *
 * @param num The unique node id.
 * @param tl_system The test system.
 * @return The peer identity wrapping the public key.
 */
struct GNUNET_PeerIdentity *
GNUNET_TESTING_get_peer (unsigned int num,
                         const struct GNUNET_TESTING_System *tl_system);




/**
 * Call #op on all simple traits.
 */
#define GNUNET_TRANSPORT_TESTING_SIMPLE_TRAITS(op, prefix)                         \
  op (prefix, connected_peers_map, const struct GNUNET_CONTAINER_MultiShortmap)    \
  op (prefix, peer_id, const struct GNUNET_PeerIdentity)                           \
  op (prefix, hello_size, const size_t)                                            \
  op (prefix, hello, const char)                                                   \
  op (prefix, application_handle, const struct GNUNET_TRANSPORT_ApplicationHandle) \
  op (prefix, state, const struct GNUNET_TESTING_StartPeerState)                   \
  op (prefix, broadcast, const enum GNUNET_GenericReturnValue)


GNUNET_TRANSPORT_TESTING_SIMPLE_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT, GNUNET_TRANSPORT_TESTING)

#endif
