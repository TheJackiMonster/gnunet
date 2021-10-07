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


struct StartPeerState_v2
{
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

  unsigned int finished;

  const char *system_label;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  struct GNUNET_TESTING_System *tl_system;

};


struct StartPeerState
{
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

  unsigned int finished;

  const char *system_label;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  struct GNUNET_TESTING_System *tl_system;

};


int
GNUNET_TRANSPORT_get_trait_state (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  struct StartPeerState **sps);


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer_v2 (const char *label,
                                    const char *system_label,
                                    uint32_t no,
                                    char *node_ip,
                                    struct GNUNET_MQ_MessageHandler *handlers,
                                    const char *cfgname);

struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer_v3 (const char *label,
                                    const char *system_label,
                                    uint32_t no,
                                    char *node_ip,
                                    struct GNUNET_MQ_MessageHandler *handlers,
                                    const char *cfgname);

struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer (const char *label,
                                 const char *system_label,
                                 char *m,
                                 char *n,
                                 char *local_m,
                                 char *node_ip,
                                 struct GNUNET_MQ_MessageHandler *handlers,
                                 const char *cfgname);


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_stop_peer (const char *label,
                                const char *start_label);


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers (const char *label,
                                    const char *start_peer_label,
                                    const char *create_label,
                                    uint32_t num);


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers_v2 (const char *label,
                                       const char *start_peer_label,
                                       const char *create_label,
                                       uint32_t num);


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd to create the testing system.
 * @param num Number globally identifying the node.
 * @param The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers_v3 (const char *label,
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
 * Create command.
 *
 * @param label name for command.
 * @param m The number of the local node of the actual network namespace.
 * @param n The number of the actual namespace.
 * @param num Number globally identifying the node.
 * @param start_peer_label Label of the cmd to start a peer.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple (const char *label,
                                  char *m,
                                  char *n,
                                  uint32_t num,
                                  const char *start_peer_label);

/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param num Number globally identifying the node.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple_v2 (const char *label,
                                     const char *start_peer_label,
                                     uint32_t num);


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param start_peer_label Label of the cmd which started the test system.
 * @param num Number globally identifying the node.
 * @param The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple_v3 (const char *label,
                                     const char *start_peer_label,
                                     const char *create_label,
                                     uint32_t num,
                                     struct GNUNET_TESTING_NetjailTopology *
                                     topology);


int
GNUNET_TRANSPORT_get_trait_peer_id (const struct
                                    GNUNET_TESTING_Command *cmd,
                                    struct GNUNET_PeerIdentity **id);

int
GNUNET_TRANSPORT_get_trait_connected_peers_map (const struct
                                                GNUNET_TESTING_Command
                                                *cmd,
                                                struct
                                                GNUNET_CONTAINER_MultiShortmap *
                                                *
                                                connected_peers_map);

int
GNUNET_TRANSPORT_get_trait_connected_peers_map_v2 (const struct
                                                   GNUNET_TESTING_Command
                                                   *cmd,
                                                   struct
                                                   GNUNET_CONTAINER_MultiShortmap
                                                   *
                                                   *
                                                   connected_peers_map);

int
GNUNET_TRANSPORT_get_trait_connected_peers_map_v3 (const struct
                                                   GNUNET_TESTING_Command
                                                   *cmd,
                                                   struct
                                                   GNUNET_CONTAINER_MultiShortmap
                                                   *
                                                   *
                                                   connected_peers_map);
int
GNUNET_TRANSPORT_get_trait_hello_size (const struct
                                       GNUNET_TESTING_Command
                                       *cmd,
                                       size_t **hello_size);

int
GNUNET_TRANSPORT_get_trait_hello (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  char **hello);


int
GNUNET_TRANSPORT_get_trait_application_handle (const struct
                                               GNUNET_TESTING_Command *cmd,
                                               struct
                                               GNUNET_TRANSPORT_ApplicationHandle
                                               **ah);

int
GNUNET_TRANSPORT_get_trait_application_handle_v2 (const struct
                                                  GNUNET_TESTING_Command *cmd,
                                                  struct
                                                  GNUNET_TRANSPORT_ApplicationHandle
                                                  **ah);

int
GNUNET_TRANSPORT_get_trait_application_handle_v3 (const struct
                                                  GNUNET_TESTING_Command *cmd,
                                                  struct
                                                  GNUNET_TRANSPORT_ApplicationHandle
                                                  **ah);

#endif
/* end of transport_testing.h */
