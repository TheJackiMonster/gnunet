/*
      This file is part of GNUnet
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
 * @file testing_api_cmd_start_peer.c
 * @brief cmd to start a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct to store information needed in callbacks.
 *
 */
struct ConnectPeersState
{
  /**
   * The testing system of this node.
   */
  struct GNUNET_TESTING_System *tl_system;

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
   * The peer identity of this peer.
   *
   */
  struct GNUNET_PeerIdentity *id;

  /**
   * The topology of the test setup.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * Connections to other peers.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_head;

  /**
   * Number of connections.
   */
  unsigned int con_num;
};


/**
 * The run method of this cmd will connect to peers.
 *
 */
static void
connect_peers_run (void *cls,
                   const struct GNUNET_TESTING_Command *cmd,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct ConnectPeersState *cps = cls;
  const struct GNUNET_TESTING_Command *system_cmd;
  struct GNUNET_TESTING_System *tl_system;


  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;
  struct GNUNET_PeerIdentity *peer;
  char *addr;
  enum GNUNET_NetworkType nt = 0;
  uint32_t num;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_AddressPrefix *pos_prefix;
  unsigned int con_num = 0;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_application_handle_v2 (peer1_cmd,
                                                    &ah);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  cps->tl_system = tl_system;

  cps->node_connections_head = GNUNET_TESTING_get_connections (cps->num,
                                                               cps->topology);

  for (pos_connection = cps->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    con_num++;
    num = GNUNET_TESTING_calculate_num (pos_connection, cps->topology);
    for (pos_prefix = pos_connection->address_prefixes_head; NULL != pos_prefix;
         pos_prefix =
           pos_prefix->next)
    {

      LOG (GNUNET_ERROR_TYPE_ERROR,
           "prefix: %s\n",
           pos_prefix->address_prefix);

      addr = GNUNET_TESTING_get_address (pos_connection,
                                         pos_prefix->address_prefix);

      peer = GNUNET_TESTING_get_pub_key (num, tl_system);

      LOG (GNUNET_ERROR_TYPE_ERROR,
           "num: %u pub_key %s addr: %s\n",
           num,
           GNUNET_CRYPTO_eddsa_public_key_to_string (&(peer->public_key)),
           addr);

      cps->id = peer;

      GNUNET_TRANSPORT_application_validate (ah,
                                             peer,
                                             nt,
                                             addr);
    }
  }
  cps->con_num = con_num;
}


/**
 * The finish function of this cmd will check if the peers we are trying to
 * connect to are in the connected peers map of the start peer cmd for this peer.
 *
 */
static int
connect_peers_finish (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  struct ConnectPeersState *cps = cls;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;
  unsigned int ret;
  struct GNUNET_ShortHashCode *key = GNUNET_new (struct GNUNET_ShortHashCode);
  struct GNUNET_HashCode hc;
  struct GNUNET_PeerIdentity *peer;
  unsigned int con_num = 0;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  unsigned int num;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map_v2 (peer1_cmd,
                                                     &connected_peers_map);

  for (pos_connection = cps->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    num = GNUNET_TESTING_calculate_num (pos_connection, cps->topology);
    peer = GNUNET_TESTING_get_pub_key (num, cps->tl_system);
    GNUNET_CRYPTO_hash (&(peer->public_key), sizeof(peer->public_key), &hc);
    memcpy (key,
            &hc,
            sizeof (*key));
    if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
          connected_peers_map,
          key))
      con_num++;
  }



  if (cps->con_num == con_num)
  {
    cont (cont_cls);
    ret = GNUNET_YES;
  }

  GNUNET_free (key);
  return ret;
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
connect_peers_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  return GNUNET_OK;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
connect_peers_cleanup (void *cls,
                       const struct GNUNET_TESTING_Command *cmd)
{
  struct ConnectPeersState *cps = cls;

  GNUNET_free (cps->id);
  GNUNET_free (cps);
}


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
                                       topology)
{
  struct ConnectPeersState *cps;

  cps = GNUNET_new (struct ConnectPeersState);
  cps->start_peer_label = start_peer_label;
  cps->num = num;
  cps->create_label = create_label;
  cps->topology = topology;


  struct GNUNET_TESTING_Command cmd = {
    .cls = cps,
    .label = label,
    .run = &connect_peers_run,
    .finish = &connect_peers_finish,
    .cleanup = &connect_peers_cleanup,
    .traits = &connect_peers_traits
  };

  return cmd;
}
