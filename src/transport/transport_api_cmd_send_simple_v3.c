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
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Struct to hold information for callbacks.
 *
 */
struct SendSimpleState
{
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
   * Label of the cmd which started the test system.
   *
   */
  const char *create_label;

  /**
   * The topology we get the connected nodes from.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;
};


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
send_simple_traits (void *cls,
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
send_simple_cleanup (void *cls,
                     const struct GNUNET_TESTING_Command *cmd)
{
  struct SendSimpleState *sss = cls;

  GNUNET_free (sss);
}


/**
 * The run method of this cmd will send a simple message to the connected peers.
 *
 */
static void
send_simple_run (void *cls,
                 const struct GNUNET_TESTING_Command *cmd,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct SendSimpleState *sss = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_TESTING_TestMessage *test;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_ShortHashCode *key = GNUNET_new (struct GNUNET_ShortHashCode);
  struct GNUNET_HashCode hc;
  struct GNUNET_TESTING_NodeConnection *node_connections_head;
  struct GNUNET_PeerIdentity *peer;
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
  uint32_t num;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  const struct GNUNET_TESTING_Command *system_cmd;
  struct GNUNET_TESTING_System *tl_system;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (sss->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map (peer1_cmd,
                                                  &connected_peers_map);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (sss->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  node_connections_head = GNUNET_TESTING_get_connections (sss->num,
                                                          sss->topology);

  for (int i = 0; i < 1; i++)
  {
    for (pos_connection = node_connections_head; NULL != pos_connection;
         pos_connection = pos_connection->next)
    {
      num = GNUNET_TESTING_calculate_num (pos_connection, sss->topology);
      peer = GNUNET_TESTING_get_pub_key (num, tl_system);
      public_key = peer->public_key;
      GNUNET_CRYPTO_hash (&public_key, sizeof(public_key), &hc);

      memcpy (key,
              &hc,
              sizeof (*key));
      mq = GNUNET_CONTAINER_multishortmap_get (connected_peers_map,
                                               key);
      env = GNUNET_MQ_msg_extra (test,
                                 1000 - sizeof(*test),
                                 GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE);
      test->num = htonl (sss->num);
      memset (&test[1],
              sss->num,
              1000 - sizeof(*test));
      GNUNET_MQ_send (mq,
                      env);
    }
  }

  GNUNET_free (key);

}


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
                                     topology)
{
  struct SendSimpleState *sss;

  sss = GNUNET_new (struct SendSimpleState);
  sss->num = num;
  sss->start_peer_label = start_peer_label;
  sss->create_label = create_label;
  sss->topology = topology;

  struct GNUNET_TESTING_Command cmd = {
    .cls = sss,
    .label = label,
    .run = &send_simple_run,
    .cleanup = &send_simple_cleanup,
    .traits = &send_simple_traits
  };

  return cmd;
}
