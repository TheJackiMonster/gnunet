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
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_transport_application_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * The run method of this cmd will connect to peers.
 *
 */
static void
connect_peers_run (void *cls,
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

  cps->is = is;
  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_application_handle (peer1_cmd,
                                                 &ah);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          cps->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  cps->tl_system = tl_system;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "cps->num: %u \n",
       cps->num);

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
      addr = GNUNET_TESTING_get_address (pos_connection,
                                         pos_prefix->address_prefix);
      if (NULL != addr)
      {
        peer = GNUNET_TESTING_get_pub_key (num, tl_system);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "validating peer number %u with identity %s\n",
                    num,
                    GNUNET_i2s (peer));
        GNUNET_TRANSPORT_application_validate (ah,
                                               peer,
                                               nt,
                                               addr);
        GNUNET_free (peer);
        GNUNET_free (addr);
      }
    }
  }
  cps->con_num = con_num;
}


/**
 * Callback from start peer cmd for signaling a peer got connected.
 *
 */
static void *
notify_connect (struct GNUNET_TESTING_Interpreter *is,
                const struct GNUNET_PeerIdentity *peer)
{
  const struct GNUNET_TESTING_Command *cmd;
  struct ConnectPeersState *cps;
  struct GNUNET_PeerIdentity *peer_connection;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  unsigned int num;
  unsigned int con_num;
  void *ret = NULL;

  cmd = GNUNET_TESTING_interpreter_lookup_command_all (is,
                                                       "connect-peers");
  cps = cmd->cls;
  con_num = cps->con_num_notified;
  for (pos_connection = cps->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    num = GNUNET_TESTING_calculate_num (pos_connection, cps->topology);
    peer_connection = GNUNET_TESTING_get_pub_key (num, cps->tl_system);
    if (0 == GNUNET_memcmp (peer,
                            peer_connection))
      cps->con_num_notified++;
    GNUNET_free (peer_connection);
  }
  if (cps->con_num == con_num)
    cps->additional_connects_notified++;

  if (cps->con_num + cps->additional_connects == cps->con_num_notified
      + cps->additional_connects_notified)
  {
    GNUNET_TESTING_async_finish (&cps->ac);
  }
  return ret;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
connect_peers_cleanup (void *cls)
{
  struct ConnectPeersState *cps = cls;

  GNUNET_free (cps);
}


/**
 * This function prepares an array with traits.
 *
 */
enum GNUNET_GenericReturnValue
connect_peers_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  struct StartPeerState *cps = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "state",
      .ptr = (const void *) cps,
    },
    GNUNET_TESTING_trait_end ()
  };
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Function to get the trait with the struct ConnectPeersState.
 *
 * @param[out] sps struct ConnectPeersState.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
enum GNUNET_GenericReturnValue
GNUNET_TRANSPORT_get_trait_connect_peer_state (
  const struct GNUNET_TESTING_Command *cmd,
  struct ConnectPeersState **cps)
{
  return cmd->traits (cmd->cls,
                      (const void **) cps,
                      "state",
                      (unsigned int) 0);
}


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
GNUNET_TRANSPORT_cmd_connect_peers (const char *label,
                                    const char *start_peer_label,
                                    const char *create_label,
                                    uint32_t num,
                                    struct GNUNET_TESTING_NetjailTopology *
                                    topology,
                                    unsigned int additional_connects)
{
  struct ConnectPeersState *cps;

  cps = GNUNET_new (struct ConnectPeersState);
  cps->start_peer_label = start_peer_label;
  cps->num = num;
  cps->create_label = create_label;
  cps->topology = topology;
  cps->notify_connect = notify_connect;
  cps->additional_connects = additional_connects;

  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = cps,
      .label = label,
      .run = &connect_peers_run,
      .ac = &cps->ac,
      .cleanup = &connect_peers_cleanup,
      .traits = &connect_peers_traits
    };

    return cmd;
  }
}
