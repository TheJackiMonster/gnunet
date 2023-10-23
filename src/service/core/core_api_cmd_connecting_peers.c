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
#include "gnunet_transport_core_service.h"

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
  struct GNUNET_TESTING_ConnectPeersState *cps = cls;
  const struct GNUNET_TESTING_StartPeerState *sps;
  const struct GNUNET_TESTING_Command *system_cmd;
  const struct GNUNET_TESTING_System *tl_system;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_PeerIdentity *peer;
  enum GNUNET_NetworkType nt = 0;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_AddressPrefix *pos_prefix;
  const enum GNUNET_GenericReturnValue *broadcast;
  unsigned int con_num = 0;
  uint32_t num;
  char *addr;
  char *addr_and_port;
  char *emsg = NULL;

  cps->is = is;
  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         cps->start_peer_label);
  GNUNET_TESTING_get_trait_broadcast (peer1_cmd,
                                        &broadcast);
  GNUNET_TESTING_get_trait_state (peer1_cmd,
                                    &sps);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          cps->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  cps->tl_system = tl_system;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "cps->num: %u \n",
       cps->num);
  

  cps->ah = GNUNET_TRANSPORT_application_init (sps->cfg);
  if (NULL == cps->ah)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to initialize the TRANSPORT application suggestion client handle for peer `%s': `%s'\n",
         sps->cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

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
        char *natted_p = strstr (pos_prefix->address_prefix, "_");

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "0 validating peer number %s %s %s\n",
                    natted_p,
                    pos_prefix->address_prefix,
                    addr);
        if (0 == GNUNET_memcmp (pos_prefix->address_prefix, "udp"))
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "validating memcmp\n");
        if (GNUNET_YES == *broadcast)
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "validating broadcast\n");
        if ((0 == GNUNET_memcmp (pos_prefix->address_prefix, "udp")) &&
            (GNUNET_YES == *broadcast) )
          GNUNET_asprintf (&addr_and_port,
                           "%s:2086",
                           addr);
        else if (NULL == natted_p)
          GNUNET_asprintf (&addr_and_port,
                           "%s:60002",
                           addr);
        else if (NULL != natted_p)
        {
          char *prefix;
          char *rest;
          char *address;

          prefix = strtok (addr, "_");
          rest = strtok (NULL, "_");
          strtok (rest, "-");
          address = strtok (NULL, "-");

          GNUNET_asprintf (&addr_and_port,
                           "%s-%s:0",
                           prefix,
                           address);

        }
        peer = GNUNET_TESTING_get_peer (num, tl_system);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "validating peer number %u with identity %s and address %s %u %s and handle %p\n",
                    num,
                    GNUNET_i2s (peer),
                    addr_and_port,
                    *broadcast,
                    pos_prefix->address_prefix,
                    cps->ah);
        GNUNET_TRANSPORT_application_validate ((struct
                                                GNUNET_TRANSPORT_ApplicationHandle
                                                *) cps->ah,
                                               peer,
                                               nt,
                                               addr_and_port);
        GNUNET_free (peer);
        GNUNET_free (addr);
        GNUNET_free (addr_and_port);
      }
    }
  }
  cps->con_num = con_num;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
connect_peers_cleanup (void *cls)
{
  struct GNUNET_TESTING_ConnectPeersState *cps = cls;

  GNUNET_free (cps->connected_peers_map);
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
  struct GNUNET_TESTING_ConnectPeersState *cps = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_connect_peer_state ((const void *) cps),
    GNUNET_TESTING_trait_end ()
  };
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect_peers (const char *label,
                                    const char *start_peer_label,
                                    const char *create_label,
                                    uint32_t num,
                                    struct GNUNET_TESTING_NetjailTopology *
                                    topology,
                                    unsigned int additional_connects,
                                    unsigned int wait_for_connect,
                                    struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_TESTING_ConnectPeersState *cps;
  unsigned int node_additional_connects;
  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map =
    GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
  unsigned int i;
  
  node_additional_connects = GNUNET_TESTING_get_additional_connects (num,
                                                                     topology);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "global: %u and local: %u additional_connects\n",
       additional_connects,
       node_additional_connects);

  if (0 != node_additional_connects)
    additional_connects = node_additional_connects;

  cps = GNUNET_new (struct GNUNET_TESTING_ConnectPeersState);
  cps->start_peer_label = start_peer_label;
  cps->num = num;
  cps->create_label = create_label;
  cps->topology = topology;
  cps->additional_connects = additional_connects;
  cps->wait_for_connect = wait_for_connect;
  cps->connected_peers_map = connected_peers_map;

  if (NULL != handlers)
  {
    for (i = 0; NULL != handlers[i].cb; i++)
      ;
    cps->handlers = GNUNET_new_array (i + 1,
                                      struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (cps->handlers,
                   handlers,
                   i * sizeof(struct GNUNET_MQ_MessageHandler));
  }

  if (GNUNET_YES == wait_for_connect)
    return GNUNET_TESTING_command_new (cps,
                                       label,
                                       &connect_peers_run,
                                       &connect_peers_cleanup,
                                       &connect_peers_traits,
                                       &cps->ac);
  else
    return GNUNET_TESTING_command_new (cps,
                                       label,
                                       &connect_peers_run,
                                       &connect_peers_cleanup,
                                       &connect_peers_traits,
                                       NULL);
}
