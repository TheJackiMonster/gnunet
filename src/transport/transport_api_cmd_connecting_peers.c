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

  struct GNUNET_TESTING_Interpreter *is;
};


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
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv_key = GNUNET_new (struct
                                                               GNUNET_CRYPTO_EddsaPrivateKey);
  struct GNUNET_CRYPTO_EddsaPublicKey *pub_key = GNUNET_new (struct
                                                             GNUNET_CRYPTO_EddsaPublicKey);
  ;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  // const struct GNUNET_TESTING_Command *peer2_cmd;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;
  struct GNUNET_PeerIdentity *peer = GNUNET_new (struct GNUNET_PeerIdentity);
  char *addr;
  // struct GNUNET_TIME_Absolute t;
  char *hello;
  // size_t *hello_size;
  enum GNUNET_NetworkType nt = 0;
  char *peer_id;
  struct GNUNET_PeerIdentity *id;
  struct GNUNET_PeerIdentity *other = GNUNET_new (struct GNUNET_PeerIdentity);
  uint32_t num;

  cps->is = is;
  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_application_handle (peer1_cmd,
                                                 &ah);

  GNUNET_TRANSPORT_get_trait_hello (peer1_cmd,
                                    &hello);

  GNUNET_TRANSPORT_get_trait_peer_id (peer1_cmd,
                                      &id);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          cps->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  if (2 == cps->num)
    num = 1;
  else
    num = 2;


  // if (strstr (hello, "60002") != NULL)
  if (2 == num)
  {
    addr = "tcp-192.168.15.2:60002";
    peer_id = "F2F3X9G1YNCTXKK7A4J6M4ZM4BBSKC9DEXZVHCWQ475M0C7PNWCG";
  }
  else
  {
    addr = "tcp-192.168.15.1:60002";
    peer_id = "4TTC9WBSVP9RJT6DVEZ7E0TDW7TQXC11NR1EMR2F8ARS87WZ2730";
  }

  priv_key = GNUNET_TESTING_hostkey_get (tl_system,
                                         num,
                                         other);

  GNUNET_CRYPTO_eddsa_key_get_public (priv_key,
                                      pub_key);

  GNUNET_CRYPTO_eddsa_public_key_from_string (peer_id,
                                              strlen (peer_id),
                                              &peer->public_key);

  peer->public_key = *pub_key;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "\nnum: %u\n peer_id: %s\n pub_key %s\n",
       num,
       peer_id,
       GNUNET_CRYPTO_eddsa_public_key_to_string (pub_key));

  cps->id = peer;

  // TODO This does not work, because the other peer is running in another local loop. We need to message between different local loops. For now we will create the hello manually with the known information about the other local peers.
  // ---------------------------------------------
  /*peer2_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->peer2_label);
  GNUNET_TRANSPORT_get_trait_peer_id (peer2_cmd,
                                    &id);
  GNUNET_TRANSPORT_get_trait_hello (peer2_cmd,
                                  &hello);
  GNUNET_TRANSPORT_get_trait_hello_size (peer2_cmd,
                                       &hello_size);

  addr = GNUNET_HELLO_extract_address (hello,
                                       *hello_size,
                                       id,
                                       &nt,
                                       &t);*/

  // ----------------------------------------------


  GNUNET_TRANSPORT_application_validate (ah,
                                         peer,
                                         nt,
                                         addr);
}


/**
 * The finish function of this cmd will check if the peer we are trying to connect to is in the connected peers map of the start peer cmd for this peer.
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
  int node_number;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->is,
                                                         cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map (peer1_cmd,
                                                  &connected_peers_map);

  node_number = 1;
  GNUNET_CRYPTO_hash (&node_number, sizeof(node_number), &hc);

  // TODO we need to store with a key identifying the netns node in the future. For now we have only one connecting node.
  memcpy (key,
          &hc,
          sizeof (*key));
  ret = GNUNET_CONTAINER_multishortmap_contains (connected_peers_map,
                                                 key);

  if (GNUNET_YES == ret)
  {
    cont (cont_cls);
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
connect_peers_cleanup (void *cls)
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
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers (const char *label,
                                    const char *start_peer_label,
                                    const char *create_label,
                                    uint32_t num)
{
  struct ConnectPeersState *cps;

  cps = GNUNET_new (struct ConnectPeersState);
  cps->start_peer_label = start_peer_label;
  cps->num = num;
  cps->create_label = create_label;


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
