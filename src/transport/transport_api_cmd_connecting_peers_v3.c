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

#define CONNECT_ADDRESS_TEMPLATE_TCP "tcp-192.168.15.%u:60002"

#define CONNECT_ADDRESS_TEMPLATE_UDP "udp-192.168.15.%u:60002"

#define ROUTER_CONNECT_ADDRESS_TEMPLATE_TCP "tcp-92.68.150.%u:60002"

#define ROUTER_CONNECT_ADDRESS_TEMPLATE_UDP "udp-92.68.150.%u:60002"

#define GLOBAL_CONNECT_ADDRESS_TEMPLATE_TCP "tcp-92.68.151.%u:60002"

#define GLOBAL_CONNECT_ADDRESS_TEMPLATE_UDP "udp-92.68.151.%u:60002"

#define PREFIX_TCP "tcp"

#define PREFIX_UDP "udp"

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

  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Number of connections.
   */
  unsigned int con_num;
};


static struct GNUNET_PeerIdentity *
get_pub_key (unsigned int num, struct GNUNET_TESTING_System *tl_system)
{
  struct GNUNET_PeerIdentity *peer = GNUNET_new (struct GNUNET_PeerIdentity);
  struct GNUNET_CRYPTO_EddsaPublicKey *pub_key = GNUNET_new (struct
                                                             GNUNET_CRYPTO_EddsaPublicKey);
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv_key = GNUNET_new (struct
                                                               GNUNET_CRYPTO_EddsaPrivateKey);

  priv_key = GNUNET_TESTING_hostkey_get (tl_system,
                                         num,
                                         peer);

  GNUNET_CRYPTO_eddsa_key_get_public (priv_key,
                                      pub_key);
  peer->public_key = *pub_key;
  return peer;
}


static int
log_nodes (void *cls, const struct GNUNET_ShortHashCode *id, void *value)
{
  struct GNUNET_TESTING_NetjailNode *node = value;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_ADDRESS_PREFIX *pos_prefix;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "plugin: %s space: %u node: %u global: %u\n",
       node->plugin,
       node->namespace_n,
       node->node_n,
       node->is_global);

  for (pos_connection = node->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {

    LOG (GNUNET_ERROR_TYPE_ERROR,
         "namespace_n: %u node_n: %u node_type: %u\n",
         pos_connection->namespace_n,
         pos_connection->node_n,
         pos_connection->node_type);

    for (pos_prefix = pos_connection->address_prefixes_head; NULL != pos_prefix;
         pos_prefix =
           pos_prefix->next)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "prefix: %s\n",
           pos_prefix->address_prefix);
    }
  }
  return GNUNET_YES;
}


static int
log_namespaces (void *cls, const struct GNUNET_ShortHashCode *id, void *value)
{
  struct GNUNET_TESTING_NetjailNamespace *namespace = value;
  struct GNUNET_TESTING_NetjailRouter *router = namespace->router;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "router_tcp: %u router_udp: %u spaces: %u\n",
       router->tcp_port,
       router->udp_port,
       namespace->namespace_n);
  GNUNET_CONTAINER_multishortmap_iterate (namespace->nodes, &log_nodes, NULL);
  return GNUNET_YES;
}


static int
log_topo (struct GNUNET_TESTING_NetjailTopology *topology)
{
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "plugin: %s spaces: %u nodes: %u known: %u\n",
       topology->plugin,
       topology->namespaces_n,
       topology->nodes_m,
       topology->nodes_x);

  GNUNET_CONTAINER_multishortmap_iterate (topology->map_namespaces,
                                          log_namespaces, NULL);
  GNUNET_CONTAINER_multishortmap_iterate (topology->map_globals, &log_nodes,
                                          NULL);
  return GNUNET_YES;
}


static struct GNUNET_TESTING_NodeConnection *
get_connections (unsigned int num, struct
                 GNUNET_TESTING_NetjailTopology *topology)
{
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_ShortHashCode *hkey;
  struct GNUNET_HashCode hc;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  unsigned int namespace_n, node_m;

  log_topo (topology);

  hkey = GNUNET_new (struct GNUNET_ShortHashCode);
  if (topology->nodes_x >= num)
  {

    GNUNET_CRYPTO_hash (&num, sizeof(num), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    node = GNUNET_CONTAINER_multishortmap_get (topology->map_globals,
                                               hkey);
  }
  else
  {
    namespace_n = (unsigned int) floor ((num - topology->nodes_x)
                                        / topology->nodes_m);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "num: %u nodes_x: %u nodes_m: %u namespace_n: %u\n",
         num,
         topology->nodes_x,
         topology->nodes_m,
         namespace_n);
    hkey = GNUNET_new (struct GNUNET_ShortHashCode);
    GNUNET_CRYPTO_hash (&namespace_n, sizeof(namespace_n), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    namespace = GNUNET_CONTAINER_multishortmap_get (topology->map_namespaces,
                                                    hkey);
    node_m = num - topology->nodes_x - topology->nodes_m * (namespace_n - 1);
    hkey = GNUNET_new (struct GNUNET_ShortHashCode);
    GNUNET_CRYPTO_hash (&node_m, sizeof(node_m), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    node = GNUNET_CONTAINER_multishortmap_get (namespace->nodes,
                                               hkey);
  }


  return node->node_connections_head;
}


static unsigned int
calculate_num (struct GNUNET_TESTING_NodeConnection *node_connection,
               struct GNUNET_TESTING_NetjailTopology *topology)
{
  unsigned int n, m, num;

  n = node_connection->namespace_n;
  m = node_connection->node_n;

  if (0 == n)
    num = m;
  else
    num = (n - 1) * topology->nodes_m + m + topology->nodes_x;

  return num;
}


static char *
get_address (struct GNUNET_TESTING_NodeConnection *connection,
             char *prefix)
{
  struct GNUNET_TESTING_NetjailNode *node;
  char *addr;

  node = connection->node;
  if (connection->namespace_n == node->namespace_n)
  {
    if (0 == strcmp (PREFIX_TCP, prefix))
    {

      GNUNET_asprintf (&addr,
                       CONNECT_ADDRESS_TEMPLATE_TCP,
                       connection->node_n);
    }
    else if (0 == strcmp (PREFIX_UDP, prefix))
    {
      GNUNET_asprintf (&addr,
                       CONNECT_ADDRESS_TEMPLATE_UDP,
                       connection->node_n);
    }
    else
    {
      GNUNET_break (0);
    }
  }
  else
  {
    if (0 == strcmp (PREFIX_TCP, prefix))
    {

      GNUNET_asprintf (&addr,
                       ROUTER_CONNECT_ADDRESS_TEMPLATE_TCP,
                       connection->namespace_n);
    }
    else if (0 == strcmp (PREFIX_UDP, prefix))
    {
      GNUNET_asprintf (&addr,
                       ROUTER_CONNECT_ADDRESS_TEMPLATE_UDP,
                       connection->namespace_n);
    }
    else
    {
      GNUNET_break (0);
    }
  }

  return addr;
}


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
  struct GNUNET_TESTING_ADDRESS_PREFIX *pos_prefix;
  unsigned int con_num = 0;

  cps->is = is;
  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_application_handle_v2 (peer1_cmd,
                                                    &ah);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          cps->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  cps->tl_system = tl_system;

  cps->node_connections_head = get_connections (cps->num, cps->topology);

  for (pos_connection = cps->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    con_num++;
    num = calculate_num (pos_connection, cps->topology);
    for (pos_prefix = pos_connection->address_prefixes_head; NULL != pos_prefix;
         pos_prefix =
           pos_prefix->next)
    {

      LOG (GNUNET_ERROR_TYPE_ERROR,
           "prefix: %s\n",
           pos_prefix->address_prefix);

      addr = get_address (pos_connection, pos_prefix->address_prefix);

      peer = get_pub_key (num, tl_system);

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

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->is,
                                                         cps->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map_v2 (peer1_cmd,
                                                     &connected_peers_map);

  for (pos_connection = cps->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    num = calculate_num (pos_connection, cps->topology);
    peer = get_pub_key (num, cps->tl_system);
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

  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = cps,
      .label = label,
      .run = &connect_peers_run,
      .ac = &cps->ac,
      .cleanup = &connect_peers_cleanup
    };

    return cmd;
  }
}
