/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 GNUnet e.V.

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
 * @file testing/testing.c
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop a peer/service
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases (or internal use of the testbed).
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "testing_api_topology.h"
#include "testing_cmds.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "testing-api", __VA_ARGS__)

#define CONNECT_ADDRESS_TEMPLATE "%s-192.168.15.%u"

#define ROUTER_CONNECT_ADDRESS_TEMPLATE "%s-92.68.150.%u"

#define KNOWN_CONNECT_ADDRESS_TEMPLATE "%s-92.68.151.%u"

#define PREFIX_TCP "tcp"

#define PREFIX_UDP "udp"

#define PREFIX_TCP_NATTED "tcp_natted"

#define PREFIX_UDP_NATTED "udp_natted"


/**
 * A helper function to log information about individual nodes.
 *
 * @param cls This is not used actually.
 * @param id The key of this value in the map.
 * @param value A struct GNUNET_TESTING_NetjailNode which holds information about a node.
 * return GNUNET_YES to continue with iterating, GNUNET_NO otherwise.
 */
static int
log_nodes (void *cls,
           const struct GNUNET_ShortHashCode *id,
           void *value)
{
  struct GNUNET_TESTING_NetjailNode *node = value;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_AddressPrefix *pos_prefix;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "plugin: %s space: %u node: %u global: %u\n",
       node->plugin,
       node->namespace_n,
       node->node_n,
       node->is_global);

  for (pos_connection = node->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "namespace_n: %u node_n: %u node_type: %u\n",
         pos_connection->namespace_n,
         pos_connection->node_n,
         pos_connection->node_type);

    for (pos_prefix = pos_connection->address_prefixes_head; NULL != pos_prefix;
         pos_prefix =
           pos_prefix->next)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "prefix: %s\n",
           pos_prefix->address_prefix);
    }
  }
  return GNUNET_YES;
}


/**
 * Helper function to log information about namespaces.
 *
 * @param cls This is not used actually.
 * @param id The key of this value in the map.
 * @param value A struct GNUNET_TESTING_NetjailNamespace which holds information about a subnet.
 * return GNUNET_YES to continue with iterating, GNUNET_NO otherwise.
 */
static int
log_namespaces (void *cls,
                const struct GNUNET_ShortHashCode *id,
                void *value)
{
  struct GNUNET_TESTING_NetjailNamespace *namespace = value;

  GNUNET_CONTAINER_multishortmap_iterate (namespace->nodes,
                                          &log_nodes,
                                          NULL);
  return GNUNET_YES;
}


/**
 * Helper function to log the configuration in case of a problem with configuration.
 *
 * @param topology The struct GNUNET_TESTING_NetjailTopology holding the configuration information.
 */
static int
log_topo (const struct GNUNET_TESTING_NetjailTopology *topology)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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


/**
 * This function extracts information about a specific node from the topology.
 *
 * @param num The global index number of the node.
 * @param[out] node_ex A struct GNUNET_TESTING_NetjailNode with information about the node.
 * @param[out] namespace_ex A struct GNUNET_TESTING_NetjailNamespace with information about the namespace
               the node is in or NULL, if the node is a global node.
 * @param[out] node_connections_ex A struct GNUNET_TESTING_NodeConnection with information about the connection
               of this node to other nodes.
*/
static void
get_node_info (unsigned int num,
               const struct GNUNET_TESTING_NetjailTopology *topology,
               struct GNUNET_TESTING_NetjailNode **node_ex,
               struct GNUNET_TESTING_NetjailNamespace **namespace_ex,
               struct GNUNET_TESTING_NodeConnection **node_connections_ex)
{
  struct GNUNET_ShortHashCode hkey;
  struct GNUNET_HashCode hc;
  unsigned int namespace_n;
  unsigned int node_m;
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  struct GNUNET_TESTING_NodeConnection *node_connections = NULL;

  log_topo (topology);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "num: %u \n",
       num);
  if (topology->nodes_x >= num)
  {

    GNUNET_CRYPTO_hash (&num, sizeof(num), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    node = GNUNET_CONTAINER_multishortmap_get (topology->map_globals,
                                               &hkey);
    if (NULL != node)
    {
      *node_ex = node;
      *node_connections_ex = node->node_connections_head;
    }
  }
  else
  {
    namespace_n = (unsigned int) ceil ((double) (num - topology->nodes_x)
                                       / topology->nodes_m);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ceil num: %u nodes_x: %u nodes_m: %u namespace_n: %u\n",
         num,
         topology->nodes_x,
         topology->nodes_m,
         namespace_n);
    GNUNET_CRYPTO_hash (&namespace_n, sizeof(namespace_n), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    namespace = GNUNET_CONTAINER_multishortmap_get (topology->map_namespaces,
                                                    &hkey);
    if (NULL != namespace)
    {
      node_m = num - topology->nodes_x - topology->nodes_m * (namespace_n - 1);
      GNUNET_CRYPTO_hash (&node_m, sizeof(node_m), &hc);
      memcpy (&hkey,
              &hc,
              sizeof (hkey));
      node = GNUNET_CONTAINER_multishortmap_get (namespace->nodes,
                                                 &hkey);
      if (NULL != node)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "node additional_connects: %u %p\n",
             node->additional_connects,
             node);
        node_connections = node->node_connections_head;
      }
      *node_ex = node;
      *namespace_ex = namespace;
      *node_connections_ex = node_connections;
    }
  }
}


/**
 * Get a node from the topology.
 *
 * @param num The specific node we want the connections for.
 * @param topology The topology we get the connections from.
 * @return The connections of the node.
 */
struct GNUNET_TESTING_NetjailNode *
GNUNET_TESTING_get_node (unsigned int num,
                         struct GNUNET_TESTING_NetjailTopology *topology)
{
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  struct GNUNET_TESTING_NodeConnection *node_connections;

  get_node_info (num, topology, &node, &namespace, &node_connections);

  return node;

}


/**
 * Get the connections to other nodes for a specific node.
 *
 * @param num The specific node we want the connections for.
 * @param topology The topology we get the connections from.
 * @return The connections of the node.
 */
struct GNUNET_TESTING_NodeConnection *
GNUNET_TESTING_get_connections (unsigned int num,
                                const struct
                                GNUNET_TESTING_NetjailTopology *topology)
{
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  struct GNUNET_TESTING_NodeConnection *node_connections;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "get_connections\n");

  get_node_info (num, topology, &node, &namespace, &node_connections);

  return node_connections;
}


static int
free_value_cb (void *cls,
               const struct GNUNET_ShortHashCode *key,
               void *value)
{
  (void) cls;

  GNUNET_free (value);

  return GNUNET_OK;
}


static int
free_subnets_cb (void *cls,
                 const struct GNUNET_ShortHashCode *key,
                 void *value)
{
  struct GNUNET_TESTING_NetjailSubnet *subnet = value;
  (void) cls;

  GNUNET_CONTAINER_multishortmap_iterate (subnet->peers,
                                          &free_value_cb,
                                          NULL);

  GNUNET_free (subnet);

  return GNUNET_OK;
}


static int
free_carriers_cb (void *cls,
                  const struct GNUNET_ShortHashCode *key,
                  void *value)
{
  struct GNUNET_TESTING_NetjailCarrier *carrier = value;
  (void) cls;

  GNUNET_CONTAINER_multishortmap_iterate (carrier->peers,
                                          &free_value_cb,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_iterate (carrier->subnets,
                                          &free_subnets_cb,
                                          NULL);

  GNUNET_free (carrier);

  return GNUNET_OK;
}


/**
 * Deallocate memory of the struct GNUNET_TESTING_NetjailTopology.
 *
 * @param topology The GNUNET_TESTING_NetjailTopology to be deallocated.
 */
void
GNUNET_TESTING_free_topology (struct GNUNET_TESTING_NetjailTopology *topology)
{
  GNUNET_CONTAINER_multishortmap_iterate (topology->backbone_peers,
                                          &free_value_cb,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_iterate (topology->carriers,
                                          &free_carriers_cb,
                                          NULL);
  GNUNET_free (topology->plugin);
  GNUNET_free (topology);
}


unsigned int
GNUNET_TESTING_calculate_num (
  struct GNUNET_TESTING_NodeConnection *node_connection,
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


/**
 * Get the address for a specific communicator from a connection.
 *
 * @param connection The connection we like to have the address from.
 * @param prefix The communicator protocol prefix.
 * @return The address of the communicator.
 */
char *
GNUNET_TESTING_get_address (struct GNUNET_TESTING_NodeConnection *connection,
                            const char *prefix)
{
  struct GNUNET_TESTING_NetjailNode *node;
  char *addr;
  const char *template;
  unsigned int node_n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "get address prefix: %s node_n: %u\n",
       prefix,
       connection->node_n);

  node = connection->node;
  if (connection->namespace_n == node->namespace_n)
  {
    template = CONNECT_ADDRESS_TEMPLATE;
    node_n = connection->node_n;
  }
  else if (0 == connection->namespace_n)
  {
    template = KNOWN_CONNECT_ADDRESS_TEMPLATE;
    node_n = connection->node_n;
  }
  else if (1 == connection->node_n)
  {
    template = ROUTER_CONNECT_ADDRESS_TEMPLATE;
    node_n = connection->namespace_n;
  }
  else
  {
    return NULL;
  }

  if (0 == strcmp (PREFIX_TCP, prefix) ||
      0 == strcmp (PREFIX_UDP, prefix) ||
      0 == strcmp (PREFIX_UDP_NATTED, prefix) ||
      0 == strcmp (PREFIX_TCP_NATTED, prefix))
  {
    GNUNET_asprintf (&addr,
                     template,
                     prefix,
                     node_n);
  }
  else
  {
    GNUNET_assert (0);
  }

  return addr;
}


/**
 * Get the number of unintentional additional connections the node waits for.
 *
 * @param num The specific node we want the additional connects for.
 * @return The number of additional connects
 */
unsigned int
GNUNET_TESTING_get_additional_connects (unsigned int num,
                                        struct GNUNET_TESTING_NetjailTopology *
                                        topology)
{
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  struct GNUNET_TESTING_NodeConnection *node_connections;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "get_additional_connects\n");

  get_node_info (num, topology, &node, &namespace, &node_connections);

  if (NULL == node)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "No info found for node %d\n", num);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "node additional_connects for node %p\n",
       node);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "node additional_connects: %u\n",
       node->additional_connects);

  return node->additional_connects;
}


char *
GNUNET_TESTING_get_plugin_from_topo (
  struct GNUNET_TESTING_NetjailTopology *njt,
  const char *my_node_id)
{
  return njt->plugin;
}


static void
create_subnet_peers (struct GNUNET_CONFIGURATION_Handle *cfg,
                     struct GNUNET_TESTING_NetjailTopology *topology,
                     struct GNUNET_TESTING_NetjailSubnet *subnet)
{
  struct GNUNET_HashCode hc = {0};
  subnet->peers = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);

  for (int i = 0; i < subnet->number_peers; i++)
  {
    struct GNUNET_ShortHashCode hkey;
    struct GNUNET_TESTING_NetjailSubnetPeer *subnet_peer = GNUNET_new (struct
                                                                       GNUNET_TESTING_NetjailSubnetPeer);

    topology->total++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Subnet peers -> Number of nodes: %u\n",
         topology->total);
    GNUNET_CRYPTO_hash (&topology->total, sizeof(topology->total), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    GNUNET_CONTAINER_multishortmap_put (subnet->peers,
                                        &hkey,
                                        subnet_peer,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
}


static void
create_subnets (struct GNUNET_CONFIGURATION_Handle *cfg,
                struct GNUNET_TESTING_NetjailTopology *topology,
                struct GNUNET_TESTING_NetjailCarrier *carrier)
{
  struct GNUNET_HashCode hc = {0};
  carrier->subnets = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);

  for (int i = 0; i < carrier->number_subnets; i++)
  {
    struct GNUNET_ShortHashCode hkey;
    struct GNUNET_TESTING_NetjailSubnet *subnet = GNUNET_new (struct
                                                              GNUNET_TESTING_NetjailSubnet);
    char *section;

    topology->total++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Subnets -> Number of nodes: %u\n",
         topology->total);
    subnet->number = topology->total;
    subnet->index = i;
    GNUNET_CRYPTO_hash (&topology->total, sizeof(topology->total), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    GNUNET_CONTAINER_multishortmap_put (carrier->subnets,
                                        &hkey,
                                        subnet,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    GNUNET_asprintf (&section, "CARRIER-%u-SUBNET-%u", carrier->index, i);
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                            section,
                                                            "SUBNET_PEERS",
                                                            (unsigned long
                                                             long *) &subnet->
                                                            number_peers))
    {
      subnet->number_peers = topology->default_subnet_peers;
    }

    create_subnet_peers (cfg, topology, subnet);

    GNUNET_free (section);
  }
}


static void
create_peers (struct GNUNET_CONFIGURATION_Handle *cfg,
              struct GNUNET_TESTING_NetjailTopology *topology,
              struct GNUNET_TESTING_NetjailCarrier *carrier)
{
  struct GNUNET_HashCode hc = {0};
  carrier->peers = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);

  for (int i = 0; i < carrier->number_peers; i++)
  {
    struct GNUNET_ShortHashCode hkey;
    struct GNUNET_TESTING_NetjailCarrierPeer *peer = GNUNET_new (struct
                                                                 GNUNET_TESTING_NetjailCarrierPeer);

    topology->total++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Carrier peers -> Number of nodes: %u\n",
         topology->total);
    peer->number = topology->total;
    GNUNET_CRYPTO_hash (&topology->total, sizeof(topology->total), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    GNUNET_CONTAINER_multishortmap_put (carrier->peers,
                                        &hkey,
                                        peer,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
}


struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_string_ (const char *input)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_HashCode hc = {0};
  struct GNUNET_TESTING_NetjailTopology *topology = GNUNET_new (struct
                                                                GNUNET_TESTING_NetjailTopology);

  topology->backbone_peers
    = GNUNET_CONTAINER_multishortmap_create (1,
                                             GNUNET_NO);
  topology->carriers
    = GNUNET_CONTAINER_multishortmap_create (1,
                                             GNUNET_NO);
  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());
  GNUNET_assert (NULL != topology->carriers);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (cfg,
                                        input,
                                        strlen (input),
                                        NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to parse configuration.\n"));
    GNUNET_CONFIGURATION_destroy (cfg);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "DEFAULTS",
                                             "SUBNETS",
                                             &topology->default_subnets))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Missing default SUBNETS!\n");
    return NULL;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                          "DEFAULTS",
                                                          "TESTBED_PLUGIN",
                                                          &topology->plugin))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Missing default TESTBED_PLUGIN!\n");
    return NULL;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "DEFAULTS",
                                                          "CARRIER_PEERS",
                                                          &(topology->
                                                            default_carrier_peers)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Missing default CARRIER_PEERS!\n");
    return NULL;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "DEFAULTS",
                                                          "SUBNET_PEERS",
                                                          &(topology->
                                                            default_subnet_peers)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Missing default SUBNET_PEERS!\n");
    return NULL;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "BACKBONE",
                                                          "CARRIERS",
                                                          &(topology->
                                                            num_carriers)))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No carrier configured!\n");
    return NULL;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "BACKBONE",
                                                          "BACKBONE_PEERS",
                                                          &(topology->
                                                            num_backbone_peers))
      )
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No backbone peers configured!\n");
    return NULL;
  }
  for (int i = 0; i < topology->num_backbone_peers; i++)
  {
    struct GNUNET_TESTING_NetjailBackbonePeer *peer = GNUNET_new (struct
                                                                  GNUNET_TESTING_NetjailBackbonePeer);
    struct GNUNET_ShortHashCode hkey;

    topology->total++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Backbone peers -> Number of nodes: %u\n",
         topology->total);
    peer->number = topology->total;
    GNUNET_CRYPTO_hash (&topology->total, sizeof(topology->total), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    GNUNET_CONTAINER_multishortmap_put (topology->backbone_peers,
                                        &hkey,
                                        peer,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  GNUNET_assert (NULL != topology->carriers);
  for (int i = 0; i < topology->num_carriers; i++)
  {
    struct GNUNET_TESTING_NetjailCarrier *carrier = GNUNET_new (struct
                                                                GNUNET_TESTING_NetjailCarrier);
    struct GNUNET_ShortHashCode hkey;
    char *section;

    topology->total++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Carrier -> Number of nodes: %u\n",
         topology->total);
    carrier->number = topology->total;
    GNUNET_CRYPTO_hash (&topology->total, sizeof(topology->total), &hc);
    memcpy (&hkey,
            &hc,
            sizeof (hkey));
    GNUNET_assert (NULL != topology->carriers);
    GNUNET_CONTAINER_multishortmap_put (topology->carriers,
                                        &hkey,
                                        carrier,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    GNUNET_asprintf (&section, "CARRIER-%u", i);
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                            section,
                                                            "SUBNETS",
                                                            (unsigned long
                                                             long *) &carrier->
                                                            number_subnets))
    {
      carrier->number_subnets = topology->default_subnets;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Carrier -> Default number of subnets: %u\n",
           carrier->number_subnets);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Carrier -> number of subnets: %u\n",
         carrier->number_subnets);
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                            section,
                                                            "CARRIER_PEERS",
                                                            (unsigned long
                                                             long *) &carrier->
                                                            number_peers))
    {
      carrier->number_peers = topology->default_carrier_peers;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Carrier -> Default number of peers: %u\n",
           carrier->number_peers);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Carrier -> Default number of peers: %u\n",
         carrier->number_peers);
    create_peers  (cfg, topology, carrier);
    create_subnets (cfg, topology, carrier);

    GNUNET_free (section);
  }

  GNUNET_free (cfg);

  return topology;
}


GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS (
  GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT,
  GNUNET_TESTING)


/* end of netjail.c */
