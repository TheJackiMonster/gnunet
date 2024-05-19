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
 * @brief API for writing an interpreter to test GNUnet components
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef NETJAIL_H
#define NETJAIL_H

#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"


/**
 * Router of a netjail subnet.
 */
struct GNUNET_TESTING_NetjailRouter
{
  /**
   * Will tcp be forwarded?
   */
  unsigned int tcp_port;

  /**
   * Will udp be forwarded?
   */
  unsigned int udp_port;
};


/**
 * Enum for the different types of nodes.
 */
enum GNUNET_TESTING_NodeType
{
  /**
   * Node in a subnet.
   */
  GNUNET_TESTING_SUBNET_NODE,

  /**
   * Global known node.
   */
  GNUNET_TESTING_GLOBAL_NODE
};

/**
 * Protocol address prefix für a connection between nodes.
 */
struct GNUNET_TESTING_AddressPrefix
{
  /**
   * Pointer to the previous prefix in the DLL.
   */
  struct GNUNET_TESTING_AddressPrefix *prev;

  /**
   * Pointer to the next prefix in the DLL.
   */
  struct GNUNET_TESTING_AddressPrefix *next;

  /**
   * The address prefix.
   */
  char *address_prefix;
};


/**
 * Node in a netjail topology.
 */
struct GNUNET_TESTING_NetjailNode;

/**
 * Connection to another node.
 */
struct GNUNET_TESTING_NodeConnection
{
  /**
   * Pointer to the previous connection in the DLL.
   */
  struct GNUNET_TESTING_NodeConnection *prev;

  /**
   * Pointer to the next connection in the DLL.
   */
  struct GNUNET_TESTING_NodeConnection *next;

  /**
   * The number of the subnet of the node this connection points to. This is 0,
   * if the node is a global known node.
   */
  unsigned int namespace_n;

  /**
   * The number of the node this connection points to.
   */
  unsigned int node_n;

  /**
   * The type of the node this connection points to.
   */
  enum GNUNET_TESTING_NodeType node_type;

  /**
   * The node which establish the connection
   */
  struct GNUNET_TESTING_NetjailNode *node;

  /**
   * Head of the DLL with the address prefixes for the protocolls this node is reachable.
   */
  struct GNUNET_TESTING_AddressPrefix *address_prefixes_head;

  /**
   * Tail of the DLL with the address prefixes for the protocolls this node is reachable.
   */
  struct GNUNET_TESTING_AddressPrefix *address_prefixes_tail;
};

/**
 * Node in the netjail topology.
 */
struct GNUNET_TESTING_NetjailNode
{
  /**
   * Head of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_head;

  /**
   * Tail of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_tail;

  /**
   * Plugin for the test case to be run on this node.
   */
  char *plugin;

  /**
   * Flag indicating if this node is a global known node.
   */
  unsigned int is_global;

  /**
   * The number of the subnet this node is running in.
   */
  unsigned int namespace_n;

  /**
   * The number of this node in the subnet.
   */
  unsigned int node_n;

  /**
   * The overall number of the node in the whole test system.
   */
  unsigned int node_number;

  /**
   * The number of unintentional additional connections this node waits for. This overwrites the global additional_connects value.
   */
  unsigned int additional_connects;

  /**
   * The number of cmds waiting for a specific barrier.
   */
  unsigned int expected_reaches;
};


/**
 * Subnet in a topology.
 */
struct GNUNET_TESTING_NetjailNamespace
{
  /**
   * The number of the subnet.
   */
  unsigned int namespace_n;

  /**
   * Router of the subnet.
   */
  struct GNUNET_TESTING_NetjailRouter *router;

  /**
   * Hash map containing the nodes in this subnet.
   */
  struct GNUNET_CONTAINER_MultiShortmap *nodes;
};

/**
 * Toplogy of our netjail setup.
 */
struct GNUNET_TESTING_NetjailTopology
{

  /**
   * Default plugin for the test case to be run on nodes.
   */
  char *plugin;

  /**
   * Total number of namespaces in the topology;
   * numbered starting from 1 (!).
   */
  unsigned int total;

  /**
   * Number of subnets.
   */
  unsigned int namespaces_n;

  /**
   * Number of nodes per subnet.
   */
  unsigned int nodes_m;

  /**
   * Number of global known nodes.
   */
  unsigned int nodes_x;

  /**
   * Hash map containing the subnets (for natted nodes) of the topology.
   */
  struct GNUNET_CONTAINER_MultiShortmap *map_namespaces;

  /**
   * Hash map containing the global known nodes which are not natted.
   */
  struct GNUNET_CONTAINER_MultiShortmap *map_globals;

  /**
   * Additional connects we do expect, beside the connects which are configured in the topology.
   */
  unsigned int additional_connects;
};


/**
 * Parse the topology data.
 *
 * @param data The topology data.
 * @return The GNUNET_TESTING_NetjailTopology
 */
struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_string_ (const char *data);


/**
 * Get the number of unintentional additional connections the node waits for.
 *
 * @param num The specific node we want the additional connects for.
 * @return The number of additional connects
 */
unsigned int
GNUNET_TESTING_get_additional_connects (
  unsigned int num,
  struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Get a node from the topology.
 *
 * @param num The specific node we want the connections for.
 * @param topology The topology we get the connections from.
 * @return The connections of the node.
 */
struct GNUNET_TESTING_NetjailNode *
GNUNET_TESTING_get_node (unsigned int num,
                         struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Get the connections to other nodes for a specific node.
 *
 * @param num The specific node we want the connections for.
 * @param topology The topology we get the connections from.
 * @return The connections of the node.
 */
struct GNUNET_TESTING_NodeConnection *
GNUNET_TESTING_get_connections (
  unsigned int num,
  const struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Get the address for a specific communicator from a connection.
 *
 * @param connection The connection we like to have the address from.
 * @param prefix The communicator protocol prefix.
 * @return The address of the communicator.
 */
char *
GNUNET_TESTING_get_address (
  struct GNUNET_TESTING_NodeConnection *connection,
  const char *prefix);


/**
 * Deallocate memory of the struct GNUNET_TESTING_NetjailTopology.
 *
 * @param[in] topology The GNUNET_TESTING_NetjailTopology to be deallocated.
 */
void
GNUNET_TESTING_free_topology (struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Calculate the unique id identifying a node from a given connection.
 *
 * @param node_connection The connection we calculate the id from.
 * @param topology The topology we get all needed information from.
 * @return The unique id of the node from the connection.
 */
unsigned int
GNUNET_TESTING_calculate_num (
  struct GNUNET_TESTING_NodeConnection *node_connection,
  struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS(op, prefix)                            \
        op (prefix, topology, const struct GNUNET_TESTING_NetjailTopology)            \
        op (prefix, topology_string, const char)                                          \
        op (prefix, async_context, struct GNUNET_TESTING_AsyncContext)                    \
        op (prefix, helper_handles, const struct GNUNET_HELPER_Handle *)

GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                      GNUNET_TESTING)


#endif
