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
#ifndef GNUNET_TESTING_NETJAIL_LIB_H
#define GNUNET_TESTING_NETJAIL_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_ng_lib.h"


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
enum GNUNET_TESTING_NODE_TYPE
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
  enum GNUNET_TESTING_NODE_TYPE node_type;

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
   * Head of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_head;

  /**
   * Tail of the DLL with the connections which shall be established to other nodes.
   */
  struct GNUNET_TESTING_NodeConnection *node_connections_tail;
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
};

/**
 * Getting the topology from file.
 *
 * @param filename The name of the topology file.
 * @return The GNUNET_TESTING_NetjailTopology
 */
struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_file (const char *filename);


/**
 * Parse the topology data.
 *
 * @param data The topology data.
 * @return The GNUNET_TESTING_NetjailTopology
 */
struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_string (char *data);


/**
 * Get the connections to other nodes for a specific node.
 *
 * @param num The specific node we want the connections for.
 * @param topology The topology we get the connections from.
 * @return The connections of the node.
 */
struct GNUNET_TESTING_NodeConnection *
GNUNET_TESTING_get_connections (unsigned int num, struct
                                GNUNET_TESTING_NetjailTopology *topology);


/**
 * Get the address for a specific communicator from a connection.
 *
 * @param connection The connection we like to have the address from.
 * @param prefix The communicator protocol prefix.
 * @return The address of the communicator.
 */
char *
GNUNET_TESTING_get_address (struct GNUNET_TESTING_NodeConnection *connection,
                            char *prefix);


/**
 * Deallocate memory of the struct GNUNET_TESTING_NetjailTopology.
 *
 * @param topology The GNUNET_TESTING_NetjailTopology to be deallocated.
 */
void
GNUNET_TESTING_free_topology (struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Calculate the unique id identifying a node from a given connction.
 *
 * @param node_connection The connection we calculate the id from.
 * @param topology The topology we get all needed information from.
 * @return The unique id of the node from the connection.
 */
unsigned int
GNUNET_TESTING_calculate_num (struct
                              GNUNET_TESTING_NodeConnection *node_connection,
                              struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Struct with information for callbacks.
 *
 */
struct BlockState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The label of this command.
   */
  const char *label;

  /**
   * If this command will block.
   */
  unsigned int asynchronous_finish;
};

/**
 * Struct to hold information for callbacks.
 *
 */
struct LocalPreparedState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * Callback to write messages to the master loop.
   *
   */
  TESTING_CMD_HELPER_write_cb write_message;
};


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_destroy (const char *label,
                                   const char *create_label);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_system_create (const char *label,
                                  const char *testdir);


int
GNUNET_TESTING_get_trait_test_system (const struct
                                      GNUNET_TESTING_Command *cmd,
                                      struct GNUNET_TESTING_System **test_system);


/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @param read_file Flag indicating if the the name of the topology file is send to the helper, or a string with the topology data.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start (const char *label,
                                  char *topology_config,
                                  unsigned int *read_file);


/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @param read_file Flag indicating if the the name of the topology file is send to the helper, or a string with the topology data.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_stop (const char *label,
                                 char *topology_config,
                                 unsigned int *read_file);


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param topology The complete topology information.
 * @param read_file Flag indicating if the the name of the topology file is send to the helper, or a string with the topology data.
 * @param topology_data If read_file is GNUNET_NO, topology_data holds the string with the topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system (
  const char *label,
  struct GNUNET_TESTING_NetjailTopology *topology,
  unsigned int *read_file,
  char *topology_data);


/**
 * Create command.
 *
 * @param label name for command.
 * @param helper_start_label label of the cmd to start the test system.
 * @param topology The complete topology information.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_testing_system (
  const char *label,
  const char *helper_start_label,
  struct GNUNET_TESTING_NetjailTopology *topology);


/**
 * Create a GNUNET_CMDS_LOCAL_FINISHED message.
 *
 * @param rv The result of the local test as GNUNET_GenericReturnValue.
 * @return The GNUNET_CMDS_LOCAL_FINISHED message.
*/
struct GNUNET_MessageHeader *
GNUNET_TESTING_send_local_test_finished_msg (enum GNUNET_GenericReturnValue rv);


/**
 * Function to get the trait with the async context.
 *
 * @param[out] ac GNUNET_TESTING_AsyncContext.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
int
GNUNET_TESTING_get_trait_async_context (
  const struct GNUNET_TESTING_Command *cmd,
  struct GNUNET_TESTING_AsyncContext **ac);


/**
 * Offer handles to testing cmd helper from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait_helper_handles (
  const struct GNUNET_TESTING_Command *cmd,
  struct GNUNET_HELPER_Handle ***helper);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_all_peers_started (
  const char *label,
  unsigned int *all_peers_started);


/**
 * Create command.
 *
 * @param label name for command.
 * @param all_peers_started Flag which will be set from outside.
 * @param asynchronous_finish If GNUNET_YES this command will not block.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_external_trigger (
  const char *label);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_peer_ready (const char *label,
                                    TESTING_CMD_HELPER_write_cb write_message);


/**
 * Create command.
 *
 * @param label name for command.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_finished (
  const char *label,
  TESTING_CMD_HELPER_write_cb write_message);

/**
 * Create command.
 *
 * @param label name for command.
 * @param write_message Callback to write messages to the master loop.
 * @param all_local_tests_prepared Flag which will be set from outside.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_prepared (const char *label,
                                        TESTING_CMD_HELPER_write_cb
                                        write_message);

/**
 * Function to get the trait with the struct LocalPreparedState.
 *
 * @param[out] lfs struct LocalPreparedState.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait_local_prepared_state (
  const struct GNUNET_TESTING_Command *cmd,
  struct LocalPreparedState **lfs);


/**
 * Function to get the trait with the internal command state BlockState.
 *
 * * @param[out] ac struct BlockState.
* @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
int
GNUNET_TESTING_get_trait_block_state (
  const struct GNUNET_TESTING_Command *cmd,
  struct BlockState **bs);

#endif
