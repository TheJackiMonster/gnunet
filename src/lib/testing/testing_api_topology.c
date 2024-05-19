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
 * Every line in the topology configuration starts with a string indicating which
 * kind of information will be configured with this line. Configuration values following
 * this string are seperated by special sequences of characters. An integer value seperated
 * by ':' is returned by this function.
 *
 * @param line The line of configuration. Example: "a:42[:43]"
 * @return An integer value (42)
 */
static unsigned int
get_first_value (const char *line)
{
  const char *colon = strchr (line, ':');
  char dummy;
  int ret;

  GNUNET_assert (NULL != colon);
  ret = sscanf (colon + 1,
                "%u%c",
                &ret,
                &dummy);
  if (2 == ret)
    GNUNET_assert (':' == dummy);
  else
    GNUNET_assert (1 == ret);
  return ret;
}


/**
 * Every line in the topology configuration starts with a string indicating
 * which kind of information will be configured with this line. This string is
 * returned by this function.
 *
 * @param line The line of configuration, e.g. "D:452"
 * @return The leading string of this configuration line ("D")
 */
static char *
get_key (const char *line)
{
  const char *colon = strchr (line, ':');

  GNUNET_assert (NULL != colon);
  return GNUNET_strndup (line,
                         colon - line);
}


/**
 * Every line in the topology configuration starts with a string indicating which
 * kind of information will be configured with this line. Configuration values following
 * this string are seperated by special sequences of characters. A string value seperated
 * by ':' is returned by this function.
 *
 * @param line The line of configuration ("FOO:BAR")
 * @return A string value ("BAR").
 */
// FIXME: avoid strdup, return const?
static char *
get_first_string_value (const char *line)
{
  const char *colon = strchr (line, ':');

  GNUNET_assert (NULL != colon);
  return GNUNET_strdup (colon + 1);
}


/**
 * Every line in the topology configuration starts with a string indicating
 * which kind of information will be configured with this line. Configuration
 * values following this string are seperated by special sequences of
 * characters. A second integer value seperated by ':' from a first value is
 * returned by this function.
 *
 * @param line The line of configuration (example: "P:1:3")
 * @return An integer value (3)
 */
static unsigned int
get_second_value (const char *line)
{
  const char *colon;
  char dummy;
  int ret;

  colon = strchr (line, ':');
  GNUNET_assert (NULL != colon);
  colon = strchr (colon + 1, ':');
  GNUNET_assert (NULL != colon);
  GNUNET_assert (1 ==
                 sscanf (colon + 1,
                         "%u%c",
                         &ret,
                         &dummy));
  return ret;
}


/**
 * Every line in the topology configuration starts with a string indicating which
 * kind of information will be configured with this line. Configuration values following
 * this string are seperated by special sequences of characters. A value might be
 * a key value pair.
 * This function returns the value for a specific key in a configuration line.
 *
 * @param key The key of the key value pair.
 * @return The value of the key value pair.
 */
static char *
get_value (const char *key, const char *line)
{
  char copy[strlen (line) + 1];
  size_t slen;
  char *token;
  char *token2;
  char *temp;
  char *rest = NULL;

  slen = strlen (line) + 1;
  memcpy (copy, line, slen);
  temp = strstr (copy, key);
  if (NULL == temp)
    return NULL;
  token = strtok_r (temp, ":", &rest);
  if (NULL == token)
    return NULL;
  token = strtok_r (NULL, ":", &rest);
  if (NULL == token)
    return NULL;
  token2 = strtok_r (token, "}", &rest);
  if (NULL == token2)
    return NULL;
  return GNUNET_strdup (token2);
}


/**
 * Every line in the topology configuration starts with a string indicating which
 * kind of information will be configured with this line. Configuration values following
 * this string are seperated by special sequences of characters. A value might be
 * a key value pair. A special key is the 'connect' key which can appear more than once.
 * The value is the information about a connection via some protocol to some other node.
 * This function returns the struct GNUNET_TESTING_NodeConnection which holds the information
 * of the connect value.
 *
 * @param value The value of the connect key value pair.
 * @return The struct GNUNET_TESTING_NodeConnection.
 */
static struct GNUNET_TESTING_NodeConnection *
get_connect_value (const char *line,
                   struct GNUNET_TESTING_NetjailNode *node)
{
  struct GNUNET_TESTING_NodeConnection *node_connection;
  char *copy;
  char *token;
  char *token2;
  unsigned int node_n;
  unsigned int namespace_n;
  char *rest = NULL;
  char *rest2 = NULL;
  struct GNUNET_TESTING_AddressPrefix *prefix;
  unsigned int sscanf_ret;

  node_connection = GNUNET_new (struct GNUNET_TESTING_NodeConnection);
  node_connection->node = node;

  copy = GNUNET_strdup (line);
  token = strtok_r (copy, ":", &rest);
  if (0 == strcmp ("{K", token))
  {
    node_connection->node_type = GNUNET_TESTING_GLOBAL_NODE;
    token = strtok_r (NULL, ":", &rest);
    GNUNET_assert (1 == sscanf (token, "%u", &node_n));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "node_n %u\n",
         node_n);
    node_connection->node_n = node_n;
    node_connection->namespace_n = 0;
  }
  else if (0 == strcmp ("{P", token))
  {
    node_connection->node_type = GNUNET_TESTING_SUBNET_NODE;
    token = strtok_r (NULL, ":", &rest);
    errno = 0;
    sscanf_ret = sscanf (token, "%u", &namespace_n);
    if (errno != 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
    }
    GNUNET_assert (0 < sscanf_ret);
    node_connection->namespace_n = namespace_n;
    token = strtok_r (NULL, ":", &rest);
    errno = 0;
    sscanf_ret = sscanf (token, "%u", &node_n);
    if (errno != 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
    }
    GNUNET_assert (0 < sscanf_ret);
    node_connection->node_n = node_n;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "node_n %u namespace_n %u node->node_n %u node->namespace_n %u\n",
         node_n,
         namespace_n,
         node->node_n,
         node->namespace_n);
  }
  else
  {
    GNUNET_break (0);
    GNUNET_free (node_connection);
    GNUNET_free (copy);
    return NULL;
  }

  while (NULL != (token = strtok_r (NULL, ":", &rest)))
  {
    prefix = GNUNET_new (struct GNUNET_TESTING_AddressPrefix);
    token2 = strtok_r (token, "}", &rest2);
    if (NULL != token2)
      prefix->address_prefix = GNUNET_strdup (token2);
    else
      prefix->address_prefix = GNUNET_strdup (token);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "address_prefix %s\n",
         prefix->address_prefix);

    GNUNET_CONTAINER_DLL_insert (node_connection->address_prefixes_head,
                                 node_connection->address_prefixes_tail,
                                 prefix);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "address_prefix %s\n",
         prefix->address_prefix);
  }

  GNUNET_free (copy);
  return node_connection;
}


/**
 * Every line in the topology configuration starts with a string indicating which
 * kind of information will be configured with this line. Configuration values following
 * this string are seperated by special sequences of characters. A value might be
 * a key value pair. A special key is the 'connect' key.
 * The value is the information about a connections via some protocol to other nodes.
 * Each connection itself is a key value pair separated by the character '|' and
 * surrounded by the characters '{' and '}'.
 * The struct GNUNET_TESTING_NodeConnection holds the information of each connection value.
 * This function extracts the values of each connection into a DLL of
 * struct GNUNET_TESTING_NodeConnection which will be added to a node.
 *
 * @param line The line of configuration.
 * @param node The struct GNUNET_TESTING_NetjailNode to which the DLL of
 *             struct GNUNET_TESTING_NodeConnection will be added.
 */
static void
node_connections (const char *line,
                  struct GNUNET_TESTING_NetjailNode *node)
{
  char *value, *value2;
  char *temp;
  char *copy;
  char *rest = NULL;
  char *rest2 = NULL;
  struct GNUNET_TESTING_NodeConnection *node_connection;

  temp = strstr (line, "connect");
  if (NULL != temp)
  {
    copy = GNUNET_strdup (temp);
    strtok_r (copy, ":", &rest);
    value = strtok_r (rest, "|", &rest2);

    while (NULL != value)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "node_connections value %s\n",
           value);
      node_connection = get_connect_value (value, node);
      if (NULL == node_connection)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "connect key was not expected in this configuration line: %s\n",
             line);
        break;
      }
      GNUNET_CONTAINER_DLL_insert (node->node_connections_head,
                                   node->node_connections_tail,
                                   node_connection);
      value2 = strstr (value, "}}");
      if (NULL != value2)
        break;
      value = strtok_r (NULL, "|", &rest2);

    }
    GNUNET_free (copy);
  }
}


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


int
free_nodes_cb (void *cls,
               const struct GNUNET_ShortHashCode *key,
               void *value)
{
  (void) cls;
  struct GNUNET_TESTING_NetjailNode *node = value;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_AddressPrefix *pos_prefix;

  while (NULL != (pos_connection = node->node_connections_head))
  {
    while (NULL != (pos_prefix = pos_connection->address_prefixes_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos_connection->address_prefixes_head,
                                   pos_connection->address_prefixes_tail,
                                   pos_prefix);
      GNUNET_free (pos_prefix->address_prefix);
      GNUNET_free (pos_prefix);
    }
    GNUNET_CONTAINER_DLL_remove (node->node_connections_head,
                                 node->node_connections_tail,
                                 pos_connection);
    GNUNET_free (pos_connection);
  }

  GNUNET_free (node->plugin);
  GNUNET_free (node);
  return GNUNET_OK;
}


int
free_namespaces_cb (void *cls,
                    const struct GNUNET_ShortHashCode *key,
                    void *value)
{
  (void) cls;
  struct GNUNET_TESTING_NetjailNamespace *namespace = value;

  GNUNET_free (namespace->router);
  GNUNET_CONTAINER_multishortmap_iterate (namespace->nodes, free_nodes_cb,
                                          namespace->nodes);
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
  GNUNET_CONTAINER_multishortmap_iterate (topology->map_namespaces,
                                          &free_namespaces_cb,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_destroy (topology->map_namespaces);
  GNUNET_CONTAINER_multishortmap_iterate (topology->map_globals,
                                          &free_nodes_cb,
                                          NULL);
  GNUNET_CONTAINER_multishortmap_destroy (topology->map_globals);
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
  char *template;
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


static void
parse_ac (struct GNUNET_TESTING_NetjailNode *p_node, const char *token)
{
  char *ac_value;
  int ret;

  ac_value = get_value ("AC", token);
  if (NULL != ac_value)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ac value: %s\n",
         ac_value);
    errno = 0;
    ret = sscanf (ac_value, "%u", &p_node->additional_connects);
    if (errno != 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "sscanf");
    }
    GNUNET_assert (0 < ret);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "AC %u\n",
         p_node->additional_connects);
  }
  else
  {
    p_node->additional_connects = 0;
  }
  GNUNET_free (ac_value);
}


char *
GNUNET_TESTING_get_plugin_from_topo (
  struct GNUNET_TESTING_NetjailTopology *njt,
  const char *my_node_id)
{
  return njt->plugin;
}


/**
 * Parse the topology data.
 *
 * @param data The topology data.
 * @return The GNUNET_TESTING_NetjailTopology
 */
struct GNUNET_TESTING_NetjailTopology *
GNUNET_TESTING_get_topo_from_string_ (const char *input)
{
  char *token;
  char *key = NULL;
  unsigned int out;
  char *rest = NULL;
  char *value = NULL;
  char *value2;
  char *data;
  int ret;
  struct GNUNET_TESTING_NetjailTopology *topo;
  struct GNUNET_TESTING_NetjailRouter *router;
  struct GNUNET_TESTING_NetjailNamespace *namespace;
  struct GNUNET_HashCode hc;

  data = GNUNET_strdup (input);
  token = strtok_r (data, "\n", &rest);
  topo = GNUNET_new (struct GNUNET_TESTING_NetjailTopology);
  topo->map_namespaces =
    GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
  topo->map_globals =
    GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);

  while (NULL != token)
  {
    if (NULL != key)
      GNUNET_free (key);
    key = get_key (token);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In the loop with token: %s beginning with %s\n",
         token,
         key);
    if (0 == strcmp (key, "M"))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for M.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "M: %u\n",
           out);
      topo->nodes_m = out;
    }
    else if (0 == strcmp (key, "N"))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for N.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "N: %u\n",
           out);
      topo->namespaces_n = out;
    }
    else if (0 == strcmp (key, "X"))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for X.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "X: %u\n",
           out);
      topo->nodes_x = out;
    }
    else if (0 == strcmp (key, "AC"))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for AC.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "AC: %u\n",
           out);
      topo->additional_connects = out;
    }
    else if (0 == strcmp (key, "T"))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first string value for T.\n");
      value = get_first_string_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "value: %s\n",
           value);
      topo->plugin = value;
    }
    else if (0 == strcmp (key, "K"))
    {
      struct GNUNET_ShortHashCode hkey_k;
      struct GNUNET_TESTING_NetjailNode *k_node = GNUNET_new (struct
                                                              GNUNET_TESTING_NetjailNode);

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for K.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "K: %u\n",
           out);
      k_node->node_n = out;
      GNUNET_CRYPTO_hash (&out, sizeof(out), &hc);
      memcpy (&hkey_k,
              &hc,
              sizeof (hkey_k));
      k_node->is_global = GNUNET_YES;

      if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
            topo->map_globals,
            &hkey_k))
        GNUNET_break (0);
      else
        GNUNET_CONTAINER_multishortmap_put (topo->map_globals,
                                            &hkey_k,
                                            k_node,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get value for key value on K.\n");
      value = get_value ("plugin", token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "value: %s\n",
           value);
      k_node->plugin = value;
      parse_ac (k_node, token);
      node_connections (token, k_node);
      GNUNET_free (value);
    }
    else if (0 == strcmp (key, "R"))
    {
      struct GNUNET_ShortHashCode hkey_r;
      router = GNUNET_new (struct GNUNET_TESTING_NetjailRouter);

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for R.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "R: %u\n",
           out);
      GNUNET_CRYPTO_hash (&out, sizeof(out), &hc);
      memcpy (&hkey_r,
              &hc,
              sizeof (hkey_r));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get value for key tcp_port on R.\n");
      value = get_value ("tcp_port", token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "tcp_port: %s\n",
           value);
      ret = sscanf (value, "%u", &(router->tcp_port));
      GNUNET_free (value);
      GNUNET_break (0 != ret && 1 >= router->tcp_port);

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get value for key udp_port on R.\n");
      value2 = get_value ("udp_port", token);
      ret = sscanf (value2, "%u", &(router->udp_port));
      GNUNET_free (value2);
      GNUNET_break (0 != ret && 1 >= router->udp_port);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "udp_port: %s\n",
           value2);
      GNUNET_free (value2);
      if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
            topo->map_namespaces,
            &hkey_r))
      {
        namespace = GNUNET_CONTAINER_multishortmap_get (topo->map_namespaces,
                                                        &hkey_r);
      }
      else
      {
        namespace = GNUNET_new (struct GNUNET_TESTING_NetjailNamespace);
        namespace->namespace_n = out;
        namespace->nodes = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
        GNUNET_CONTAINER_multishortmap_put (topo->map_namespaces,
                                            &hkey_r,
                                            namespace,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      }
      namespace->router = router;

    }
    else if (0 == strcmp (key, "P"))
    {
      struct GNUNET_TESTING_NetjailNode *p_node = GNUNET_new (struct
                                                              GNUNET_TESTING_NetjailNode);
      struct GNUNET_ShortHashCode hkey_p;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get first Value for P.\n");
      out = get_first_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "P: %u\n",
           out);
      GNUNET_CRYPTO_hash (&out, sizeof(out), &hc);
      memcpy (&hkey_p,
              &hc,
              sizeof (hkey_p));

      if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
            topo->map_namespaces,
            &hkey_p))
      {
        namespace = GNUNET_CONTAINER_multishortmap_get (topo->map_namespaces,
                                                        &hkey_p);
      }
      else
      {
        namespace = GNUNET_new (struct GNUNET_TESTING_NetjailNamespace);
        namespace->nodes = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
        namespace->namespace_n = out;
        GNUNET_CONTAINER_multishortmap_put (topo->map_namespaces,
                                            &hkey_p,
                                            namespace,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get second Value for P.\n");
      out = get_second_value (token);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "P: %u\n",
           out);
      GNUNET_CRYPTO_hash (&out, sizeof(out), &hc);
      memcpy (&hkey_p,
              &hc,
              sizeof (hkey_p));
      if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
            namespace->nodes,
            &hkey_p))
      {
        GNUNET_break (0);
      }
      else
      {

        GNUNET_CONTAINER_multishortmap_put (namespace->nodes,
                                            &hkey_p,
                                            p_node,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Get value for key plugin on P.\n");
        value = get_value ("plugin", token);
        if (NULL != value)
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "plugin: %s\n",
               value);
          p_node->plugin = value;
        }
        p_node->node_n = out;
        p_node->namespace_n = namespace->namespace_n;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Get AC Value for P.\n");
      parse_ac (p_node, token);
      node_connections (token, p_node);
    }
    token = strtok_r (NULL, "\n", &rest);
    if (NULL != token)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Next token %s\n",
           token);
  }
  if (NULL != key)
    GNUNET_free (key);
  GNUNET_free (data);
  return topo;
}


GNUNET_TESTING_SIMPLE_NETJAIL_TRAITS (
  GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT,
  GNUNET_TESTING)


/* end of netjail.c */
