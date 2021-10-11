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
 * @file testing_api_cmd_backchannel_check.c
 * @brief cmd to start a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_common.h"
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

#define UDP "udp"

/**
 * Maximum length allowed for line input.
 */
#define MAX_LINE_LENGTH 1024

/**
 * Struct to store information needed in callbacks.
 *
 */
struct CheckState
{
  /**
   * The number of the node in a network namespace.
   */
  unsigned int node_n;

  /**
   * The number of the network namespace.
   */
  unsigned int namespace_n;

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

  /**
   * Number of received backchannel messages.
   */
  unsigned int received_backchannel_msgs;

  /**
   * Array with search strings.
   */
  char **search_string;

  /**
   * File handle for log file.
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * Task which handles the reading
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Stream to read log file lines.
   */
  FILE *stream;

  /**
   * Did we get all bachchannel messages.
   */
  enum GNUNET_GenericReturnValue finished;
};

/**
 *
 * @param cls The cmd state CheckState.
 */
static void
read_from_log (void *cls)
{
  struct CheckState *cs = cls;
  char line[MAX_LINE_LENGTH + 1];
  char *search_string;


  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "read_from_log\n");

  cs->fh = GNUNET_DISK_file_open ("test.out",
                                  GNUNET_DISK_OPEN_READ,
                                  GNUNET_DISK_PERM_USER_READ);

  cs->task = NULL;

  /* read message from line and handle it */
  cs->stream = fdopen (cs->fh->fd, "r");
  memset (line, 0, MAX_LINE_LENGTH + 1);

  // fgets (line, MAX_LINE_LENGTH, cs->stream);
  // while (NULL != line &&  0 != strcmp (line, ""))// '\0' != line[0])
  while  (NULL != fgets (line, MAX_LINE_LENGTH, cs->stream))
  {
    /*LOG (GNUNET_ERROR_TYPE_DEBUG,
         "cs->received_backchannel_msgs: %u\n",
         cs->received_backchannel_msgs);*/
    /*if (NULL == strstr (line, "line"))
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "line: %s",
           line);*/


    for (int i = 0; i < cs->con_num; i++)
    {
      search_string = cs->search_string[i];
      /*LOG (GNUNET_ERROR_TYPE_DEBUG,
           "search %u %u: %s %p\n",
           i,
           cs->con_num,
           cs->search_string[i],
           cs->search_string);
      fprintf (stderr,
      line);*/
      if (NULL != strstr (line,
                          search_string))
      // "Delivering backchannel message from 4TTC to F7B5 of type 1460 to udp"))
      // cs->search_string[i]))
      {
        cs->received_backchannel_msgs++;
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "received_backchannel_msgs %u con_num %u\n",
             cs->received_backchannel_msgs,
             cs->con_num);
        if (cs->received_backchannel_msgs == cs->con_num)
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "search finished %lu %lu %u\n",
               strlen (cs->search_string[i]),
               strlen (
                 "Delivering backchannel message from 4TTC to F7B5 of type 1460 to udp"),
               strcmp (
                 "Delivering backchannel message from 4TTC to F7B5 of type 1460 to udp",
                 cs->search_string[i]));
          cs->finished = GNUNET_YES;
          fclose (cs->stream);
          return;
        }
      }
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "read_from_log end\n");
  fclose (cs->stream);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                &read_from_log,
                                cs);
  /*if (NULL == fgets (line, MAX_LINE_LENGTH, cs->stream))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "read null\n");
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &read_from_log,
                                  cs);
    return;
    }*/
  /*else {
    cs->task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      cs->fh,
                                      &read_from_log,
                                      cs);


                                      }*/
}


static enum GNUNET_GenericReturnValue
will_the_other_node_connect_via_udp (
  struct CheckState *cs,
  const struct GNUNET_TESTING_NetjailNode *node)
// struct GNUNET_TESTING_NodeConnection *connection)
{
  // struct GNUNET_TESTING_NetjailTopology *topology = cs->topology;
  // unsigned int node_n = connection->node_n;
  // unsigned int namespace_n = connection->namespace_n;
  // struct GNUNET_HashCode hc;
  // struct GNUNET_ShortHashCode *key = GNUNET_new (struct GNUNET_ShortHashCode);
  // struct GNUNET_HashCode hc_namespace;
  /*struct GNUNET_ShortHashCode *key_namespace = GNUNET_new (struct
    GNUNET_ShortHashCode);*/
  // struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NodeConnection *pos_connection;
  struct GNUNET_TESTING_AddressPrefix *pos_prefix;
  // struct GNUNET_TESTING_NetjailNamespace *namespace;
  // struct GNUNET_CONTAINER_MultiShortmap *map;

  /* if (0 == connection->namespace_n) */
  /* { */
  /*   map = topology->map_globals; */
  /* } */
  /* else */
  /* { */
  /*   GNUNET_CRYPTO_hash (&namespace_n, sizeof(namespace_n), &hc_namespace); */
  /*   memcpy (key_namespace, */
  /*           &hc_namespace, */
  /*           sizeof (*key_namespace)); */
  /*   if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains ( */
  /*         topology->map_namespaces, */
  /*         key_namespace)) */
  /*   { */
  /*     namespace = GNUNET_CONTAINER_multishortmap_get (topology->map_namespaces, */
  /*                                                     key_namespace); */
  /*     map = namespace->nodes; */
  /*   } */
  /*   else */
  /*     GNUNET_assert (0); */
  /* } */

  /* GNUNET_CRYPTO_hash (&node_n, sizeof(node_n), &hc); */
  /* memcpy (key, */
  /*         &hc, */
  /*         sizeof (*key)); */
  /* if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains ( */
  /*       map, */
  /*       key)) */
  /* { */
  /*   node = GNUNET_CONTAINER_multishortmap_get (cs->topology->map_globals, */
  /*                                              key); */
  /*   for (pos_connection = node->node_connections_head; NULL != pos_connection; */
  /*        pos_connection = pos_connection->next) */
  /*   { */
  /*     if ((node->namespace_n == pos_connection->namespace_n) && */
  /*         (node->node_n == pos_connection->node_n) ) */
  /*     { */
  /*       for (pos_prefix = pos_connection->address_prefixes_head; NULL != */
  /*            pos_prefix; */
  /*            pos_prefix = */
  /*              pos_prefix->next) */
  /*       { */
  /*         if (0 == strcmp (UDP, pos_prefix->address_prefix)) */
  /*         { */
  /*           return GNUNET_YES; */
  /*         } */
  /*       } */
  /*     } */
  /*   } */
  /* } */

  for (pos_connection = node->node_connections_head; NULL != pos_connection;
       pos_connection = pos_connection->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connect via udp %u %u %u %u\n",
                node->namespace_n,
                cs->namespace_n,
                node->node_n,
                cs->node_n);
    if ((pos_connection->namespace_n == cs->namespace_n) &&
        (pos_connection->node_n == cs->node_n) )
    {
      for (pos_prefix = pos_connection->address_prefixes_head; NULL !=
           pos_prefix;
           pos_prefix =
             pos_prefix->next)
      {
        if (0 == strcmp (UDP, pos_prefix->address_prefix))
        {
          return GNUNET_YES;
        }
      }
    }
  }

  return GNUNET_NO;
}

static void
add_search_string (struct CheckState *cs, const struct
                   GNUNET_TESTING_NetjailNode *node)
{
  unsigned int num;
  struct GNUNET_PeerIdentity *peer;
  struct GNUNET_PeerIdentity *us;
  char *buf;
  char *part_one = "Delivering backchannel message from ";
  char *part_two = " to ";
  char *part_three = " of type 1460 to udp";
  char *peer_id;
  char *us_id;

  if (0 == node->namespace_n)
    num = node->node_n;
  else
    num = (node->namespace_n - 1) * cs->topology->nodes_m + node->node_n
          + cs->topology->nodes_x;

  // num = GNUNET_TESTING_calculate_num (pos_connection, cs->topology);
  peer = GNUNET_TESTING_get_pub_key (num, cs->tl_system);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "peer: %s num %u\n",
       GNUNET_i2s (peer),
       num);
  us = GNUNET_TESTING_get_pub_key (cs->num, cs->tl_system);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "us: %s cs->num %d\n",
       GNUNET_i2s (us),
       cs->num);

  GNUNET_asprintf (&peer_id,
                   "%s",
                   GNUNET_i2s (peer));
  GNUNET_asprintf (&us_id,
                   "%s",
                   GNUNET_i2s (us));

  if (0 < GNUNET_asprintf (&buf,
                           "%s%s%s%s%s",
                           part_one,
                           us_id,
                           part_two,
                           peer_id,
                           part_three))
  {
    GNUNET_array_append (cs->search_string,
                         cs->con_num,
                         buf);
    /*LOG (GNUNET_ERROR_TYPE_DEBUG,
         "con_num: %u search: %s %p\n",
         cs->con_num,
         cs->search_string[cs->con_num - 1],
         cs->search_string);*/
  }
  else
    GNUNET_assert (0);
}


/**
 * The run method of this cmd will connect to peers.
 *
 */
static void
backchannel_check_run (void *cls,
                       const struct GNUNET_TESTING_Command *cmd,
                       struct GNUNET_TESTING_Interpreter *is)
{
  struct CheckState *cs = cls;
  // char *buf;
  // char *part_one = "Delivering backchannel message from ";
  // char *part_two = " of type 1460 to udp";
  const struct GNUNET_TESTING_Command *system_cmd;
  struct GNUNET_TESTING_System *tl_system;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;
  // struct GNUNET_PeerIdentity *peer;
  // uint32_t num;
  // struct GNUNET_TESTING_NodeConnection *pos_connection;
  // unsigned int con_num = 0;
  struct GNUNET_CONTAINER_MultiShortmapIterator *node_it;
  struct GNUNET_CONTAINER_MultiShortmapIterator *namespace_it;
  struct GNUNET_ShortHashCode node_key;
  struct GNUNET_ShortHashCode namespace_key;
  const struct GNUNET_TESTING_NetjailNode *node;
  const struct GNUNET_TESTING_NetjailNamespace *namespace;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (
    cs->start_peer_label);
  GNUNET_TRANSPORT_get_trait_application_handle_v2 (peer1_cmd,
                                                    &ah);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (cs->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  cs->tl_system = tl_system;

  cs->node_connections_head = GNUNET_TESTING_get_connections (cs->num,
                                                              cs->topology);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "check run\n");


  node_it = GNUNET_CONTAINER_multishortmap_iterator_create (
    cs->topology->map_globals);

  while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (node_it,
                                                                     &node_key,
                                                                     (const
                                                                      void**) &
                                                                     node))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "namespace_n %u node_n %u\n",
         node->namespace_n,
         node->node_n);
    if (GNUNET_YES == will_the_other_node_connect_via_udp (cs, node))
    {
      add_search_string (cs, node);
    }
  }
  namespace_it = GNUNET_CONTAINER_multishortmap_iterator_create (
    cs->topology->map_namespaces);
  while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (
           namespace_it,
           &namespace_key,
           (const
            void**) &namespace))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "namespace_n %u\n",
         node->namespace_n);
    node_it = GNUNET_CONTAINER_multishortmap_iterator_create (
      namespace->nodes);
    while (GNUNET_YES == GNUNET_CONTAINER_multishortmap_iterator_next (node_it,
                                                                       &node_key,
                                                                       (const
                                                                        void**)
                                                                       &node))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "namespace_n %u node_n %u\n",
           node->namespace_n,
           node->node_n);
      if (GNUNET_YES == will_the_other_node_connect_via_udp (cs, node))
      {
        add_search_string (cs, node);
      }
    }
  }
  /* for (pos_connection = cs->node_connections_head; NULL != pos_connection; */
  /*      pos_connection = pos_connection->next) */
  /* { */

  /*   if (GNUNET_YES == will_the_other_node_connect_via_udp (cs, node)) */
  /*   { */
  /*     num = GNUNET_TESTING_calculate_num (pos_connection, cs->topology); */
  /*     peer = GNUNET_TESTING_get_pub_key (num, tl_system); */
  /*     LOG (GNUNET_ERROR_TYPE_DEBUG, */
  /*          "peer: %s\n", */
  /*          GNUNET_i2s (peer)); */

  /*     if (0 < GNUNET_asprintf (&buf, */
  /*                              "%s%s%s", */
  /*                              part_one, */
  /*                              GNUNET_i2s (peer), */
  /*                              part_two)) */
  /*     { */
  /*       GNUNET_array_append (cs->search_string, */
  /*                            con_num, */
  /*                            buf); */
  /*       /\*LOG (GNUNET_ERROR_TYPE_DEBUG, */
  /*            "con_num: %u search: %s %p\n", */
  /*            con_num, */
  /*            cs->search_string[con_num - 1], */
  /*            cs->search_string);*\/ */
  /*     } */
  /*     else */
  /*       GNUNET_assert (0); */
  /*   } */


  /* } */
  // cs->con_num = con_num;
  if (0 != cs->con_num)
  {
    cs->task =
      GNUNET_SCHEDULER_add_now (&read_from_log,
                                cs);
  }
  else
    cs->finished = GNUNET_YES;

}


/**
 * The finish function of this cmd will check if the peers we are trying to
 * connect to are in the connected peers map of the start peer cmd for this peer.
 *
 */
static int
backchannel_check_finish (void *cls,
                          GNUNET_SCHEDULER_TaskCallback cont,
                          void *cont_cls)
{
  struct CheckState *cs = cls;

  if (cs->finished)
  {
    cont (cont_cls);
  }
  return cs->finished;
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
backchannel_check_traits (void *cls,
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
backchannel_check_cleanup (void *cls,
                           const struct GNUNET_TESTING_Command *cmd)
{
  struct ConnectPeersState *cs = cls;

  GNUNET_free (cs);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param start_peer_label Label of the cmd to start a peer.
 * @param create_label Label of the cmd to create the testing system.
 * @param num Number globally identifying the node.
 * @param node_n The number of the node in a network namespace.
 * @param namespace_n The number of the network namespace.
 * @param The topology for the test setup.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_backchannel_check (const char *label,
                                        const char *start_peer_label,
                                        const char *create_label,
                                        uint32_t num,
                                        unsigned int node_n,
                                        unsigned int namespace_n,
                                        struct GNUNET_TESTING_NetjailTopology *
                                        topology)
{
  struct CheckState *cs;

  cs = GNUNET_new (struct CheckState);
  cs->start_peer_label = start_peer_label;
  cs->num = num;
  cs->create_label = create_label;
  cs->topology = topology;
  cs->node_n = node_n;
  cs->namespace_n = namespace_n;

  struct GNUNET_TESTING_Command cmd = {
    .cls = cs,
    .label = label,
    .run = &backchannel_check_run,
    .finish = &backchannel_check_finish,
    .cleanup = &backchannel_check_cleanup,
    .traits = &backchannel_check_traits
  };

  return cmd;
}
