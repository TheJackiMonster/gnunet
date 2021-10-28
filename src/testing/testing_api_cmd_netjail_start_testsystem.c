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
 * @file testing/testing_api_cmd_hello_world.c
 * @brief Command to start the netjail peers.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "testing_cmds.h"

#define NETJAIL_EXEC_SCRIPT "./../testing/netjail_exec.sh"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct to store messages send/received by the helper into a DLL
 *
 */
struct HelperMessage
{

  /**
   * Kept in a DLL.
   */
  struct HelperMessage *next;

  /**
   * Kept in a DLL.
   */
  struct HelperMessage *prev;

  /**
   * Size of the original message.
   */
  uint16_t bytes_msg;

  /* Followed by @e bytes_msg of msg.*/
};


/**
 * Struct to store information handed over to callbacks.
 *
 */
struct NetJailState
{
  /**
   * Global state of the interpreter, used by a command
   * to access information about other commands.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The complete topology information.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * Head of the DLL which stores messages received by the helper.
   *
   */
  struct HelperMessage *hp_messages_head;

  /**
   * Tail of the DLL which stores messages received by the helper.
   *
   */
  struct HelperMessage *hp_messages_tail;

  /**
   * Array with handles of helper processes.
   */
  struct GNUNET_HELPER_Handle **helper;

  /**
   * Size of the array NetJailState#helper.
   *
   */
  unsigned int n_helper;

  /**
   * Number of nodes in a natted subnet.
   *
   */
  unsigned int local_m;

  /**
   * Number of natted subnets.
   *
   */
  unsigned int global_n;

  /**
   * Number of global known nodes.
   *
   */
  unsigned int known;

  /**
   * The send handle for the helper
   */
  // struct GNUNET_HELPER_SendHandle **shandle;

  /**
   * Size of the array NetJailState#shandle.
   *
   */
  // unsigned int n_shandle;

  /**
   * The messages send to the helper.
   */
  struct GNUNET_MessageHeader **msg;

  /**
   * Size of the array NetJailState#msg.
   *
   */
  unsigned int n_msg;

  /**
   * Number of test environments started.
   *
   */
  unsigned int number_of_testsystems_started;

  /**
   * Number of peers started.
   *
   */
  unsigned int number_of_peers_started;

  /**
   * Number of local tests finished.
   *
   */
  unsigned int number_of_local_tests_finished;

  /**
   * Number of local tests prepared to finish.
   *
   */
  unsigned int number_of_local_tests_prepared;

  /**
   * Name of the test case plugin the helper will load.
   *
   */
  char *plugin_name;

  /**
   * HEAD of the DLL containing TestingSystemCount.
   *
   */
  struct TestingSystemCount *tbcs_head;

  /**
   * TAIL of the DLL containing TestingSystemCount.
   *
   */
  struct TestingSystemCount *tbcs_tail;
};

/**
 * Struct containing the number of the test environment and the NetJailState which
 * will be handed to callbacks specific to a test environment.
 */
struct TestingSystemCount
{
  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *next;

  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *prev;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle *shandle;// **shandle;

  /**
   * Size of the array NetJailState#shandle.
   *
   */
  // unsigned int n_shandle;

  /**
   * The number of the test environment.
   *
   */
  unsigned int count;

  /**
   * Struct to store information handed over to callbacks.
   *
   */
  struct NetJailState *ns;
};

/**
* Code to clean up resource this cmd used.
*
* @param cls closure
*/
static void
netjail_exec_cleanup (void *cls)
{
  struct NetJailState *ns = cls;
  struct HelperMessage *message_pos;
  struct  TestingSystemCount *tbc_pos;

  while (NULL != (message_pos = ns->hp_messages_head))
  {
    GNUNET_CONTAINER_DLL_remove (ns->hp_messages_head,
                                 ns->hp_messages_tail,
                                 message_pos);
    GNUNET_free (message_pos);
  }
  while (NULL != (tbc_pos = ns->tbcs_head))
  {
    GNUNET_CONTAINER_DLL_remove (ns->tbcs_head,
                                 ns->tbcs_tail,
                                 tbc_pos);
    GNUNET_free (tbc_pos);
  }
  GNUNET_TESTING_free_topology (ns->topology);
  GNUNET_free (ns);
}


/**
 * This function prepares an array with traits.
 *
 */
static int
netjail_exec_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  struct NetJailState *ns = cls;
  struct GNUNET_HELPER_Handle **helper = ns->helper;
  struct HelperMessage *hp_messages_head = ns->hp_messages_head;


  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "helper_handles",
      .ptr = (const void *) helper,
    },
    {
      .index = 1,
      .trait_name = "hp_msgs_head",
      .ptr = (const void *) hp_messages_head,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Offer handles to testing cmd helper from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_helper_handles (const struct
                                         GNUNET_TESTING_Command *cmd,
                                         struct GNUNET_HELPER_Handle ***
                                         helper)
{
  return cmd->traits (cmd->cls,
                      (const void **) helper,
                      "helper_handles",
                      (unsigned int) 0);
}


/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
clear_msg (void *cls, int result)
{
  struct TestingSystemCount *tbc = cls;
  struct NetJailState *ns = tbc->ns;

  GNUNET_assert (NULL != tbc->shandle);// [tbc->count - 1]);
  tbc->shandle = NULL;// [tbc->count - 1] = NULL;
  GNUNET_free (ns->msg[tbc->count - 1]);
  ns->msg[tbc->count - 1] = NULL;
}


static void
send_message_to_locals (
  unsigned int i,
  unsigned int j,
  struct NetJailState *ns,
  struct GNUNET_MessageHeader *header
  )
{
  // unsigned int total_number = ns->local_m * ns->global_n + ns->known;
  struct GNUNET_HELPER_Handle *helper;
  struct TestingSystemCount *tbc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "send message of type %u to locals\n",
       header->type);
  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;
  // TODO This needs to be more generic. As we send more messages back and forth, we can not grow the arrays again and again, because this is to error prone.
  if (0 == i)
    tbc->count = j; // + total_number;
  else
    tbc->count = (i - 1) * ns->local_m + j + ns->known; // + total_number ;

  helper = ns->helper[tbc->count - 1];// - total_number];

  GNUNET_array_append (ns->msg, ns->n_msg, header);

  struct GNUNET_HELPER_SendHandle *sh = GNUNET_HELPER_send (
    helper,
    header,
    GNUNET_NO,
    &clear_msg,
    tbc);

  tbc->shandle = sh;
  // GNUNET_array_append (tbc->shandle, tbc->n_shandle, sh);
}


static void
send_all_local_tests_prepared (unsigned int i, unsigned int j, struct
                               NetJailState *ns)
{
  struct GNUNET_CMDS_ALL_LOCAL_TESTS_PREPARED *reply;
  size_t msg_length;


  msg_length = sizeof(struct GNUNET_CMDS_ALL_LOCAL_TESTS_PREPARED);
  reply = GNUNET_new (struct GNUNET_CMDS_ALL_LOCAL_TESTS_PREPARED);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED);
  reply->header.size = htons ((uint16_t) msg_length);

  send_message_to_locals (i, j, ns, &reply->header);
}


static void
send_all_peers_started (unsigned int i, unsigned int j, struct NetJailState *ns)
{

  struct GNUNET_CMDS_ALL_PEERS_STARTED *reply;
  size_t msg_length;


  msg_length = sizeof(struct GNUNET_CMDS_ALL_PEERS_STARTED);
  reply = GNUNET_new (struct GNUNET_CMDS_ALL_PEERS_STARTED);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED);
  reply->header.size = htons ((uint16_t) msg_length);

  send_message_to_locals (i, j, ns, &reply->header);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
helper_mst (void *cls, const struct GNUNET_MessageHeader *message)
{
  // struct TestingSystemCount *tbc = cls;
  struct NetJailState *ns = cls;// tbc->ns;
  struct HelperMessage *hp_msg;
  unsigned int total_number = ns->local_m * ns->global_n + ns->known;
  // uint16_t message_type = ntohs (message->type);

  /*switch (message_type)
  {
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY:
    ns->number_of_testsystems_started++;
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED:
    ns->number_of_peers_started++;
    if (ns->number_of_peers_started == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_peers_started (0,i, ns);
      }
      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_peers_started (i,j, ns);
        }
      }
      ns->number_of_peers_started = 0;
    }
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED:
    ns->number_of_local_tests_prepared++;
    if (ns->number_of_local_tests_prepared == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_local_tests_prepared (0,i, ns);
      }

      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_local_tests_prepared (i,j, ns);
        }
      }
    }
    break;
  case GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED:
    ns->number_of_local_tests_finished++;
    if (ns->number_of_local_tests_finished == total_number)
    {
      GNUNET_TESTING_async_finish (&ns->ac);
    }
    break;
  default:
    hp_msg = GNUNET_new (struct HelperMessage);
    hp_msg->bytes_msg = message->size;
    memcpy (&hp_msg[1], message, message->size);
    GNUNET_CONTAINER_DLL_insert (ns->hp_messages_head, ns->hp_messages_tail,
                                 hp_msg);
                                 }*/
  if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY == ntohs (message->type))
  {
    ns->number_of_testsystems_started++;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED == ntohs (
             message->type))
  {
    ns->number_of_peers_started++;
    if (ns->number_of_peers_started == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_peers_started (0,i, ns);
      }

      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_peers_started (i,j, ns);
        }
      }
      ns->number_of_peers_started = 0;
    }
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED == ntohs (
             message->type))
  {
    ns->number_of_local_tests_prepared++;
    if (ns->number_of_local_tests_prepared == total_number)
    {
      for (int i = 1; i <= ns->known; i++)
      {
        send_all_local_tests_prepared (0,i, ns);
      }

      for (int i = 1; i <= ns->global_n; i++)
      {
        for (int j = 1; j <= ns->local_m; j++)
        {
          send_all_local_tests_prepared (i,j, ns);
        }
      }
    }
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED == ntohs (
             message->type))
  {
    ns->number_of_local_tests_finished++;
    if (ns->number_of_local_tests_finished == total_number)
    {
      GNUNET_TESTING_async_finish (&ns->ac);
    }
  }
  else
  {
    hp_msg = GNUNET_new (struct HelperMessage);
    hp_msg->bytes_msg = message->size;
    memcpy (&hp_msg[1], message, message->size);
    GNUNET_CONTAINER_DLL_insert (ns->hp_messages_head, ns->hp_messages_tail,
                                 hp_msg);
  }


  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "total %u sysstarted %u peersstarted %u prep %u finished %u %u %u %u\n",
       total_number,
       ns->number_of_testsystems_started,
       ns->number_of_peers_started,
       ns->number_of_local_tests_prepared,
       ns->number_of_local_tests_finished,
       ns->local_m,
       ns->global_n,
       ns->known);




  return GNUNET_OK;
}


/**
 * Callback called if there was an exception during execution of the helper.
 *
 */
static void
exp_cb (void *cls)
{
  struct TestingSystemCount *tbc = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
  GNUNET_TESTING_async_fail (&(tbc->ns->ac));
}


/**
 * Function to initialize a init message for the helper.
 *
 * @param plugin_name Name of the test case plugin the helper will load.
 *
 */
static struct GNUNET_CMDS_HelperInit *
create_helper_init_msg_ (const char *plugin_name)
{
  struct GNUNET_CMDS_HelperInit *msg;
  uint16_t plugin_name_len;
  uint16_t msg_size;

  GNUNET_assert (NULL != plugin_name);
  plugin_name_len = strlen (plugin_name);
  msg_size = sizeof(struct GNUNET_CMDS_HelperInit) + plugin_name_len;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT);
  msg->plugin_name_size = htons (plugin_name_len);
  GNUNET_memcpy ((char *) &msg[1],
                 plugin_name,
                 plugin_name_len);
  return msg;
}


/**
 * Function which start a single helper process.
 *
 */
static void
start_helper (struct NetJailState *ns,
              unsigned int m,
              unsigned int n)
{
  struct GNUNET_HELPER_Handle *helper;
  struct GNUNET_CMDS_HelperInit *msg;
  struct TestingSystemCount *tbc;
  char *m_char;
  char *n_char;
  char *global_n_char;
  char *local_m_char;
  char *known_char;
  char *node_id;
  char *plugin;
  pid_t pid;
  unsigned int script_num;
  struct GNUNET_ShortHashCode *hkey;
  struct GNUNET_HashCode hc;
  struct GNUNET_TESTING_NetjailTopology *topology = ns->topology;
  struct GNUNET_TESTING_NetjailNode *node;
  struct GNUNET_TESTING_NetjailNamespace *namespace;


  if (0 == n)
    script_num = m - 1;
  else
    script_num = n - 1 + (n - 1) * ns->local_m + m + ns->known;
  pid = getpid ();

  GNUNET_asprintf (&m_char, "%u", m);
  GNUNET_asprintf (&n_char, "%u", n);
  GNUNET_asprintf (&local_m_char, "%u", ns->local_m);
  GNUNET_asprintf (&global_n_char, "%u",ns->global_n);
  GNUNET_asprintf (&known_char, "%u",ns->known);
  GNUNET_asprintf (&node_id, "%06x-%08x\n",
                   pid,
                   script_num);


  char *const script_argv[] = {NETJAIL_EXEC_SCRIPT,
                               m_char,
                               n_char,
                               GNUNET_OS_get_libexec_binary_path (
                                 HELPER_CMDS_BINARY),
                               global_n_char,
                               local_m_char,
                               node_id,
                               NULL};

  unsigned int helper_check = GNUNET_OS_check_helper_binary (
    NETJAIL_EXEC_SCRIPT,
    GNUNET_YES,
    NULL);

  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;
  if (0 == n)
    tbc->count = m;
  else
    tbc->count = (n - 1) * ns->local_m + m + ns->known;

  GNUNET_CONTAINER_DLL_insert (ns->tbcs_head,
                               ns->tbcs_tail,
                               tbc);


  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                NETJAIL_EXEC_SCRIPT);
    GNUNET_TESTING_interpreter_fail (ns->is);
  }
  else if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                NETJAIL_EXEC_SCRIPT);
    GNUNET_TESTING_interpreter_fail (ns->is);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sysstarted %u peersstarted %u prep %u finished %u %u %u %u\n",
       ns->number_of_testsystems_started,
       ns->number_of_peers_started,
       ns->number_of_local_tests_prepared,
       ns->number_of_local_tests_finished,
       ns->local_m,
       ns->global_n,
       ns->known);

  GNUNET_array_append (ns->helper, ns->n_helper, GNUNET_HELPER_start (
                         GNUNET_YES,
                         NETJAIL_EXEC_SCRIPT,
                         script_argv,
                         &helper_mst,
                         &exp_cb,
                         ns));

  helper = ns->helper[tbc->count - 1];

  hkey = GNUNET_new (struct GNUNET_ShortHashCode);

  plugin = topology->plugin;

  if (0 == m)
  {

    GNUNET_CRYPTO_hash (&n, sizeof(n), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    if (1 == GNUNET_CONTAINER_multishortmap_contains (topology->map_globals,
                                                      hkey))
    {
      node = GNUNET_CONTAINER_multishortmap_get (topology->map_globals,
                                                 hkey);
      if (NULL != node->plugin)
        plugin = node->plugin;
    }

  }
  else
  {
    GNUNET_CRYPTO_hash (&m, sizeof(m), &hc);
    memcpy (hkey,
            &hc,
            sizeof (*hkey));
    if (1 == GNUNET_CONTAINER_multishortmap_contains (topology->map_namespaces,
                                                      hkey))
    {
      namespace = GNUNET_CONTAINER_multishortmap_get (topology->map_namespaces,
                                                      hkey);
      GNUNET_CRYPTO_hash (&n, sizeof(n), &hc);
      memcpy (hkey,
              &hc,
              sizeof (*hkey));
      if (1 == GNUNET_CONTAINER_multishortmap_contains (namespace->nodes,
                                                        hkey))
      {
        node = GNUNET_CONTAINER_multishortmap_get (namespace->nodes,
                                                   hkey);
        if (NULL != node->plugin)
          plugin = node->plugin;
      }
    }


  }

  msg = create_helper_init_msg_ (plugin);

  GNUNET_array_append (ns->msg, ns->n_msg, &msg->header);

  // GNUNET_array_append (tbc->shandle, tbc->n_shandle,
  tbc->shandle = GNUNET_HELPER_send (
    helper,
    &msg->header,
    GNUNET_NO,
    &clear_msg,
    tbc);                     // );

  if (NULL == tbc->shandle)// [tbc->count - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_free (msg);
    GNUNET_TESTING_interpreter_fail (ns->is);
  }
  GNUNET_free (hkey);
}


/**
* This function starts a helper process for each node.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
netjail_exec_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;

  ns->is = is;
  for (int i = 1; i <= ns->known; i++)
  {
    start_helper (ns,
                  i,
                  0);
  }

  for (int i = 1; i <= ns->global_n; i++)
  {
    for (int j = 1; j <= ns->local_m; j++)
    {
      start_helper (ns,
                    j,
                    i);
    }
  }
}


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param topology_config Configuration file for the test topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system (const char *label,
                                                 const char *topology_config)
{
  struct NetJailState *ns;

  struct GNUNET_TESTING_NetjailTopology *topology =
    GNUNET_TESTING_get_topo_from_file (topology_config);

  ns = GNUNET_new (struct NetJailState);
  ns->local_m = topology->nodes_m;
  ns->global_n = topology->namespaces_n;
  ns->known = topology->nodes_x;
  ns->plugin_name = topology->plugin;
  ns->topology = topology;

  struct GNUNET_TESTING_Command cmd = {
    .cls = ns,
    .label = label,
    .run = &netjail_exec_run,
    .ac = &ns->ac,
    .cleanup = &netjail_exec_cleanup,
    .traits = &netjail_exec_traits
  };

  return cmd;
}
