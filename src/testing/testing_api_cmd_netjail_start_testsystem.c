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
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * Pointer to the return value of the test.
   *
   */
  unsigned int *rv;

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
   * Number of nodes in a network namespace. //TODO make this a unsigned int
   *
   */
  char *local_m;

  /**
   * Number of network namespaces. //TODO make this a unsigned int
   *
   */
  char *global_n;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle **shandle;

  /**
   * Size of the array NetJailState#shandle.
   *
   */
  unsigned int n_shandle;

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
  unsigned int number_of_local_test_finished;

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
                                         struct GNUNET_HELPER_Handle ***helper)
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

  GNUNET_assert (NULL != ns->shandle[tbc->count - 1]);
  ns->shandle[tbc->count - 1] = NULL;
  GNUNET_free (ns->msg[tbc->count - 1]);
  ns->msg[tbc->count - 1] = NULL;
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
  struct TestingSystemCount *tbc = cls;
  struct NetJailState *ns = tbc->ns;
  struct HelperMessage *hp_msg;

  if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY == ntohs (message->type))
  {
    ns->number_of_testsystems_started++;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED == ntohs (
             message->type))
  {
    ns->number_of_peers_started++;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED == ntohs (
             message->type))
  {
    ns->number_of_local_test_finished++;
  }
  else
  {
    hp_msg = GNUNET_new (struct HelperMessage);
    hp_msg->bytes_msg = message->size;
    memcpy (&hp_msg[1], message, message->size);
    GNUNET_CONTAINER_DLL_insert (ns->hp_messages_head, ns->hp_messages_tail,
                                 hp_msg);
  }

  return GNUNET_OK;
}


/**
 * Callback called if there was an exception during execution of the helper.
 *
 */
static void
exp_cb (void *cls)
{
  struct NetJailState *ns = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
  *ns->rv = 1;
}


/**
 * Function to initialize a init message for the helper.
 *
 * @param m_char The actual node in a namespace. //TODO Change this to unsigned int
 * @param n_char The actual namespace. //TODO Change this to unsigned int
 * @param plugin_name Name of the test case plugin the helper will load.
 *
 */
static struct GNUNET_CMDS_HelperInit *
create_helper_init_msg_ (char *m_char,
                         char *n_char,
                         const char *plugin_name)
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
start_helper (struct NetJailState *ns, struct
              GNUNET_CONFIGURATION_Handle *config,
              char *m_char,
              char *n_char)
{
  struct GNUNET_HELPER_Handle *helper;
  struct GNUNET_CMDS_HelperInit *msg;
  struct TestingSystemCount *tbc;
  char *const script_argv[] = {
    NETJAIL_EXEC_SCRIPT,
    m_char,
    n_char,
    GNUNET_OS_get_libexec_binary_path (
      HELPER_CMDS_BINARY),
    ns->global_n,
    ns->local_m,
    NULL
  };
  unsigned int m = atoi (m_char);
  unsigned int n = atoi (n_char);
  unsigned int helper_check = GNUNET_OS_check_helper_binary (
    NETJAIL_EXEC_SCRIPT,
    GNUNET_YES,
    NULL);

  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;
  tbc->count = (n - 1) * atoi (ns->local_m) + m;

  GNUNET_CONTAINER_DLL_insert (ns->tbcs_head, ns->tbcs_tail,
                               tbc);


  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                NETJAIL_EXEC_SCRIPT);
    *ns->rv = 1;
  }
  else if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                NETJAIL_EXEC_SCRIPT);
    *ns->rv = 1;
  }
  GNUNET_array_append (ns->helper,
                       ns->n_helper,
                       GNUNET_HELPER_start (
                         GNUNET_YES,
                         NETJAIL_EXEC_SCRIPT,
                         script_argv,
                         &helper_mst,
                         &exp_cb,
                         tbc));

  helper = ns->helper[tbc->count - 1];

  msg = create_helper_init_msg_ (m_char,
                                 n_char,
                                 ns->plugin_name);
  GNUNET_array_append (ns->msg, ns->n_msg, &msg->header);

  GNUNET_array_append (ns->shandle, ns->n_shandle, GNUNET_HELPER_send (
                         helper,
                         &msg->header,
                         GNUNET_NO,
                         &clear_msg,
                         tbc));

  if (NULL == ns->shandle[tbc->count - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_free (msg);
    *ns->rv = 1;
  }
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
  char str_m[12];
  char str_n[12];
  struct NetJailState *ns = cls;
  struct GNUNET_CONFIGURATION_Handle *config =
    GNUNET_CONFIGURATION_create ();

  for (int i = 1; i <= atoi (ns->global_n); i++)
  {
    for (int j = 1; j <= atoi (ns->local_m); j++)
    {
      sprintf (str_n, "%d", i);
      sprintf (str_m, "%d", j);
      start_helper (ns, config,
                    str_m,
                    str_n);
    }
  }
}


/**
 * This function checks on three different information.
 *
 * 1. Did all helpers start. This is only logged.
 * 2. Did all peer start.
 *    In this case a GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED is send to all peers.
 * 3. Did all peers finished the test case. In this case interpreter_next will be called.
 *
 * => FIXME: must change _completely_.
 */
static int
netjail_start_finish (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  unsigned int ret = GNUNET_NO;
  struct NetJailState *ns = cls;
  unsigned int total_number = atoi (ns->local_m) * atoi (ns->global_n);
  struct GNUNET_CMDS_ALL_PEERS_STARTED *reply;
  size_t msg_length;
  struct GNUNET_HELPER_Handle *helper;
  struct TestingSystemCount *tbc;

  if (ns->number_of_local_test_finished == total_number)
  {
    ret = GNUNET_YES;
    cont (cont_cls);
  }

  if (ns->number_of_testsystems_started == total_number)
  {
    ns->number_of_testsystems_started = 0;
  }

  if (ns->number_of_peers_started == total_number)
  {
    for (int i = 1; i <= atoi (ns->global_n); i++)
    {
      for (int j = 1; j <= atoi (ns->local_m); j++)
      {
        tbc = GNUNET_new (struct TestingSystemCount);
        tbc->ns = ns;
        // TODO This needs to be more generic. As we send more messages back and forth, we can not grow the arrays again and again, because this is to error prone.
        tbc->count = (i - 1) * atoi (ns->local_m) + j + total_number;

        helper = ns->helper[tbc->count - 1 - total_number];
        msg_length = sizeof(struct GNUNET_CMDS_ALL_PEERS_STARTED);
        reply = GNUNET_new (struct GNUNET_CMDS_ALL_PEERS_STARTED);
        reply->header.type = htons (
          GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED);
        reply->header.size = htons ((uint16_t) msg_length);

        GNUNET_array_append (ns->msg, ns->n_msg, &reply->header);

        struct GNUNET_HELPER_SendHandle *sh = GNUNET_HELPER_send (
          helper,
          &reply->header,
          GNUNET_NO,
          &clear_msg,
          tbc);

        GNUNET_array_append (ns->shandle, ns->n_shandle, sh);
      }
    }
    ns->number_of_peers_started = 0;
  }
  return ret;
}


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param local_m Number of nodes in a network namespace. //TODO make this a unsigned int
 * @param global_n Number of network namespaces. //TODO make this a unsigned int
 * @param plugin_name Name of the test case plugin the helper will load.
 * @param rv Pointer to the return value of the test.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system (const char *label,
                                                 char *local_m,
                                                 char *global_n,
                                                 char *plugin_name,
                                                 unsigned int *rv)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->local_m = local_m;
  ns->global_n = global_n;
  ns->plugin_name = plugin_name;
  ns->rv = rv;

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
