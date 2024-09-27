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
 * @file testing/testing_api_cmd_netjail_start_cmds_helper.c
 * @brief Command to start the netjail peers.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "testing_api_barrier.h"
#include "testing_api_loop.h"
#include "testing_cmds.h"
#include "testing_api_topology.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * Struct containing the number of the netjail node and the NetJailState which
 * will be handed to callbacks specific to a test environment.
 */
struct TestingSystemCount;


/**
 * Struct to store information handed over to callbacks.
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
   * Command with topology data.
   */
  const char *topology_cmd_label;

  /**
   * Array with handles of helper processes.
   */
  struct HelperState **helpers;

  /**
   * Time after this cmd has to finish.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Timeout task.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *tbc_head;

  /**
   * Kept in a DLL.
   */
  struct TestingSystemCount *tbc_tail;

  /**
   * Data about our topology as a string.
   */
  const char *topology_data;

  /**
   * Size of the array @e helpers.
   */
  unsigned int n_helpers;

  /**
   * Counts number of helpers that finished.
   */
  unsigned int n_finished;

  /**
   * Set to true if we already failed the command.
   */
  bool failed;
};

struct HelperState
{
  /**
   * The state of this command.
   */
  struct NetJailState *ns;

  /**
   * The helper handle for this state.
   */
  struct GNUNET_HELPER_Handle *helper;

  /**
   * Did we got a GNUNET_TESTING_CommandLocalFinished message?
   */
  enum GNUNET_GenericReturnValue finished;
};

/**
 * Struct containing the number of the netjail node and the NetJailState which
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
  struct GNUNET_HELPER_SendHandle *shandle;

  /**
   * Struct to store information handed over to callbacks.
   */
  struct NetJailState *ns;


};


/**
 * The network namespace number of a node.
 */
unsigned int node_number;


/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result #GNUNET_OK on success,
 *               #GNUNET_NO if helper process died
 *               #GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
clear_msg (void *cls,
           enum GNUNET_GenericReturnValue result)
{
  struct TestingSystemCount *tbc = cls;
  struct NetJailState *ns = tbc->ns;

  GNUNET_assert (NULL != tbc->shandle);
  tbc->shandle = NULL;
  GNUNET_CONTAINER_DLL_remove (ns->tbc_head,
                               ns->tbc_tail,
                               tbc);
  GNUNET_free (tbc);
  if ( (! ns->failed) &&
       (GNUNET_OK != result) )
  {
    ns->failed = true;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed sending message to helper!\n");
    GNUNET_TESTING_FAIL (ns->is);
  }
}


static void
handle_helper_barrier_reached (
  void *cls,
  const struct GNUNET_TESTING_CommandBarrierReached *rm)
{
  struct HelperState *hs = cls;
  struct NetJailState *ns = hs->ns;
  struct GNUNET_TESTING_Barrier *barrier;

  barrier = GNUNET_TESTING_get_barrier2_ (ns->is,
                                          &rm->barrier_key);
  if (NULL == barrier)
  {
    if (! ns->failed)
    {
      ns->failed = true;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "We did not found the barrier that was supposedly reached.!\n");
      GNUNET_TESTING_async_fail (&ns->ac); 
    }
    return;
  }
  if (barrier->inherited)
  {
    /* pass on to parent */
    GNUNET_TESTING_loop_notify_parent_ (ns->is,
                                        &rm->header);
  }
  else
  {
    barrier->reached++;
    if (barrier->reached == barrier->expected_reaches)
    {
      struct GNUNET_TESTING_CommandBarrierSatisfied cbs = {
        .header.size
          = htons (sizeof (cbs)),
        .header.type
          = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE),
        .barrier_key
          = rm->barrier_key
      };

      GNUNET_assert (! barrier->satisfied);
      barrier->satisfied = true;
      /* unblock children */
      GNUNET_TESTING_loop_notify_children_ (ns->is,
                                            &cbs.header);
      /* unblock self */
      for (unsigned int i = 0; i<barrier->cnt_waiting; i++)
        GNUNET_TESTING_async_finish (barrier->waiting[i]);
      GNUNET_array_grow (barrier->waiting,
                         barrier->cnt_waiting,
                         0);
    }
  }
}


static void
handle_helper_local_finished (
  void *cls,
  const struct GNUNET_TESTING_CommandLocalFinished *lf)
{
  struct HelperState *hs = cls;
  struct NetJailState *ns = hs->ns;

  GNUNET_HELPER_stop (hs->helper, GNUNET_YES);
  hs->finished = GNUNET_YES;
  ns->n_finished++;
  if ( (! ns->failed) &&
       (GNUNET_OK != ntohl (lf->rv)) )
  {
    ns->failed = true;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Helper finished with error!\n");
    GNUNET_TESTING_async_fail (&ns->ac);
    return;
  }
  if (ns->n_finished == ns->n_helpers)
  {
    GNUNET_SCHEDULER_cancel (ns->timeout_task);
    ns->timeout_task = NULL;
    GNUNET_TESTING_async_finish (&ns->ac);
  }
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param message the actual message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static enum GNUNET_GenericReturnValue
helper_mst (void *cls,
            const struct GNUNET_MessageHeader *message)
{
  struct HelperState *hs = cls;
  struct NetJailState *ns = hs->ns;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (
      helper_barrier_reached,
      GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED,
      struct GNUNET_TESTING_CommandBarrierReached,
      hs),
    GNUNET_MQ_hd_fixed_size (
      helper_local_finished,
      GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED,
      struct GNUNET_TESTING_CommandLocalFinished,
      hs),
    GNUNET_MQ_handler_end ()
  };
  enum GNUNET_GenericReturnValue ret;

  ret = GNUNET_MQ_handle_message (handlers,
                                  message);
  if (GNUNET_OK != ret)
  {
    GNUNET_break (0);
    if (! ns->failed)
    {
      ns->failed = true;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "We got an unknown message from the helper process!\n");
      GNUNET_TESTING_async_fail (&ns->ac);
    }
  }
  return ret;
}


/**
 * Callback called if there was an exception during execution of the helper.
 */
static void
exp_cb (void *cls)
{
  struct HelperState *hs = cls;
  struct NetJailState *ns = hs->ns;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Called exp_cb.\n");
  // TODO find in ns->helpers[] and remove???
  hs->helper = NULL;
  hs->finished = GNUNET_YES;
  if (NULL != ns->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ns->timeout_task);
    ns->timeout_task = NULL;
  }
  if (! ns->failed)
    GNUNET_TESTING_async_fail (&ns->ac);
}


static enum GNUNET_GenericReturnValue
add_barrier (void *cls,
             const struct GNUNET_ShortHashCode *key,
             void *value)
{
  struct GNUNET_ShortHashCode **bar_posp = cls;
  struct GNUNET_ShortHashCode *bar_pos = *bar_posp;

  *bar_pos = *key;
  *bar_posp = bar_pos + 1;
  return GNUNET_OK;
}


/**
 * @return true on success
 */
static bool
send_start_messages (struct NetJailState *ns,
                     struct GNUNET_HELPER_Handle *helper)
{
  struct GNUNET_TESTING_CommandHelperInit *msg;
  struct TestingSystemCount *tbc;
  struct GNUNET_ShortHashCode *bar;
  struct GNUNET_ShortHashCode *bar_pos;
  unsigned int num_barriers = GNUNET_TESTING_barrier_count_ (ns->is);
  size_t topo_length;
  size_t msg_len;

  topo_length = strlen (ns->topology_data) + 1;
  GNUNET_assert (topo_length < SIZE_MAX - sizeof (*msg));
  GNUNET_assert (SIZE_MAX / sizeof (struct GNUNET_ShortHashCode) >
                 num_barriers);
  GNUNET_assert (sizeof (*msg) + topo_length <
                 SIZE_MAX
                 - num_barriers * sizeof (struct GNUNET_ShortHashCode));
  msg_len = sizeof (*msg) + topo_length
            + num_barriers * sizeof (struct GNUNET_ShortHashCode);
  if (msg_len > UINT16_MAX)
  {
    /* ask a wizard to enhance the protocol;
       start with gzip topology_data? multiple
       init messages for barriers + topo data,
       etc.*/
    GNUNET_break (0);
    return false;
  }
  msg = GNUNET_malloc (msg_len);
  msg->header.size = htons ((uint16_t) msg_len);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT);
  msg->barrier_count = htonl (num_barriers);
  bar = (struct GNUNET_ShortHashCode *) &msg[1];
  bar_pos = bar;
  GNUNET_TESTING_barrier_iterate_ (ns->is,
                                   &add_barrier,
                                   &bar_pos);
  GNUNET_assert (bar_pos == &bar[num_barriers]);
  memcpy (&bar[num_barriers],
          ns->topology_data,
          topo_length);
  tbc = GNUNET_new (struct TestingSystemCount);
  tbc->ns = ns;
  tbc->shandle = GNUNET_HELPER_send (
    helper,
    &msg->header,
    GNUNET_NO,
    &clear_msg,
    tbc);
  GNUNET_free (msg);
  if (NULL == tbc->shandle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_free (tbc);
    return false;
  }
  GNUNET_CONTAINER_DLL_insert (ns->tbc_head,
                               ns->tbc_tail,
                               tbc);
  return true;
}


/**
 * Function which start a single helper process.
 * @return true on success
 */
static bool
start_helper (struct NetJailState *ns,
              unsigned int script_num)
{
  char *gnunet_cmds_helper
    = GNUNET_OS_get_libexec_binary_path (HELPER_CMDS_BINARY);
  char node_id[32];
  char *data_dir;
  char *script_name;
  struct GNUNET_HELPER_Handle *helper;
  struct HelperState *hs = GNUNET_new (struct HelperState);

  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&script_name,
                   "%s%s",
                   data_dir,
                   NETJAIL_EXEC_SCRIPT);
  GNUNET_snprintf (node_id,
                   sizeof (node_id),
                   "if%06x-%06x\n",
                   (unsigned int) getpid (),
                   script_num);
  {
    char *const script_argv[] = {
      script_name,
      node_id,
      gnunet_cmds_helper,
      node_id,
      NULL
    };
    hs->ns = ns;
    helper = GNUNET_HELPER_start (
                                  GNUNET_YES,                             /* with control pipe */
                                  script_argv[0],
                                  script_argv,
                                  &helper_mst,
                                  &exp_cb,
                                  hs);
    hs->helper = helper;
  }
  GNUNET_free (gnunet_cmds_helper);
  if (NULL == helper)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Starting helper failed. Is NULL.\n");
    GNUNET_break (0);
    GNUNET_free (hs);
    return false;
  }
  GNUNET_array_append (ns->helpers,
                       ns->n_helpers,
                       hs);
  GNUNET_TESTING_add_netjail_helper_ (ns->is,
                                      helper);
  GNUNET_free (data_dir);
  GNUNET_free (script_name);
  return send_start_messages (ns,
                              helper);
}


/**
 * Function run when the cmd terminates (good or bad) with timeout.
 *
 * @param cls the interpreter state
 */
static void
do_timeout (void *cls)
{
  struct NetJailState *ns = cls;

  ns->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Terminating cmd due to global timeout\n");
  GNUNET_TESTING_async_finish (&ns->ac);
}


static int
start_peer (void *cls,
                      const struct GNUNET_ShortHashCode *key,
                      void *value)
{
  struct NetJailState *ns = cls;

  if (! start_helper (ns, node_number))
  {
    return GNUNET_SYSERR;
  }
  node_number++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer helper %u started.\n",
              node_number);
  return GNUNET_OK;
}


static int
start_subnets (void *cls,
                      const struct GNUNET_ShortHashCode *key,
                      void *value)
{
  struct NetJailState *ns = cls;
  struct GNUNET_TESTING_NetjailSubnet *subnet = value;

  node_number++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting subnet %u.\n",
              node_number);
  if (GNUNET_SYSERR == GNUNET_CONTAINER_multishortmap_iterate (subnet->peers,
                                                           &start_peer,
                                                           ns))
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Subnet started.\n");
  return GNUNET_OK;
}


static int
start_carriers (void *cls,
                const struct GNUNET_ShortHashCode *key,
                void *value)
{
  struct NetJailState *ns = cls;
  struct GNUNET_TESTING_NetjailCarrier *carrier = value;

  node_number++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting carrier %u.\n",
              node_number);
  if (GNUNET_SYSERR == GNUNET_CONTAINER_multishortmap_iterate (carrier->peers,
                                                           &start_peer,
                                                           ns))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == GNUNET_CONTAINER_multishortmap_iterate (carrier->subnets,
                                                           &start_subnets,
                                                           ns))
    return GNUNET_SYSERR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Carrier started.\n");
  return GNUNET_OK;
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
  struct GNUNET_TESTING_NetjailTopology *topology;
  bool failed = false;
  const struct GNUNET_TESTING_Command *topo_cmd;

  ns->is = is;
  topo_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                        ns->topology_cmd_label);
  if (NULL == topo_cmd)
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_OK !=
      GNUNET_TESTING_get_trait_topology_string (topo_cmd,
                                                &ns->topology_data))
    GNUNET_TESTING_FAIL (is);
  topology
    = GNUNET_TESTING_get_topo_from_string_ (ns->topology_data);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Number of nodes: %u\n",
       topology->total);
  if (GNUNET_SYSERR == GNUNET_CONTAINER_multishortmap_iterate (topology->backbone_peers,
                                                           &start_peer,
                                                           ns))
    failed = true;
  if (true == failed || GNUNET_SYSERR == GNUNET_CONTAINER_multishortmap_iterate (topology->carriers,
                                                                             &start_carriers,
                                                                             ns))
    failed = true;
  
  GNUNET_TESTING_free_topology (topology);
  if (failed)
  {
    ns->failed = true;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to start helpers!\n");
    GNUNET_TESTING_FAIL (is);
  }
  else
    ns->timeout_task
      = GNUNET_SCHEDULER_add_delayed (ns->timeout,
                                    &do_timeout,
                                    ns);
}


/**
 * Code to clean up resource this cmd used.
 *
 * @param cls closure
 */
static void
netjail_exec_cleanup (void *cls)
{
  struct NetJailState *ns = cls;

  if (NULL != ns->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ns->timeout_task);
    ns->timeout_task = NULL;
  }
  for (unsigned int i = 0; i<ns->n_helpers; i++)
  {
    if (GNUNET_NO == ns->helpers[i]->finished)
      GNUNET_HELPER_stop (ns->helpers[i]->helper,
                          GNUNET_YES);
    GNUNET_free (ns->helpers[i]);
  }
  GNUNET_free (ns);
}


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
netjail_exec_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  struct NetJailState *ns = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_trait_end ()
  };

  (void) ns;
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Create command.
 *
 * @param label Name for the command.
 * @param topology_data topology data
 * @param timeout Before this timeout is reached this cmd MUST finish.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_helpers (
  const char *label,
  const char *topology_cmd_label,
  struct GNUNET_TIME_Relative timeout)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->topology_cmd_label = topology_cmd_label;
  ns->timeout = timeout;
  return GNUNET_TESTING_command_new_ac (ns,
                                        label,
                                        &netjail_exec_run,
                                        &netjail_exec_cleanup,
                                        &netjail_exec_traits,
                                        &ns->ac);
}
