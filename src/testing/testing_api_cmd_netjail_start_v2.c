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
 * @brief Command to start the netjail script.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

#define NETJAIL_START_SCRIPT "./../testing/netjail_start_v2.sh"

/**
 * Struct to hold information for callbacks.
 *
 */
struct NetJailState
{
  // Child Wait handle
  struct GNUNET_ChildWaitHandle *cwh;

  /**
   * Configuration file for the test topology.
   */
  char *topology_config;

  /**
   * The process id of the start script.
   */
  struct GNUNET_OS_Process *start_proc;

  // Flag indication if the script finished.
  // FIXME: document 3 values
  enum GNUNET_GenericReturnValue finished;
};


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
netjail_start_cleanup (void *cls,
                       const struct GNUNET_TESTING_Command *cmd)
{
  struct NetJailState *ns = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "netjail_start_cleanup!\n");

  if (NULL != ns->cwh)
  {
    GNUNET_wait_child_cancel (ns->cwh);
    ns->cwh = NULL;
  }
  if (NULL != ns->start_proc)
  {
    GNUNET_assert (0 ==
                   GNUNET_OS_process_kill (ns->start_proc,
                                           SIGKILL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_OS_process_wait (ns->start_proc));
    GNUNET_OS_process_destroy (ns->start_proc);
    ns->start_proc = NULL;
  }
  GNUNET_free (ns);
}


/**
 * Trait function of this cmd does nothing.
 *
 */
static int
netjail_start_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  return GNUNET_OK;
}


/**
 * Callback which will be called if the setup script finished.
 *
 */
static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  struct NetJailState *ns = cls;

  if (0 == exit_code)
  {
    ns->finished = GNUNET_YES;
  }
  else
  {
    // FIXME: log status code
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Child completed with an error!\n");
    ns->finished = GNUNET_SYSERR;
  }
  GNUNET_OS_process_destroy (ns->start_proc);
  ns->start_proc = NULL;
}



/**
* The run method starts the script which setup the network namespaces.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
netjail_start_run (void *cls,
                   const struct GNUNET_TESTING_Command *cmd,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;
  char pid[15];
  enum GNUNET_GenericReturnValue helper_check;

  // FIXME: NETJAIL_START_SCRIPT like this is bad,
  // use location from share/gnunet/ of installed
  // binary in case libgnunettesting is used as a lib!
  helper_check = GNUNET_OS_check_helper_binary (
    NETJAIL_START_SCRIPT,
    GNUNET_YES,
    NULL);

  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                NETJAIL_START_SCRIPT);
    GNUNET_TESTING_interpreter_fail ();
    return;
  }
  if (GNUNET_SYSERR == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                NETJAIL_START_SCRIPT);
    GNUNET_TESTING_interpreter_fail ();
    return;
  }

  GNUNET_snprintf (pid,
                   sizeof (pid),
                   "%u",
                   getpid ());
  {
    char *const script_argv[] = {
      NETJAIL_START_SCRIPT,
      ns->topology_config,
      pid,
      NULL
    };
    
    ns->start_proc
      = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ERR,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NETJAIL_START_SCRIPT,
                                     script_argv);
  }
  ns->cwh = GNUNET_wait_child (ns->start_proc,
                               &child_completed_callback,
                               ns);
  GNUNET_break (NULL != ns->cwh);
}


/**
 * This function checks the flag NetJailState
 * 
 * FIXME: fix comment!
 * #finished, if this cmd finished.
 *
 */
static enum GNUNET_GenericReturnValue
netjail_start_finish (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  struct NetJailState *ns = cls;

  if (GNUNET_NO != ns->finished)
  {
    cont (cont_cls);
  }
  // FIXME: cont should be called later in the else case!
  return ns->finished;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param topology_config Configuration file for the test topology.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_v2 (const char *label,
                                     char *topology_config)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->topology_config = topology_config;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = ns,
      .label = label,
      .run = &netjail_start_run,
      .finish = &netjail_start_finish,
      .cleanup = &netjail_start_cleanup,
      .traits = &netjail_start_traits
    };

    return cmd;
  }
}
