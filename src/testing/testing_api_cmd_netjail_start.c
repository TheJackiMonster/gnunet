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

#define NETJAIL_START_SCRIPT "./../testing/netjail_start.sh"

/**
 * Struct to hold information for callbacks.
 *
 */
struct NetJailState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  // Child Wait handle
  struct GNUNET_ChildWaitHandle *cwh;

  // Number of local nodes in each namespace.
  char *local_m;

  // The number of namespaces.
  char *global_n;

  /**
   * The process id of the start script.
   */
  struct GNUNET_OS_Process *start_proc;
};


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
netjail_start_cleanup (void *cls)
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
 * Callback which will be called if the setup script finished.
 *
 */
static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  struct NetJailState *ns = cls;

  GNUNET_OS_process_destroy (ns->start_proc);
  ns->start_proc = NULL;
  if (0 == exit_code)
  {
    GNUNET_TESTING_async_finish (&ns->ac);
  }
  else
  {
    // FIXME: log status code
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Child completed with an error!\n");
    GNUNET_TESTING_async_fail (&ns->ac);
  }
}


/**
* The run method starts the script which setup the network namespaces.
*
* @param cls closure.
* @param is interpreter state.
*/
static void
netjail_start_run (void *cls,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;
  char *const script_argv[] = {
    NETJAIL_START_SCRIPT,
    ns->local_m,
    ns->global_n,
    NULL
  };
  unsigned int helper_check = GNUNET_OS_check_helper_binary (
    NETJAIL_START_SCRIPT,
    GNUNET_YES,
    NULL);

  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No SUID for %s!\n",
                NETJAIL_START_SCRIPT);
    GNUNET_TESTING_interpreter_fail (is);
  }
  else if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                NETJAIL_START_SCRIPT);
    GNUNET_TESTING_interpreter_fail (is);
  }

  ns->start_proc = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ERR,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NETJAIL_START_SCRIPT,
                                                script_argv);

  ns->cwh = GNUNET_wait_child (ns->start_proc,
                               &child_completed_callback,
                               ns);
  GNUNET_break (NULL != ns->cwh);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param local_m Number of local nodes in each namespace.
 * @param global_n The number of namespaces.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start (const char *label,
                                  char *local_m,
                                  char *global_n)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->local_m = local_m;
  ns->global_n = global_n;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = ns,
      .label = label,
      .run = &netjail_start_run,
      .ac = &ns->ac,
      .cleanup = &netjail_start_cleanup
    };

    return cmd;
  }
}
