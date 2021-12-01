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
#include "gnunet_testing_netjail_lib.h"
#include "testing_cmds.h"


/**
 * Struct to store information handed over to callbacks.
 *
 */
struct StopHelperState
{

  /**
   * The complete topology information.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  const char *helper_start_label;

  /**
   * The process handle
   */
  struct GNUNET_HELPER_Handle **helper;

  unsigned int local_m;

  unsigned int global_n;

  /**
   * Number of global known nodes.
   *
   */
  unsigned int known;
};


/**
* Code to clean up resource this cmd used.
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
stop_testing_system_cleanup (void *cls)
{
  struct StopHelperState *shs = cls;

  GNUNET_free (shs);
}


/**
* This function stops the helper process for each node.
*
* @param cls closure.
* @param is interpreter state.
*/
static void
stop_testing_system_run (void *cls,
                         struct GNUNET_TESTING_Interpreter *is)
{
  struct StopHelperState *shs = cls;
  const struct GNUNET_HELPER_Handle **helper;
  const struct GNUNET_TESTING_Command *start_helper_cmd;

  start_helper_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                                shs->
                                                                helper_start_label);
  GNUNET_TESTING_get_trait_helper_handles (start_helper_cmd,
                                           &helper);

  for (int i = 1; i <= shs->known; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "i: %u\n",
                i);
    GNUNET_HELPER_stop (helper[i - 1],
                        GNUNET_YES);
  }

  for (int i = 1; i <= shs->global_n; i++)
  {
    for (int j = 1; j <= shs->local_m; j++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "i: %u j: %u\n",
                  i,
                  j);
      GNUNET_HELPER_stop (helper[(i - 1) * shs->local_m + j + shs->known - 1],
                          GNUNET_YES);
    }
  }
}


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
  struct GNUNET_TESTING_NetjailTopology *topology)
{
  struct StopHelperState *shs;

  shs = GNUNET_new (struct StopHelperState);
  shs->helper_start_label = helper_start_label;
  shs->local_m = topology->nodes_m;
  shs->global_n = topology->namespaces_n;
  shs->known = topology->nodes_x;
  shs->topology = topology;

  struct GNUNET_TESTING_Command cmd = {
    .cls = shs,
    .label = label,
    .run = &stop_testing_system_run,
    .cleanup = &stop_testing_system_cleanup,
  };

  return cmd;
}
