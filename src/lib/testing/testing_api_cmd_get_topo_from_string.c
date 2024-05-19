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
 * @file testing/testing_api_cmd_netjail_start.c
 * @brief Command to start the netjail script.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"

struct TopologyState
{
  /**
   * The label of the command.
   */
  char *label;

  /**
   * The topology we parsed.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * A string with the name of the topology file, if @e read_file is true,
   * otherwise a string containing the topology data.
   */
  char *topology_data;

  /**
   * Are we reading from file, or did we get a string with the topology data?
   */
  bool read_file;
}

/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
netjail_topology_cleanup (void *cls)
{
  struct NetJailState *ts = cls;

  GNUNET_free (ts);
}

/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
netjail_topology_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  struct NetJailState *ts = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_get_topology ((const void *) ts->topology),
    GNUNET_TESTING_make_trait_get_topology_string ((const void *) ts->topology_string),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}

/**
* The run method starts the script which setup the network namespaces.
*
* @param cls closure.
* @param is interpreter state.
*/
static void
netjail_topology_run (void *cls,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct TopologyState *ts = cls;

  ts->topology = GNUNET_TESTING_get_topo_from_string (topology_string);
}

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_get_topo_from_string (
                                     const char *label,
                                     char *topology_string)
{
  struct TopologyState *ts;

  ts = GNUNET_new (struct TopologyState);
  ts->label = label;
  ts->topology_string = topology_string;
  return GNUNET_TESTING_command_new_ac (
    ts,
    label,
    &run,
    &cleanup,
    traits,
    &ts->ac);
}
