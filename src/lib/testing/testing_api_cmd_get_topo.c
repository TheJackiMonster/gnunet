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
 * @file testing/testing_api_cmd_get_topo.c
 * @brief Command to start the netjail script.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "testing_api_topology.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log_from (kind, "udp-backchannel",__VA_ARGS__)

struct TopologyState
{
  /**
   * The label of the command.
   */
  const char *label;

  /**
   * The topology we parsed.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * A string with the name of the topology file, if @e read_file is true,
   * otherwise a string containing the topology data.
   */
  const char *topology_string;

  /**
   * Same as @e topology_string, but set if we need
   * to release the memory.
   */
  char *topology_alloc;

  /**
   * A string with the name of the topology file.
   */
  const char *file_name;
};

/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
cleanup (void *cls)
{
  struct TopologyState *ts = cls;

  if (NULL != ts->topology)
  {
    GNUNET_TESTING_free_topology (ts->topology);
    ts->topology = NULL;
  }
  GNUNET_free (ts->topology_alloc);
  GNUNET_free (ts);
}


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
traits (void *cls,
        const void **ret,
        const char *trait,
        unsigned int index)
{
  struct TopologyState *ts = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_topology (ts->topology),
    GNUNET_TESTING_make_trait_topology_string (ts->topology_string),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static char *
get_topo_string_from_file (const char *topology_data_file)
{
  uint64_t fs;
  char *data;

  if (GNUNET_YES !=
      GNUNET_DISK_file_test (topology_data_file))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Topology file %s not found\n",
         topology_data_file);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (topology_data_file,
                             &fs,
                             GNUNET_YES,
                             GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Could not determine size of topology file %s\n",
         topology_data_file);
    return NULL;
  }
  data = GNUNET_malloc_large (fs + 1);
  GNUNET_assert (NULL != data);
  if (fs !=
      GNUNET_DISK_fn_read (topology_data_file,
                           data,
                           fs))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Topology file %s cannot be read\n",
         topology_data_file);
    GNUNET_free (data);
    return NULL;
  }
  return data;
}


/**
 * The run method starts the script which setup the network namespaces.
 *
 * @param cls closure.
 * @param is interpreter state.
 */
static void
run (void *cls,
     struct GNUNET_TESTING_Interpreter *is)
{
  struct TopologyState *ts = cls;

  if (NULL == ts->topology_string)
  {
    ts->topology_alloc
      = get_topo_string_from_file (ts->file_name);
    if (NULL == ts->topology_alloc)
      GNUNET_TESTING_FAIL (is);
    ts->topology_string = ts->topology_alloc;
  }
  ts->topology
    = GNUNET_TESTING_get_topo_from_string_ (ts->topology_string);
  if (NULL == ts->topology)
    GNUNET_TESTING_FAIL (is);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_load_topology_from_file (
  const char *label,
  const char *file_name)
{
  struct TopologyState *ts;

  ts = GNUNET_new (struct TopologyState);
  ts->label = label;
  ts->file_name = file_name;
  return GNUNET_TESTING_command_new_ac (
    ts,
    label,
    &run,
    &cleanup,
    traits,
    NULL);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_load_topology_from_string (
  const char *label,
  const char *topology_string)
{
  struct TopologyState *ts;

  GNUNET_assert (NULL != topology_string);
  ts = GNUNET_new (struct TopologyState);
  ts->label = label;
  if (NULL != topology_string)
  {
    ts->topology_alloc = GNUNET_strdup (topology_string);
    ts->topology_string = ts->topology_alloc;
  }
  return GNUNET_TESTING_command_new_ac (
    ts,
    label,
    &run,
    &cleanup,
    traits,
    NULL);
}
