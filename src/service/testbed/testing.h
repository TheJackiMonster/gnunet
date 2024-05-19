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
 * @author t3sserakt
 */
#ifndef TESTING_H
#define TESTING_H
#include "gnunet_util_lib.h"
#include "gnunet_testing_plugin.h"


/**
 * Handle for a plugin.
 */
struct TestcasePlugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_TESTING_PluginFunctions *api;

  /**
   * IP address of the specific node the helper is running for.
   *
   */
  char *node_ip;

  /**
   * Name of the test case plugin.
   *
   */
  char *plugin_name;

  /**
   * The number of namespaces
   *
   */
  char *global_n;

  /**
   * The number of local nodes per namespace.
   *
   */
  char *local_m;

  /**
   * The number of the namespace this node is in.
   *
   */
  char *n;

  /**
   * The number of the node in the namespace.
   *
   */
  char *m;
};

struct CommandListEntry
{
  struct CommandListEntry *next;

  struct CommandListEntry *prev;

  struct GNUNET_TESTING_Command *command;
};


struct GNUNET_TESTING_Barrier
{
  /**
   * Pointer to the previous prefix in the DLL.
   */
  struct GNUNET_TESTING_Barrier *prev;

  /**
   * Pointer to the next prefix in the DLL.
   */
  struct GNUNET_TESTING_Barrier *next;

  /**
   * Head of the DLL with local commands the barrier is attached too.
   */
  struct CommandListEntry *cmds_head;

  /**
   * Tail of the DLL with local commands the barrier is attached too.
   */
  struct CommandListEntry *cmds_tail;

  /**
   * Hash map containing the global known nodes which are not natted.
   */
  struct GNUNET_CONTAINER_MultiShortmap *nodes;

  /**
   * Name of the barrier.
   */
  const char *name;

  /**
   * Is this barrier running on the master.
   */
  unsigned int running_on_master;

  /**
   * Number of commands attached to this barrier.
   */
  unsigned int expected_reaches;

  /**
   * Number of commands which reached this barrier.
   */
  unsigned int reached;

  /**
   * Percentage of of commands which need to reach the barrier to change state.
   * Can not be used together with to_be_reached;
   */
  double percentage_to_be_reached;

  /**
   * Number of commands which need to reach the barrier to change state.
   * Can not be used together with percentage_to_be_reached;
   */
  unsigned int number_to_be_reached;

  /*
   * No barrier locally. Shadow created. Real barrier created elsewhere.
   */
  unsigned int shadow;
};


/**
 * Call #op on all simple traits.
 */
#define GNUNET_TESTING_SIMPLE_TESTBED_TRAITS(op, prefix)                            \
        op (prefix, get_topology, const struct GNUNET_TESTING_NetjailTopology)            \
        op (prefix, get_topology_string, const char *)                                           \
        op (prefix, test_system, const struct GNUNET_TESTING_System)                      \
        op (prefix, async_context, struct GNUNET_TESTING_AsyncContext)                    \
        op (prefix, helper_handles, const struct GNUNET_HELPER_Handle *)                  \
        op (prefix, block_state, struct GNUNET_TESTING_BlockState)

GNUNET_TESTING_SIMPLE_TESTBED_TRAITS (GNUNET_TESTING_MAKE_DECL_SIMPLE_TRAIT,
                                      GNUNET_TESTING)


#endif
