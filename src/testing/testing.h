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

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message send to a child loop to inform the child loop about a barrier being advanced.
 * FIXME: This is not packed and contains a char*... no payload documentation.
 */
struct CommandBarrierAdvanced
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ADVANCED
   */
  struct GNUNET_MessageHeader header;

  /* followed by 0-terminated barrier name */
};

/**
 * Message send by a child loop to inform the master loop how much
 * GNUNET_CMDS_BARRIER_REACHED messages the child will send.
 * FIXME: Not packed and contains char*; int in NBO? bitlength undefined.
 */
struct CommandBarrierAttached
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * How often the child loop will reach the barrier.
   */
  uint32_t expected_reaches GNUNET_PACKED;

  /**
   * The number of the node the barrier is running on.
   */
  uint32_t node_number GNUNET_PACKED;

  /* followed by 0-terminated barrier name */
};

struct GNUNET_TESTING_CommandBarrierReached
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The number of the node the barrier is reached.
   */
  uint32_t node_number GNUNET_PACKED;

  /**
   * The number of reach messages which most likely will send.
   */
  uint32_t expected_number_of_reached_messages GNUNET_PACKED;

  /* followed by 0-terminated barrier name */
};

GNUNET_NETWORK_STRUCT_END

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
 * Advance internal pointer to next command.
 *
 * @param cls batch internal state
 * @return true if we could advance, false if the batch
 *         has completed and cannot advance anymore
 */
bool
GNUNET_TESTING_cmd_batch_next_ (void *cls);


/**
 * Test if this command is a batch command.
 *
 * @return false if not, true if it is a batch command
 */
bool
GNUNET_TESTING_cmd_is_batch_ (const struct GNUNET_TESTING_Command *cmd);


/**
 * Obtain what command the batch is at.
 *
 * @return cmd current batch command
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_cmd_batch_get_current_ (const struct GNUNET_TESTING_Command *cmd);


/**
 * Set what command the batch should be at.  Needed for
 * loops. We may want to change this to take a label
 * and/or expose it in the public API in the future.
 * Not used for now.
 *
 * @param cmd current batch command
 * @param new_ip where to move the IP
 */
void
GNUNET_TESTING_cmd_batch_set_current_ (const struct GNUNET_TESTING_Command *cmd,
                                       unsigned int new_ip);


// Wait for barrier to be reached by all;
// async version implies reached but does not
// wait on other peers to reach it.
/**
 * FIXME: Documentation
 * Create command.
 *
 * @param label name for command.
 * @param barrier_label The name of the barrier we wait for and which will be reached.
 * @param asynchronous_finish If GNUNET_YES this command will not block. Can be NULL.
 * @param asynchronous_finish If GNUNET_YES this command will not block. Can be NULL.
 * @param node_number The global numer of the node the cmd runs on.
 * @param running_on_master Is this cmd running on the master loop.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_reached (
  const char *label,
  const char *barrier_label,
  unsigned int asynchronous_finish,
  unsigned int node_number,
  unsigned int running_on_master,
  GNUNET_TESTING_cmd_helper_write_cb write_message);


/**
 * FIXME: Return type
 * FIXME: Documentation
 * Can we advance the barrier?
 *
 * @param barrier The barrier in question.
 * @return GNUNET_YES if we can advance the barrier, GNUNET_NO if not.
 */
unsigned int
GNUNET_TESTING_can_barrier_advance (struct GNUNET_TESTING_Barrier *barrier);


/**
 * FIXME: Naming
 * Send Message to netjail nodes that a barrier can be advanced.
 *
 * @param is The interpreter loop.
 * @param barrier_name The name of the barrier to advance.
 * @param global_node_number The global number of the node to inform.
 */
void
GNUNET_TESTING_send_barrier_advance (struct GNUNET_TESTING_Interpreter *is,
                                     const char *barrier_name,
                                     unsigned int global_node_number);


/**
 * Finish all "barrier reached" comands attached to this barrier.
 *
 * @param barrier The barrier in question.
 */
void
GNUNET_TESTING_finish_attached_cmds (struct GNUNET_TESTING_Interpreter *is,
                                     const char *barrier_name);


/**
 * Send Message to master loop that cmds being attached to a barrier.
 *
 * @param is The interpreter loop.
 * @param barrier_name The name of the barrier to advance.
 * @param subnet_number The number of the subnet.
 * @param node_number The node to inform.
 * @param write_message Callback to write messages to the master loop.
 */
void
GNUNET_TESTING_send_barrier_attach (struct GNUNET_TESTING_Interpreter *is,
                                     char *barrier_name,
                                    unsigned int global_node_number,
                                    unsigned int expected_reaches,
                                    GNUNET_TESTING_cmd_helper_write_cb write_message);


/**
 * Getting a node from a map by global node number.
 *
 * @param nodes The map.
 * @param node_number The global node number.
 * @return The node.
 */
struct GNUNET_TESTING_NetjailNode *
GNUNET_TESTING_barrier_get_node (struct GNUNET_CONTAINER_MultiShortmap *nodes,
                                 unsigned int node_number);


/**
  * Deleting all barriers create in the context of this interpreter.
  *
  * @param is The interpreter.
  */
void
GNUNET_TESTING_delete_barriers (struct GNUNET_TESTING_Interpreter *is);


/**
 * Getting a barrier from the interpreter.
 *
 * @param is The interpreter.
 * @param barrier_name The name of the barrier.
 * @return The barrier.
 */
struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier (struct GNUNET_TESTING_Interpreter *is,
                            const char *barrier_name);


/**
 * Add a barrier to the loop.
 *
 * @param is The interpreter.
 * @param barrier The barrier to add.
 */
void
GNUNET_TESTING_interpreter_add_barrier (struct GNUNET_TESTING_Interpreter *is,
                                        struct GNUNET_TESTING_Barrier *barrier);


#endif
