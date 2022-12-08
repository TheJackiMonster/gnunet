/*
      This file is part of GNUnet
      Copyright (C) 2022 GNUnet e.V.

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
 * @file include/gnunet_testing_barrier.h
 * @brief API to manage barriers.
 * @author t3sserakt
 */

#ifndef GNUNET_TESTING_BARRIER_LIB_H
#define GNUNET_TESTING_BARRIER_LIB_H

#include "gnunet_testing_lib.h"
#include "gnunet_testing_netjail_lib.h"

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
   struct GNUNET_TESTING_Command *cmds_head;

  /**
   * Tail of the DLL with local commands the barrier is attached too.
   */
   struct GNUNET_TESTING_Command *cmds_tail;

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
 * Message send to a child loop to inform the child loop about a barrier being advanced.
 */
struct GNUNET_TESTING_CommandBarrierAdvanced
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ADVANCED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The name of the barrier.
   */
  const char *barrier_name;
};

/**
 * Message send by a child loop to inform the master loop how much 
 * GNUNET_CMDS_BARRIER_REACHED messages the child will send.
 */
struct GNUNET_TESTING_CommandBarrierAttached
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The name of the barrier.
   */
  const char *barrier_name;

  /**
   * How often the child loop will reach the barrier.
   */
  unsigned int expected_reaches;

  /**
   * The number of the node the barrier is running on.
   */
  unsigned int node_number;
};


struct GNUNET_TESTING_CommandBarrierReached
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED
   */
  struct GNUNET_MessageHeader header;

  /**
   * The name of the barrier.
   */
  const char *barrier_name;

  /**
   * The number of the node the barrier is reached.
   */
  unsigned int node_number;

  /**
   * The number of reach messages which most likely will send.
   */
  unsigned int expected_number_of_reached_messages;
};


/**
 * Adding a node to the map of nodes of a barrier.
 *
 * @param nodes Map of nodes.
 * @param node The node to add.
 */
void
GNUNET_TESTING_barrier_add_node (struct GNUNET_CONTAINER_MultiShortmap *nodes,
                                 struct GNUNET_TESTING_NetjailNode *node);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_create (
 const char *label,
 double percentage_to_be_reached,
 unsigned int number_to_be_reached);


// Wait for barrier to be reached by all;
// async version implies reached but does not
// wait on other peers to reach it.
/**
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
  TESTING_CMD_HELPER_write_cb write_message);


/**
 * Can we advance the barrier?
 *
 * @param barrier The barrier in question.
 * @return GNUNET_YES if we can advance the barrier, GNUNET_NO if not.
 */
unsigned int
GNUNET_TESTING_can_barrier_advance (struct GNUNET_TESTING_Barrier *barrier);


/**
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
                                     struct GNUNET_TESTING_Barrier *barrier);


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
                                    TESTING_CMD_HELPER_write_cb write_message);


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


#endif
/* end of testing_barrier.h */
