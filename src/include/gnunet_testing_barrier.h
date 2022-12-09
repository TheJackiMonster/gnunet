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

#define GNUNET_TESTING_BARRIER_MAX 32

#include "gnunet_testing_plugin.h"

/**
 * A testing barrier
 * FIXME better description
 */
struct GNUNET_TESTING_Barrier;

/**
 * An entry for a barrier list
 */
struct GNUNET_TESTING_BarrierListEntry
{
  /* DLL */
  struct GNUNET_TESTING_BarrierListEntry *next;

  /* DLL */
  struct GNUNET_TESTING_BarrierListEntry *prev;

  /* The barrier */
  struct GNUNET_TESTING_Barrier *barrier;
};

/**
 * A list to hold barriers provided by plugins
 */
struct GNUNET_TESTING_BarrierList
{
  /** List head **/
  struct GNUNET_TESTING_BarrierListEntry *head;

  /** List tail **/
  struct GNUNET_TESTING_BarrierListEntry *tail;
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
 * Create a new #GNUNET_TESTING_Barrier
 */
struct GNUNET_TESTING_Barrier*
GNUNET_TESTING_barrier_new (const char *testcase_name);

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
  GNUNET_TESTING_cmd_helper_write_cb write_message);


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


#endif
/* end of testing_barrier.h */
