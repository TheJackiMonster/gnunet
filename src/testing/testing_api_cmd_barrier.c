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
 * @file testing/testing_api_cmd_barrier.c
 * @brief Barrier functionality.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_barrier.h"

struct BarrierState
{
  /*
   * Our barrier.
   */
  struct GNUNET_TESTING_Barrier *barrier;

    /*
   * Our label.
   */
  const char *label;
};


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
                                    TESTING_CMD_HELPER_write_cb write_message)
{
  struct GNUNET_TESTING_CommandBarrierAttached *atm = GNUNET_new (struct GNUNET_TESTING_CommandBarrierAttached);
  size_t msg_length = sizeof(struct GNUNET_TESTING_CommandBarrierAttached);

  atm->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED);
  atm->header.size = htons ((uint16_t) msg_length);
  atm->barrier_name = barrier_name;
  atm->expected_reaches = expected_reaches;
  atm->node_number = global_node_number;
  write_message ((struct GNUNET_MessageHeader *) atm, msg_length);

  GNUNET_free (atm);
}


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
                                     unsigned int global_node_number)
{
  struct GNUNET_TESTING_CommandBarrierAdvanced *adm = GNUNET_new (struct GNUNET_TESTING_CommandBarrierAdvanced);
  size_t msg_length = sizeof(struct GNUNET_TESTING_CommandBarrierAdvanced);

  adm->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ADVANCED);
  adm->header.size = htons ((uint16_t) msg_length);
  adm->barrier_name = barrier_name;
  GNUNET_TESTING_send_message_to_netjail (is,
                                         global_node_number,
                                         &adm->header);
  GNUNET_free (adm);
}


/**
 * Can we advance the barrier?
 *
 * @param barrier The barrier in question.
 * @return GNUNET_YES if we can advance the barrier, GNUNET_NO if not.
 */
unsigned int
GNUNET_TESTING_can_barrier_advance (struct GNUNET_TESTING_Barrier *barrier)
{
  unsigned int expected_reaches = barrier->expected_reaches;
  unsigned int reached = barrier->reached;
  double percentage_to_be_reached = barrier->percentage_to_be_reached;
  unsigned int number_to_be_reached = barrier->number_to_be_reached;

  if ((0 < percentage_to_be_reached &&
       (double)expected_reaches/reached*100) >= percentage_to_be_reached ||
      (0 < number_to_be_reached && reached >= number_to_be_reached ))
  {
    return GNUNET_YES;
  }
  else
  {
    return GNUNET_NO;
  }
}


/**
 * Offer internal data from a "barrier" CMD, to other commands.
 *
 * @param cls closure.
 * @param[out] ret result.
 * @param trait name of the trait.
 * @param index index number of the object to offer.
 * @return #GNUNET_OK on success.
 */
static enum GNUNET_GenericReturnValue
barrier_traits (void *cls,
              const void **ret,
              const char *trait,
              unsigned int index)
{
  struct BarrierState *bs = cls;

  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_trait_end ()
  };

  /* Always return current command.  */
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}

/**
 * Cleanup the state from a "barrier" CMD, and possibly
 * cancel a pending operation thereof.
 *
 * @param cls closure.
 */
static void
barrier_cleanup (void *cls)
{
  struct BarrierState *brs = cls;

  GNUNET_free (brs->barrier);
  GNUNET_free (brs);
}

/**
 * Run the command.
 *
 * @param cls closure.
 * @param is the interpreter state.
 */
static void
barrier_run (void *cls,
           struct GNUNET_TESTING_Interpreter *is)
{
  struct BarrierState *brs = cls;

  GNUNET_TESTING_barrier_add (is, brs->barrier);
}

/**
 * Adding a node to the map of nodes of a barrier.
 *
 * @param nodes Map of nodes.
 * @param node The node to add.
 */
void
GNUNET_TESTING_barrier_add_node (struct GNUNET_CONTAINER_MultiShortmap *nodes,
                                 struct GNUNET_TESTING_NetjailNode *node)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode key;

  GNUNET_CRYPTO_hash (&(node->node_number), sizeof(node->node_number), &hc);
  memcpy (&key, &hc, sizeof (key));
  GNUNET_CONTAINER_multishortmap_put (nodes,
                                      &key,
                                      node,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
}


/**
 * Getting a node from a map by global node number.
 *
 * @param nodes The map.
 * @param node_number The global node number.
 * @return The node.
 */
struct GNUNET_TESTING_NetjailNode *
GNUNET_TESTING_barrier_get_node (struct GNUNET_CONTAINER_MultiShortmap *nodes,
                                 unsigned int node_number)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode *key;

  GNUNET_CRYPTO_hash (&(node_number), sizeof(node_number), &hc);
  memcpy (&key,
              &hc,
              sizeof (key));
  return GNUNET_CONTAINER_multishortmap_get (nodes, key);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_create (const char *label,
 double percentage_to_be_reached,
 unsigned int number_to_be_reached)
{
  struct GNUNET_TESTING_Barrier *barrier;
  struct BarrierState *bs;

  bs = GNUNET_new (struct BarrierState);
  bs->label = label;
  barrier = GNUNET_new (struct GNUNET_TESTING_Barrier);
  barrier->name = label;
  GNUNET_assert (0 < percentage_to_be_reached && 0 == number_to_be_reached ||
                 0 ==  percentage_to_be_reached && 0 < number_to_be_reached);
  barrier->percentage_to_be_reached;
  barrier->number_to_be_reached;
  bs->barrier = barrier;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = bs,
      .label = label,
      .run = &barrier_run,
      .cleanup = &barrier_cleanup,
      .traits = &barrier_traits
    };

    return cmd;
  }
}
