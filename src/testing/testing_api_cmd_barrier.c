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
#include "testing.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_testing_barrier.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

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

// FIXME Unused function
void
GNUNET_TESTING_send_barrier_attach (struct GNUNET_TESTING_Interpreter *is,
                                    char *barrier_name,
                                    unsigned int global_node_number,
                                    unsigned int expected_reaches,
                                    GNUNET_TESTING_cmd_helper_write_cb
                                    write_message)
{
  struct CommandBarrierAttached *atm = GNUNET_new (struct
                                                   CommandBarrierAttached);
  size_t msg_length = sizeof(struct CommandBarrierAttached);
  size_t name_len;

  name_len = strlen (barrier_name) + 1;
  atm->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED);
  atm->header.size = htons ((uint16_t) msg_length);
  atm->expected_reaches = expected_reaches;
  atm->node_number = global_node_number;
  memcpy (&atm[1], barrier_name, name_len);
  write_message ((struct GNUNET_MessageHeader *) atm, msg_length);

  GNUNET_free (atm);
}


unsigned int
GNUNET_TESTING_barrier_crossable (struct GNUNET_TESTING_Barrier *barrier)
{
  unsigned int expected_reaches = barrier->expected_reaches;
  unsigned int reached = barrier->reached;
  double percentage_to_be_reached = barrier->percentage_to_be_reached;
  unsigned int number_to_be_reached = barrier->number_to_be_reached;
  double percentage_reached = (double) reached / expected_reaches * 100;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%u %f %f %u %u\n",
       expected_reaches,
       percentage_to_be_reached,
       percentage_reached,
       number_to_be_reached,
       reached);

  if (((0 < percentage_to_be_reached) &&
       (percentage_reached >= percentage_to_be_reached)) ||
      ((0 < number_to_be_reached) && (reached >= number_to_be_reached)))
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

  TST_interpreter_add_barrier (is, brs->barrier);
}

struct GNUNET_TESTING_NetjailNode *
GNUNET_TESTING_barrier_get_node (struct GNUNET_TESTING_Barrier *barrier,
                                 unsigned int node_number)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode key;

  GNUNET_CRYPTO_hash (&(node_number), sizeof(node_number), &hc);
  memcpy (&key,
          &hc,
          sizeof (key));
  return GNUNET_CONTAINER_multishortmap_get (barrier->nodes, &key);
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
  barrier->percentage_to_be_reached = percentage_to_be_reached;
  barrier->number_to_be_reached = number_to_be_reached;
  GNUNET_assert ((0 < percentage_to_be_reached && 0 == number_to_be_reached) ||
                 (0 ==  percentage_to_be_reached && 0 < number_to_be_reached));
  bs->barrier = barrier;
  return GNUNET_TESTING_command_new (bs, label,
                                     &barrier_run,
                                     &barrier_cleanup,
                                     &barrier_traits,
                                     NULL);
}
