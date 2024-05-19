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
 * @file testing/testing_api_cmd_barrier_reached.c
 * @brief Command to signal barrier was reached.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "testing_api_loop.h"
#include "testing_cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct with information for callbacks.
 *
 */
struct BarrierReachedState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The label of this command.
   */
  const char *label;

  /**
   * The name of the barrier this commands wait (if finishing asynchronous) for or/and reaches.
   */
  const char *barrier_name;

};


/**
 * Run the command.
 *
 * @param cls closure.
 * @param is the interpreter state.
 */
static void
barrier_reached_run (void *cls,
                     struct GNUNET_TESTING_Interpreter *is)
{
  struct BarrierReachedState *brs = cls;
  struct GNUNET_TESTING_Barrier *barrier;

  barrier = GNUNET_TESTING_get_barrier_ (is,
                                         brs->barrier_name);
  if (NULL == barrier)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No barrier `%s'\n",
                brs->barrier_name);
    GNUNET_TESTING_async_fail (&brs->ac);
    return;
  }
  if (barrier->satisfied)
  {
    GNUNET_TESTING_async_finish (&brs->ac);
    return;
  }
  if (barrier->inherited)
  {
    struct GNUNET_TESTING_CommandBarrierReached cbr = {
      .header.size = htons (sizeof (cbr)),
      .header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED)
    };

    GNUNET_TESTING_barrier_name_hash_ (brs->barrier_name,
                                       &cbr.barrier_key);
    GNUNET_TESTING_loop_notify_parent_ (is,
                                        &cbr.header);
    return;
  }
  barrier->reached++;
  if (barrier->reached == barrier->expected_reaches)
  {
    struct GNUNET_TESTING_CommandBarrierSatisfied cbs = {
      .header.size = htons (sizeof (cbs)),
      .header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE)
    };

    GNUNET_TESTING_barrier_name_hash_ (brs->barrier_name,
                                       &cbs.barrier_key);
    barrier->satisfied = true;
    GNUNET_TESTING_loop_notify_children_ (is,
                                          &cbs.header);
  }
  if (barrier->satisfied)
  {
    GNUNET_TESTING_async_finish (&brs->ac);
    return;
  }
  barrier->cmd_ac = &brs->ac;
}


/**
 * Cleanup the state from a "barrier reached" CMD, and possibly
 * cancel a pending operation thereof.
 *
 * @param cls closure.
 */
static void
barrier_reached_cleanup (void *cls)
{
  struct BarrierReachedState *brs = cls;

  GNUNET_free (brs);
}


/**
 * Offer internal data from a "batch" CMD, to other commands.
 *
 * @param cls closure.
 * @param[out] ret result.
 * @param trait name of the trait.
 * @param index index number of the object to offer.
 * @return #GNUNET_OK on success.
 */
static enum GNUNET_GenericReturnValue
barrier_reached_traits (void *cls,
                        const void **ret,
                        const char *trait,
                        unsigned int index)
{
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_reached (
  const char *label,
  const char *barrier_label)
{
  struct BarrierReachedState *brs;

  brs = GNUNET_new (struct BarrierReachedState);
  brs->label = label;
  brs->barrier_name = barrier_label;
  return GNUNET_TESTING_command_new_ac (
    brs,
    label,
    &barrier_reached_run,
    &barrier_reached_cleanup,
    &barrier_reached_traits,
    &brs->ac);
}
