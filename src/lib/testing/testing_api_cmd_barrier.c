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
#include "gnunet_testing_lib.h"
#include "barrier.h"
#include "testing_api_loop.h"


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
  struct GNUNET_TESTING_Barrier *barrier = cls;

  GNUNET_free (barrier);
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
  struct GNUNET_TESTING_Barrier *barrier = cls;

  GNUNET_TESTING_add_barrier_ (is,
                               barrier);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_barrier_create (
  const char *label,
  unsigned int number_to_be_reached)
{
  struct GNUNET_TESTING_Barrier *barrier;

  barrier = GNUNET_new (struct GNUNET_TESTING_Barrier);
  GNUNET_TESTING_barrier_name_hash_ (label,
                                     &barrier->barrier_id);
  barrier->expected_reaches = number_to_be_reached;
  return GNUNET_TESTING_command_new (barrier,
                                     label,
                                     &barrier_run,
                                     &barrier_cleanup,
                                     &barrier_traits);
}
