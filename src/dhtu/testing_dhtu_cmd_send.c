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
 * @file testing/testing_dhtu_cmd_send.c
 * @brief use DHTU to send a message
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"


/**
 * State for the 'send' command.
 */
struct SendState
{

  /**
   * Mandatory context for async commands.
   */
  struct GNUNET_TESTING_AsyncContext ac;

};


/**
 *
 *
 * @param cls a `struct SendState`
 */
static void
send_cleanup (void *cls)
{
  struct SendState *ss = cls;

  GNUNET_free (ss);
}


/**
 * Return trains of the ``send`` command.
 *
 * @param cls closure.
 * @param[out] ret result
 * @param trait name of the trait.
 * @param index index number of the object to offer.
 * @return #GNUNET_OK on success.
 *         #GNUNET_NO if no trait was found
 */
static enum GNUNET_GenericReturnValue
send_traits (void *cls,
             const void **ret,
             const char *trait,
             unsigned int index)
{
  return GNUNET_NO;
}


/**
 * Run the 'send' command.
 *
 * @param cls closure.
 * @param is interpreter state.
 */
static void
send_run (void *cls,
          struct GNUNET_TESTING_Interpreter *is)
{
  struct SendState *ss = cls;

#if 0
  other_cmd = GNUNET_TESTING_interpreter_lookup_command (ss->other_label);
  GNUNET_TESTING_get_trait_XXX (other_cmd,
                                &data);
#endif
  GNUNET_TESTING_async_finish (&ss->ac);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_DHTU_cmd_send (const char *label)
{
  struct SendState *ss;

  ss = GNUNET_new (struct SendState);

  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = ss,
      .label = label,
      .run = &send_run,
      .ac = &ss->ac,
      .cleanup = &send_cleanup,
      .traits = &send_traits
    };

    return cmd;
  }
}
