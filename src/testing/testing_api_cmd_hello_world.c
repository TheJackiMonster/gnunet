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
 * @file testing/testing_api_cmd_hello_world.c
 * @brief implementation of a hello world command.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"

struct HelloWorldState
{
  char *message;
  const char *birthLabel;
};


/**
 *
 *
 * @param cls closure
 */
static void
hello_world_cleanup (void *cls)
{
  struct HelloWorldState *hs = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Cleaning up message %s\n",
              hs->message);
  GNUNET_free (hs);
}


/**
 *
 *
 * @param cls closure.
 * @param[out] ret result
 * @param trait name of the trait.
 * @param index index number of the object to offer.
 * @return #GNUNET_OK on success.
 */
static enum GNUNET_GenericReturnValue
hello_world_traits (void *cls,
                    const void **ret,
                    const char *trait,
                    unsigned int index)
{
  return GNUNET_NO;
}


/**
* Run the "hello world" CMD.
*
* @param cls closure.
* @param is interpreter state.
*/
static void
hello_world_run (void *cls,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct HelloWorldState *hs = cls;
  const struct GNUNET_TESTING_Command *birth_cmd;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%s\n",
              hs->message);
  birth_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         hs->birthLabel);
  GNUNET_TESTING_get_trait_what_am_i (birth_cmd,
                                      &hs->message);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Now I am a %s\n",
              hs->message);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param message initial message.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world (const char *label,
                                const char *birthLabel,
                                char *message)
{
  struct HelloWorldState *hs;

  hs = GNUNET_new (struct HelloWorldState);
  hs->message = "Hello World, I was nobody!";
  hs->birthLabel = birthLabel;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = hs,
      .label = label,
      .run = &hello_world_run,
      .cleanup = &hello_world_cleanup,
      .traits = &hello_world_traits
    };

    return cmd;
  }
}
