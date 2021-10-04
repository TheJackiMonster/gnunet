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
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

struct HelloWorldBirthState
{
  struct GNUNET_TIME_Absolute *date;
  char *what_am_i;
};

/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
hello_world_birth_cleanup (void *cls)
{
  struct HelloWorldBirthState *hbs = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Finished birth of %s\n",
              hbs->what_am_i);
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
static int
hello_world_birth_traits (void *cls,
                          const void **ret,
                          const char *trait,
                          unsigned int index)
{
  struct HelloWorldBirthState *hbs = cls;
  const char *what_am_i = hbs->what_am_i;

  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "what_am_i",
      .ptr = (const void *) what_am_i,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
* Run the "hello world" CMD.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
hello_world_birth_run (void *cls,
                       struct GNUNET_TESTING_Interpreter *is)
{
  struct HelloWorldBirthState *hbs = cls;
  struct GNUNET_TIME_Relative relative;

  relative = GNUNET_TIME_absolute_get_difference (*hbs->date,
                                                  GNUNET_TIME_absolute_get ());

  if (0 == relative.rel_value_us % 10)
  {
    hbs->what_am_i = "creature!";
  }
  else if (0 == relative.rel_value_us % 2)
  {
    hbs->what_am_i = "girl!";
  }
  else
  {
    hbs->what_am_i = "boy!";
  }
}


/**
 * Offer data from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_what_am_i (const struct GNUNET_TESTING_Command *cmd,
                                    char **what_am_i)
{
  return cmd->traits (cmd->cls,
                      (const void **) what_am_i,
                      "what_am_i",
                      (unsigned int) 0);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param now when the command was started.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world_birth (const char *label,
                                      struct GNUNET_TIME_Absolute *now)
{
  struct HelloWorldBirthState *hbs;

  hbs = GNUNET_new (struct HelloWorldBirthState);
  hbs->date = now;

  struct GNUNET_TESTING_Command cmd = {
    .cls = hbs,
    .label = label,
    .run = &hello_world_birth_run,
    .cleanup = &hello_world_birth_cleanup,
    .traits = &hello_world_birth_traits
  };

  return cmd;
}
