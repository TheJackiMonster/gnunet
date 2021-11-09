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
 * @file testing_api_cmd_block_until_all_peers_started.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct with information for callbacks.
 *
 */
struct BlockState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * The label of this command.
   */
  const char *label;
};


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
block_until_all_peers_started_cleanup (void *cls)
{
  struct BlockState *bs = cls;

  GNUNET_free (bs);
}

static int
block_until_external_trigger_traits (void *cls,
                                     const void **ret,
                                     const char *trait,
                                     unsigned int index)
{
  struct BlockState *bs = cls;
  struct GNUNET_TESTING_AsyncContext *ac = &bs->ac;
  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "async_context",
      .ptr = (const void *) ac,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Function to get the trait with the async context.
 *
 * @param[out] ac GNUNET_TESTING_AsyncContext.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 */
int
GNUNET_TESTING_get_trait_async_context (
  const struct GNUNET_TESTING_Command *cmd,
  struct GNUNET_TESTING_AsyncContext **ac)
{
  return cmd->traits (cmd->cls,
                      (const void **) ac,
                      "async_context",
                      (unsigned int) 0);
}


/**
 * This function does nothing but to start the cmd.
 *
 */
static void
block_until_all_peers_started_run (void *cls,
                                   struct GNUNET_TESTING_Interpreter *is)
{
  struct BlockState *bs = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "block %s running!\n",
       bs->label);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param all_peers_started Flag which will be set from outside.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_external_trigger (const char *label)
{
  struct BlockState *bs;

  bs = GNUNET_new (struct BlockState);
  bs->label = label;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = bs,
      .label = label,
      .run = &block_until_all_peers_started_run,
      .ac = &bs->ac,
      .cleanup = &block_until_all_peers_started_cleanup,
      .traits = block_until_external_trigger_traits
    };

    return cmd;
  }
}
