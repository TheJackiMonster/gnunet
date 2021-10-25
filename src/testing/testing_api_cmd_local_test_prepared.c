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
 * @file testing_api_cmd_local_test_prepared.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "testing_cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * This function prepares an array with traits.
 *
 */
enum GNUNET_GenericReturnValue
local_test_prepared_traits (void *cls,
                            const void **ret,
                            const char *trait,
                            unsigned int index)
{
  struct LocalPreparedState *lfs = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "state",
      .ptr = (const void *) lfs,
    },
    GNUNET_TESTING_trait_end ()
  };
  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Function to get the trait with the struct LocalPreparedState.
 *
 * @param[out] lfs struct LocalPreparedState.
 * @return #GNUNET_OK if no error occurred, #GNUNET_SYSERR otherwise.
 *
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_get_trait_local_prepared_state (
  const struct GNUNET_TESTING_Command *cmd,
  struct LocalPreparedState **lfs)
{
  return cmd->traits (cmd->cls,
                      (const void **) lfs,
                      "state",
                      (unsigned int) 0);
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
local_test_prepared_cleanup (void *cls)
{
  struct LocalPreparedState *lfs = cls;

  GNUNET_free (lfs);
}


/**
 * This function sends a GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TESTS_PREPARED message to the master loop.
 *
 */
static void
local_test_prepared_run (void *cls,
                         struct GNUNET_TESTING_Interpreter *is)
{
  struct LocalPreparedState *lfs = cls;

  struct GNUNET_CMDS_LOCAL_TEST_PREPARED *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_CMDS_LOCAL_TEST_PREPARED);
  reply = GNUNET_new (struct GNUNET_CMDS_LOCAL_TEST_PREPARED);
  reply->header.type = htons (
    GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED);
  reply->header.size = htons ((uint16_t) msg_length);
  lfs->write_message ((struct GNUNET_MessageHeader *) reply, msg_length);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param write_message Callback to write messages to the master loop.
 * @param all_local_tests_prepared Flag which will be set from outside.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_prepared (const char *label,
                                        TESTING_CMD_HELPER_write_cb
                                        write_message)
{
  struct LocalPreparedState *lfs;

  lfs = GNUNET_new (struct LocalPreparedState);
  lfs->write_message = write_message;

  struct GNUNET_TESTING_Command cmd = {
    .cls = lfs,
    .label = label,
    .run = &local_test_prepared_run,
    .ac = &lfs->ac,
    .cleanup = &local_test_prepared_cleanup,
    .traits = &local_test_prepared_traits
  };

  return cmd;
}
