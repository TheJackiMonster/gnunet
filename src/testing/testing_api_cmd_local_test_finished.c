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
 * @file testing_api_cmd_local_test_finished.c
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
 * Struct to hold information for callbacks.
 *
 */
struct LocalFinishedState
{
  /**
   * Callback to write messages to the master loop.
   *
   */
  TESTING_CMD_HELPER_write_cb write_message;

  /**
   * The message send back to the master loop.
   *
   */
  struct GNUNET_CMDS_LOCAL_FINISHED *reply;
};


/**
 * Trait function of this cmd does nothing.
 *
 */
static enum GNUNET_GenericReturnValue
local_test_finished_traits (void *cls,
                            const void **ret,
                            const char *trait,
                            unsigned int index)
{
  return GNUNET_NO;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
local_test_finished_cleanup (void *cls)
{
  struct LocalFinishedState *lfs = cls;

  GNUNET_free (lfs->reply);
  GNUNET_free (lfs);
}


/**
 * This function sends a GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED message to the master loop.
 *
 */
static void
local_test_finished_run (void *cls,
                         struct GNUNET_TESTING_Interpreter *is)
{
  struct LocalFinishedState *lfs = cls;
  struct GNUNET_CMDS_LOCAL_FINISHED *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_CMDS_LOCAL_FINISHED);
  reply = GNUNET_new (struct GNUNET_CMDS_LOCAL_FINISHED);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED);
  reply->header.size = htons ((uint16_t) msg_length);
  lfs->reply = reply;
  lfs->write_message ((struct GNUNET_MessageHeader *) reply,
                      msg_length);
}


/**
 * This finish function will stop the local loop without shutting down the
 * scheduler, because we do not call the continuation, which is the
 * interpreter_next method.
 *
 */
static enum GNUNET_GenericReturnValue
local_test_finished_finish (void *cls,
                            GNUNET_SCHEDULER_TaskCallback cont,
                            void *cont_cls)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopping local loop\n");
  return GNUNET_YES;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_finished (
  const char *label,
  TESTING_CMD_HELPER_write_cb write_message)
{
  struct LocalFinishedState *lfs;

  lfs = GNUNET_new (struct LocalFinishedState);
  lfs->write_message = write_message;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = lfs,
      .label = label,
      .run = &local_test_finished_run,
      .finish = &local_test_finished_finish,
      .cleanup = &local_test_finished_cleanup,
      .traits = &local_test_finished_traits
    };

    return cmd;
  }
}
