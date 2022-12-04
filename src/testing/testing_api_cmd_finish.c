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
 * @file testing/testing_api_cmd_finish.c
 * @brief command to wait for completion of async command
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"


/**
 * Struct to use for command-specific context information closure of a command waiting
 * for another command.
 */
struct FinishState
{
  /**
   * Closure for all commands with command-specific context information.
   */
  void *cls;

  /**
   * Label of the asynchronous command the synchronous command of this closure waits for.
   */
  const char *async_label;

  /**
   * Task for running the finish method of the asynchronous task the command is waiting for.
   */
  struct GNUNET_SCHEDULER_Task *finish_task;

  /**
   * Function to call when done.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * How long to wait until finish fails hard?
   */
  struct GNUNET_TIME_Relative timeout;

};


/**
 * Function called when the command we are waiting on
 * is finished. Hence we are finished, too.
 *
 * @param cls a `struct FinishState` being notified
 */
static void
done_finish (void *cls)
{
  struct FinishState *finish_state = cls;

  GNUNET_SCHEDULER_cancel (finish_state->finish_task);
  finish_state->finish_task = NULL;
  GNUNET_TESTING_async_finish (&finish_state->ac);
}


/**
 * Function triggered if the command we are waiting
 * for did not complete on time.
 *
 * @param cls our `struct FinishState`
 */
static void
timeout_finish (void *cls)
{
  struct FinishState *finish_state = cls;

  finish_state->finish_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout waiting for command `%s' to finish\n",
              finish_state->async_label);
  GNUNET_TESTING_async_fail (&finish_state->ac);
}


/**
 * Run method of the command created by the interpreter to wait for another
 * command to finish.
 *
 */
static void
run_finish (void *cls,
            struct GNUNET_TESTING_Interpreter *is)
{
  struct FinishState *finish_state = cls;
  const struct GNUNET_TESTING_Command *async_cmd;
  struct GNUNET_TESTING_AsyncContext *aac;

  async_cmd
    = GNUNET_TESTING_interpreter_lookup_command (is,
                                                 finish_state->async_label);
  if (NULL == async_cmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Did not find command `%s'\n",
                finish_state->async_label);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  if ( (NULL == (aac = async_cmd->ac)) ||
       (! async_cmd->asynchronous_finish) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot finish `%s': not asynchronous\n",
                finish_state->async_label);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  if (GNUNET_NO != aac->finished)
  {
    /* Command is already finished, so are we! */
    GNUNET_TESTING_async_finish (&finish_state->ac);
    return;
  }
  finish_state->finish_task
    = GNUNET_SCHEDULER_add_delayed (finish_state->timeout,
                                    &timeout_finish,
                                    finish_state);
  aac->cont = &done_finish;
  aac->cont_cls = finish_state;
}


/**
 * Cleanup state of a finish command.
 *
 * @param cls a `struct FinishState` to clean up
 */
static void
cleanup_finish (void *cls)
{
  struct FinishState *finish_state = cls;

  if (NULL != finish_state->finish_task)
  {
    GNUNET_SCHEDULER_cancel (finish_state->finish_task);
    finish_state->finish_task = NULL;
  }
  GNUNET_free (finish_state);
}


const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_finish (const char *finish_label,
                           const char *cmd_ref,
                           struct GNUNET_TIME_Relative timeout)
{
  struct FinishState *finish_state;

  finish_state = GNUNET_new (struct FinishState);
  finish_state->async_label = cmd_ref;
  finish_state->timeout = timeout;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = finish_state,
      .label = finish_label,
      .run = &run_finish,
      .ac = &finish_state->ac,
      .cleanup = &cleanup_finish
    };

    return cmd;
  }
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_make_unblocking (struct GNUNET_TESTING_Command cmd)
{
  /* do not permit this function to be used on
     a finish command! */
  GNUNET_assert (cmd.run != &run_finish);
  cmd.asynchronous_finish = true;
  return cmd;
}
