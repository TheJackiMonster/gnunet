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
   * Interpreter we are part of.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Function to call when done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * How long to wait until finish fails hard?
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Set to #GNUNET_OK if the @a async_label command finished on time
   */
  enum GNUNET_GenericReturnValue finished;

};


/**
 */
static void
done_finish (void *cls)
{
  struct FinishState *finish_state = cls;

  GNUNET_SCHEDULER_cancel (finish_state->finish_task);
  finish_state->finish_task = NULL;
  finish_state->finished = GNUNET_YES;
  if (NULL != finish_state->cont)
  {
    finish_state->cont (finish_state->cont_cls);
  }
}


/**
 */
static void
timeout_finish (void *cls)
{
  struct FinishState *finish_state = cls;

  finish_state->finish_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout waiting for command `%s' to finish\n",
              finish_state->async_label);
  finish_state->finished = GNUNET_SYSERR;
  GNUNET_TESTING_interpreter_fail (finish_state->is);
}


/**
 * Run method of the command created by the interpreter to wait for another
 * command to finish.
 *
 */
static void
run_finish_on_ref (void *cls,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct FinishState *finish_state = cls;
  const struct GNUNET_TESTING_Command *async_cmd;

  finish_state->is = is;
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
  if ( (NULL == async_cmd->finish) ||
       (! async_cmd->asynchronous_finish) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot finish `%s': not asynchronous\n",
                finish_state->async_label);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  finish_state->finish_task
    = GNUNET_SCHEDULER_add_delayed (finish_state->timeout,
                                    &timeout_finish,
                                    finish_state);
  async_cmd->finish (async_cmd->cls,
                     &done_finish,
                     finish_state);
}


/**
 * Wait for any asynchronous execution of @e run to conclude,
 * then call finish_cont. Finish may only be called once per command.
 *
 * This member may be NULL if this command is a synchronous command,
 * and also should be set to NULL once the command has finished.
 *
 * @param cls closure
 * @param cont function to call upon completion, can be NULL
 * @param cont_cls closure for @a cont
 * @return
 *    #GNUNET_NO if the command is still running and @a cont will be called later
 *    #GNUNET_OK if the command completed successfully and @a cont was called
 *    #GNUNET_SYSERR if the operation @a cont was NOT called
 */
static enum GNUNET_GenericReturnValue
finish_finish_on_ref (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  struct FinishState *finish_state = cls;

  switch (finish_state->finished)
  {
  case GNUNET_OK:
    cont (cont_cls);
    break;
  case GNUNET_SYSERR:
    GNUNET_break (0);
    break;
  case GNUNET_NO:
    if (NULL != finish_state->cont)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    finish_state->cont = cont;
    finish_state->cont_cls = cont_cls;
    break;
  }
  return finish_state->finished;
}


/**
 * Create (synchronous) command that waits for another command to finish.
 * If @a cmd_ref did not finish after @a timeout, this command will fail
 * the test case.
 *
 * @param finish_label label for this command
 * @param cmd_ref reference to a previous command which we should
 *        wait for (call `finish()` on)
 * @param timeout how long to wait at most for @a cmd_ref to finish
 * @return a finish-command.
 */
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
      .run = &run_finish_on_ref,
      .finish = &finish_finish_on_ref
    };

    return cmd;
  }
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_make_unblocking (struct GNUNET_TESTING_Command cmd)
{
  /* do not permit this function to be used on
     a finish command! */
  GNUNET_assert (cmd.run != &run_finish_on_ref);
  cmd.asynchronous_finish = true;
  return cmd;
}
