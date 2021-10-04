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
 * @file testing/testing_api_loop.c
 * @brief main interpreter loop for testcases
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 *
 * FIXME:
 * - interpreter failure is NOT returned properly yet!
 * - abuse of shutdown logic for interpreter termination
 *   => API design flaw to be fixed!
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "testing.h"


/**
 * Lookup command by label.
 *
 * @param is interpreter to lookup command in
 * @param label label to look for
 * @return NULL if command was not found
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Attempt to lookup command for empty label\n");
    return NULL;
  }
  /* Search backwards as we most likely reference recent commands */
  for (int i = is->ip; i >= 0; i--)
  {
    const struct GNUNET_TESTING_Command *cmd = &is->commands[i];

    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->label) &&
         (0 == strcmp (cmd->label,
                       label)) )
      return cmd;

    if (GNUNET_TESTING_cmd_is_batch (cmd))
    {
#define BATCH_INDEX 1
      struct GNUNET_TESTING_Command *batch;
      struct GNUNET_TESTING_Command *current;
      struct GNUNET_TESTING_Command *icmd;
      const struct GNUNET_TESTING_Command *match;

      current = GNUNET_TESTING_cmd_batch_get_current (cmd);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_TESTING_get_trait_cmd (cmd,
                                                   BATCH_INDEX,
                                                   &batch));
      /* We must do the loop forward, but we can find the last match */
      match = NULL;
      for (unsigned int j = 0;
           NULL != (icmd = &batch[j])->label;
           j++)
      {
        if (current == icmd)
          break; /* do not go past current command */
        if ( (NULL != icmd->label) &&
             (0 == strcmp (icmd->label,
                           label)) )
          match = icmd;
      }
      if (NULL != match)
        return match;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Command not found: %s\n",
              label);
  return NULL;

}


/**
 * Run the main interpreter loop that performs exchange operations.
 *
 * @param cls contains the `struct InterpreterState`
 */
static void
interpreter_run (void *cls);


/**
 * Current command is done, run the next one.
 */
static void
interpreter_next (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  static unsigned long long ipc;
  static struct GNUNET_TIME_Absolute last_report;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
    return; /* ignore, we already failed! */
  if (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    GNUNET_TESTING_cmd_batch_next (is);
  }
  else
  {
    cmd->finish_time = GNUNET_TIME_absolute_get ();
    is->ip++;
  }
  if (0 == (ipc % 1000))
  {
    if (0 != ipc)
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Interpreter executed 1000 instructions in %s\n",
                  GNUNET_STRINGS_relative_time_to_string (
                    GNUNET_TIME_absolute_get_duration (last_report),
                    GNUNET_YES));
    last_report = GNUNET_TIME_absolute_get ();
  }
  ipc++;
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
}


/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter of the test
 */
void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
    return; /* ignore, we already failed! */
  if (NULL != cmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed at command `%s'\n",
                cmd->label);
    while (GNUNET_TESTING_cmd_is_batch (cmd))
    {
      cmd = GNUNET_TESTING_cmd_batch_get_current (cmd);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed in batch at command `%s'\n",
                  cmd->label);
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed with CMD being NULL!\n");
  }
  is->result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void)
{
  static struct GNUNET_TESTING_Command cmd = {
    .label = NULL
  };

  return cmd;
}


/**
 * Obtain current label.
 */
const char *
GNUNET_TESTING_interpreter_get_current_label (
  struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  return cmd->label;
}


/**
 * Run the main interpreter loop.
 *
 * @param cls contains the `struct GNUNET_TESTING_Interpreter`
 */
static void
interpreter_run (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  is->task = NULL;
  if (NULL == cmd->label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running command END\n");
    is->result = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL != cmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running command `%s'\n",
                cmd->label);
  }
  cmd->start_time
    = cmd->last_req_time
      = GNUNET_TIME_absolute_get ();
  cmd->num_tries = 1;
  cmd->run (cmd->cls,
            is);
  if ( (NULL != cmd->finish) &&
       (! cmd->asynchronous_finish) )
  {
    cmd->finish (cmd->cls,
                 &interpreter_next,
                 is);
  }
  else
  {
    interpreter_next (is);
  }
}


/**
 * Function run when the test terminates (good or bad).
 * Cleans up our state.
 *
 * @param cls the interpreter state.
 */
static void
do_shutdown (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd;
  const char *label;

  label = is->commands[is->ip].label;
  if (NULL == label)
    label = "END";
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Executing shutdown at `%s'\n",
              label);
  for (unsigned int j = 0;
       NULL != (cmd = &is->commands[j])->label;
       j++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaning up cmd %s\n",
                cmd->label);
    cmd->cleanup (cmd->cls);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaned up cmd %s\n",
                cmd->label);
  }
  if (NULL != is->finish_task)
  {
    GNUNET_SCHEDULER_cancel (is->finish_task);
    is->finish_task = NULL;
  }
  if (NULL != is->task)
  {
    GNUNET_SCHEDULER_cancel (is->task);
    is->task = NULL;
  }
  if (NULL != is->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (is->timeout_task);
    is->timeout_task = NULL;
  }
  GNUNET_free (is->commands);
  GNUNET_free (is);
}


/**
 * Function run when the test terminates (good or bad) with timeout.
 *
 * @param cls the interpreter state
 */
static void
do_timeout (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;

  is->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Terminating test due to timeout\n");
  GNUNET_SCHEDULER_shutdown ();
}


enum GNUNET_GenericReturnValue
GNUNET_TESTING_run (const char *cfg_filename,
                    struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_TESTING_Interpreter *is;
  unsigned int i;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);
  /* get the number of commands */
  for (i = 0; NULL != commands[i].label; i++)
    ;
  is->commands = GNUNET_new_array (i + 1,
                                   struct GNUNET_TESTING_Command);
  memcpy (is->commands,
          commands,
          sizeof (struct GNUNET_TESTING_Command) * i);
  is->timeout_task
    = GNUNET_SCHEDULER_add_delayed (timeout,
                                    &do_timeout,
                                    is);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 is);
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
  return GNUNET_OK;
}


/**
 * Closure for #loop_run().
 */
struct MainParams
{
  const char *cfg_filename;
  struct GNUNET_TESTING_Command *commands;
  struct GNUNET_TIME_Relative timeout;
  int rv;
};


/**
 * Main function to run the test cases.
 *
 * @param cls a `struct MainParams *`
 */
static void
loop_run (void *cls)
{
  struct MainParams *mp = cls;

  if (GNUNET_OK !=
      GNUNET_TESTING_run (mp->cfg_filename,
                          mp->commands,
                          mp->timeout))
  {
    GNUNET_break (0);
    mp->rv = EXIT_FAILURE;
  }
}


int
GNUNET_TESTING_main (const char *cfg_filename,
                     struct GNUNET_TESTING_Command *commands,
                     struct GNUNET_TIME_Relative timeout)
{
  struct MainParams mp = {
    .cfg_filename = cfg_filename,
    .commands = commands,
    .timeout = timeout,
    .rv = EXIT_SUCCESS
  };

  GNUNET_SCHEDULER_run (&loop_run,
                        &mp);
  return mp.rv;
}


/* end of testing_api_loop.c */
