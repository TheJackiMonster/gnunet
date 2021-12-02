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
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "testing.h"

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter
{

  /**
   * Function to call with the test result.
   */
  GNUNET_TESTING_ResultCallback rc;

  /**
   * Closure for @e rc.
   */
  void *rc_cls;

  /**
   * Commands the interpreter will run.
   */
  struct GNUNET_TESTING_Command *commands;

  /**
   * Number of GNUNET_TESTING_Command in commands.
   */
  unsigned int cmds_n;

  /**
   * Interpreter task (if one is scheduled).
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Final task that returns the result.
   */
  struct GNUNET_SCHEDULER_Task *final_task;

  /**
   * Task run on timeout.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Instruction pointer.  Tells #interpreter_run() which instruction to run
   * next.  Need (signed) int because it gets -1 when rewinding the
   * interpreter to the first CMD.
   */
  int ip;

  /**
   * Result of the testcases, #GNUNET_OK on success
   */
  enum GNUNET_GenericReturnValue result;

};


const struct GNUNET_TESTING_Command *
get_command (struct GNUNET_TESTING_Interpreter *is,
             const char *label,
             unsigned int future)
{
  int start_i = GNUNET_NO == future ? is->ip : is->cmds_n - 1;
  int end_i = GNUNET_NO == future ? 0 : is->ip + 1;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "start_i: %u end_i: %u\n",
              start_i,
              end_i);
  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Attempt to lookup command for empty label\n");
    return NULL;
  }

  for (int i = start_i; i >= end_i; i--)
  {
    const struct GNUNET_TESTING_Command *cmd = &is->commands[i];

    if (NULL != cmd->label)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "label to compare %s\n",
                  cmd->label);
    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->label) &&
         (0 == strcmp (cmd->label,
                       label)) )
      return cmd;

    if (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
#define BATCH_INDEX 1
      const struct GNUNET_TESTING_Command *batch;
      struct GNUNET_TESTING_Command *current;
      const struct GNUNET_TESTING_Command *icmd;
      const struct GNUNET_TESTING_Command *match;

      current = GNUNET_TESTING_cmd_batch_get_current_ (cmd);
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
              "Command `%s' not found\n",
              label);
  return NULL;
}


/**
 * Lookup command by label.
 * Only future commands are looked up.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_future_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  return get_command (is, label, GNUNET_YES);
}


/**
 * Lookup command by label.
 * Only commands from current command to commands in the past are looked up.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  return get_command (is, label, GNUNET_NO);
}


/**
 * Lookup command by label.
 * All commands, first into the past, then into the furture are looked up.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command_all (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  const struct GNUNET_TESTING_Command *cmd;

  cmd = get_command (is, label, GNUNET_NO);
  if (NULL == cmd)
    cmd = get_command (is, label, GNUNET_YES);
  return cmd;
}


/**
 * Finish the test run, return the final result.
 *
 * @param cls the `struct GNUNET_TESTING_Interpreter`
 */
static void
finish_test (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd;
  const char *label;

  is->final_task = NULL;
  label = is->commands[is->ip].label;
  if (NULL == label)
    label = "END";
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Interpreter finishes at `%s' with status %d\n",
              label,
              is->result);
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
  is->rc (is->rc_cls,
          is->result);
  GNUNET_free (is);
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
  cmd->finish_time = GNUNET_TIME_absolute_get ();
  if ( (! GNUNET_TESTING_cmd_is_batch_ (cmd)) ||
       (! GNUNET_TESTING_cmd_batch_next_ (cmd->cls)) )
    is->ip++;
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


void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
  {
    GNUNET_break (0);
    return; /* ignore, we already failed! */
  }
  if (NULL != cmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed at command `%s'\n",
                cmd->label);
    while (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
      cmd = GNUNET_TESTING_cmd_batch_get_current_ (cmd);
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
  GNUNET_assert (NULL == is->final_task);
  is->final_task = GNUNET_SCHEDULER_add_now (&finish_test,
                                             is);
}


/**
 * Returns the actual running command.
 *
 * @param is Global state of the interpreter, used by a command
 *        to access information about other commands.
 * @return The actual running command.
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_get_current_command (
  struct GNUNET_TESTING_Interpreter *is)
{
  return &is->commands[is->ip];
}

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
    finish_test (is);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running command `%s'\n",
              cmd->label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "start time of %p expected 0 is `%lu'\n",
              cmd,
              cmd->start_time.abs_value_us);
  cmd->start_time
    = cmd->last_req_time
      = GNUNET_TIME_absolute_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "start time of %p expected something is `%lu'\n",
              cmd,
              cmd->start_time.abs_value_us);
  cmd->num_tries = 1;
  if (NULL != cmd->ac)
  {
    cmd->ac->is = is;
    cmd->ac->cont = &interpreter_next;
    cmd->ac->cont_cls = is;
    cmd->ac->finished = GNUNET_NO;
  }
  cmd->run (cmd->cls,
            is);
  if (NULL == cmd->ac)
  {
    interpreter_next (is);
  }
  else if ( (cmd->asynchronous_finish) &&
            (NULL != cmd->ac->cont) )
  {
    cmd->ac->cont = NULL;
    interpreter_next (is);
  }
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
              "Terminating test due to global timeout\n");
  is->result = GNUNET_SYSERR;
  finish_test (is);
}


/**
 * Check if the command is running.
 *
 * @param cmd The command to check.
 * @return GNUNET_NO if the command is not running, GNUNET_YES if it is running.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_running (const struct GNUNET_TESTING_Command *command)
{
  return 0 != command->start_time.abs_value_us && 0 ==
         command->finish_time.abs_value_us;
}


/**
 * Check if a command is finished.
 *
 * @param cmd The command to check.
 * @return GNUNET_NO if the command is not finished, GNUNET_YES if it is finished.
 */
enum GNUNET_GenericReturnValue
GNUNET_TESTING_finished (struct GNUNET_TESTING_Command *command)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Relative diff = GNUNET_TIME_absolute_get_difference (
    command->finish_time,
    now);
  return 0 < diff.rel_value_us;
}


void
GNUNET_TESTING_run (struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout,
                    GNUNET_TESTING_ResultCallback rc,
                    void *rc_cls)
{
  struct GNUNET_TESTING_Interpreter *is;
  unsigned int i;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);
  is->rc = rc;
  is->rc_cls = rc_cls;
  /* get the number of commands */
  for (i = 0; NULL != commands[i].label; i++)
    ;
  is->cmds_n = i + 1;
  is->commands = GNUNET_new_array (is->cmds_n,
                                   struct GNUNET_TESTING_Command);
  memcpy (is->commands,
          commands,
          sizeof (struct GNUNET_TESTING_Command) * i);
  is->timeout_task
    = GNUNET_SCHEDULER_add_delayed (timeout,
                                    &do_timeout,
                                    is);
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
}


/**
 * Closure for #loop_run().
 */
struct MainParams
{

  /**
   * NULL-label terminated array of commands.
   */
  struct GNUNET_TESTING_Command *commands;

  /**
   * Global timeout for the test.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Set to #EXIT_FAILURE on error.
   */
  int rv;
};


/**
 * Function called with the final result of the test.
 *
 * @param cls the `struct MainParams`
 * @param rv #GNUNET_OK if the test passed
 */
static void
handle_result (void *cls,
               enum GNUNET_GenericReturnValue rv)
{
  struct MainParams *mp = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Test exits with status %d\n",
              rv);
  if (GNUNET_OK != rv)
    mp->rv = EXIT_FAILURE;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function to run the test cases.
 *
 * @param cls a `struct MainParams *`
 */
static void
loop_run (void *cls)
{
  struct MainParams *mp = cls;

  GNUNET_TESTING_run (mp->commands,
                      mp->timeout,
                      &handle_result,
                      mp);
}


int
GNUNET_TESTING_main (struct GNUNET_TESTING_Command *commands,
                     struct GNUNET_TIME_Relative timeout)
{
  struct MainParams mp = {
    .commands = commands,
    .timeout = timeout,
    .rv = EXIT_SUCCESS
  };

  GNUNET_SCHEDULER_run (&loop_run,
                        &mp);
  return mp.rv;
}


void
GNUNET_TESTING_async_fail (struct GNUNET_TESTING_AsyncContext *ac)
{
  GNUNET_assert (GNUNET_NO == ac->finished);
  ac->finished = GNUNET_SYSERR;
  GNUNET_TESTING_interpreter_fail (ac->is);
  if (NULL != ac->cont)
  {
    ac->cont (ac->cont_cls);
    ac->cont = NULL;
  }
}


void
GNUNET_TESTING_async_finish (struct GNUNET_TESTING_AsyncContext *ac)
{
  GNUNET_assert (GNUNET_NO == ac->finished);
  ac->finished = GNUNET_OK;
  if (NULL != ac->cont)
  {
    ac->cont (ac->cont_cls);
    ac->cont = NULL;
  }
}


/* end of testing_api_loop.c */
