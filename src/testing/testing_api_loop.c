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

    if (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
#define BATCH_INDEX 1
      struct GNUNET_TESTING_Command *batch;
      struct GNUNET_TESTING_Command *current;
      struct GNUNET_TESTING_Command *icmd;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running command `%s'\n",
              cmd->label);
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
  is->commands = GNUNET_new_array (i + 1,
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


/* end of testing_api_loop.c */
