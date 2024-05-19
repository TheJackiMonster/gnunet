/*
      This file is part of GNUnet
      Copyright (C) 2021-2024 GNUnet e.V.

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
#include "gnunet_testing_lib.h"
#include "testing_api_loop.h"
#include "testing_api_cmd_batch.h"
#include "testing_api_topology.h"
#include "testing_cmds.h"


struct SendContext
{
  struct SendContext *next;
  struct SendContext *prev;

  /**
   * Handle to a send op
   */
  struct GNUNET_HELPER_SendHandle *send_handle;

  struct GNUNET_TESTING_Interpreter *is;
};

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter
{
  /**
   * Array with handles of helper processes for communication with netjails.
   */
  struct GNUNET_HELPER_Handle **helpers;

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
   * Map with barriers for this loop.
   */
  struct GNUNET_CONTAINER_MultiShortmap *barriers;

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
   * Hash map mapping variable names to commands.
   */
  struct GNUNET_CONTAINER_MultiHashMap *vars;

  struct SendContext *sender_head;
  struct SendContext *sender_tail;

  /**
   * Function to call to send messages to our parent.
   */
  GNUNET_TESTING_cmd_helper_write_cb parent_writer;

  /**
   * Number of GNUNET_TESTING_Command in @e commands.
   */
  unsigned int cmds_n;

  /**
   * Size of the array @e helpers.
   */
  unsigned int n_helpers;

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

  /**
   * Is the interpreter finishing?
   */
  bool finishing;

};


/**
 * Lookup command by label.
 *
 * @param is interpreter to lookup command in
 * @param label label of the command to lookup.
 * @param future true to look into the future, false to look into the past
 * @return the command, if it is found, or NULL.
 */
static const struct GNUNET_TESTING_Command *
get_command (struct GNUNET_TESTING_Interpreter *is,
             const char *label,
             bool future)
{
  int start_i = future ? is->cmds_n - 1 : is->ip;
  int end_i = future ? is->ip + 1 : 0;

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

    if (NULL != cmd->run)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "label to compare %s\n",
                  cmd->label.value);
    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->run) &&
         (0 == strcmp (cmd->label.value,
                       label)) )
      return cmd;

    if (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
      struct GNUNET_TESTING_Command **batch;
      struct GNUNET_TESTING_Command *current;
      const struct GNUNET_TESTING_Command *icmd;
      const struct GNUNET_TESTING_Command *match;

      current = GNUNET_TESTING_cmd_batch_get_current_ (cmd);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_TESTING_get_trait_batch_cmds (cmd,
                                                          &batch));
      /* We must do the loop forward, but we can find the last match */
      match = NULL;
      for (unsigned int j = 0;
           NULL != (icmd = &(*batch)[j])->run;
           j++)
      {
        if (current == icmd)
          break; /* do not go past current command */
        if ( (NULL != icmd->run) &&
             (0 == strcmp (icmd->label.value,
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


const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_future_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  return get_command (is,
                      label,
                      true);
}


const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  return get_command (is,
                      label,
                      false);
}


const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command_all (
  struct GNUNET_TESTING_Interpreter *is,
  const char *label)
{
  const struct GNUNET_TESTING_Command *cmd;

  cmd = get_command (is,
                     label,
                     false);
  if (NULL == cmd)
    cmd = get_command (is,
                       label,
                       true);
  return cmd;
}


const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_get_command (
  struct GNUNET_TESTING_Interpreter *is,
  const char *name)
{
  const struct GNUNET_TESTING_Command *cmd;
  struct GNUNET_HashCode h_name;

  GNUNET_CRYPTO_hash (name,
                      strlen (name),
                      &h_name);
  cmd = GNUNET_CONTAINER_multihashmap_get (is->vars,
                                           &h_name);
  if (NULL == cmd)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Command not found by name: %s\n",
                name);
  return cmd;
}


static void
send_finished (void *cls,
               enum GNUNET_GenericReturnValue result)
{
  struct SendContext *sctx = cls;
  struct GNUNET_TESTING_Interpreter *is = sctx->is;

  GNUNET_break (GNUNET_OK == result);
  GNUNET_CONTAINER_DLL_remove (is->sender_head,
                               is->sender_tail,
                               sctx);
  GNUNET_free (sctx);
}


void
GNUNET_TESTING_loop_notify_children_ (struct GNUNET_TESTING_Interpreter *is,
                                      const struct GNUNET_MessageHeader *hdr)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Send notification to children of type %u\n",
              (unsigned int) ntohs (hdr->type));
  for (unsigned int i = 0; i<is->n_helpers; i++)
  {
    struct SendContext *sctx;

    sctx = GNUNET_new (struct SendContext);
    sctx->is = is;
    GNUNET_CONTAINER_DLL_insert (is->sender_head,
                                 is->sender_tail,
                                 sctx);
    sctx->send_handle
      = GNUNET_HELPER_send (is->helpers[i],
                            hdr,
                            false, /* never drop */
                            &send_finished,
                            sctx);
  }
}


void
GNUNET_TESTING_loop_notify_parent_ (struct GNUNET_TESTING_Interpreter *is,
                                    const struct GNUNET_MessageHeader *hdr)
{
  if (NULL == is->parent_writer)
  {
    /* We have no parent, this is impossible! */
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  is->parent_writer (hdr);
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

  is->finishing = true;
  is->final_task = NULL;
  label = is->commands[is->ip].label.value;
  if (NULL == is->commands[is->ip].run)
    label = "END";
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Interpreter finishes at `%s' with status %d\n",
              label,
              is->result);
  for (unsigned int j = 0;
       NULL != (cmd = &is->commands[j])->run;
       j++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaning up cmd %s\n",
                cmd->label.value);
    cmd->cleanup (cmd->cls);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaned up cmd %s\n",
                cmd->label.value);
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
  {
    struct SendContext *sctx;

    while (NULL != (sctx = is->sender_head))
    {
      GNUNET_CONTAINER_DLL_remove (is->sender_head,
                                   is->sender_tail,
                                   sctx);
      GNUNET_HELPER_send_cancel (sctx->send_handle);
      GNUNET_free (sctx);
    }
  }
  GNUNET_free (is->commands);
  is->rc (is->rc_cls,
          is->result);
  if (NULL != is->barriers)
  {
    GNUNET_CONTAINER_multishortmap_destroy (is->barriers);
    is->barriers = NULL;
  }
  if (NULL != is->vars)
  {
    GNUNET_CONTAINER_multihashmap_destroy (is->vars);
    is->vars = NULL;
  }
  GNUNET_free (is->helpers);
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
                    true));
    last_report = GNUNET_TIME_absolute_get ();
  }
  ipc++;
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
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
  if (NULL == cmd->run)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Running command END\n");
    is->result = GNUNET_OK;
    finish_test (is);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Running command `%s'\n",
              cmd->label.value);
  cmd->last_req_time
    = GNUNET_TIME_absolute_get ();
  if (0 == cmd->num_tries)
    cmd->start_time = cmd->last_req_time;
  cmd->num_tries = 1;
  if (NULL != cmd->name)
  {
    struct GNUNET_HashCode h_name;

    GNUNET_CRYPTO_hash (cmd->name,
                        strlen (cmd->name),
                        &h_name);
    (void) GNUNET_CONTAINER_multihashmap_put (
      is->vars,
      &h_name,
      cmd,
      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  if (NULL != cmd->ac)
  {
    cmd->ac->is = is;
    cmd->ac->finished = GNUNET_NO;
  }
  cmd->run (cmd->cls,
            is);
  if ( (NULL == cmd->ac) ||
       (cmd->asynchronous_finish) )
  {
    if (NULL != cmd->ac)
      cmd->ac->next_called = true;
    interpreter_next (is);
  }
}


void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd
    = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
  {
    GNUNET_break (0);
    return; /* ignore, we already failed! */
  }
  if (NULL != cmd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed during command `%s'\n",
                cmd->label.value);
    while (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
      cmd = GNUNET_TESTING_cmd_batch_get_current_ (cmd);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed in batch during command `%s'\n",
                  cmd->label.value);
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


void
GNUNET_TESTING_async_fail (struct GNUNET_TESTING_AsyncContext *ac)
{
  GNUNET_assert (GNUNET_NO == ac->finished);
  ac->finished = GNUNET_SYSERR;
  GNUNET_TESTING_interpreter_fail (ac->is);
}


void
GNUNET_TESTING_async_finish (struct GNUNET_TESTING_AsyncContext *ac)
{
  GNUNET_assert (GNUNET_NO == ac->finished);
  ac->finished = GNUNET_OK;
  if (NULL != ac->notify_finished)
  {
    ac->notify_finished (ac->notify_finished_cls);
    ac->notify_finished = NULL;
  }
  if (! ac->next_called)
  {
    ac->next_called = true;
    interpreter_next (ac->is);
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


static void
setup_is (struct GNUNET_TESTING_Interpreter *is,
          const struct GNUNET_TESTING_Command *bcommand,
          const struct GNUNET_TESTING_Command *commands)
{
  unsigned int i;

  is->vars = GNUNET_CONTAINER_multihashmap_create (1024,
                                                   false);
  /* get the number of commands */
  for (i = 0; NULL != commands[i].run; i++)
    ;
  if (NULL != bcommand)
    i++;
  is->cmds_n = i + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got %u commands\n",
              i);
  is->commands = GNUNET_malloc_large (
    (i + 1)
    * sizeof (struct GNUNET_TESTING_Command));
  GNUNET_assert (NULL != is->commands);
  if (NULL == bcommand)
  {
    memcpy (is->commands,
            commands,
            sizeof (struct GNUNET_TESTING_Command) * i);
  }
  else
  {
    is->commands[0] = *bcommand;
    memcpy (&is->commands[1],
            commands,
            sizeof (struct GNUNET_TESTING_Command) * i);
  }
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
}


struct GNUNET_TESTING_Interpreter *
GNUNET_TESTING_run (const struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout,
                    GNUNET_TESTING_ResultCallback rc,
                    void *rc_cls)
{
  struct GNUNET_TESTING_Interpreter *is;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);
  is->timeout_task
    = GNUNET_SCHEDULER_add_delayed (timeout,
                                    &do_timeout,
                                    is);
  is->rc = rc;
  is->rc_cls = rc_cls;
  setup_is (is,
            NULL,
            commands);
  return is;
}


static struct GNUNET_TESTING_Interpreter *
start_testcase (
  void *cls,
  const char *topology_data,
  uint32_t inherited_barrier_count,
  const struct GNUNET_ShortHashCode *inherited_barriers,
  GNUNET_TESTING_cmd_helper_write_cb parent_writer,
  GNUNET_TESTING_ResultCallback finish_cb,
  void *finish_cb_cls)
{
  const struct GNUNET_TESTING_Command *commands = cls;
  struct GNUNET_TESTING_Interpreter *is;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);
  if (0 != inherited_barrier_count)
  {
    is->barriers
      = GNUNET_CONTAINER_multishortmap_create (inherited_barrier_count * 4 / 3,
                                               true);
    for (unsigned int j = 0; j<inherited_barrier_count; j++)
    {
      struct GNUNET_TESTING_Barrier *barrier;

      barrier = GNUNET_new (struct GNUNET_TESTING_Barrier);
      barrier->barrier_id = inherited_barriers[j];
      barrier->inherited = true;
      (void) GNUNET_CONTAINER_multishortmap_put (
        is->barriers,
        &barrier->barrier_id,
        barrier,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
    }
  }
  is->parent_writer = parent_writer;
  is->rc = finish_cb;
  is->rc_cls = finish_cb_cls;
  {
    struct GNUNET_TESTING_Command bcmd;

    bcmd = GNUNET_TESTING_cmd_set_var (
      "topology",
      GNUNET_TESTING_cmd_load_topology_from_string (
        "_boot_",
        topology_data));
    setup_is (is,
              &bcmd,
              commands);
  }
  return is;

}


struct GNUNET_TESTING_PluginFunctions *
GNUNET_TESTING_make_plugin (
  const struct GNUNET_TESTING_Command *commands)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_TESTING_PluginFunctions);
  api->cls = (void *) commands;
  api->start_testcase = &start_testcase;
  return api;
}


void
GNUNET_TESTING_add_netjail_helper_ (struct GNUNET_TESTING_Interpreter *is,
                                    struct GNUNET_HELPER_Handle *helper)
{
  GNUNET_array_append (is->helpers,
                       is->n_helpers,
                       helper);
}


struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier2_ (struct GNUNET_TESTING_Interpreter *is,
                              const struct GNUNET_ShortHashCode *create_key)
{
  return GNUNET_CONTAINER_multishortmap_get (is->barriers,
                                             create_key);
}


struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             const char *barrier_name)
{
  struct GNUNET_ShortHashCode create_key;

  if (NULL == is->barriers)
    return NULL;
  GNUNET_TESTING_barrier_name_hash_ (barrier_name,
                                     &create_key);
  return GNUNET_TESTING_get_barrier2_ (is,
                                       &create_key);
}


void
GNUNET_TESTING_add_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             struct GNUNET_TESTING_Barrier *barrier)
{
  if (NULL == is->barriers)
    is->barriers
      = GNUNET_CONTAINER_multishortmap_create (1,
                                               true);
  /* We always use the barrier we encountered
     most recently under a given label, thus replace */
  (void) GNUNET_CONTAINER_multishortmap_put (
    is->barriers,
    &barrier->barrier_id,
    barrier,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
}


/* end of testing_api_loop.c */
