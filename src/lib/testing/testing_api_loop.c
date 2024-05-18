/*
      This file is part of GNUnet
      Copyright (C) 2021-2023 GNUnet e.V.

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
#include "gnunet_testing_plugin.h"
#include "gnunet_testing_barrier.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing.h"

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter
{
  /**
   * Array with handles of helper processes for communication with netjails.
   */
  const struct GNUNET_HELPER_Handle **helpers;

  /**
   * Handle to a send op
   */
  struct GNUNET_HELPER_SendHandle *send_handle;

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


/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result #GNUNET_OK on success,
 *               #GNUNET_NO if helper process died
 *               #GNUNET_SYSERR during GNUNET_HELPER_stop()
 */
static void
clear_msg (void *cls,
           enum GNUNET_GenericReturnValue result)
{
  GNUNET_assert (GNUNET_YES == result);
}


/**
 * Send message to a netjail node that a barrier can be crossed.
 *
 * @param is The interpreter loop.
 * @param barrier_name The name of the barrier to cross.
 * @param global_node_number The global number of the node to inform.
 */
static void
send_barrier_crossable (struct GNUNET_TESTING_Interpreter *is,
                        const char *barrier_name,
                        unsigned int global_node_number)
{
  struct CommandBarrierCrossable *adm;
  size_t msg_length;
  size_t name_len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send barrier crossable for barrier `%s'\n",
              barrier_name);
  name_len = strlen (barrier_name);
  msg_length = sizeof(struct CommandBarrierCrossable) + name_len + 1;
  adm = GNUNET_malloc (msg_length);
  adm->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE);
  adm->header.size = htons ((uint16_t) msg_length);
  memcpy (&adm[1], barrier_name, name_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send message of type %u to locals\n",
              ntohs (adm->header.type));
  /**
     FIXME: This should probably be put into a linked list
     inside is and cleaned up at some point.
  */
  is->send_handle = GNUNET_HELPER_send (
    (struct GNUNET_HELPER_Handle *) is->helpers[global_node_number - 1],
    &adm->header,
    GNUNET_NO,
    &clear_msg,
    NULL);
  GNUNET_free (adm);
}


/**
 * Closure for #free_barrier_node_cb().
 */
struct FreeBarrierNodeCbCls
{
  /**
   * The interpreter.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * The barrier from which the nodes are freed..
   */
  struct GNUNET_TESTING_Barrier *barrier;
};


static enum GNUNET_GenericReturnValue
free_barrier_node_cb (void *cls,
                      const struct GNUNET_ShortHashCode *key,
                      void *value)
{
  struct FreeBarrierNodeCbCls *free_barrier_node_cb_cls = cls;
  struct GNUNET_TESTING_NetjailNode *node = value;
  struct GNUNET_TESTING_Barrier *barrier = free_barrier_node_cb_cls->barrier;
  struct GNUNET_TESTING_Interpreter *is = free_barrier_node_cb_cls->is;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "free_barrier_node_cb\n");
  if (! is->finishing)
  {
    send_barrier_crossable (is,
                            barrier->name,
                            node->node_number);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multishortmap_remove (
                   barrier->nodes,
                   key,
                   node));
  return GNUNET_YES;
}


static void
free_barrier_nodes (struct GNUNET_TESTING_Interpreter *is,
                    struct GNUNET_TESTING_Barrier *barrier)
{
  struct FreeBarrierNodeCbCls free_barrier_node_cb_cls = {
    .barrier = barrier,
    .is = is
  };

  if (NULL == barrier->nodes)
    return;
  GNUNET_CONTAINER_multishortmap_iterate (barrier->nodes,
                                          &free_barrier_node_cb,
                                          &free_barrier_node_cb_cls);
  GNUNET_CONTAINER_multishortmap_destroy (barrier->nodes);
  barrier->nodes = NULL;
}


static enum GNUNET_GenericReturnValue
free_barriers_cb (void *cls,
                  const struct GNUNET_ShortHashCode *key,
                  void *value)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Barrier *barrier = value;
  struct CommandListEntry *pos;

  free_barrier_nodes (is,
                      barrier);
  while (NULL != (pos = barrier->cmds_head))
  {
    GNUNET_CONTAINER_DLL_remove (barrier->cmds_head,
                                 barrier->cmds_tail,
                                 pos);
    GNUNET_free (pos);
  }
  GNUNET_free (barrier);
  return GNUNET_YES;
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
  if (NULL != is->send_handle)
  {
    GNUNET_HELPER_send_cancel (is->send_handle);
    is->send_handle = NULL;
  }
  GNUNET_free (is->commands);
  is->rc (is->rc_cls,
          is->result);
  GNUNET_CONTAINER_multishortmap_iterate (is->barriers,
                                          &free_barriers_cb,
                                          is);
  GNUNET_CONTAINER_multishortmap_destroy (is->barriers);
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
                cmd->label.value);
    while (GNUNET_TESTING_cmd_is_batch_ (cmd))
    {
      cmd = GNUNET_TESTING_cmd_batch_get_current_ (cmd);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed in batch at command `%s'\n",
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


/**
 * Returns the actual running command.
 * FIXME: needed? not in header!
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


struct GNUNET_TESTING_Interpreter *
GNUNET_TESTING_run (const struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout,
                    GNUNET_TESTING_ResultCallback rc,
                    void *rc_cls)
{
  struct GNUNET_TESTING_Interpreter *is;
  unsigned int i;

  is = GNUNET_new (struct GNUNET_TESTING_Interpreter);
  is->rc = rc;
  is->rc_cls = rc_cls;
  is->barriers = GNUNET_CONTAINER_multishortmap_create (1,
                                                        false);
  /* get the number of commands */
  for (i = 0; NULL != commands[i].run; i++)
    ;
  is->cmds_n = i + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got %u commands\n",
              i);
  is->commands = GNUNET_malloc_large (
    (i + 1)
    * sizeof (struct GNUNET_TESTING_Command));
  GNUNET_assert (NULL != is->commands);
  memcpy (is->commands,
          commands,
          sizeof (struct GNUNET_TESTING_Command) * i);
  is->timeout_task
    = GNUNET_SCHEDULER_add_delayed (timeout,
                                    &do_timeout,
                                    is);
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
  return is;
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_command_new_ac (
  void *cls,
  const char *label,
  GNUNET_TESTING_CommandRunRoutine run,
  GNUNET_TESTING_CommandCleanupRoutine cleanup,
  GNUNET_TESTING_CommandGetTraits traits,
  struct GNUNET_TESTING_AsyncContext *ac)
{
  struct GNUNET_TESTING_Command cmd = {
    .cls = cls,
    .run = run,
    .ac = ac,
    .cleanup = cleanup,
    .traits = traits
  };

  GNUNET_assert (NULL != run);
  if (NULL != label)
    GNUNET_TESTING_set_label (&cmd.label,
                              label);
  return cmd;
}


void
GNUNET_TESTING_set_label (struct GNUNET_TESTING_CommandLabel *label,
                          const char *value)
{
  size_t len;

  len = strlen (value);
  GNUNET_assert (len <=
                 GNUNET_TESTING_CMD_MAX_LABEL_LENGTH);
  memcpy (label->value,
          value,
          len + 1);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void)
{
  struct GNUNET_TESTING_Command cmd = {
    .run = NULL
  };

  return cmd;
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
GNUNET_TESTING_add_netjail_helper_ (struct GNUNET_TESTING_Interpreter *is,
                                    const struct GNUNET_HELPER_Handle *helper)
{
  GNUNET_array_append (is->helpers,
                       is->n_helpers,
                       helper);
}


struct GNUNET_TESTING_Barrier *
GNUNET_TESTING_get_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             const char *barrier_name)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode create_key;

  GNUNET_CRYPTO_hash (barrier_name,
                      strlen (barrier_name),
                      &hc);
  memcpy (&create_key,
          &hc,
          sizeof (create_key));
  return GNUNET_CONTAINER_multishortmap_get (is->barriers,
                                             &create_key);
}


/**
 * Add a barrier to the interpreter.
 *
 * @param is The interpreter.
 * @param barrier The barrier to add.
 */
void
GNUNET_TESTING_add_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                             struct GNUNET_TESTING_Barrier *barrier)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode create_key;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding barrier %s locally\n",
              barrier->name);
  GNUNET_CRYPTO_hash (barrier->name,
                      strlen (barrier->name),
                      &hc);
  memcpy (&create_key,
          &hc,
          sizeof (create_key));
  GNUNET_CONTAINER_multishortmap_put (is->barriers,
                                      &create_key,
                                      barrier,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
}


void
GNUNET_TESTING_finish_barrier_ (struct GNUNET_TESTING_Interpreter *is,
                                const char *barrier_name)
{
  struct CommandListEntry *pos;
  struct GNUNET_TESTING_Barrier *barrier;

  barrier = GNUNET_TESTING_get_barrier_ (is,
                                         barrier_name);
  if (NULL == barrier)
    return;
  while (NULL != (pos = barrier->cmds_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command label %s\n",
                pos->command->label.value);
    if ( (GNUNET_NO == pos->command->ac->finished) &&
         (GNUNET_NO == pos->command->asynchronous_finish) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "command label %s finish\n",
                  pos->command->label.value);
      GNUNET_TESTING_async_finish (pos->command->ac);
    }
    else if (GNUNET_NO == pos->command->ac->finished)
    {
      pos->command->asynchronous_finish = GNUNET_YES;
    }
    GNUNET_CONTAINER_DLL_remove (barrier->cmds_head,
                                 barrier->cmds_tail,
                                 pos);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command entry label %s removed\n",
                pos->command->label.value);
    GNUNET_free (pos);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command entry freed\n");
  }
  free_barrier_nodes (is,
                      barrier);
}


/* end of testing_api_loop.c */
