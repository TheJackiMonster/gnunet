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
#include "gnunet_common.h"
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
  const struct GNUNET_HELPER_Handle **helper;

  /**
   * Size of the array helper.
   *
   */
  unsigned int n_helper;

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

  /**
   * Is the interpreter finishing?
   */
  unsigned int finishing;

};

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

    if (NULL != cmd->run)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "label to compare %s\n",
                  cmd->label);
    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->run) &&
         (0 == strcmp (cmd->label,
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

  is->finishing = GNUNET_YES;
  is->final_task = NULL;
  label = is->commands[is->ip].label;
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
  GNUNET_free (is->helper);
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
  if (NULL == cmd->run)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running command END\n");
    is->result = GNUNET_OK;
    finish_test (is);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
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


enum GNUNET_GenericReturnValue
GNUNET_TESTING_running (const struct GNUNET_TESTING_Command *command)
{
  return 0 != command->start_time.abs_value_us && 0 ==
         command->finish_time.abs_value_us;
}


enum GNUNET_GenericReturnValue
GNUNET_TESTING_finished (const struct GNUNET_TESTING_Command *command)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Relative diff = GNUNET_TIME_absolute_get_difference (
    command->finish_time,
    now);
  return 0 < diff.rel_value_us;
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
  is->barriers = GNUNET_CONTAINER_multishortmap_create (1,GNUNET_NO);
  /* get the number of commands */
  for (i = 0; NULL != commands[i].run; i++)
    ;
  is->cmds_n = i + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got %u commands\n", i);
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

  return is;
}

struct GNUNET_TESTING_Command
GNUNET_TESTING_command_new (void *cls,
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
  memset (&cmd.label, 0, sizeof (cmd.label));
  if (NULL != label)
    strncpy (cmd.label, label, GNUNET_TESTING_CMD_MAX_LABEL_LENGTH);

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

/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
clear_msg (void *cls, int result)
{
  GNUNET_assert (GNUNET_YES == result);
}

/**
 * Adding a helper handle to the interpreter.
 *
 * @param is The interpreter.
 * @param helper The helper handle.
 */
void
GNUNET_TESTING_add_netjail_helper (struct GNUNET_TESTING_Interpreter *is,
                                   const struct GNUNET_HELPER_Handle *helper)
{
  GNUNET_array_append (is->helper, is->n_helper, helper);
}


/**
 * Send Message to netjail nodes. 
 *
 * @param is The interpreter.
 * @param global_node_number The netjail node to inform.
 * @param header The message to send.
 */
void
send_message_to_netjail (struct GNUNET_TESTING_Interpreter *is,
                                        unsigned int global_node_number,
                                        struct GNUNET_MessageHeader *header)
{
  const struct GNUNET_HELPER_Handle *helper;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send message of type %u to locals\n",
              ntohs (header->type));
  helper = is->helper[global_node_number - 1];
  struct GNUNET_HELPER_SendHandle *sh = GNUNET_HELPER_send (
    (struct GNUNET_HELPER_Handle *) helper,
    header,
    GNUNET_NO,
    &clear_msg,
    NULL);
}

void
TST_interpreter_send_barrier_crossable (struct GNUNET_TESTING_Interpreter *is,
                                      const char *barrier_name,
                                      unsigned int global_node_number)
{
  struct CommandBarrierCrossable *adm;
  size_t msg_length;
  size_t name_len;
  char *terminator = "\0";

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send barrier name %s barrier_name\n",
              barrier_name);
  name_len = strlen (barrier_name);
  msg_length = sizeof(struct CommandBarrierCrossable) + name_len + 1;
  adm = GNUNET_malloc (msg_length);
  adm->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE);
  adm->header.size = htons ((uint16_t) msg_length);
  memcpy (&adm[1], barrier_name, name_len);
  send_message_to_netjail (is,
                                          global_node_number,
                                          &adm->header);
  GNUNET_free (adm);
}



int
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
  if (GNUNET_NO == is->finishing)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TST_interpreter_send_barrier_crossable\n");
    TST_interpreter_send_barrier_crossable (is,
                                          barrier->name,
                                          node->node_number);
  }
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multishortmap_remove (barrier->nodes, key, node));
  return GNUNET_YES;
}


/**
  * Getting a barrier from the interpreter.
  *
  * @param is The interpreter.
  * @param barrier_name The name of the barrier.
  * @return The barrier.
  */
struct GNUNET_TESTING_Barrier *
TST_interpreter_get_barrier (struct GNUNET_TESTING_Interpreter *is,
                            const char *barrier_name)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode create_key;
  struct GNUNET_TESTING_Barrier *barrier;

  GNUNET_CRYPTO_hash (barrier_name, strlen (barrier_name), &hc);
  memcpy (&create_key,
          &hc,
          sizeof (create_key));
  barrier = GNUNET_CONTAINER_multishortmap_get (is->barriers, &create_key);
  return barrier;
}


/**
 * Finish all "barrier reached" comands attached to this barrier.
 *
 * @param barrier The barrier in question.
 */
void
TST_interpreter_finish_attached_cmds (struct GNUNET_TESTING_Interpreter *is,
                                      const char *barrier_name)
{
  struct CommandListEntry *pos;
  struct FreeBarrierNodeCbCls *free_barrier_node_cb_cls;
  struct GNUNET_TESTING_Barrier *barrier = TST_interpreter_get_barrier (is,
                                                                       barrier_name);

  while (NULL != barrier && NULL != (pos = barrier->cmds_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command label %s\n",
                pos->command->label);
    if (GNUNET_NO == pos->command->ac->finished &&
        GNUNET_NO == pos->command->asynchronous_finish)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command label %s finish\n",
                pos->command->label);
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
                pos->command->label);
    GNUNET_free (pos);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "command entry freed\n");
  }
  if (NULL != barrier->nodes)
  {
    free_barrier_node_cb_cls = GNUNET_new (struct FreeBarrierNodeCbCls);
    free_barrier_node_cb_cls->barrier = barrier;
    free_barrier_node_cb_cls->is = is;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "freeing nodes\n");
    GNUNET_CONTAINER_multishortmap_iterate (barrier->nodes, free_barrier_node_cb,
                                            free_barrier_node_cb_cls);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nodes freed\n");
    GNUNET_free (free_barrier_node_cb_cls);
    GNUNET_CONTAINER_multishortmap_destroy (barrier->nodes);
    barrier->nodes = NULL;
  }
}


int
free_barriers_cb (void *cls,
                  const struct GNUNET_ShortHashCode *key,
                  void *value)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Barrier *barrier = value;
  struct CommandListEntry *pos;
  struct FreeBarrierNodeCbCls *free_barrier_node_cb_cls;

  if (NULL != barrier->nodes)
  {
    free_barrier_node_cb_cls = GNUNET_new (struct FreeBarrierNodeCbCls);
    free_barrier_node_cb_cls->barrier = barrier;
    free_barrier_node_cb_cls->is = is;
    GNUNET_CONTAINER_multishortmap_iterate (barrier->nodes, free_barrier_node_cb,
                                            free_barrier_node_cb_cls);
    GNUNET_CONTAINER_multishortmap_destroy (barrier->nodes);
    barrier->nodes = NULL;
  }

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
  * Deleting all barriers create in the context of this interpreter.
  *
  * @param is The interpreter.
  */
void
TST_interpreter_delete_barriers (struct GNUNET_TESTING_Interpreter *is)
{
  GNUNET_CONTAINER_multishortmap_iterate (is->barriers,
                                          free_barriers_cb,
                                          is);
  GNUNET_CONTAINER_multishortmap_destroy (is->barriers);
}


/**
 * Add a barrier to the loop.
 *
 * @param is The interpreter.
 * @param barrier The barrier to add.
 */
void
TST_interpreter_add_barrier (struct GNUNET_TESTING_Interpreter *is,
                                        struct GNUNET_TESTING_Barrier *barrier)
{
  struct GNUNET_HashCode hc;
  struct GNUNET_ShortHashCode create_key;

  GNUNET_CRYPTO_hash (barrier->name, strlen (barrier->name), &hc);
  memcpy (&create_key,
          &hc,
          sizeof (create_key));
  GNUNET_CONTAINER_multishortmap_put (is->barriers,
                                      &create_key,
                                      barrier,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
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
