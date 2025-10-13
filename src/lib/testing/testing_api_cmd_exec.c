/*
      This file is part of GNUnet
      Copyright (C) 2023 GNUnet e.V.

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
 * @file testing_api_cmd_exec.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

struct BashScriptState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * Callback handed over to the command, which should
   * be called upon death or completion of the script.
   */
  GNUNET_ChildCompletedCallback cb;

  /**
   * Wait for death of @e start_proc.
   */
  struct GNUNET_ChildWaitHandle *cwh;

  /**
  * The process id of the script.
  */
  struct GNUNET_OS_Process *start_proc;

  /**
   * NULL-terminated array of command-line arguments.
   */
  char **args;

  /**
   *
   */
  enum GNUNET_OS_ProcessStatusType expected_type;

  /**
   *
   */
  unsigned long int expected_exit_code;

};

/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
exec_bash_script_cleanup (void *cls)
{
  struct BashScriptState *bss = cls;

  if (NULL != bss->cwh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cancel child\n");
    GNUNET_wait_child_cancel (bss->cwh);
    bss->cwh = NULL;
  }
  if (NULL != bss->start_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Kill process\n");
    GNUNET_assert (0 ==
                   GNUNET_OS_process_kill (bss->start_proc,
                                           SIGKILL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_OS_process_wait (bss->start_proc));
    GNUNET_OS_process_destroy (bss->start_proc);
    bss->start_proc = NULL;
  }
  for (unsigned int i = 0; NULL != bss->args[i]; i++)
    GNUNET_free (bss->args[i]);
  GNUNET_free (bss->args);
  GNUNET_free (bss);
}


/**
 * Callback which will be called if the setup script finished.
 *
 */
static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  struct BashScriptState *bss = cls;

  bss->cwh = NULL;
  GNUNET_OS_process_destroy (bss->start_proc);
  bss->start_proc = NULL;
  if ( (bss->expected_type != type) ||
       (bss->expected_exit_code != exit_code) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Child failed with error %lu (wanted %lu) %d/%d!\n",
                exit_code,
                bss->expected_exit_code,
                type,
                bss->expected_type);
    GNUNET_TESTING_async_fail (&bss->ac);
    return;
  }
  GNUNET_TESTING_async_finish (&bss->ac);
}


/**
 * Run method of the command created by the interpreter to wait for another
 * command to finish.
 *
 */
static void
exec_bash_script_run (void *cls,
                      struct GNUNET_TESTING_Interpreter *is)
{
  struct BashScriptState *bss = cls;

  GNUNET_assert (NULL == bss->cwh);
  bss->start_proc
    = GNUNET_OS_start_process_vap (
        GNUNET_OS_INHERIT_STD_ERR,
        NULL,
        NULL,
        NULL,
        bss->args[0],
        bss->args);
  bss->cwh = GNUNET_wait_child (bss->start_proc,
                                &child_completed_callback,
                                bss);
  GNUNET_break (NULL != bss->cwh);
}


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
traits (void *cls,
        const void **ret,
        const char *trait,
        unsigned int index)
{
  struct BashScriptState *bss = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_TESTING_make_trait_process (&bss->start_proc),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  char *const script_argv[])
{
  struct BashScriptState *bss;
  unsigned int cnt;

  cnt = 0;
  while (NULL != script_argv[cnt])
    cnt++;
  bss = GNUNET_new (struct BashScriptState);
  bss->args = GNUNET_new_array (cnt + 1,
                                char *);
  for (unsigned int i = 0; i<cnt; i++)
    bss->args[i] = GNUNET_strdup (script_argv[i]);
  bss->expected_type = expected_type;
  bss->expected_exit_code = expected_exit_code;
  return GNUNET_TESTING_command_new_ac (
    bss,
    label,
    &exec_bash_script_run,
    &exec_bash_script_cleanup,
    &traits,
    &bss->ac);
}


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_va (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  ...)
{
  struct BashScriptState *bss;
  va_list ap;
  const char *arg;
  unsigned int cnt;

  bss = GNUNET_new (struct BashScriptState);
  va_start (ap,
            expected_exit_code);
  cnt = 1;
  while (NULL != (arg = va_arg (ap,
                                const char *)))
    cnt++;
  va_end (ap);
  bss->args = GNUNET_new_array (cnt,
                                char *);
  cnt = 0;
  va_start (ap,
            expected_exit_code);
  while (NULL != (arg = va_arg (ap,
                                const char *)))
    bss->args[cnt++] = GNUNET_strdup (arg);
  va_end (ap);
  bss->expected_type = expected_type;
  bss->expected_exit_code = expected_exit_code;
  return GNUNET_TESTING_command_new_ac (
    bss,
    label,
    &exec_bash_script_run,
    &exec_bash_script_cleanup,
    &traits,
    &bss->ac);
}
