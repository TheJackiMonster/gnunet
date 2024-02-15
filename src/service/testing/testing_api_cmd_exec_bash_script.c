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
 * @file testing_api_cmd_local_test_prepared.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

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

  // Child Wait handle
  struct GNUNET_ChildWaitHandle *cwh;

   /**
   * The process id of the script.
   */
  struct GNUNET_OS_Process *start_proc;

  /**
   * Script this cmd will execute.
   */
  const char *script;


  /**
   * Arguments for the script
   */
  char **script_argv;

  /**
   * Size of script_argv.
   */
  int argc;
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

  GNUNET_OS_process_destroy (bss->start_proc);
  bss->start_proc = NULL;
  bss->cwh = NULL;
  if (0 == exit_code)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Child succeeded!\n");
    GNUNET_TESTING_async_finish (&bss->ac);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Child failed with error %lu!\n",
                exit_code);
    GNUNET_TESTING_async_fail (&bss->ac);
  }
  bss->cb (cls, type, exit_code);
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
  enum GNUNET_GenericReturnValue helper_check;

  helper_check = GNUNET_OS_check_helper_binary (
    bss->script_argv[0],
    GNUNET_YES,
    NULL);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "script_name %s\n",
       bss->script_argv[0]);

  if (GNUNET_NO == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,        
                "No SUID for %s!\n",
                bss->script_argv[0]);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }
  if (GNUNET_SYSERR == helper_check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s not found!\n",
                bss->script_argv[0]);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  bss->start_proc = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ERR,
                                     NULL,
                                     NULL,
                                     NULL,
                                     bss->script_argv[0],
                                     bss->script_argv);
  bss->cwh = GNUNET_wait_child (bss->start_proc,
                               &child_completed_callback,
                               bss);
  GNUNET_break (NULL != bss->cwh);
}

const struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_bash_script (const char *label,
                                     const char *script,
                                     char *const script_argv[],
                                     int argc,
                                     GNUNET_ChildCompletedCallback cb)
{
  struct BashScriptState *bss;
  char *data_dir;
  char *script_name;
  unsigned int c;

  data_dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf (&script_name, "%s%s", data_dir, script);

  bss = GNUNET_new (struct BashScriptState);
  bss->cb = cb;
  bss->script_argv = GNUNET_malloc (sizeof(char *) * (argc + 2));

  bss->script_argv[0] = GNUNET_strdup (script_name);
  for (c = 0; c < argc; c++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "script_argv %u: %s\n",
         c,
         script_argv[c]);
    bss->script_argv[c + 1] = GNUNET_strdup (script_argv[c]);
  }
  bss->script_argv[c + 1] = NULL;
  return GNUNET_TESTING_command_new (bss,
                                     label,
                                     &exec_bash_script_run,
                                     &exec_bash_script_cleanup,
                                     NULL,
                                     &bss->ac);
}
