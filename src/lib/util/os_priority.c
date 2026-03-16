/*
     This file is part of GNUnet
     Copyright (C) 2002, 2003, 2004, 2005, 2006, 2011 GNUnet e.V.

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
 * @file util/os_priority.c
 * @brief Methods to set process priority
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"
#include <unistr.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-os-priority", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
        GNUNET_log_from_strerror (kind, "util-os-priority", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
        GNUNET_log_from_strerror_file (kind, "util-os-priority", syscall, \
                                       filename)

#define GNUNET_OS_CONTROL_PIPE "GNUNET_OS_CONTROL_PIPE"

/**
 * Handle for the #parent_control_handler() Task.
 */
static struct GNUNET_SCHEDULER_Task *pch;

/**
 * Handle for the #shutdown_pch() Task.
 */
static struct GNUNET_SCHEDULER_Task *spch;


/**
 * This handler is called on shutdown to remove the #pch.
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
shutdown_pch (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;

  GNUNET_SCHEDULER_cancel (pch);
  pch = NULL;
  GNUNET_DISK_file_close (control_pipe);
  control_pipe = NULL;
}


/**
 * This handler is called when there are control data to be read on the pipe
 *
 * @param cls the `struct GNUNET_DISK_FileHandle` of the control pipe
 */
static void
parent_control_handler (void *cls)
{
  struct GNUNET_DISK_FileHandle *control_pipe = cls;
  char sig;
  char *pipe_fd;
  ssize_t ret;

  pch = NULL;
  ret = GNUNET_DISK_file_read (control_pipe, &sig, sizeof(sig));
  if (sizeof(sig) != ret)
  {
    if (-1 == ret)
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "GNUNET_DISK_file_read");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Closing control pipe\n");
    GNUNET_DISK_file_close (control_pipe);
    control_pipe = NULL;
    GNUNET_SCHEDULER_cancel (spch);
    spch = NULL;
    return;
  }
  pipe_fd = getenv (GNUNET_OS_CONTROL_PIPE);
  GNUNET_assert ((NULL == pipe_fd) || (strlen (pipe_fd) <= 0));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got control code %d from parent via pipe %s\n",
       sig,
       pipe_fd);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  GNUNET_SIGNAL_raise ((int) sig);
}


void
GNUNET_OS_install_parent_control_handler (void *cls)
{
  const char *env_buf;
  char *env_buf_end;
  struct GNUNET_DISK_FileHandle *control_pipe;
  uint64_t pipe_fd;

  (void) cls;
  if (NULL != pch)
  {
    /* already done, we've been called twice... */
    GNUNET_break (0);
    return;
  }
  env_buf = getenv (GNUNET_OS_CONTROL_PIPE);
  if ((NULL == env_buf) || (strlen (env_buf) <= 0))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not installing a handler because $%s is empty\n",
         GNUNET_OS_CONTROL_PIPE);
    setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
    return;
  }
  errno = 0;
  pipe_fd = strtoull (env_buf, &env_buf_end, 16);
  if ((0 != errno) || (env_buf == env_buf_end))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "strtoull", env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
    return;
  }
  if (pipe_fd >= FD_SETSIZE)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "GNUNET_OS_CONTROL_PIPE `%s' contains garbage?\n",
         env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
    return;
  }

  control_pipe = GNUNET_DISK_get_handle_from_int_fd ((int) pipe_fd);

  if (NULL == control_pipe)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "open", env_buf);
    setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding parent control handler pipe `%s' to the scheduler\n",
       env_buf);
  pch = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        control_pipe,
                                        &parent_control_handler,
                                        control_pipe);
  spch = GNUNET_SCHEDULER_add_shutdown (&shutdown_pch, control_pipe);
  setenv (GNUNET_OS_CONTROL_PIPE, "", 1);
}


/**
 * Handle to a command.
 */
struct GNUNET_OS_CommandHandle
{
  /**
   * Process handle.
   */
  struct GNUNET_Process *eip;

  /**
   * Handle to the output pipe.
   */
  struct GNUNET_DISK_PipeHandle *opipe;

  /**
   * Read-end of output pipe.
   */
  const struct GNUNET_DISK_FileHandle *r;

  /**
   * Function to call on each line of output.
   */
  GNUNET_OS_LineProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Buffer for the output.
   */
  char buf[1024];

  /**
   * Task reading from pipe.
   */
  struct GNUNET_SCHEDULER_Task *rtask;

  /**
   * When to time out.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Current read offset in buf.
   */
  size_t off;
};


void
GNUNET_OS_command_stop (struct GNUNET_OS_CommandHandle *cmd)
{
  if (NULL != cmd->proc)
  {
    GNUNET_assert (NULL != cmd->rtask);
    GNUNET_SCHEDULER_cancel (cmd->rtask);
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_process_kill (cmd->eip,
                                     SIGKILL));
  GNUNET_break (GNUNET_OK ==
                GNUNET_process_wait (cmd->eip,
                                     true,
                                     NULL,
                                     NULL));
  GNUNET_process_destroy (cmd->eip);
  GNUNET_DISK_pipe_close (cmd->opipe);
  GNUNET_free (cmd);
}


/**
 * Read from the process and call the line processor.
 *
 * @param cls the `struct GNUNET_OS_CommandHandle *`
 */
static void
cmd_read (void *cls)
{
  struct GNUNET_OS_CommandHandle *cmd = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;
  GNUNET_OS_LineProcessor proc;
  char *end;
  ssize_t ret;

  cmd->rtask = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if (GNUNET_YES !=
      GNUNET_NETWORK_fdset_handle_isset (tc->read_ready,
                                         cmd->r))
  {
    /* timeout */
    proc = cmd->proc;
    cmd->proc = NULL;
    proc (cmd->proc_cls, NULL);
    return;
  }
  ret = GNUNET_DISK_file_read (cmd->r,
                               &cmd->buf[cmd->off],
                               sizeof(cmd->buf) - cmd->off);
  if (ret <= 0)
  {
    if ((cmd->off > 0) && (cmd->off < sizeof(cmd->buf)))
    {
      cmd->buf[cmd->off] = '\0';
      cmd->proc (cmd->proc_cls, cmd->buf);
    }
    proc = cmd->proc;
    cmd->proc = NULL;
    proc (cmd->proc_cls, NULL);
    return;
  }
  end = memchr (&cmd->buf[cmd->off], '\n', ret);
  cmd->off += ret;
  while (NULL != end)
  {
    *end = '\0';
    cmd->proc (cmd->proc_cls, cmd->buf);
    memmove (cmd->buf, end + 1, cmd->off - (end + 1 - cmd->buf));
    cmd->off -= (end + 1 - cmd->buf);
    end = memchr (cmd->buf, '\n', cmd->off);
  }
  cmd->rtask =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_absolute_get_remaining (
                                      cmd->timeout),
                                    cmd->r,
                                    &cmd_read,
                                    cmd);
}


struct GNUNET_OS_CommandHandle *
GNUNET_OS_command_run (GNUNET_OS_LineProcessor proc,
                       void *proc_cls,
                       struct GNUNET_TIME_Relative timeout,
                       const char *binary,
                       ...)
{
  struct GNUNET_OS_CommandHandle *cmd;
  struct GNUNET_Process *eip;
  struct GNUNET_DISK_PipeHandle *opipe;
  va_list ap;

  opipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_BLOCKING_RW);
  if (NULL == opipe)
    return NULL;
  va_start (ap, binary);
  /* redirect stdout, don't inherit stderr/stdin */
  eip = GNUNET_process_create (GNUNET_OS_INHERIT_STD_NONE);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_process_set_options (
                   eip,
                   GNUNET_process_option_inherit_wpipe (opipe,
                                                        STDOUT_FILENO)));
  if (GNUNET_OK !=
      GNUNET_process_run_command_va (eip,
                                     binary,
                                     ap))
  {
    GNUNET_process_destroy (eip);
    va_end (ap);
    GNUNET_DISK_pipe_close (opipe);
    return NULL;
  }
  va_end (ap);
  GNUNET_DISK_pipe_close_end (opipe,
                              GNUNET_DISK_PIPE_END_WRITE);
  cmd = GNUNET_new (struct GNUNET_OS_CommandHandle);
  cmd->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  cmd->eip = eip;
  cmd->opipe = opipe;
  cmd->proc = proc;
  cmd->proc_cls = proc_cls;
  cmd->r = GNUNET_DISK_pipe_handle (opipe,
                                    GNUNET_DISK_PIPE_END_READ);
  cmd->rtask = GNUNET_SCHEDULER_add_read_file (timeout,
                                               cmd->r,
                                               &cmd_read, cmd);
  return cmd;
}


/* end of os_priority.c */
