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
 * @file testing/child_management.c
 * @brief Handling of child processes in GNUnet.
 * @author Christian Grothoff (ANASTASIS)
 * @author Dominik Meister (ANASTASIS)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_child_management_lib.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)


/**
 * Struct which defines a Child Wait handle
 */
struct GNUNET_ChildWaitHandle
{
  /**
   * Linked list to the next child
   */
  struct GNUNET_ChildWaitHandle *next;
  /**
   * Linked list to the previous child
   */
  struct GNUNET_ChildWaitHandle *prev;
  /**
   * Child process which is managed
   */
  struct GNUNET_OS_Process *proc;
  /**
   * Callback which is called upon completion/death of the child task
   */
  GNUNET_ChildCompletedCallback cb;
  /**
   * Closure for the handle
   */
  void *cb_cls;
};


/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

static struct GNUNET_SIGNAL_Context *shc_chld;

static struct GNUNET_SCHEDULER_Task *sig_task;

static struct GNUNET_ChildWaitHandle *cwh_head;

static struct GNUNET_ChildWaitHandle *cwh_tail;

/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died) or when user presses CTRL-C.
 *
 * @param cls closure, NULL
 */
static void
maint_child_death (void *cls)
{
  char buf[16];
  const struct GNUNET_DISK_FileHandle *pr;
  struct GNUNET_ChildWaitHandle *nxt;

  (void) cls;
  sig_task = NULL;
  /* drain pipe */
  pr = GNUNET_DISK_pipe_handle (sigpipe,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (! GNUNET_DISK_handle_invalid (pr));
  (void) GNUNET_DISK_file_read (pr,
                                buf,
                                sizeof(buf));

  /* find applicable processes that exited */
  for (struct GNUNET_ChildWaitHandle *cwh = cwh_head;
       NULL != cwh;
       cwh = nxt)
  {
    enum GNUNET_OS_ProcessStatusType type;
    long unsigned int exit_code = 0;

    nxt = cwh->next;
    if (GNUNET_OK ==
        GNUNET_OS_process_status (cwh->proc,
                                  &type,
                                  &exit_code))
    {
      GNUNET_CONTAINER_DLL_remove (cwh_head,
                                   cwh_tail,
                                   cwh);
      cwh->cb (cwh->cb_cls,
               type,
               exit_code);
      GNUNET_free (cwh);
    }
  }
  if (NULL == cwh_head)
    return;
  /* wait for more */
  sig_task = GNUNET_SCHEDULER_add_read_file (
    GNUNET_TIME_UNIT_FOREVER_REL,
    GNUNET_DISK_pipe_handle (sigpipe,
                             GNUNET_DISK_PIPE_END_READ),
    &maint_child_death,
    NULL);
}


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death (void)
{
  static char c;
  int old_errno = errno; /* back-up errno */

  GNUNET_break (
    1 ==
    GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle (sigpipe,
                                                     GNUNET_DISK_PIPE_END_WRITE),
                            &c,
                            sizeof(c)));
  errno = old_errno; /* restore errno */
}


static void
child_management_start (void)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Trying to start child management.\n");
  if (NULL != sigpipe)
    return; /* already initialized */
  sigpipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE);
  GNUNET_assert (sigpipe != NULL);
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD,
                                   &sighandler_child_death);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Child management started.\n");
}


/**
 * Clean up.
 */
static void
child_management_done (void)
{
  if (NULL != sig_task)
  {
    GNUNET_SCHEDULER_cancel (sig_task);
    sig_task = NULL;
  }
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Child management stopped.\n");
}


struct GNUNET_ChildWaitHandle *
GNUNET_wait_child (struct GNUNET_OS_Process *proc,
                   GNUNET_ChildCompletedCallback cb,
                   void *cb_cls)
{
  struct GNUNET_ChildWaitHandle *cwh;

  child_management_start ();
  cwh = GNUNET_new (struct GNUNET_ChildWaitHandle);
  cwh->proc = proc;
  cwh->cb = cb;
  cwh->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert (cwh_head,
                               cwh_tail,
                               cwh);
  if (NULL == sig_task)
  {
    sig_task = GNUNET_SCHEDULER_add_read_file (
      GNUNET_TIME_UNIT_FOREVER_REL,
      GNUNET_DISK_pipe_handle (sigpipe,
                               GNUNET_DISK_PIPE_END_READ),
      &maint_child_death,
      NULL);
  }
  return cwh;
}


void
GNUNET_wait_child_cancel (struct GNUNET_ChildWaitHandle *cwh)
{
  GNUNET_CONTAINER_DLL_remove (cwh_head,
                               cwh_tail,
                               cwh);
  GNUNET_free (cwh);
  if (NULL != cwh_head)
    return;
  child_management_done ();
}
