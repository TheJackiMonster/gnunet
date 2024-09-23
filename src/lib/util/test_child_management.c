/*
  This file is part of GNUnet
  Copyright (C) 2014-2021 GNUnet e.V.

  GNUNET is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 3, or
  (at your option) any later version.

  GNUNET is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public
  License along with GNUNET; see the file COPYING.  If not, see
  <http://www.gnu.org/licenses/>
*/

/**
 * @file lib/test_child_management.c
 * @brief testcase to test the child management
 * @author Christian Grothoff
 * @author Dominik Meister
 */

#include "platform.h"
#include "gnunet_util_lib.h"


static struct GNUNET_ChildWaitHandle *cwh;

static int global_ret;

static struct GNUNET_OS_Process *pid;


static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  FILE *file;
  char code[9];

  cwh = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Process extided with code: %lu \n",
              exit_code);
  file = fopen ("child_management_test.txt", "r");
  if (NULL == file)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "could not find file: child_management_test.txt in %s:%u\n",
                __FILE__,
                __LINE__);
    global_ret = 1;
    return;
  }
  if (0 == fscanf (file,
                   "%8s",
                   code))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "could not read file: child_management_test.txt in %s:%u\n",
                __FILE__,
                __LINE__);
    global_ret = 1;
    return;
  }

  if (0 != strcmp ("12345678", code))
  {
    global_ret = 1;
    return;
  }
  GNUNET_OS_process_destroy (pid);
  pid = NULL;
  GNUNET_break (0 == unlink ("child_management_test.txt"));
  GNUNET_SCHEDULER_shutdown ();
  global_ret = 0;
}


static void
do_shutdown (void *cls)
{
  if (NULL != cwh)
  {
    GNUNET_wait_child_cancel (cwh);
    cwh = NULL;
  }
  if (NULL != pid)
  {
    GNUNET_assert (0 ==
                   GNUNET_OS_process_kill (pid,
                                           SIGKILL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_OS_process_wait (pid));
    GNUNET_OS_process_destroy (pid);
    pid = NULL;
  }
}


static void
test_child_management (void *cls)
{
  const char *command = "./child_management_test.sh";
  struct GNUNET_DISK_PipeHandle *p;
  struct GNUNET_DISK_FileHandle *out;

  (void) cls;
  p = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE);
  if (NULL == p)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "pipe");
    global_ret = 2;
    return;
  }
  pid = GNUNET_OS_start_process (0,
                                 p,
                                 NULL,
                                 NULL,
                                 command,
                                 command,
                                 "1234",
                                 "5678",
                                 NULL);
  if (NULL == pid)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "fork");
    GNUNET_break (GNUNET_OK ==
                  GNUNET_DISK_pipe_close (p));
    global_ret = 1;
    return;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_pipe_close_end (p,
                                            GNUNET_DISK_PIPE_END_READ));
  out = GNUNET_DISK_pipe_detach_end (p,
                                     GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_assert (NULL != out);
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_pipe_close (p));

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Alright");
  cwh = GNUNET_wait_child (pid,
                           &child_completed_callback,
                           cls);
  GNUNET_break (NULL != cwh);
  GNUNET_assert (5 ==
                 GNUNET_DISK_file_write (out,
                                         "Hello",
                                         5));
  GNUNET_break (GNUNET_OK ==
                GNUNET_DISK_file_close (out));
}


int
main (int argc,
      const char *const argv[])
{
  GNUNET_log_setup (argv[0],
                    "DEBUG",
                    NULL);
  GNUNET_SCHEDULER_run (&test_child_management,
                        NULL);
  return global_ret;
}


/* end of test_anastasis_child_management.c */
