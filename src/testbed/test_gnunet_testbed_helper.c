/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 3, or (at your
      option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      General Public License for more details.

      You should have received a copy of the GNU General Public License
      along with GNUnet; see the file COPYING.  If not, write to the
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file testbed/test_gnunet_testbed_helper.c
 * @brief Testcase for testing gnunet-testbed-helper.c
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "testbed_helper.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)


/**
 * Handle to the helper process
 */
static struct GNUNET_HELPER_Handle *helper;

/**
 * Message to helper
 */
static struct GNUNET_TESTBED_HelperInit msg;


/**
 * Message send handle
 */
static struct GNUNET_HELPER_SendHandle *shandle;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Shutdown task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{  
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  GNUNET_HELPER_stop (helper);  
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_HELPER_send_cancel (shandle);
  if (GNUNET_SCHEDULER_NO_TASK == shutdown_task)
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Continuation function.
 * 
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void 
cont_cb (void *cls, int result)
{
  shandle = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Message sent\n");
  GNUNET_assert (GNUNET_OK == result);
  if (GNUNET_SCHEDULER_NO_TASK == shutdown_task)
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}



/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void 
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  char * const binary_argv[] = {
    "gnunet-testbed-helper",
    NULL
    };

  helper = GNUNET_HELPER_start ("gnunet-testbed-helper", binary_argv,
                                NULL, NULL);
  GNUNET_assert (NULL != helper);
  msg.header.size = htons (sizeof (struct GNUNET_TESTBED_HelperInit));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT);
  msg.cname_size = htons (0);
  msg.config_size = htons (0);
  shandle = GNUNET_HELPER_send (helper,
                                (const struct GNUNET_MessageHeader *) &msg,
                                GNUNET_NO, cont_cb, NULL);
  GNUNET_assert (NULL != shandle);
  abort_task = GNUNET_SCHEDULER_add_delayed 
    (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1), &do_abort, NULL);
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

   if (GNUNET_OK != 
       GNUNET_PROGRAM_run (argc, argv, "test_gnunet_testbed_helper",
                           "Testcase for testing gnunet-testbed-helper.c",
                           options, &run, NULL))
     return 1;
  else return 0;
}
