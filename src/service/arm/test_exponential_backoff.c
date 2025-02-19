/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2016 GNUnet e.V.

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
 * @file arm/test_exponential_backoff.c
 * @brief testcase for gnunet-service-arm.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"

#define LOG(...) GNUNET_log (GNUNET_ERROR_TYPE_INFO, __VA_ARGS__)

#define LOG_BACKOFF GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define SERVICE_TEST_TIMEOUT GNUNET_TIME_UNIT_FOREVER_REL

#define FIVE_MILLISECONDS GNUNET_TIME_relative_multiply ( \
          GNUNET_TIME_UNIT_MILLISECONDS, 5)

#define SERVICE "do-nothing"

#define BINARY "mockup-service"

#define CFGFILENAME "test_arm_api_data2.conf"


static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ARM_Handle *arm;

static struct GNUNET_ARM_MonitorHandle *mon;

static struct GNUNET_ARM_Operation *op;

static struct GNUNET_SCHEDULER_Task *kt;

static int ok = 1;

static int phase = 0;

static int trialCount;

static bool arm_stopped;

static struct GNUNET_TIME_Absolute startedWaitingAt;

struct GNUNET_TIME_Relative waitedFor;

struct GNUNET_TIME_Relative waitedFor_prev;

#if LOG_BACKOFF
static FILE *killLogFilePtr;

static char *killLogFileName;
#endif

/**
 * Connection to the service that is being shutdown.
 */
static struct GNUNET_MQ_Handle *mq;

/**
 * Task set up to cancel the shutdown request on timeout.
 */
static struct GNUNET_SCHEDULER_Task *cancel_task;


static void
kill_task (void *cbData);


/**
 * Shutting down took too long, cancel receive and return error.
 *
 * @param cls closure
 */
static void
service_shutdown_timeout (void *cls)
{
  cancel_task = NULL;
  GNUNET_MQ_destroy (mq);
  mq = NULL;
  GNUNET_break (0);
  ok = 32;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct ShutdownContext *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Service shutdown complete (MQ error).\n");
  GNUNET_SCHEDULER_cancel (cancel_task);
  cancel_task = NULL;
  GNUNET_MQ_destroy (mq);
  mq = NULL;
}


static void
kill_task (void *cbData)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end ()
  };

  kt = NULL;
  if (trialCount == 13)
  {
    LOG ("Saw enough kills, asking ARM to stop mock service for good\n");
    GNUNET_ARM_request_service_stop (arm,
                                     SERVICE,
                                     NULL,
                                     NULL);
    ok = 0;
    trialCount++;
    return;
  }
  mq = GNUNET_CLIENT_connect (cfg,
                              SERVICE,
                              handlers,
                              &mq_error_handler,
                              NULL);
  GNUNET_assert (NULL != mq);
  trialCount++;
  LOG ("Sending a shutdown request to the mock service\n");
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_ARM_STOP); /* FIXME: abuse of message type */
  GNUNET_MQ_send (mq,
                  env);
  GNUNET_assert (NULL == cancel_task);
  cancel_task
    = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                    &service_shutdown_timeout,
                                    NULL);
}


static void
disconnect_all (void *cls)
{
  (void) cls;
  cancel_task = NULL;
  GNUNET_ARM_disconnect (arm);
  GNUNET_ARM_monitor_stop (mon);
  if (NULL != kt)
  {
    GNUNET_SCHEDULER_cancel (kt);
    kt = NULL;
  }
}


static void
finish_shutdown (void *cls,
                 enum GNUNET_ARM_RequestStatus status,
                 enum GNUNET_ARM_Result result)
{
  (void) cls;
  (void) status;
  (void) result;
  op = NULL;
  GNUNET_assert (NULL == cancel_task);
  cancel_task
    = GNUNET_SCHEDULER_add_now (&disconnect_all,
                                NULL);
}


static void
trigger_disconnect (void *cls)
{
  if (NULL != op)
  {
    GNUNET_ARM_operation_cancel (op);
    op = NULL;
  }
  if (NULL != mq)
  {
    GNUNET_MQ_destroy (mq);
    mq = NULL;
  }
  if (NULL != cancel_task)
  {
    GNUNET_SCHEDULER_cancel (cancel_task);
    cancel_task = NULL;
  }
  if (! arm_stopped)
  {
    op = GNUNET_ARM_request_service_stop (arm,
                                          "arm",
                                          &finish_shutdown,
                                          NULL);
    return;
  }
  finish_shutdown (NULL,
                   GNUNET_ARM_REQUEST_SENT_OK,
                   GNUNET_ARM_RESULT_STOPPED);
}


static void
arm_stop_cb (void *cls,
             enum GNUNET_ARM_RequestStatus status,
             enum GNUNET_ARM_Result result)
{
  op = NULL;
  arm_stopped = true;
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STOPPED);
  LOG ("ARM service stopped\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
clear_op_cb (void *cls,
             enum GNUNET_ARM_RequestStatus status,
             enum GNUNET_ARM_Result result)
{
  LOG ("ARM operation complete\n");
  op = NULL;
}


static void
srv_status (void *cls,
            const char *service,
            enum GNUNET_ARM_ServiceMonitorStatus status)
{
  if (status == GNUNET_ARM_SERVICE_MONITORING_STARTED)
  {
    LOG ("ARM monitor started, starting mock service\n");
    phase++;
    GNUNET_assert (NULL == op);
    op = GNUNET_ARM_request_service_start (arm,
                                           SERVICE,
                                           GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                           &clear_op_cb,
                                           NULL);
    return;
  }
  if (0 != strcasecmp (service,
                       SERVICE))
    return; /* not what we care about */
  if (phase == 1)
  {
    GNUNET_break (status == GNUNET_ARM_SERVICE_STARTING);
    GNUNET_break (phase == 1);
    LOG ("do-nothing is starting\n");
    phase++;
    ok = 1;
    startedWaitingAt = GNUNET_TIME_absolute_get ();
    GNUNET_assert (NULL == kt);
    kt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                       &kill_task,
                                       NULL);
  }
  else if (phase == 2)
  {
    /* We passively monitor ARM for status updates. ARM should tell us
     * when do-nothing dies (no need to run a service upness test ourselves).
     */
    if (status == GNUNET_ARM_SERVICE_STARTING)
    {
      waitedFor = GNUNET_TIME_absolute_get_duration (startedWaitingAt);
      LOG ("Waited for: %s\n",
           GNUNET_STRINGS_relative_time_to_string (waitedFor,
                                                   true));

      LOG ("do-nothing is starting, killing it...\n");
      GNUNET_assert (NULL == kt);
      kt = GNUNET_SCHEDULER_add_now (&kill_task,
                                     &ok);
    }
    else if ( (status == GNUNET_ARM_SERVICE_STOPPED) &&
              (trialCount == 14))
    {
      phase++;
      LOG ("do-nothing stopped working %u times, we are done here\n",
           (unsigned int) trialCount);
      GNUNET_assert (NULL == op);
      op = GNUNET_ARM_request_service_stop (arm,
                                            "arm",
                                            &arm_stop_cb,
                                            NULL);
    }
  }
}


static void
arm_start_cb (void *cls,
              enum GNUNET_ARM_RequestStatus status,
              enum GNUNET_ARM_Result result)
{
  op = NULL;
  GNUNET_break (status == GNUNET_ARM_REQUEST_SENT_OK);
  GNUNET_break (result == GNUNET_ARM_RESULT_STARTING);
  GNUNET_break (phase == 0);
  LOG ("Sent 'START' request for arm to ARM %s\n",
       (status == GNUNET_ARM_REQUEST_SENT_OK)
       ? "successfully"
       : "unsuccessfully");
}


static void
task (void *cls,
      char *const *args,
      const char *cfgfile,
      const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  arm = GNUNET_ARM_connect (cfg,
                            NULL,
                            NULL);
  if (NULL == arm)
  {
    GNUNET_break (0);
    return;
  }
  mon = GNUNET_ARM_monitor_start (cfg,
                                  &srv_status,
                                  NULL);
  if (NULL == mon)
  {
    GNUNET_break (0);
    GNUNET_ARM_disconnect (arm);
    arm = NULL;
    return;
  }
  GNUNET_assert (NULL == op);
  op = GNUNET_ARM_request_service_start (arm,
                                         "arm",
                                         GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                         &arm_start_cb,
                                         NULL);
  GNUNET_SCHEDULER_add_shutdown (&trigger_disconnect,
                                 NULL);
}


static int
check ()
{
  char *const argv[] = {
    (char*) "test-exponential-backoff",
    (char*) "-c", (char*) CFGFILENAME,
    (char*) "-L", (char*) "INFO",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  /* Running ARM  and running the do_nothing task */
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                          (sizeof(argv) / sizeof(char *)) - 1,
                          argv,
                          "test-exponential-backoff",
                          "nohelp",
                          options,
                          &task,
                          NULL))
    return 31;
  return ok;
}


#ifndef PATH_MAX
/**
 * Assumed maximum path length (for the log file name).
 */
#define PATH_MAX 4096
#endif


static int
init (void)
{
  struct GNUNET_CONFIGURATION_Handle *cfg_;
  char pwd[PATH_MAX];
  char *binary;

  cfg_ = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_parse (cfg_,
                                  "test_arm_api_data.conf"))
  {
    GNUNET_CONFIGURATION_destroy (cfg_);
    return GNUNET_SYSERR;
  }
  if (NULL == getcwd (pwd,
                      PATH_MAX))
    return GNUNET_SYSERR;
  GNUNET_assert (0 < GNUNET_asprintf (&binary,
                                      "%s/%s",
                                      pwd,
                                      BINARY));
  GNUNET_CONFIGURATION_set_value_string (cfg_,
                                         SERVICE,
                                         "BINARY",
                                         binary);
  GNUNET_free (binary);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_write (cfg_,
                                  CFGFILENAME))
  {
    GNUNET_CONFIGURATION_destroy (cfg_);
    return GNUNET_SYSERR;
  }
  GNUNET_CONFIGURATION_destroy (cfg_);

#if LOG_BACKOFF
  killLogFileName = GNUNET_DISK_mktemp ("exponential-backoff-waiting.log");
  if (NULL == (killLogFilePtr = fopen (killLogFileName,
                                       "w")))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "fopen",
                              killLogFileName);
    GNUNET_free (killLogFileName);
    return GNUNET_SYSERR;
  }
#endif
  return GNUNET_OK;
}


static void
houseKeep (void)
{
#if LOG_BACKOFF
  GNUNET_assert (0 == fclose (killLogFilePtr));
  GNUNET_free (killLogFileName);
#endif
  (void) unlink (CFGFILENAME);
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-exponential-backoff",
                    "DEBUG",
                    NULL);

  if (GNUNET_OK != init ())
    return 1;
  ret = check ();
  houseKeep ();
  return ret;
}


/* end of test_exponential_backoff.c */
