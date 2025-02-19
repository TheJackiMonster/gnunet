/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012, 2013 GNUnet e.V.

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
 * @file arm/gnunet-arm.c
 * @brief arm for writing a tool
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_util_lib.h"

/**
 * Set if we are to shutdown all services (including ARM).
 */
static int end;

/**
 * Set if we are to start default services (including ARM).
 */
static int start;

/**
 * Set if we are to stop/start default services (including ARM).
 */
static int restart;

/**
 * Set if we should delete configuration and temp directory on exit.
 */
static int delete;

/**
 * Set if we should not print status messages.
 */
static int quiet;

/**
 * Set if we should print all services, including stopped ones.
 */
static int show_all;

/**
 * Monitor ARM activity.
 */
static int monitor;

/**
 * Set if we should print a list of currently running services.
 */
static int list;

/**
 * Set to the name of a service to start.
 */
static char *init;

/**
 * Set to the name of a service to kill.
 */
static char *term;

/**
 * Set to the name of the config file used.
 */
static char *config_file;

/**
 * Set to the directory where runtime files are stored.
 */
static char *dir;

/**
 * Final status code.
 */
static int ret;

/**
 * Connection with ARM.
 */
static struct GNUNET_ARM_Handle *h;

/**
 * Monitor connection with ARM.
 */
static struct GNUNET_ARM_MonitorHandle *m;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Processing stage that we are in.  Simple counter.
 */
static unsigned int phase;

/**
 * User defined timestamp for completing operations.
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Task to be run on timeout.
 */
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * Do we want to give our stdout to gnunet-service-arm?
 */
static int no_stdout;

/**
 * Do we want to give our stderr to gnunet-service-arm?
 */
static int no_stderr;

/**
 * Handle for the task running the #action_loop().
 */
static struct GNUNET_SCHEDULER_Task *al_task;

/**
 * Current operation.
 */
static struct GNUNET_ARM_Operation *op;

/**
 * Attempts to delete configuration file and GNUNET_HOME
 * on ARM shutdown provided the end and delete options
 * were specified when gnunet-arm was run.
 */
static void
delete_files ()
{
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Will attempt to remove configuration file %s and service directory %s\n",
    config_file,
    dir);
  if (0 != unlink (config_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to remove configuration file %s\n"),
                config_file);
  }
  if (GNUNET_OK != GNUNET_DISK_directory_remove (dir))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to remove servicehome directory %s\n"),
                dir);
  }
}


/**
 * Main continuation-passing-style loop.  Runs the various
 * jobs that we've been asked to do in order.
 *
 * @param cls closure, unused
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  if (NULL != al_task)
  {
    GNUNET_SCHEDULER_cancel (al_task);
    al_task = NULL;
  }
  if (NULL != op)
  {
    GNUNET_ARM_operation_cancel (op);
    op = NULL;
  }
  if (NULL != h)
  {
    GNUNET_ARM_disconnect (h);
    h = NULL;
  }
  if (NULL != m)
  {
    GNUNET_ARM_monitor_stop (m);
    m = NULL;
  }
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  if ( (GNUNET_YES == end) &&
       (GNUNET_YES == delete) )
    delete_files ();
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
}


/**
 * Returns a string interpretation of @a rs
 *
 * @param rs the request status from ARM
 * @return a string interpretation of the request status
 */
static const char *
req_string (enum GNUNET_ARM_RequestStatus rs)
{
  switch (rs)
  {
  case GNUNET_ARM_REQUEST_SENT_OK:
    return _ ("Message was sent successfully");

  case GNUNET_ARM_REQUEST_DISCONNECTED:
    return _ ("We disconnected from ARM before we could send a request");
  }
  return _ ("Unknown request status");
}


/**
 * Returns a string interpretation of the @a result
 *
 * @param result the arm result
 * @return a string interpretation
 */
static const char *
ret_string (enum GNUNET_ARM_Result result)
{
  switch (result)
  {
  case GNUNET_ARM_RESULT_STOPPED:
    return _ ("is stopped");

  case GNUNET_ARM_RESULT_STARTING:
    return _ ("is starting");

  case GNUNET_ARM_RESULT_STOPPING:
    return _ ("is stopping");

  case GNUNET_ARM_RESULT_IS_STARTING_ALREADY:
    return _ ("is starting already");

  case GNUNET_ARM_RESULT_IS_STOPPING_ALREADY:
    return _ ("is stopping already");

  case GNUNET_ARM_RESULT_IS_STARTED_ALREADY:
    return _ ("is started already");

  case GNUNET_ARM_RESULT_IS_STOPPED_ALREADY:
    return _ ("is stopped already");

  case GNUNET_ARM_RESULT_IS_NOT_KNOWN:
    return _ ("service is not known to ARM");

  case GNUNET_ARM_RESULT_START_FAILED:
    return _ ("service failed to start");

  case GNUNET_ARM_RESULT_IN_SHUTDOWN:
    return _ ("service cannot be manipulated because ARM is shutting down");
  }
  return _ ("Unknown result code.");
}


/**
 * Main task that runs our various operations in order.
 *
 * @param cls closure
 */
static void
action_loop (void *cls);


/**
 * Function called whenever we connect to or disconnect from ARM.
 * Terminates the process if we fail to connect to the service on
 * our first attempt.
 *
 * @param cls closure
 * @param connected #GNUNET_YES if connected, #GNUNET_NO if disconnected,
 *                  #GNUNET_SYSERR on error.
 */
static void
conn_status (void *cls,
             int connected)
{
  static int once;

  (void) cls;
  if ( (GNUNET_SYSERR == connected) &&
       (0 == once) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Fatal error initializing ARM API.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  once = 1;
}


/**
 * We have requested ARM to be started, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
start_callback (void *cls,
                enum GNUNET_ARM_RequestStatus rs,
                enum GNUNET_ARM_Result result)
{
  (void) cls;
  op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    fprintf (stdout,
             _ ("Failed to start the ARM service: %s\n"),
             req_string (rs));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_ARM_RESULT_STARTING != result) &&
      (GNUNET_ARM_RESULT_IS_STARTED_ALREADY != result))
  {
    fprintf (stdout,
             _ ("Failed to start the ARM service: %s\n"),
             ret_string (result));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM service [re]start successful\n");
  start = 0;
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
}


/**
 * We have requested ARM to be stopped, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
stop_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               enum GNUNET_ARM_Result result)
{
  char *msg;

  (void) cls;
  op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg,
                     "%s",
                     _ (
                       "Failed to send a stop request to the ARM service: %s\n")
                     );
    fprintf (stdout, msg, req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ( (GNUNET_ARM_RESULT_STOPPING != result) &&
       (GNUNET_ARM_RESULT_STOPPED != result) &&
       (GNUNET_ARM_RESULT_IS_STOPPED_ALREADY != result) )
  {
    fprintf (stdout,
             _ ("Failed to stop the ARM service: %s\n"),
             ret_string (result));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ARM service shutdown successful\n");
  end = 0;
  if (restart)
  {
    restart = 0;
    start = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Initiating an ARM restart\n");
  }
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
}


/**
 * We have requested a service to be started, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
init_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               enum GNUNET_ARM_Result result)
{
  (void) cls;
  op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    fprintf (stdout,
             _ ("Failed to send a request to start the `%s' service: %s\n"),
             init,
             req_string (rs));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_ARM_RESULT_STARTING != result) &&
      (GNUNET_ARM_RESULT_IS_STARTED_ALREADY != result))
  {
    fprintf (stdout,
             _ ("Failed to start the `%s' service: %s\n"),
             init,
             ret_string (result));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Service %s [re]started successfully\n",
              init);
  GNUNET_free (init);
  init = NULL;
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
}


/**
 * We have requested a service to be stopped, this function
 * is called with the result of the operation.  Informs the
 * use of the result; on success, we continue with the event
 * loop, on failure we terminate the process.
 *
 * @param cls closure unused
 * @param rs what happened to our request
 * @param result if the request was processed, this is the result
 *               according to ARM
 */
static void
term_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               enum GNUNET_ARM_Result result)
{
  char *msg;

  (void) cls;
  op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&msg,
                     _ (
                       "Failed to send a request to kill the `%s' service: %%s\n"),
                     term);
    fprintf (stdout,
             msg,
             req_string (rs));
    GNUNET_free (msg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ( (GNUNET_ARM_RESULT_STOPPED != result) &&
       (GNUNET_ARM_RESULT_IS_STOPPED_ALREADY != result) )
  {
    fprintf (stdout,
             _ ("Failed to kill the `%s' service: %s\n"),
             term,
             ret_string (result));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Service %s stopped successfully\n",
              term);
  GNUNET_free (term);
  term = NULL;
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
}


/**
 * Function called with the list of running services. Prints
 * the list to stdout, then starts the event loop again.
 * Prints an error message and terminates the process on errors.
 *
 * @param cls closure (unused)
 * @param rs request status (success, failure, etc.)
 * @param count number of services in the list
 * @param list list of services managed by arm
 */
static void
list_callback (void *cls,
               enum GNUNET_ARM_RequestStatus rs,
               unsigned int count,
               const struct GNUNET_ARM_ServiceInfo *service_info)
{
  unsigned int num_stopped = 0;
  unsigned int num_started = 0;
  unsigned int num_stopping = 0;
  unsigned int num_failed = 0;
  unsigned int num_finished = 0;
  (void) cls;
  op = NULL;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    char *msg;

    GNUNET_asprintf (&msg,
                     "%s",
                     _ ("Failed to request a list of services: %s\n"));
    fprintf (stdout,
             msg,
             req_string (rs));
    GNUNET_free (msg);
    ret = 3;
    GNUNET_SCHEDULER_shutdown ();
  }
  if (NULL == service_info)
  {
    fprintf (stderr,
             "%s",
             _ ("Error communicating with ARM. ARM not running?\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 3;
    return;
  }
  for (unsigned int i = 0; i < count; i++)
  {
    switch (service_info[i].status)
    {
    case GNUNET_ARM_SERVICE_STATUS_STOPPED:
      num_stopped++;
      break;
    case GNUNET_ARM_SERVICE_STATUS_FAILED:
      num_failed++;
      break;
    case GNUNET_ARM_SERVICE_STATUS_FINISHED:
      num_finished++;
      break;
    case GNUNET_ARM_SERVICE_STATUS_STARTED:
      num_started++;
      break;
    case GNUNET_ARM_SERVICE_STATUS_STOPPING:
      num_stopping++;
      fprintf (stdout,
               "%s (binary='%s', status=stopping)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    default:
      GNUNET_break_op (0);
      fprintf (stdout,
               "%s (binary='%s', status=unknown)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    }
  }
  if (! quiet)
  {
    if (show_all)
      fprintf (stdout,
               "%s",
               _ ("All services:\n"));
    else
      fprintf (stdout,
               "%s",
               _ ("Services (excluding stopped services):\n"));
    if (num_stopped || num_failed || num_finished || num_stopping ||
        num_started)
    {
      int sep = 0;
      fprintf (stdout, "(");
      if (0 != num_started)
      {
        if (sep)
          fprintf (stdout, " / ");
        fprintf (stdout,
                 "started: %u",
                 num_started);
        sep = 1;
      }
      if (0 != num_failed)
      {
        if (sep)
          fprintf (stdout, " / ");
        fprintf (stdout,
                 "failed: %u",
                 num_failed);
        sep = 1;
      }
      if (0 != num_stopping)
      {
        if (sep)
          fprintf (stdout, " / ");
        fprintf (stdout,
                 "stopping: %u",
                 num_stopping);
        sep = 1;
      }
      if (0 != num_stopped)
      {
        if (sep)
          fprintf (stdout, " / ");
        fprintf (stdout,
                 "stopped: %u",
                 num_stopped);
        sep = 1;
      }
      if (0 != num_finished)
      {
        if (sep)
          fprintf (stdout, " / ");
        fprintf (stdout,
                 "finished: %u",
                 num_finished);
        sep = 1;
      }
      fprintf (stdout, ")\n");
    }
    else
    {
      fprintf (stdout,
               "%s",
               _ ("(No services configured.)\n"));
    }
  }
  for (unsigned int i = 0; i < count; i++)
  {
    struct GNUNET_TIME_Relative restart_in;
    switch (service_info[i].status)
    {
    case GNUNET_ARM_SERVICE_STATUS_STOPPED:
      if (show_all)
        fprintf (stdout,
                 "%s (binary='%s', status=stopped)\n",
                 service_info[i].name,
                 service_info[i].binary);
      break;
    case GNUNET_ARM_SERVICE_STATUS_FAILED:
      restart_in = GNUNET_TIME_absolute_get_remaining (service_info[i].
                                                       restart_at);
      fprintf (stdout,
               "%s (binary='%s', status=failed, exit_status=%d, restart_delay='%s')\n",
               service_info[i].name,
               service_info[i].binary,
               service_info[i].last_exit_status,
               GNUNET_STRINGS_relative_time_to_string (restart_in,
                                                       GNUNET_YES));
      break;
    case GNUNET_ARM_SERVICE_STATUS_FINISHED:
      fprintf (stdout,
               "%s (binary='%s', status=finished)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    case GNUNET_ARM_SERVICE_STATUS_STARTED:
      fprintf (stdout,
               "%s (binary='%s', status=started)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    case GNUNET_ARM_SERVICE_STATUS_STOPPING:
      fprintf (stdout,
               "%s (binary='%s', status=stopping)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    default:
      GNUNET_break_op (0);
      fprintf (stdout,
               "%s (binary='%s', status=unknown)\n",
               service_info[i].name,
               service_info[i].binary);
      break;
    }
  }
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
}


/**
 * Main action loop.  Runs the various jobs that we've been asked to
 * do, in order.
 *
 * @param cls closure, unused
 */
static void
action_loop (void *cls)
{
  (void) cls;
  al_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running requested actions\n");
  while (1)
  {
    switch (phase++)
    {
    case 0:
      if (NULL != term)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Termination action\n");
        op = GNUNET_ARM_request_service_stop (h,
                                              term,
                                              &term_callback,
                                              NULL);
        return;
      }
      break;

    case 1:
      if (end || restart)
      {
        if (GNUNET_YES !=
            GNUNET_CLIENT_test (cfg,
                                "arm"))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "GNUnet not running, cannot stop the peer\n");
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "End action\n");
          op = GNUNET_ARM_request_service_stop (h,
                                                "arm",
                                                &stop_callback,
                                                NULL);
          return;
        }
      }
      break;

    case 2:
      if (start)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Start action\n");
        op =
          GNUNET_ARM_request_service_start (h,
                                            "arm",
                                            (no_stdout
                                             ? 0
                                             : GNUNET_OS_INHERIT_STD_OUT)
                                            | (no_stderr
                                               ? 0
                                               : GNUNET_OS_INHERIT_STD_ERR),
                                            &start_callback,
                                            NULL);
        return;
      }
      break;

    case 3:
      if (NULL != init)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Initialization action\n");
        op = GNUNET_ARM_request_service_start (h,
                                               init,
                                               GNUNET_OS_INHERIT_STD_NONE,
                                               &init_callback,
                                               NULL);
        return;
      }
      break;

    case 4:
      if (list)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Going to list all running services controlled by ARM.\n");
        op = GNUNET_ARM_request_service_list (h,
                                              &list_callback,
                                              &list);
        return;
      }
      break;

    case 5:
      if (monitor)
      {
        if (! quiet)
          fprintf (stderr,
                   _ ("Now only monitoring, press CTRL-C to stop.\n"));
        quiet =
          0;       /* does not make sense to stay quiet in monitor mode at this time */
        return;       /* done with tasks, just monitor */
      }
      break;

    default:     /* last phase */
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
}


/**
 * Function called when a service starts or stops.
 *
 * @param cls closure
 * @param service service name
 * @param status status of the service
 */
static void
srv_status (void *cls,
            const char *service,
            enum GNUNET_ARM_ServiceMonitorStatus status)
{
  const char *msg;

  (void) cls;
  switch (status)
  {
  case GNUNET_ARM_SERVICE_MONITORING_STARTED:
    return;   /* this should be done silently */

  case GNUNET_ARM_SERVICE_STOPPED:
    msg = _ ("Stopped %s.\n");
    break;

  case GNUNET_ARM_SERVICE_STARTING:
    msg = _ ("Starting %s...\n");
    break;

  case GNUNET_ARM_SERVICE_STOPPING:
    msg = _ ("Stopping %s...\n");
    break;

  default:
    msg = NULL;
    break;
  }
  if (! quiet)
  {
    if (NULL != msg)
      fprintf (stderr,
               msg,
               service);
    else
      fprintf (stderr,
               _ ("Unknown status %u for service %s.\n"),
               status,
               service);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got service %s status %d\n",
              service,
              (int) status);
}


/**
 * Task run on timeout (if -T is given).
 */
static void
timeout_task_cb (void *cls)
{
  (void) cls;
  timeout_task = NULL;
  ret = 2;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  (void) cls;
  (void) args;
  (void) cfgfile;
  cfg = GNUNET_CONFIGURATION_dup (c);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "PATHS",
                                             "GNUNET_HOME",
                                             &dir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "PATHS",
                               "GNUNET_HOME");
    return;
  }
  (void) GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                  "arm",
                                                  "CONFIG",
                                                  &config_file);
  if (NULL == (h = GNUNET_ARM_connect (cfg,
                                       &conn_status,
                                       NULL)))
    return;
  if (monitor)
    m = GNUNET_ARM_monitor_start (cfg,
                                  &srv_status,
                                  NULL);
  al_task = GNUNET_SCHEDULER_add_now (&action_loop,
                                      NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  if (0 != timeout.rel_value_us)
    timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout,
                                    &timeout_task_cb,
                                    NULL);
}


/**
 * The main function to obtain arm from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error, 2 on timeout
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('e',
                               "end",
                               gettext_noop ("stop all GNUnet services"),
                               &end),
    GNUNET_GETOPT_option_string ('i',
                                 "init",
                                 "SERVICE",
                                 gettext_noop ("start a particular service"),
                                 &init),
    GNUNET_GETOPT_option_string ('k',
                                 "kill",
                                 "SERVICE",
                                 gettext_noop ("stop a particular service"),
                                 &term),
    GNUNET_GETOPT_option_flag ('a',
                               "all",
                               gettext_noop (
                                 "also show stopped services (used with -I)"),
                               &show_all),
    GNUNET_GETOPT_option_flag ('s',
                               "start",
                               gettext_noop (
                                 "start all GNUnet default services"),
                               &start),
    GNUNET_GETOPT_option_flag ('r',
                               "restart",
                               gettext_noop (
                                 "stop and start all GNUnet default services"),
                               &restart),
    GNUNET_GETOPT_option_flag ('d',
                               "delete",
                               gettext_noop (
                                 "delete config file and directory on exit"),
                               &delete),
    GNUNET_GETOPT_option_flag ('m',
                               "monitor",
                               gettext_noop ("monitor ARM activities"),
                               &monitor),
    GNUNET_GETOPT_option_flag ('q',
                               "quiet",
                               gettext_noop ("don't print status messages"),
                               &quiet),
    GNUNET_GETOPT_option_relative_time (
      'T',
      "timeout",
      "DELAY",
      gettext_noop (
        "exit with error status if operation does not finish after DELAY"),
      &timeout),
    GNUNET_GETOPT_option_flag ('I',
                               "info",
                               gettext_noop (
                                 "list currently running services"),
                               &list),
    GNUNET_GETOPT_option_flag (
      'O',
      "no-stdout",
      gettext_noop ("don't let gnunet-service-arm inherit standard output"),
      &no_stdout),
    GNUNET_GETOPT_option_flag (
      'E',
      "no-stderr",
      gettext_noop ("don't let gnunet-service-arm inherit standard error"),
      &no_stderr),
    GNUNET_GETOPT_OPTION_END
  };
  int lret;

  if (GNUNET_OK ==
      (lret = GNUNET_PROGRAM_run (
         GNUNET_OS_project_data_gnunet (),
         argc,
         argv,
         "gnunet-arm",
         gettext_noop (
           "Control services and the Automated Restart Manager (ARM)"),
         options,
         &run,
         NULL)))
  {
    return ret;
  }
  return lret;
}


/* end of gnunet-arm.c */
