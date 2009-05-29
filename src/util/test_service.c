/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/test_service.c
 * @brief tests for service.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 12435

#define MY_TYPE 256

static struct GNUNET_SCHEDULER_Handle *sched;

static struct GNUNET_SERVICE_Context *sctx;

static void
end_it (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CLIENT_Connection *client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down service\n");
  GNUNET_CLIENT_service_shutdown (client);
  GNUNET_CLIENT_disconnect (client);
  if (sctx != NULL)
    GNUNET_SERVICE_stop (sctx);
}


static size_t
build_msg (void *cls, size_t size, void *buf)
{
  struct GNUNET_CLIENT_Connection *client = cls;
  struct GNUNET_MessageHeader *msg = buf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client connected, transmitting\n");
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (msg));
  GNUNET_SCHEDULER_add_continuation (sched,
                                     GNUNET_YES,
                                     &end_it,
                                     client,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  return sizeof (struct GNUNET_MessageHeader);
}

static void
ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service confirmed running\n");
  sched = tc->sched;
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  client = GNUNET_CLIENT_connect (tc->sched, "test_service", cfg);
  GNUNET_assert (client != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting, waiting to transmit\n");
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_SECONDS,
                                       &build_msg, client);
}

static void
recv_cb (void *cls,
         struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving client message...\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static struct GNUNET_SERVER_MessageHandler myhandlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};

static void
runner (void *cls,
        struct GNUNET_SCHEDULER_Handle *sched,
        struct GNUNET_SERVER_Handle *server,
        struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service initializing\n");
  GNUNET_SERVER_add_handlers (server, myhandlers);
  GNUNET_CLIENT_service_test (sched,
                              "test_service",
                              cfg, GNUNET_TIME_UNIT_SECONDS, &ready, cfg);
}

static void
term (void *cls, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ok = cls;
  *ok = 0;
}

/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  int ok = 1;
  char *const argv[] = {
    "test_service",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting service\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVICE_run (5,
                                     argv,
                                     "test_service",
                                     &runner, &ok, &term, &ok));
  GNUNET_assert (0 == ok);
  return ok;
}

static void
ready6 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_CLIENT_Connection *client;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "V6 ready\n");
  sched = tc->sched;
  GNUNET_assert (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  client = GNUNET_CLIENT_connect (tc->sched, "test_service6", cfg);
  GNUNET_assert (client != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "V6 client connected\n");
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_SECONDS,
                                       &build_msg, client);
}

static void
runner6 (void *cls,
         struct GNUNET_SCHEDULER_Handle *sched,
         struct GNUNET_SERVER_Handle *server,
         struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initializing v6 service\n");
  GNUNET_SERVER_add_handlers (server, myhandlers);
  GNUNET_CLIENT_service_test (sched,
                              "test_service6",
                              cfg, GNUNET_TIME_UNIT_SECONDS, &ready6, cfg);
}

/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check6 ()
{
  int ok = 1;
  char *const argv[] = {
    "test_service6",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting v6 service\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVICE_run (5,
                                     argv,
                                     "test_service6",
                                     &runner6, &ok, &term, &ok));
  GNUNET_assert (0 == ok);
  return ok;
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check6d ()
{
  int ok = 1;
  char *const argv[] = {
    "test_service6",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    "-d",
    NULL
  };
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting V6 as daemon\n");
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVICE_run (6,
                                     argv,
                                     "test_service6",
                                     &runner6, &ok, &term, &ok));
  GNUNET_break (0 == ok);
  return ok;
}


static void
start_stop_main (void *cls,
                 struct GNUNET_SCHEDULER_Handle *sched,
                 char *const *args,
                 const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ret = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting service using start method\n");
  sctx = GNUNET_SERVICE_start ("test_service", sched, cfg);
  runner (cls, sched, GNUNET_SERVICE_get_server (sctx), cfg);
  *ret = 0;
}


static int
check_start_stop ()
{
  char *const argv[] = {
    "test-service-program",
    "-c",
    "test_service_data.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret = 1;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (5,
                                     argv,
                                     "test-service-program",
                                     "no help",
                                     options, &start_stop_main, &ret));

  GNUNET_break (0 == ret);
  return ret;
}


int
main (int argc, char *argv[])
{
  int ret = 0;
  int s;

  GNUNET_log_setup ("test-service",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check ();
  ret += check ();
  s = SOCKET (PF_INET6, SOCK_STREAM, 0);
  if (s == -1)
    {
      if ((errno == ENOBUFS) ||
          (errno == ENOMEM) || (errno == ENFILE) || (errno == EACCES))
        {
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
          return 1;
        }
      fprintf (stderr,
               "IPv6 support seems to not be available (%s), not testing it!\n",
               strerror (errno));
    }
  else
    {
      GNUNET_break (0 == CLOSE (s));
      ret += check6 ();
      ret += check6d ();        /* with daemonization */
    }
  ret += check_start_stop ();

  return ret;
}

/* end of test_service.c */
