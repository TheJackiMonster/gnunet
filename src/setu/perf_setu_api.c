/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @file set/test_setu_api.c
 * @brief testcase for setu_api.c
 * @author Florian Dold
 * @author Elias Summermatter
 */
#include "platform.h"
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_setu_service.h"
#include <sys/sysinfo.h>
#include <pthread.h>


static struct GNUNET_PeerIdentity local_id;

static struct GNUNET_HashCode app_id;

static struct GNUNET_SETU_Handle *set1;

static struct GNUNET_SETU_Handle *set2;

static struct GNUNET_SETU_ListenHandle *listen_handle;

static struct GNUNET_SETU_OperationHandle *oh1;

static struct GNUNET_SETU_OperationHandle *oh2;

static const struct GNUNET_CONFIGURATION_Handle *config;

static int ret;

static struct GNUNET_SCHEDULER_Task *tt;


/**
 * Handles configuration file for setu performance test
 *
 */
static struct GNUNET_CONFIGURATION_Handle *setu_cfg;


static void
result_cb_set1 (void *cls,
                const struct GNUNET_SETU_Element *element,
                uint64_t size,
                enum GNUNET_SETU_Status status)
{
  switch (status)
  {
  case GNUNET_SETU_STATUS_ADD_LOCAL:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "set 1: got element\n");
    break;

  case GNUNET_SETU_STATUS_FAILURE:
    GNUNET_break (0);
    oh1 = NULL;
    fprintf (stderr, "set 1: received failure status!\n");
    ret = 1;
    if (NULL != tt)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
    }
    GNUNET_SCHEDULER_shutdown ();
    break;

  case GNUNET_SETU_STATUS_DONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "set 1: done\n");
    oh1 = NULL;
    if (NULL != set1)
    {
      GNUNET_SETU_destroy (set1);
      set1 = NULL;
    }
    if (NULL == set2)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
      GNUNET_SCHEDULER_shutdown ();
    }
    break;

  default:
    GNUNET_assert (0);
  }
}


static void
result_cb_set2 (void *cls,
                const struct GNUNET_SETU_Element *element,
                uint64_t size,
                enum GNUNET_SETU_Status status)
{
  switch (status)
  {
  case GNUNET_SETU_STATUS_ADD_LOCAL:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "set 2: got element\n");
    break;

  case GNUNET_SETU_STATUS_FAILURE:
    GNUNET_break (0);
    oh2 = NULL;
    fprintf (stderr, "set 2: received failure status\n");
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    break;

  case GNUNET_SETU_STATUS_DONE:
    oh2 = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "set 2: done\n");
    GNUNET_SETU_destroy (set2);
    set2 = NULL;
    if (NULL == set1)
    {
      GNUNET_SCHEDULER_cancel (tt);
      tt = NULL;
      GNUNET_SCHEDULER_shutdown ();
    }
    break;

  default:
    GNUNET_assert (0);
  }
}


static void
listen_cb (void *cls,
           const struct GNUNET_PeerIdentity *other_peer,
           const struct GNUNET_MessageHeader *context_msg,
           struct GNUNET_SETU_Request *request)
{
  GNUNET_assert (NULL != context_msg);
  GNUNET_assert (ntohs (context_msg->type) == GNUNET_MESSAGE_TYPE_DUMMY);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "listen cb called\n");
  oh2 = GNUNET_SETU_accept (request,
                            (struct GNUNET_SETU_Option[]){ 0 },
                            &result_cb_set2,
                            NULL);
  GNUNET_SETU_commit (oh2, set2);
}


/**
 * Start the set operation.
 *
 * @param cls closure, unused
 */
static void
start (void *cls)
{
  struct GNUNET_MessageHeader context_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting reconciliation\n");
  context_msg.size = htons (sizeof context_msg);
  context_msg.type = htons (GNUNET_MESSAGE_TYPE_DUMMY);
  listen_handle = GNUNET_SETU_listen (config,
                                      &app_id,
                                      &listen_cb,
                                      NULL);
  oh1 = GNUNET_SETU_prepare (&local_id,
                             &app_id,
                             &context_msg,
                             (struct GNUNET_SETU_Option[]){ 0 },
                             &result_cb_set1,
                             NULL);
  GNUNET_SETU_commit (oh1, set1);
}


/**
 * Generate random byte stream
 */

unsigned char *
gen_rdm_bytestream (size_t num_bytes)
{
  unsigned char *stream = GNUNET_malloc (num_bytes);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, stream, num_bytes);
  return stream;
}


/**
 * Generate random sets
 */

static void
initRandomSets (int overlap, int set1_size, int set2_size, int
                element_size_in_bytes)
{
  struct GNUNET_SETU_Element element;
  element.element_type = 0;

  // Add elements to both sets
  for (int i = 0; i < overlap; i++)
  {
    element.data = gen_rdm_bytestream (element_size_in_bytes);
    element.size = element_size_in_bytes;
    GNUNET_SETU_add_element (set1, &element, NULL, NULL);
    GNUNET_SETU_add_element (set2, &element, NULL, NULL);
    set1_size--;
    set2_size--;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "initialized elements in both sets\n");

  // Add other elements to set 1
  while (set1_size>0)
  {
    element.data = gen_rdm_bytestream (element_size_in_bytes);
    element.size = element_size_in_bytes;
    GNUNET_SETU_add_element (set1, &element, NULL, NULL);
    set1_size--;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "initialized elements in set1\n");

  // Add other elements to set 2
  while (set2_size > 0)
  {
    element.data = gen_rdm_bytestream (element_size_in_bytes);
    element.size = element_size_in_bytes;

    if (set2_size != 1)
    {
      GNUNET_SETU_add_element (set2, &element,NULL, NULL);
    }
    else
    {
      GNUNET_SETU_add_element (set2, &element,&start, NULL);
    }

    set2_size--;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "initialized elements in set2\n");
}


/**
 * Function run on timeout.
 *
 * @param cls closure
 */
static void
timeout_fail (void *cls)
{
  tt = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE, "Testcase failed with timeout\n");
  GNUNET_SCHEDULER_shutdown ();
  ret = 1;
}


/**
 * Function run on shutdown.
 *
 * @param cls closure
 */
static void
do_shutdown (void *cls)
{
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
  if (NULL != oh1)
  {
    GNUNET_SETU_operation_cancel (oh1);
    oh1 = NULL;
  }
  if (NULL != oh2)
  {
    GNUNET_SETU_operation_cancel (oh2);
    oh2 = NULL;
  }
  if (NULL != set1)
  {
    GNUNET_SETU_destroy (set1);
    set1 = NULL;
  }
  if (NULL != set2)
  {
    GNUNET_SETU_destroy (set2);
    set2 = NULL;
  }
  if (NULL != listen_handle)
  {
    GNUNET_SETU_listen_cancel (listen_handle);
    listen_handle = NULL;
  }
}


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using 'GNUNET_TESTING_peer_run'.
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_SETU_OperationHandle *my_oh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running preparatory tests\n");
  tt = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
    &timeout_fail,
    NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  config = cfg;
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_get_peer_identity (cfg,
                                                               &local_id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "my id (from CRYPTO): %s\n",
              GNUNET_i2s (&local_id));
  GNUNET_TESTING_peer_get_identity (peer,
                                    &local_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "my id (from TESTING): %s\n",
              GNUNET_i2s (&local_id));
  set1 = GNUNET_SETU_create (cfg);
  set2 = GNUNET_SETU_create (cfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created sets %p and %p for union operation\n",
              set1,
              set2);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &app_id);

  /* test if canceling an uncommitted request works! */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Launching and instantly stopping set operation\n");
  my_oh = GNUNET_SETU_prepare (&local_id,
                               &app_id,
                               NULL,
                               (struct GNUNET_SETU_Option[]){ 0 },
                               NULL,
                               NULL);
  GNUNET_SETU_operation_cancel (my_oh);

  /* test the real set reconciliation */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running real set-reconciliation\n");
  // init_set1 ();
  // limit ~23800 element total
  initRandomSets (490, 500,500,32);
}


void
perf_thread ()
{
  GNUNET_TESTING_service_run ("perf_setu_api",
                              "arm",
                              "test_setu.conf",
                              &run,
                              NULL);

}


static void
run_petf_thread (int total_runs)
{
  int core_count = get_nprocs_conf ();
  pid_t child_pid, wpid;
  int status = 0;

// Father code (before child processes start)
  for (int processed = 0; processed < total_runs;)
  {
    for (int id = 0; id < core_count; id++)
    {
      if (processed >= total_runs)
        break;

      if ((child_pid = fork ()) == 0)
      {
        perf_thread ();
        exit (0);
      }
      processed += 1;
    }
    while ((wpid = wait (&status)) > 0)
      ;

  }
}


static void
execute_perf ()
{

  /**
  * Erase statfile
  */
  remove ("perf_stats.csv");
  remove ("perf_failure_bucket_number_factor.csv");
  for (int out_out_ctr = 3; out_out_ctr <= 3; out_out_ctr++)
  {

    for (int out_ctr = 20; out_ctr <= 20; out_ctr++)
    {
      float base = 0.1;
      float x = out_ctr * base;
      char factor[10];
      char *buffer = gcvt (x, 4, factor);
      setu_cfg = GNUNET_CONFIGURATION_create ();
      GNUNET_CONFIGURATION_set_value_string (setu_cfg, "IBF",
                                             "BUCKET_NUMBER_FACTOR",
                                             buffer);                      // Factor default=4
      GNUNET_CONFIGURATION_set_value_number (setu_cfg, "IBF",
                                             "NUMBER_PER_BUCKET", 3);                      // K default=4
      GNUNET_CONFIGURATION_set_value_string (setu_cfg, "PERFORMANCE",
                                             "TRADEOFF", "2");                              // default=0.25
      GNUNET_CONFIGURATION_set_value_string (setu_cfg, "PERFORMANCE",
                                             "MAX_SET_DIFF_FACTOR_DIFFERENTIAL",
                                             "20000");    // default=0.25
      GNUNET_CONFIGURATION_set_value_number (setu_cfg, "BOUNDARIES",
                                             "UPPER_ELEMENT", 5000);


      if (GNUNET_OK != GNUNET_CONFIGURATION_write (setu_cfg, "perf_setu.conf"))
        GNUNET_log (
          GNUNET_ERROR_TYPE_ERROR,
          _ ("Failed to write subsystem default identifier map'.\n"));
      run_petf_thread (100);
    }

  }
  return;
}


int
main (int argc, char **argv)
{

  GNUNET_log_setup ("perf_setu_api",
                    "WARNING",
                    NULL);
  execute_perf ();
  return 0;
}
