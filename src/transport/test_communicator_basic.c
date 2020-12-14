/*
    This file is part of GNUnet.
    Copyright (C) 2019 GNUnet e.V.

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
* @file transport/test_communicator_basic.c
* @brief test the communicators
* @author Julius Bünger
* @author Martin Schanzenbach
*/
#include "platform.h"
#include "gnunet_util_lib.h"
#include "transport-testing-communicator.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_signatures.h"
#include "gnunet_testing_lib.h"
#include "transport.h"
#include "gnunet_statistics_service.h"

#include <inttypes.h>


#define LOG(kind, ...) GNUNET_log_from (kind, \
                                        "test_transport_communicator", \
                                        __VA_ARGS__)

#define NUM_PEERS 2

static struct GNUNET_SCHEDULER_Task *to_task;

static int queue_est = GNUNET_NO;

static struct GNUNET_PeerIdentity peer_id[NUM_PEERS];

static char *communicator_binary;

static struct
GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_hs[NUM_PEERS];

static struct GNUNET_CONFIGURATION_Handle *cfg_peers[NUM_PEERS];

static struct GNUNET_STATISTICS_Handle *stats[NUM_PEERS];

static char *cfg_peers_name[NUM_PEERS];

static int ret;

static size_t long_message_size;

static struct GNUNET_TIME_Absolute start_short;

static struct GNUNET_TIME_Absolute start_long;

static struct GNUNET_TIME_Absolute timeout;

static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *my_tc;

static char *test_name;

static struct GNUNET_STATISTICS_GetHandle *box_stats;

static struct GNUNET_STATISTICS_GetHandle *rekey_stats;

#define SHORT_MESSAGE_SIZE 128

#define LONG_MESSAGE_SIZE 32000 /* FIXME */

#define BURST_PACKETS 5000

#define TOTAL_ITERATIONS 1

#define PEER_A 0

#define PEER_B 1

static unsigned int iterations_left = TOTAL_ITERATIONS;

#define TIMEOUT_MULTIPLIER 1

#define DELAY \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,200)

#define SHORT_BURST_WINDOW \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,2)

#define LONG_BURST_WINDOW \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,2)

enum TestPhase
{
  TP_INIT,
  TP_BURST_SHORT,
  TP_BURST_LONG,
  TP_SIZE_CHECK
};


static size_t num_sent_short = 0;

static size_t num_sent_long = 0;

static size_t num_sent_size = 0;

static uint32_t ack = 0;

static enum TestPhase phase;

static size_t num_received_short = 0;

static size_t num_received_long = 0;

static size_t num_received_size = 0;

static uint64_t avg_latency = 0;

static struct GNUNET_TIME_Relative duration;


static void
communicator_available_cb (void *cls,
                           struct
                           GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                           *tc_h,
                           enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
                           char *address_prefix)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Communicator available. (cc: %u, prefix: %s)\n",
       cc,
       address_prefix);
}

static void
open_queue (void *cls)
{
  char *address = cls;

  if (NULL != tc_hs[PEER_A]->c_mq)
  {
    queue_est = GNUNET_YES;
    GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (tc_hs[PEER_A],
                                                                &peer_id[PEER_B],
                                                                address);
  }
  else
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &open_queue,
                                  address);
  }
}

static void
add_address_cb (void *cls,
                struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
                tc_h,
                const char *address,
                struct GNUNET_TIME_Relative expiration,
                uint32_t aid,
                enum GNUNET_NetworkType nt)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New address. (addr: %s, expir: %" PRIu32 ", ID: %" PRIu32 ", nt: %u\n",
       address,
       expiration.rel_value_us,
       aid,
       nt);
  // addresses[1] = GNUNET_strdup (address);
  if ((0 == strcmp ((char*) cls, cfg_peers_name[PEER_B])) &&
      (GNUNET_NO == queue_est))
  {
    open_queue (address);
  }
}


/**
 * @brief Callback that informs whether the requested queue will be
 * established
 *
 * Implements #GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback.
 *
 * @param cls Closure - unused
 * @param tc_h Communicator handle - unused
 * @param will_try #GNUNET_YES if queue will be established
 *                #GNUNET_NO if queue will not be established (bogous address)
 */
static void
queue_create_reply_cb (void *cls,
                       struct
                       GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
                       tc_h,
                       int will_try)
{
  if (GNUNET_YES == will_try)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue will be established!\n");
  else
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Queue won't be established (bougus address?)!\n");
}


static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
handle_backchannel_cb (void *cls,
                       struct GNUNET_MessageHeader *msg,
                       struct GNUNET_PeerIdentity *pid)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Handling BC message...\n");
  if (0 == memcmp (&peer_id[PEER_A], pid, sizeof (*pid)))
    return tc_hs[PEER_A];
  else
    return tc_hs[PEER_B];
}


static char*
make_payload (size_t payload_size)
{
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_AbsoluteNBO ts_n;
  char *payload = GNUNET_malloc (payload_size);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Making payload of size %lu\n", payload_size);
  GNUNET_assert (payload_size >= 8); // So that out timestamp fits
  ts = GNUNET_TIME_absolute_get ();
  ts_n = GNUNET_TIME_absolute_hton (ts);
  memset (payload, 'a', payload_size);
  memcpy (payload, &ts_n, sizeof (struct GNUNET_TIME_AbsoluteNBO));
  return payload;
}


static void
latency_timeout (void *cls)
{

  size_t num_sent = 0;
  size_t num_received = 0;

  to_task = NULL;
  if (GNUNET_TIME_absolute_get_remaining (timeout).rel_value_us > 0)
  {
    to_task = GNUNET_SCHEDULER_add_at (timeout,
                                       &latency_timeout,
                                       NULL);
    return;
  }

  switch (phase)
  {
  case TP_BURST_SHORT:
    num_sent = num_sent_short;
    num_received = num_received_short;
    break;
  case TP_BURST_LONG:
    num_sent = num_sent_long;
    num_received = num_received_long;
    break;
  case TP_SIZE_CHECK:
    num_sent = num_sent_size;
    num_received = num_received_size;
    break;
  }
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Latency too high. Test failed. (Phase: %d. Sent: %lu, Received: %lu)\n",
       phase, num_sent, num_received);
  ret = 2;
  GNUNET_SCHEDULER_shutdown ();
}

/*static void
  size_test (void *cls);*/

static void
size_test (void *cls)
{
  char *payload;
  size_t max_size = 64000;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "size_test_cb %u\n",
       num_sent_size);
  GNUNET_assert (TP_SIZE_CHECK == phase);
  if (LONG_MESSAGE_SIZE != long_message_size)
    max_size = long_message_size;
  if (ack + 10 > max_size)
    return; /* Leave some room for our protocol, so not 2^16 exactly */
  ack += 10;
  payload = make_payload (ack);
  num_sent_size++;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                        (ack < max_size)
                                                        ? &size_test
                                                        : NULL,
                                                        NULL,
                                                        payload,
                                                        ack);
  GNUNET_free (payload);
  timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (
                                                GNUNET_TIME_UNIT_SECONDS,
                                                TIMEOUT_MULTIPLIER));
}

/*static void
size_test (void *cls)
{
  GNUNET_SCHEDULER_add_delayed (DELAY,
                                &size_test_cb,
                                NULL);
                                }*/

static void
long_test (void *cls);

static void
long_test_cb (void *cls)
{
  char *payload;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "long_test_cb %u/%u\n",
       num_sent_long,
       num_received_long);
  payload = make_payload (long_message_size);
  num_sent_long++;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                        ((BURST_PACKETS
                                                          * 0.91 ==
                                                          num_received_long) ||
                                                         (BURST_PACKETS ==
                                                          num_sent_long))
                                                        ? NULL
                                                        : &long_test,
                                                        NULL,
                                                        payload,
                                                        long_message_size);
  GNUNET_free (payload);
  timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (
                                                GNUNET_TIME_UNIT_SECONDS,
                                                TIMEOUT_MULTIPLIER));
}

static void
long_test (void *cls)
{
  /*LOG (GNUNET_ERROR_TYPE_DEBUG,
       "long_test %u\n",
       num_sent_long);*/
  GNUNET_SCHEDULER_add_delayed (DELAY,
                                &long_test_cb,
                                NULL);
}

static void
short_test (void *cls);

static void
short_test_cb (void *cls)
{
  char *payload;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "short_test_cb %u/%u\n",
       num_sent_short,
       num_received_short);
  payload = make_payload (SHORT_MESSAGE_SIZE);
  num_sent_short++;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                        ((BURST_PACKETS
                                                          * 0.91 ==
                                                          num_received_short) ||
                                                         (BURST_PACKETS ==
                                                          num_sent_short))
                                                        ? NULL
                                                        : &short_test,
                                                        NULL,
                                                        payload,
                                                        SHORT_MESSAGE_SIZE);
  GNUNET_free (payload);
  timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (
                                                GNUNET_TIME_UNIT_SECONDS,
                                                TIMEOUT_MULTIPLIER));
}

static void
short_test (void *cls)
{
  GNUNET_SCHEDULER_add_delayed (DELAY,
                                &short_test_cb,
                                NULL);
}


static int test_prepared = GNUNET_NO;

/**
 * This helps establishing the backchannel
 */
static void
prepare_test (void *cls)
{
  char *payload;

  if (GNUNET_YES == test_prepared)
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &short_test,
                                  NULL);
    return;
  }
  test_prepared = GNUNET_YES;
  payload = make_payload (SHORT_MESSAGE_SIZE);
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (my_tc,
                                                        &prepare_test,
                                                        NULL,
                                                        payload,
                                                        SHORT_MESSAGE_SIZE);
  GNUNET_free (payload);
}


/**
 * @brief Handle opening of queue
 *
 * Issues sending of test data
 *
 * Implements #GNUNET_TRANSPORT_TESTING_AddQueueCallback
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param tc_queue Handle to newly opened queue
 */
static void
add_queue_cb (void *cls,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *
              tc_queue,
              size_t mtu)
{
  if (TP_INIT != phase)
    return;
  if (0 != strcmp ((char*) cls, cfg_peers_name[0]))
    return; // TODO?
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queue established, starting test...\n");
  start_short = GNUNET_TIME_absolute_get ();
  my_tc = tc_h;
  if (0 != mtu) /* Message header overhead */
    long_message_size = mtu - sizeof(struct GNUNET_TRANSPORT_SendMessageTo)
                        - sizeof(struct GNUNET_MessageHeader);
  else
    long_message_size = LONG_MESSAGE_SIZE;
  phase = TP_BURST_SHORT;
  timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (
                                                GNUNET_TIME_UNIT_SECONDS,
                                                TIMEOUT_MULTIPLIER));
  GNUNET_assert (NULL == to_task);
  to_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (
                                            GNUNET_TIME_UNIT_SECONDS,
                                            TIMEOUT_MULTIPLIER),
                                          &latency_timeout,
                                          NULL);
  // prepare_test (NULL);
  short_test (NULL);
}


static void
update_avg_latency (const char*payload)
{
  struct GNUNET_TIME_AbsoluteNBO *ts_n;
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_Relative latency;
  size_t num_received = 0;

  ts_n = (struct GNUNET_TIME_AbsoluteNBO *) payload;
  ts = GNUNET_TIME_absolute_ntoh (*ts_n);
  latency = GNUNET_TIME_absolute_get_duration (ts);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Latency of received packet: %u\n",
       latency);
  switch (phase)
  {
  case TP_BURST_SHORT:
    num_received = num_received_short;
    break;
  case TP_BURST_LONG:
    num_received = num_received_long;
    break;
  case TP_SIZE_CHECK:
    num_received = num_received_size;
    break;
  }
  if (1 >= num_received)
    avg_latency = latency.rel_value_us;
  else
    avg_latency = ((avg_latency * (num_received - 1)) + latency.rel_value_us)
                  / num_received;

}

process_statistics_box_done (void *cls, int success)
{
  if (NULL != box_stats)
    box_stats = NULL;
  if (NULL == rekey_stats)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}

process_statistics_rekey_done (void *cls, int success)
{
  if (NULL != rekey_stats)
    rekey_stats = NULL;
  if (NULL == box_stats)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}

static int
process_statistics (void *cls,
                    const char *subsystem,
                    const char *name,
                    uint64_t value,
                    int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Statistic: Name %s and value %lu\n",
              name,
              value);
  if ((0 == strcmp ("rekey", test_name)) && (0 == strcmp (
                                               "# rekeying successful",
                                               name)) && (0 == value))
  {
    ret = 2;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No successful rekeying!\n");
    GNUNET_SCHEDULER_shutdown ();
  }
  if ((0 == strcmp ("backchannel", test_name))  &&
      (0 == strcmp (
         "# messages decrypted with BOX",
         name))
      && (9000 > value))
  {
    ret = 2;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Not enough BOX messages!\n");
    GNUNET_SCHEDULER_shutdown ();
  }
  if ((0 == strcmp ("rekey", test_name))  &&
      (0 == strcmp (
         "# messages decrypted with BOX",
         name))
      && (6000 > value))
  {
    ret = 2;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Not enough BOX messages!\n");
    GNUNET_SCHEDULER_shutdown ();
  }
  return GNUNET_OK;
}

/**
 * @brief Handle an incoming message
 *
 * Implements #GNUNET_TRANSPORT_TESTING_IncomingMessageCallback

 * @param cls Closure
 * @param tc_h Handle to the receiving communicator
 * @param msg Received message
 */
static void
incoming_message_cb (void *cls,
                     struct
                     GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                     *tc_h,
                     const char*payload,
                     size_t payload_len)
{
  if (0 != strcmp ((char*) cls, cfg_peers_name[NUM_PEERS - 1]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "unexpected receiver...\n");
    return;
  }
  /* Reset timeout */
  timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (
                                                GNUNET_TIME_UNIT_SECONDS,
                                                TIMEOUT_MULTIPLIER));
  switch (phase)
  {
  case TP_INIT:
    GNUNET_break (0);
    break;
  case TP_BURST_SHORT:
    {
      GNUNET_assert (SHORT_MESSAGE_SIZE == payload_len);
      num_received_short++;
      duration = GNUNET_TIME_absolute_get_duration (start_short);
      update_avg_latency (payload);
      if (num_received_short == BURST_PACKETS * 0.91)
      {
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "Short size packet test done.\n");
        char *goodput = GNUNET_STRINGS_byte_size_fancy ((SHORT_MESSAGE_SIZE
                                                         * num_received_short
                                                         * 1000
                                                         * 1000)
                                                        / duration.rel_value_us);
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "%lu/%lu packets in %llu us (%s/s) -- avg latency: %llu us\n",
             (unsigned long) num_received_short,
             (unsigned long) num_sent_short,
             (unsigned long long) duration.rel_value_us,
             goodput,
             (unsigned long long) avg_latency);
        GNUNET_free (goodput);
        start_long = GNUNET_TIME_absolute_get ();
        phase = TP_BURST_LONG;
        // num_sent_short = 0;
        avg_latency = 0;
        // num_received = 0;
        long_test (NULL);
      }
      break;
    }
  case TP_BURST_LONG:
    {
      if (long_message_size != payload_len)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Ignoring packet with wrong length\n");
        return;   // Ignore
      }
      num_received_long++;
      duration = GNUNET_TIME_absolute_get_duration (start_long);
      update_avg_latency (payload);
      if (num_received_long == BURST_PACKETS * 0.91)
      {
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "Long size packet test done.\n");
        char *goodput = GNUNET_STRINGS_byte_size_fancy ((long_message_size
                                                         * num_received_long
                                                         * 1000
                                                         * 1000)
                                                        / duration.
                                                        rel_value_us);

        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "%lu/%lu packets in %llu us (%s/s) -- avg latency: %llu us\n",
             (unsigned long) num_received_long,
             (unsigned long) num_sent_long,
             (unsigned long long) duration.rel_value_us,
             goodput,
             (unsigned long long) avg_latency);
        GNUNET_free (goodput);
        ack = 0;
        phase = TP_SIZE_CHECK;
        // num_received = 0;
        // num_sent_long = 0;
        avg_latency = 0;
        size_test (NULL);
      }
      break;
    }
  case TP_SIZE_CHECK:
    {
      size_t max_size = 64000;

      GNUNET_assert (TP_SIZE_CHECK == phase);
      if (LONG_MESSAGE_SIZE != long_message_size)
        max_size = long_message_size;
      num_received_size++;
      update_avg_latency (payload);
      if (num_received_size >= (max_size) / 10)
      {
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "Size packet test done.\n");
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "%lu/%lu packets -- avg latency: %llu us\n",
             (unsigned long) num_received_size,
             (unsigned long) num_sent_size,
             (unsigned long long) avg_latency);
        num_received_size = 0;
        num_sent_size = 0;
        avg_latency = 0;
        iterations_left--;
        if (0 != iterations_left)
        {
          start_short = GNUNET_TIME_absolute_get ();
          phase = TP_BURST_SHORT;
          num_sent_short = 0;
          num_sent_long = 0;
          num_received_short = 0;
          num_received_long = 0;
          short_test (NULL);
          break;
        }
        if ((0 == strcmp ("rekey", test_name))||(0 == strcmp ("backchannel",
                                                              test_name)) )
        {
          if (NULL != box_stats)
            GNUNET_STATISTICS_get_cancel (box_stats);
          box_stats = GNUNET_STATISTICS_get (stats[1],
                                             "C-UDP",
                                             "# messages decrypted with BOX",
                                             process_statistics_box_done,
                                             &process_statistics,
                                             NULL);
          if (NULL != rekey_stats)
            GNUNET_STATISTICS_get_cancel (rekey_stats);
          rekey_stats = GNUNET_STATISTICS_get (stats[0],
                                               "C-UDP",
                                               "# rekeying successful",
                                               process_statistics_rekey_done,
                                               &process_statistics,
                                               NULL);
        }
        else{
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "Finished\n");
          GNUNET_SCHEDULER_shutdown ();
        }
      }
      break;
    }
  }
}


static void
do_shutdown (void *cls)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "shuting down test.\”");

  if (NULL != box_stats)
  {
    GNUNET_STATISTICS_get_cancel (box_stats);
    box_stats = NULL;
  }
  if (NULL != rekey_stats)
  {
    GNUNET_STATISTICS_get_cancel (rekey_stats);
    rekey_stats = NULL;
  }
  if (NULL != to_task)
  {
    GNUNET_SCHEDULER_cancel (to_task);
    to_task = NULL;
  }
  for (unsigned int i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_TRANSPORT_TESTING_transport_communicator_service_stop (tc_hs[i]);
    GNUNET_STATISTICS_destroy (stats[i], GNUNET_NO);
  }
}


/**
 * @brief Main function called by the scheduler
 *
 * @param cls Closure - Handle to confiation
 */
static void
run (void *cls)
{
  ret = 0;
  // num_received = 0;
  // num_sent = 0;
  for (unsigned int i = 0; i < NUM_PEERS; i++)
  {
    tc_hs[i] = GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
      "transport",
      communicator_binary,
      cfg_peers_name[i],
      &peer_id[i],
      &communicator_available_cb,
      &add_address_cb,
      &queue_create_reply_cb,
      &add_queue_cb,
      &incoming_message_cb,
      &handle_backchannel_cb,
      cfg_peers_name[i]);   /* cls */

    if ((0 == strcmp ("rekey", test_name))||(0 == strcmp ("backchannel",
                                                          test_name)) )
    {
      stats[i] = GNUNET_STATISTICS_create ("C-UDP",
                                           cfg_peers[i]);
    }
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
}


int
main (int argc,
      char *const *argv)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *private_key;
  char *communicator_name;
  char *test_mode;
  char *cfg_peer;

  phase = TP_INIT;
  ret = 1;
  test_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  communicator_name = strchr (test_name, '-');
  communicator_name[0] = '\0';
  communicator_name++;
  test_mode = test_name;

  GNUNET_asprintf (&communicator_binary,
                   "gnunet-communicator-%s",
                   communicator_name);

  if (GNUNET_OK !=
      GNUNET_log_setup ("test_communicator_basic",
                        "DEBUG",
                        NULL))
  {
    fprintf (stderr, "Unable to setup log\n");
    GNUNET_break (0);
    return 2;
  }
  for (unsigned int i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_asprintf ((&cfg_peer),
                     "test_communicator_%s_%s_peer%u.conf",
                     communicator_name, test_mode, i + 1);
    cfg_peers_name[i] = cfg_peer;
    cfg_peers[i] = GNUNET_CONFIGURATION_create ();
    if (GNUNET_YES ==
        GNUNET_DISK_file_test (cfg_peers_name[i]))
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg_peers[i],
                                     cfg_peers_name[i]))
      {
        fprintf (stderr,
                 "Malformed configuration file `%s', exiting ...\n",
                 cfg_peers_name[i]);
        return 1;
      }
    }
    else
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg_peers[i],
                                     NULL))
      {
        fprintf (stderr,
                 "Configuration file %s does not exist, exiting ...\n",
                 cfg_peers_name[i]);
        return 1;
      }
    }
    private_key =
      GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg_peers[i]);
    if (NULL == private_key)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Unable to get peer ID\n");
      return 1;
    }
    GNUNET_CRYPTO_eddsa_key_get_public (private_key,
                                        &peer_id[i].public_key);
    GNUNET_free (private_key);
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Identity of peer %u is %s\n",
         i,
         GNUNET_i2s_full (&peer_id[i]));
  }
  LOG (GNUNET_ERROR_TYPE_MESSAGE, "Starting test...\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "argv[0]: %s\n",
       argv[0]);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "test_name: %s\n",
       test_name);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "communicator_name: %s\n",
       communicator_name);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "communicator_binary: %s\n",
       communicator_binary);

  GNUNET_SCHEDULER_run (&run,
                        NULL);
  return ret;
}
