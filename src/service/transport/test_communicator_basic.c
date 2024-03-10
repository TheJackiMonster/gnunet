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
#include "gnunet_signatures.h"
#include "gnunet_testing_lib.h"
#include "transport.h"
#include "gnunet_statistics_service.h"

#include <inttypes.h>


#define LOG(kind, ...) GNUNET_log_from (kind, \
                                        "test_transport_communicator", \
                                        __VA_ARGS__)

#define NUM_PEERS 2

static struct GNUNET_SCHEDULER_Task *to_task[NUM_PEERS];

static int queue_est = GNUNET_NO;

static struct GNUNET_PeerIdentity peer_id[NUM_PEERS];

static char *communicator_binary;

static struct
GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_hs[NUM_PEERS];

static struct GNUNET_CONFIGURATION_Handle *cfg_peers[NUM_PEERS];

static struct GNUNET_STATISTICS_Handle *stats[NUM_PEERS];

static char *cfg_peers_name[NUM_PEERS];

static int finished[NUM_PEERS];

static int ret;

static int bidirect = GNUNET_NO;

static size_t long_message_size;

static struct GNUNET_TIME_Absolute start_short[NUM_PEERS];

static struct GNUNET_TIME_Absolute start_long[NUM_PEERS];

static struct GNUNET_TIME_Absolute timeout[NUM_PEERS];

// static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *my_tc;

static char *communicator_name;

static char *test_name;

static struct GNUNET_STATISTICS_GetHandle *box_stats[NUM_PEERS];

static struct GNUNET_STATISTICS_GetHandle *rekey_stats[NUM_PEERS];

#define TEST_SECTION "test-setup"

#define SHORT_MESSAGE_SIZE 128

#define LONG_MESSAGE_SIZE 32000 /* FIXME */

#define ALLOWED_PACKET_LOSS 91

#define BURST_PACKETS 5000

#define TOTAL_ITERATIONS 1

#define PEER_A 0

#define PEER_B 1

static unsigned int iterations_left[NUM_PEERS];

#define TIMEOUT_MULTIPLIER 5

#define DEFAULT_DELAY \
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

static unsigned int phase_short[NUM_PEERS];

static unsigned int phase_long[NUM_PEERS];

static unsigned int phase_size[NUM_PEERS];

static long long unsigned int allowed_packet_loss_short;

static long long unsigned int allowed_packet_loss_long;

static long long unsigned int burst_packets_short;

static long long unsigned int burst_packets_long;

static long long unsigned int delay_long_value;

static long long unsigned int delay_short_value;

static struct GNUNET_TIME_Relative delay_short;

static struct GNUNET_TIME_Relative delay_long;

static size_t num_sent_short[NUM_PEERS];

static size_t num_sent_long[NUM_PEERS];

static size_t num_sent_size[NUM_PEERS];

static uint32_t ack[NUM_PEERS];

static enum TestPhase phase[NUM_PEERS];

static size_t num_received_short[NUM_PEERS];

static size_t num_received_long[NUM_PEERS];

static size_t num_received_size[NUM_PEERS];

static uint64_t avg_latency[NUM_PEERS];

static void
communicator_available_cb (
  void *cls,
  struct
  GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
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
  const char *address = cls;

  if (NULL != tc_hs[PEER_A]->c_mq)
  {
    queue_est = GNUNET_YES;
    GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (tc_hs[PEER_A],
                                                                &peer_id[PEER_B]
                                                                ,
                                                                address);
  }
  else
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &open_queue,
                                  (void *) address);
  }
}


static void
add_address_cb (
  void *cls,
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  const char *address,
  struct GNUNET_TIME_Relative expiration,
  uint32_t aid,
  enum GNUNET_NetworkType nt)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New address. (addr: %s, expir: %s, ID: %" PRIu32 ", nt: %u\n",
       address,
       GNUNET_STRINGS_relative_time_to_string (expiration,
                                               GNUNET_NO),
       aid,
       (int) nt);
  // addresses[1] = GNUNET_strdup (address);
  if ((0 == strcmp ((char*) cls, cfg_peers_name[PEER_B])) &&
      (GNUNET_NO == queue_est))
  {
    open_queue ((void *) address);
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
queue_create_reply_cb (
  void *cls,
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  int will_try)
{
  (void) cls;
  (void) tc_h;
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

  (void) tc_h;
  (void) msg;
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


static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
get_tc_h (unsigned int peer_nr)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got peer %u\n",
       peer_nr);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handle %p peer 0\n",
       tc_hs[0]);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handle %p peer 1\n",
       tc_hs[1]);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handle %p get\n",
       tc_hs[peer_nr]);

  return tc_hs[peer_nr];
}


static unsigned int
get_peer_nr_from_tc (struct
                     GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  if (tc_h == get_tc_h (0))
    return PEER_A;
  else
    return PEER_B;
}


static unsigned int
get_peer_nr (void *cls, unsigned int get_the_other_one)
{
  if (0 == strcmp ((char*) cls, cfg_peers_name[0]))
    return get_the_other_one ? PEER_B : PEER_A;
  else
    return get_the_other_one ? PEER_A : PEER_B;
}


static void
process_statistics_box_done (void *cls, int success)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  unsigned int peer_nr;

  peer_nr = get_peer_nr_from_tc (tc_h);

  if (NULL != box_stats[peer_nr])
    box_stats[peer_nr] = NULL;
  if (NULL == rekey_stats[peer_nr])
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}


static void
process_statistics_rekey_done (void *cls, int success)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  unsigned int peer_nr;

  peer_nr = get_peer_nr_from_tc (tc_h);

  if (NULL != rekey_stats[peer_nr])
    rekey_stats[peer_nr] = NULL;
  if (NULL == box_stats[peer_nr])
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Statistic: Name %s and value %" PRIu64 "\n",
              name,
              value);
  if ((0 == strcmp ("rekey", test_name)) && (0 == strcmp (
                                               "# rekeying successful",
                                               name)))
  {
    if (0 == value)
    {
      ret = 2;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "No successful rekeying!\n");
      GNUNET_SCHEDULER_shutdown ();
    }
    LOG (GNUNET_ERROR_TYPE_MESSAGE,
         "Successful rekeys: %llu\n",
         (unsigned long long) value);
  }
  if ((0 == strcmp ("backchannel", test_name)) &&
      (0 == strcmp (
         "# messages decrypted with BOX",
         name))
      && (9000 > value))
  {
    ret = 2;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Not enough BOX messages! (want: %u, have %llu)\n",
                9000, (unsigned long long) value);
    GNUNET_SCHEDULER_shutdown ();
  }
  if ((0 == strcmp ("rekey", test_name)) &&
      (0 == strcmp (
         "# messages decrypted with BOX",
         name))
      && (6000 > value))
  {
    ret = 2;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Not enough BOX messages! (want: %u, have %llu)\n",
                6000, (unsigned long long) value);
    GNUNET_SCHEDULER_shutdown ();
  }
  return GNUNET_OK;
}


static void
short_test (void *cls);

static void
short_test_cb (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  unsigned int peer_nr;
  char *payload;

  peer_nr = get_peer_nr_from_tc (tc_h);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "short_test_cb %u/%u for peer %u and handle %p\n",
       (unsigned int) num_sent_short[peer_nr],
       (unsigned int) num_received_short[peer_nr],
       peer_nr,
       tc_h);
  payload = make_payload (SHORT_MESSAGE_SIZE);
  num_sent_short[peer_nr]++;
  if (burst_packets_short == num_sent_short[peer_nr])
    tc_h->cont = NULL;
  else
    tc_h->cont = short_test;
  tc_h->cont_cls = cls;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (tc_h,
                                                        NULL,
                                                        cls,
                                                        payload,
                                                        SHORT_MESSAGE_SIZE);
  GNUNET_free (payload);
  timeout[peer_nr] = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER));
}


static void
short_test (void *cls)
{
  GNUNET_SCHEDULER_add_delayed (delay_short,
                                &short_test_cb,
                                cls);
}


static void
size_test (void *cls)
{
  unsigned int peer_nr;
  char *payload;
  size_t max_size = 64000;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;

  peer_nr = get_peer_nr_from_tc (tc_h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "size_test_cb %u\n",
       (unsigned int) num_sent_size[peer_nr]);
  GNUNET_assert (TP_SIZE_CHECK == phase[peer_nr]);
  if (LONG_MESSAGE_SIZE != long_message_size)
    max_size = long_message_size;
  if (ack[peer_nr] + 10 > max_size)
    return; /* Leave some room for our protocol, so not 2^16 exactly */
  ack[peer_nr] += 10;
  payload = make_payload (ack[peer_nr]);
  num_sent_size[peer_nr]++;
  if (ack[peer_nr] >= max_size)
    tc_h->cont = NULL;
  else
    tc_h->cont = size_test;
  tc_h->cont_cls = cls;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (tc_h,
                                                        NULL,
                                                        cls,
                                                        payload,
                                                        ack[peer_nr]);
  GNUNET_free (payload);
  timeout[peer_nr] = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER));
}


static void
long_test (void *cls);

static void
long_test_cb (void *cls)
{
  unsigned int peer_nr;
  char *payload;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;

  peer_nr = get_peer_nr_from_tc (tc_h);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "long_test_cb %u/%u\n",
       (unsigned int) num_sent_long[peer_nr],
       (unsigned int) num_received_long[peer_nr]);
  payload = make_payload (long_message_size);
  num_sent_long[peer_nr]++;
  if (burst_packets_long == num_sent_long[peer_nr])
    tc_h->cont = NULL;
  else
    tc_h->cont = long_test;
  tc_h->cont_cls = cls;
  GNUNET_TRANSPORT_TESTING_transport_communicator_send (tc_h,
                                                        NULL,
                                                        cls,
                                                        payload,
                                                        long_message_size);
  GNUNET_free (payload);
  timeout[peer_nr] = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER));
}


static void
long_test (void *cls)
{
  GNUNET_SCHEDULER_add_delayed (delay_long,
                                &long_test_cb,
                                cls);
}


static void
choose_phase (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  unsigned int peer_nr;

  peer_nr = get_peer_nr_from_tc (tc_h);

  if (GNUNET_YES == phase_short[peer_nr])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Choose phase short with peer %u and Handle %p\n",
                peer_nr,
                tc_h);
    phase[peer_nr] =  TP_BURST_SHORT;
    start_short[peer_nr] = GNUNET_TIME_absolute_get ();
    short_test (tc_h);
  }
  else if (GNUNET_YES == phase_long[peer_nr])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Choose phase long with peer %u\n",
                peer_nr);
    phase[peer_nr] =  TP_BURST_LONG;
    start_long[peer_nr] = GNUNET_TIME_absolute_get ();
    long_test (tc_h);
  }
  else if (GNUNET_YES == phase_size[peer_nr])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Choose phase size\n");
    phase[peer_nr] =  TP_SIZE_CHECK;
    size_test (tc_h);
  }
  else
  {
    if ((0 == strcmp ("udp", communicator_name)) && ((0 == strcmp ("rekey",
                                                                   test_name))
                                                     || (0 == strcmp (
                                                           "backchannel",
                                                           test_name))) )
    {
      if (NULL != box_stats[peer_nr])
        GNUNET_STATISTICS_get_cancel (box_stats[peer_nr]);
      box_stats[peer_nr] = GNUNET_STATISTICS_get (stats[1],
                                                  "C-UDP",
                                                  "# messages decrypted with BOX",
                                                  process_statistics_box_done,
                                                  &process_statistics,
                                                  tc_h);
      if (NULL != rekey_stats[peer_nr])
        GNUNET_STATISTICS_get_cancel (rekey_stats[peer_nr]);
      rekey_stats[peer_nr] = GNUNET_STATISTICS_get (stats[1],
                                                    "C-UDP",
                                                    "# rekeying successful",
                                                    process_statistics_rekey_done,
                                                    &process_statistics,
                                                    tc_h);
    }
    else
    {
      if ((GNUNET_NO == bidirect) || (((PEER_A == peer_nr) &&
                                       finished[PEER_B]) || ((PEER_B ==
                                                              peer_nr) &&
                                                             finished
                                                             [PEER_A])))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Finished\n");
        GNUNET_SCHEDULER_shutdown ();
      }
      finished[peer_nr] = GNUNET_YES;
    }
  }
}


static void
finish_phase_long (unsigned int peer_nr)
{
  static struct GNUNET_TIME_Relative duration;

  duration = GNUNET_TIME_absolute_get_duration (start_long[peer_nr]);
  LOG (GNUNET_ERROR_TYPE_MESSAGE,
       "Long size packet test  for peer %u done.\n",
       peer_nr);
  char *goodput = GNUNET_STRINGS_byte_size_fancy (
    (long_message_size * num_received_long[peer_nr] * 1000 * 1000)
    / duration.
    rel_value_us);

  LOG (GNUNET_ERROR_TYPE_MESSAGE,
       "%lu/%lu packets in %llu us (%s/s) -- avg latency: %llu us\n",
       (unsigned long) num_received_long[peer_nr],
       (unsigned long) num_sent_long[peer_nr],
       (unsigned long long) duration.rel_value_us,
       goodput,
       (unsigned long long) avg_latency[peer_nr]);
  GNUNET_free (goodput);
  ack[peer_nr] = 0;
  // phase = TP_SIZE_CHECK;
  // num_received = 0;
  // num_sent_long = 0;
  avg_latency[peer_nr] = 0;
  // size_test (NULL);
  phase_long[peer_nr] = GNUNET_NO;
  choose_phase (get_tc_h (peer_nr));
}


static void
finish_phase_short (unsigned int peer_nr)
{
  static struct GNUNET_TIME_Relative duration;

  duration = GNUNET_TIME_absolute_get_duration (start_short[peer_nr]);
  LOG (GNUNET_ERROR_TYPE_MESSAGE,
       "Short size packet test for peer %u done.\n",
       peer_nr);
  char *goodput = GNUNET_STRINGS_byte_size_fancy (
    (SHORT_MESSAGE_SIZE * num_received_short[peer_nr] * 1000 * 1000)
    / duration.rel_value_us);
  LOG (GNUNET_ERROR_TYPE_MESSAGE,
       "%lu/%lu packets in %llu us (%s/s) -- avg latency: %llu us\n",
       (unsigned long) num_received_short[peer_nr],
       (unsigned long) num_sent_short[peer_nr],
       (unsigned long long) duration.rel_value_us,
       goodput,
       (unsigned long long) avg_latency[peer_nr]);
  GNUNET_free (goodput);
  // start_long = GNUNET_TIME_absolute_get ();
  // phase = TP_BURST_LONG;
  // num_sent_short = 0;
  avg_latency[peer_nr] = 0;
  // num_received = 0;
  phase_short[peer_nr] = GNUNET_NO;
  choose_phase (get_tc_h (peer_nr));
  // long_test (NULL);
}


static void
latency_timeout (void *cls)
{

  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  unsigned int peer_nr;
  size_t num_sent = 0;
  size_t num_received = 0;

  peer_nr = get_peer_nr_from_tc (tc_h);
  to_task[peer_nr] = NULL;

  switch (phase[peer_nr])
  {
  case TP_INIT:
    GNUNET_assert (0);
    break;
  case TP_BURST_SHORT:
    num_sent = num_sent_short[peer_nr];
    num_received = num_received_short[peer_nr];
    if ((num_sent_short[peer_nr] == burst_packets_short) &&
        (num_received_short[peer_nr] >
         burst_packets_short
         / 100
         *
         allowed_packet_loss_short) )
    {
      finish_phase_short (peer_nr);
      to_task[peer_nr] = GNUNET_SCHEDULER_add_at (timeout[peer_nr],
                                                  &latency_timeout,
                                                  cls);
      return;
    }
    break;
  case TP_BURST_LONG:
    num_sent = num_sent_long[peer_nr];
    num_received = num_received_long[peer_nr];
    if ((num_sent_long[peer_nr] == burst_packets_long) &&
        (num_received_long[peer_nr] >
         burst_packets_long
         / 100
         *
         allowed_packet_loss_long) )
    {
      finish_phase_long (peer_nr);
      to_task[peer_nr] = GNUNET_SCHEDULER_add_at (timeout[peer_nr],
                                                  &latency_timeout,
                                                  cls);
      return;
    }
    break;
  case TP_SIZE_CHECK:
    num_sent = num_sent_size[peer_nr];
    num_received = num_received_size[peer_nr];
    break;
  }
  if (GNUNET_TIME_absolute_get_remaining (timeout[peer_nr]).rel_value_us > 0)
  {
    to_task[peer_nr] = GNUNET_SCHEDULER_add_at (timeout[peer_nr],
                                                &latency_timeout,
                                                cls);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Latency too high. Test failed. (Phase: %d. Sent: %lu, Received: %lu)\n",
       phase[peer_nr], num_sent, num_received);
  ret = 2;
  GNUNET_SCHEDULER_shutdown ();
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

  unsigned int peer_nr;

  peer_nr = get_peer_nr (cls, GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handle %p add %u %u\n",
       tc_h,
       peer_nr,
       get_peer_nr_from_tc (tc_h));
  if ((GNUNET_NO == bidirect) && (0 != strcmp ((char*) cls, cfg_peers_name[0])))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue available at receiving peer\n");
    return; // TODO?
  }
  else if (TP_INIT != phase[peer_nr])
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queue established, starting test...\n");
  if (UINT16_MAX != mtu) /* Message header overhead */
    long_message_size = mtu - sizeof(struct GNUNET_TRANSPORT_SendMessageTo)
                        - sizeof(struct GNUNET_MessageHeader);
  else
    long_message_size = LONG_MESSAGE_SIZE;
  timeout[peer_nr] = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER));
  GNUNET_assert (NULL == to_task[peer_nr]);
  to_task[peer_nr] = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER),
    &latency_timeout,
    tc_h);
  choose_phase (tc_h);
}


static void
update_avg_latency (const char *payload, unsigned int peer_nr)
{
  struct GNUNET_TIME_AbsoluteNBO *ts_n;
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_Relative latency;
  size_t num_received = 0;

  ts_n = (struct GNUNET_TIME_AbsoluteNBO *) payload;
  ts = GNUNET_TIME_absolute_ntoh (*ts_n);
  latency = GNUNET_TIME_absolute_get_duration (ts);

  switch (phase[peer_nr])
  {
  case TP_INIT:
    GNUNET_assert (0);
    break;
  case TP_BURST_SHORT:
    num_received = num_received_short[peer_nr];
    break;
  case TP_BURST_LONG:
    num_received = num_received_long[peer_nr];
    break;
  case TP_SIZE_CHECK:
    num_received = num_received_size[peer_nr];
    break;
  }
  if (1 >= num_received)
    avg_latency[peer_nr] = latency.rel_value_us;
  else
    avg_latency[peer_nr] = ((avg_latency[peer_nr] * (num_received - 1))
                            + latency.rel_value_us)
                           / num_received;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Latency of received packet by peer %u: %s with avg latency %" PRIu64
       "\n",
       peer_nr,
       GNUNET_STRINGS_relative_time_to_string (latency,
                                               GNUNET_YES),
       avg_latency[peer_nr]);
}


static void
load_phase_config ()
{

  phase_short[0] =  GNUNET_CONFIGURATION_get_value_yesno (cfg_peers[0],
                                                          TEST_SECTION,
                                                          "PHASE_SHORT");
  if (GNUNET_SYSERR == phase_short[0])
    phase_short[0] = GNUNET_YES;

  phase_short[1] = phase_short[0];

  phase_long[0] =  GNUNET_CONFIGURATION_get_value_yesno (cfg_peers[0],
                                                         TEST_SECTION,
                                                         "PHASE_LONG");

  if (GNUNET_SYSERR == phase_long[0])
    phase_long[0] = GNUNET_YES;

  phase_long[1] = phase_long[0];

  phase_size[0] =   GNUNET_CONFIGURATION_get_value_yesno (cfg_peers[0],
                                                          TEST_SECTION,
                                                          "PHASE_SIZE");

  if (GNUNET_SYSERR == phase_size[0])
    phase_size[0] = GNUNET_YES;

  phase_size[1] = phase_size[0];
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
incoming_message_cb (
  void *cls,
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  const char *payload,
  size_t payload_len)
{
  unsigned int peer_nr;


  peer_nr = get_peer_nr (cls, GNUNET_YES);

  if ((GNUNET_NO == bidirect) && (0 != strcmp ((char*) cls,
                                               cfg_peers_name[NUM_PEERS - 1])))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "unexpected receiver...\n");
    return;
  }
  /* Reset timeout */
  timeout[peer_nr] = GNUNET_TIME_relative_to_absolute (
    GNUNET_TIME_relative_multiply (
      GNUNET_TIME_UNIT_SECONDS,
      TIMEOUT_MULTIPLIER));
  switch (phase[peer_nr])
  {
  case TP_INIT:
    GNUNET_break (0);
    break;
  case TP_BURST_SHORT:
    {
      GNUNET_assert (SHORT_MESSAGE_SIZE == payload_len);
      num_received_short[peer_nr]++;

      update_avg_latency (payload, peer_nr);
      if ((num_sent_short[peer_nr] == burst_packets_short) &&
          (num_received_short[peer_nr] ==
           burst_packets_short))
      {
        finish_phase_short (peer_nr);
      }
      break;
    }
  case TP_BURST_LONG:
    {
      if (long_message_size != payload_len)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Ignoring packet with wrong length (have: %lu, want: %lu)\n",
             payload_len, long_message_size);
        return;   // Ignore
      }
      num_received_long[peer_nr]++;

      update_avg_latency (payload, peer_nr);
      if ((num_sent_long[peer_nr] == burst_packets_long) &&
          (num_received_long[peer_nr] >
           burst_packets_long))
      {
        finish_phase_long (peer_nr);
      }
      break;
    }
  case TP_SIZE_CHECK:
    {
      size_t max_size = 64000;

      GNUNET_assert (TP_SIZE_CHECK == phase[peer_nr]);
      if (LONG_MESSAGE_SIZE != long_message_size)
        max_size = long_message_size;
      num_received_size[peer_nr]++;
      update_avg_latency (payload, peer_nr);
      if ((GNUNET_YES == phase_size[peer_nr]) && (num_received_size[peer_nr] >=
                                                  (max_size) / 10) )
      {
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "Size packet test  for peer %u done.\n",
             peer_nr);
        LOG (GNUNET_ERROR_TYPE_MESSAGE,
             "%lu/%lu packets -- avg latency: %llu us\n",
             (unsigned long) num_received_size[peer_nr],
             (unsigned long) num_sent_size[peer_nr],
             (unsigned long long) avg_latency[peer_nr]);
        iterations_left[peer_nr]--;
        phase_size[peer_nr] = GNUNET_NO;
        if (0 != iterations_left[peer_nr])
        {
          // start_short = GNUNET_TIME_absolute_get ();
          // phase = TP_BURST_SHORT;
          num_received_size[peer_nr] = 0;
          num_sent_size[peer_nr] = 0;
          avg_latency[peer_nr] = 0;
          num_sent_short[peer_nr] = 0;
          num_sent_long[peer_nr] = 0;
          num_received_short[peer_nr] = 0;
          num_received_long[peer_nr] = 0;
          // short_test (NULL);
          if (((PEER_A == peer_nr) && finished[PEER_B]) || ((PEER_B ==
                                                             peer_nr) &&
                                                            finished[PEER_A]))
          {
            load_phase_config ();
          }
        }
        choose_phase (get_tc_h (peer_nr));
      }
      break;
    }
  }
}


static void
do_shutdown (void *cls)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "shutting down test.\n");

  for (unsigned int i = 0; i < NUM_PEERS; i++)
  {
    if (NULL != box_stats[i])
    {
      GNUNET_STATISTICS_get_cancel (box_stats[i]);
      box_stats[i] = NULL;
    }
    if (NULL != rekey_stats[i])
    {
      GNUNET_STATISTICS_get_cancel (rekey_stats[i]);
      rekey_stats[i] = NULL;
    }
    if (NULL != to_task[i])
    {
      GNUNET_SCHEDULER_cancel (to_task[i]);
      to_task[i] = NULL;
    }
    GNUNET_STATISTICS_destroy (stats[i], GNUNET_YES);
    GNUNET_TRANSPORT_TESTING_transport_communicator_service_stop (tc_hs[i]);
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

    if ((0 == strcmp ("udp", communicator_name)) && ((0 == strcmp ("rekey",
                                                                   test_name))
                                                     ||
                                                     (0 == strcmp (
                                                        "backchannel",
                                                        test_name))) )
    {
      stats[i] = GNUNET_STATISTICS_create ("C-UDP",
                                           cfg_peers[i]);
    }
    else if ((0 == strcmp ("bidirect", test_name)))
    {
      bidirect = GNUNET_YES;
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
  char *test_mode;
  char *cfg_peer;

  iterations_left[0] = TOTAL_ITERATIONS;
  iterations_left[1] = TOTAL_ITERATIONS;
  phase[0] = TP_INIT;
  phase[1] = TP_INIT;
  ret = 1;
  test_name = GNUNET_STRINGS_get_suffix_from_binary_name (argv[0]);
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "ALLOWED_PACKET_LOSS_SHORT",
                                             &allowed_packet_loss_short))
    allowed_packet_loss_short = ALLOWED_PACKET_LOSS;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "ALLOWED_PACKET_LOSS_LONG",
                                             &allowed_packet_loss_long))
    allowed_packet_loss_long = ALLOWED_PACKET_LOSS;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "BURST_PACKETS_SHORT",
                                             &burst_packets_short))
    burst_packets_short = BURST_PACKETS;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "BURST_PACKETS_LONG",
                                             &burst_packets_long))
    burst_packets_long = BURST_PACKETS;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "DELAY_SHORT",
                                             &delay_short_value))
    delay_short = DEFAULT_DELAY;
  else
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                   delay_short_value);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg_peers[0],
                                             TEST_SECTION,
                                             "DELAY_SHORT",
                                             &delay_long_value))
    delay_long = DEFAULT_DELAY;
  else
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                   delay_long_value);
  load_phase_config ();
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
