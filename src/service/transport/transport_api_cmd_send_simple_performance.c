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
 * @file testing_api_cmd_start_peer.c
 * @brief cmd to start a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

/**
 * Struct to hold information for callbacks.
 *
 */
struct SendSimplePerfState
{
  /**
   * Context for our asynchronous completion.
   */
  struct GNUNET_TESTING_AsyncContext ac;

  /**
   * Label of the cmd to start a peer.
   *
   */
  const char *start_peer_label;

  /**
   * Label of the cmd which started the test system.
   *
   */
  const char *create_label;

  /**
   * The topology we get the connected nodes from.
   */
  struct GNUNET_TESTING_NetjailTopology *topology;

  /**
   * Size of the message in bytes.
   */
  unsigned int size;

  /**
   * Maximum number of messages per peer.
   */
  unsigned int max_send;
};

struct MQWrapper
{
  /**
   * State of the command.
   */
  struct SendSimplePerfState *sss;

  /**
   * Message queue for a peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Number of messages allready send.
   */
  uint32_t num_send;
};

/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
send_simple_cleanup (void *cls)
{
  struct SendSimpleState *sss = cls;

  GNUNET_free (sss);
}


static void
send_simple_single (void *cls)
{
  struct MQWrapper *mq_wrapper = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_TESTING_PerformanceTestMessage *test;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  mq_wrapper->num_send++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending simple test message with size %u number %u with mq %p max %u\n",
       mq_wrapper->sss->size,
       mq_wrapper->num_send,
       mq_wrapper->mq,
       mq_wrapper->sss->max_send);

  env = GNUNET_MQ_msg_extra (test,
                             mq_wrapper->sss->size - sizeof(*test),
                             GNUNET_TRANSPORT_TESTING_SIMPLE_PERFORMANCE_MTYPE);
  test->num = htonl (mq_wrapper->num_send);
  test->time_send = GNUNET_TIME_absolute_hton (now);
  memset (&test[1],
          '1',
          mq_wrapper->sss->size - sizeof(*test));
  GNUNET_MQ_send (mq_wrapper->mq,
                  env);
  if (mq_wrapper->sss->max_send > mq_wrapper->num_send)
    GNUNET_SCHEDULER_add_now (&send_simple_single, mq_wrapper);
  else
    GNUNET_TESTING_async_finish (&mq_wrapper->sss->ac);
}


static int
send_simple_cb  (void *cls,
                 const struct GNUNET_ShortHashCode *key,
                 void *value)
{
  struct SendSimplePerfState *sss = cls;
  struct GNUNET_MQ_Handle *mq = value;
  struct MQWrapper *mq_wrapper = GNUNET_new (struct MQWrapper);

  mq_wrapper->sss = sss;
  mq_wrapper->mq = mq;
  send_simple_single (mq_wrapper);

  return GNUNET_OK;
}


/**
 * The run method of this cmd will send a simple message to the connected peers.
 *
 */
static void
send_simple_run (void *cls,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct SendSimplePerfState *sss = cls;
  const struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  const struct GNUNET_TESTING_Command *system_cmd;
  const struct GNUNET_TESTING_System *tl_system;


  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                         sss->start_peer_label);
  GNUNET_TRANSPORT_get_trait_connected_peers_map (peer1_cmd,
                                                  &connected_peers_map);

  system_cmd = GNUNET_TESTING_interpreter_lookup_command (is,
                                                          sss->create_label);
  GNUNET_TESTING_get_trait_test_system (system_cmd,
                                        &tl_system);

  GNUNET_CONTAINER_multishortmap_iterate (
    (struct GNUNET_CONTAINER_MultiShortmap *)
    connected_peers_map, send_simple_cb,
    sss);
}


struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple_performance (const char *label,
                                              const char *start_peer_label,
                                              const char *create_label,
                                              uint32_t num,
                                              int size,
                                              int max_send,
                                              struct
                                              GNUNET_TESTING_NetjailTopology *
                                              topology)
{
  struct SendSimplePerfState *sss;
  struct GNUNET_TESTING_Command cmd;

  sss = GNUNET_new (struct SendSimplePerfState);
  sss->start_peer_label = start_peer_label;
  sss->create_label = create_label;
  sss->topology = topology;
  sss->size = size;
  sss->max_send = max_send;

  cmd = GNUNET_TESTING_command_new (sss,
                                    label,
                                    &send_simple_run,
                                    &send_simple_cleanup,
                                    NULL,
                                    &sss->ac);
  cmd.asynchronous_finish = GNUNET_YES;
  return cmd;
}
