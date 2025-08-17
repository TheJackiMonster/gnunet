/*
      This file is part of GNUnet
      Copyright (C) 2024 GNUnet e.V.

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
 * @file src/service/core/testing_core_recv.c
 * @brief a function to receive messages from another peer
 * @author ch3
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_testing_core_lib.h"


/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from (kind, "testing-core-recv", __VA_ARGS__)


struct RecvState;


struct ChannelCount
{
  struct GNUNET_TESTING_CORE_Channel *channel;
  struct RecvState *rs;
  uint64_t num_messages_received;
};


struct RecvState
{
  struct ChannelCount *channel_count;
  uint32_t num_channels;
  uint64_t num_messages_target;
  struct GNUNET_TESTING_CORE_ConnectState *connect_state;
  struct GNUNET_TESTING_AsyncContext ac;
};


static void
handle_msg_test (void *cls,
                 struct GNUNET_TESTING_CORE_Channel *channel,
                 const struct GNUNET_TESTING_CORE_Message *msg);


static void
do_finish_cmd_delayed (void *cls)
{
  struct RecvState *rs = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finishing test delayed\n");
  GNUNET_TESTING_async_finish (&rs->ac);
  GNUNET_free (rs);
}


static void
remove_recv_handler (struct GNUNET_TESTING_CORE_ConnectState *connect_state)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Removing recv handler\n");
  for (uint64_t i = 0; i < connect_state->recv_handlers_len; i++)
  {
    if (&handle_msg_test == connect_state->recv_handlers[i])
    {
      // FIXME this is the dirty solution. The attempt below did for whatever
      // reason not work.
      connect_state->recv_handlers[i] = NULL;
      //LOG (GNUNET_ERROR_TYPE_DEBUG,
      //    "recv handlers[0]: %p, handle_msg_test: %p, (%lu)\n",
      //    connect_state->recv_handlers[0],
      //    &handle_msg_test,
      //    sizeof (&handle_msg_test));
      //LOG (GNUNET_ERROR_TYPE_DEBUG,
      //    "recv handlers: %p, %" PRIu64 "\n",
      //    connect_state->recv_handlers,
      //    connect_state->recv_handlers_len);
      //GNUNET_memcpy (&connect_state->recv_handlers[i],
      //               &connect_state->recv_handlers[i+1],
      //               (connect_state->connect_cbs_len - i - 1) *
      //                 sizeof (handle_msg_test));
      //LOG (GNUNET_ERROR_TYPE_DEBUG,
      //    "recv handlers: %p, %" PRIu64 "\n",
      //    connect_state->recv_handlers,
      //    connect_state->recv_handlers_len);
      //GNUNET_array_grow (connect_state->recv_handlers,
      //                   connect_state->recv_handlers_len,
      //                   connect_state->recv_handlers_len - 1);
    }
  }
}


static void
handle_msg_test (void *cls,
                 struct GNUNET_TESTING_CORE_Channel *channel,
                 const struct GNUNET_TESTING_CORE_Message *msg)
{
  //struct ChannelCount *channel_count = cls;
  struct RecvState *rs = cls;
  struct ChannelCount *channel_count;
  uint32_t channel_i;
  uint64_t num_messages_received;
  uint64_t num_messages_target;
  enum GNUNET_GenericReturnValue ret;

  LOG (GNUNET_ERROR_TYPE_INFO, "received test message %" PRIu64 " (%" PRIu64 ") %s\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch),
       msg->node_id);

  /* First, find the channel count struct with the channel over which we
   * received this message */
  channel_count = NULL;
  channel_i = rs->num_channels; /* For error checking -
                                   should be overwritten in the following loop. */
  for (uint32_t i = 0; i<rs->num_channels; i++)
  {
    struct ChannelCount *channel_count_iter = &rs->channel_count[i];
    if (NULL == channel_count_iter->channel)
    {
      channel_count = channel_count_iter;
      channel_count->channel = channel;
      channel_count->rs = rs;
      channel_i = i;
      break;
    }
    else if (channel == channel_count_iter->channel)
    {
      channel_count = channel_count_iter;
      channel_i = i;
      break;
    }
    // else: continue until suitable channel count structure is found
  }
  if (NULL == channel_count)
  {
    /* no suitable channel was found -> add this channel */
    GNUNET_array_grow (rs->channel_count,
                       rs->num_channels,
                       rs->num_channels + 1);
    channel_count = &rs->channel_count[rs->num_channels - 1];
    channel_count->channel = channel;
    channel_count->rs = rs;
    channel_i = rs->num_channels;
  }

  /* Then update number of received messages */
  channel_count->num_messages_received++;

  /* Finally check if this and then other channels received the correct amount
   * potentially finish. */
  num_messages_received = channel_count->num_messages_received;
  num_messages_target = channel_count->rs->num_messages_target;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received %" PRIu64 " messages (of %" PRIu64 " on channel %" PRIu32 ")\n",
      num_messages_received,
      num_messages_target,
      channel_i);
  if (num_messages_target > num_messages_received) return;
  if (num_messages_target < num_messages_received) GNUNET_assert (0);
  //if (num_messages_target == num_messages_received)
  //  GNUNET_TESTING_async_finish (&rs->ac);
  ret = GNUNET_YES;
  for (uint32_t i = 0; i < rs->num_channels; i++)
  {
    channel_count = &rs->channel_count[i];
    if (channel_count->num_messages_received != rs->num_messages_target)
      ret = GNUNET_NO;
  }
  if (GNUNET_YES == ret)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Received all expected messages on all channels\n");
    remove_recv_handler (rs->connect_state);
    // TODO do we want to keep track of this task?
    /* If we finish this task, this ARM will shut down this peer, taking with
     * it core and with it all the messages still in transit.
     * Adding a bit of delay gives the other peer a chance to still receive
     * them.
     * This might be done nicer - via a barrier? Check the other node's receive
     * state?
     * The number of 3 Milliseconds was chosen by looking at logs and then
     * continuously runnint the test and seeing how many actually work reliably
     * (Increased it quite a bit in the end for valgrind - no repeated tests
     * this time.)
     */
    (void) GNUNET_SCHEDULER_add_delayed (
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100),
      do_finish_cmd_delayed,
      rs);
  }
}


static void
exec_recv_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct RecvState *rs = cls;
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state;

  if (GNUNET_OK != GNUNET_CORE_TESTING_get_trait_connect (
        // TODO make the "connect" an input to the command
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        &connect_state)) {
    GNUNET_assert (0);
  };
  rs->connect_state = connect_state;
  // FIXME: set cls per handler
  GNUNET_array_append (connect_state->recv_handlers,
                       connect_state->recv_handlers_len,
                       &handle_msg_test);
  // FIXME is the following ok?
  ((struct GNUNET_TESTING_CORE_ConnectState *)connect_state)->recv_handlers_cls = rs;
}


static void
exec_recv_cleanup (void *cls)
{
  //struct RecvState *rs = cls;
  // TODO

  //GNUNET_free (rs->channel_count);
  //GNUNET_free (rs);
}


const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_recv (
  const char *label,
  uint64_t num_messages)
{
  struct RecvState *rs;

  // TODO this could be a static global variable
  rs = GNUNET_new (struct RecvState);
  rs->num_channels = 0;
  rs->channel_count = GNUNET_new_array (rs->num_channels, struct ChannelCount);
  rs->num_messages_target = num_messages;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_recv)\n");
  return GNUNET_TESTING_command_new_ac (
      rs, // state
      label,
      &exec_recv_run,
      &exec_recv_cleanup,
      NULL, // traits
      &rs->ac); // FIXME
}


/* end of src/service/core/testing_core_recv.c */
