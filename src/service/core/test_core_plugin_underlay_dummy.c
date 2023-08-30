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
 * @file src/service/core/test_core_plugin_underlay_dummy.c
 * @brief a plugin to provide the API for running test cases.
 * @author ch3
 * TODO:
 *  - try to avoid generic pointer and globally known struct UnderlayDummyState
 *  - cleaner separate the waiting for connection to finish out of _cmd_connect()
 *  - test closing of connection
 *  - test opening connection after closing
 *  - test multiple peers at once
 *  - test discovery of peers
 *  - test _connect_to_peer()
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#include "gnunet_core_underlay_dummy.h"


#define NUM_MESSAGES 10

#define MTYPE 12345

/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from_nocheck (kind, "core-plugin-underlay-dummy", __VA_ARGS__)


struct GNUNET_UNDERLAY_DUMMY_Message
{
  struct GNUNET_MessageHeader header;
  // The following will be used for debugging
  uint64_t id; // id of the message
  uint64_t batch; // first batch of that peer (for this test 0 or 1)
  //uint64_t peer; // number of sending peer (for this test 0 or 1)
};


struct Channel;


typedef void
(*handle_msg)(
  void *cls,
  struct Channel *channel,
  const struct GNUNET_UNDERLAY_DUMMY_Message *msg);


struct UnderlayDummyState;


struct Channel
{
  struct Channel *next;
  struct Channel *prev;
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Handle *mq;
};


typedef void *
(*UnderlayDummy_connect_cb) (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  struct GNUNET_MQ_Handle *mq);


struct UnderlayDummy_ConnectCb
{
  UnderlayDummy_connect_cb callback;
  void *cls;
};


struct UnderlayDummyState
{
  struct GNUNET_CORE_UNDERLAY_DUMMY_Handle *h;
  struct GNUNET_TESTING_AsyncContext ac;
  enum GNUNET_GenericReturnValue finished;
  const char *node_id;
  // FIXME: set cls per handler
  void *recv_handlers_cls;
  uint32_t recv_handlers_len;
  handle_msg *recv_handlers;

  struct UnderlayDummy_ConnectCb *connect_cbs;
  uint32_t connect_cbs_len;

  struct Channel *channels_head;
  struct Channel *channels_tail;
  //struct Channel **channels;
  //uint32_t channels_len;
};


struct UnderlayDummyRecvState;


struct ChannelCount
{
  struct Channel *channel;
  struct UnderlayDummyRecvState *udrs;
  uint64_t num_messages_received;
};


struct UnderlayDummyRecvState
{
  struct ChannelCount *channel_count;
  uint32_t num_channels;
  uint64_t num_messages_target;
  struct GNUNET_TESTING_AsyncContext ac;
};


struct UnderlayDummySendState
{
  uint64_t num_messages;
};


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
connect_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  struct UnderlayDummyState *uds = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_CORE_make_trait_connect (uds),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static void
handle_test (void *cls, const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  struct Channel *channel = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received message (%" PRIu64 ", %" PRIu64 ") - going to call handlers\n",
      GNUNET_ntohll (msg->id),
      GNUNET_ntohll (msg->batch));
  for (uint32_t i = 0; i < channel->uds->recv_handlers_len; i++)
  {
    // FIXME: set cls per handler
    channel->uds->recv_handlers[i] (channel->uds->recv_handlers_cls,
                                    channel,
                                    msg);
  }

  GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (channel->uds->h,
                                               channel->mq);
}


static void
*notify_connect_cb (
  void *cls,
  uint32_t num_addresses,
  const char *addresses[static num_addresses],
  struct GNUNET_MQ_Handle *mq,
  const struct GNUNET_PeerIdentity *peer_id)
{
  struct UnderlayDummyState *uds = cls;
  struct Channel *channel;
  (void) peer_id; /* unused - the underlay dummy doesn't know abot peer ids */

  LOG (GNUNET_ERROR_TYPE_DEBUG, "A new connection was established\n");

  channel = GNUNET_new (struct Channel);
  channel->uds = uds;
  channel->mq = mq;
  GNUNET_CONTAINER_DLL_insert (uds->channels_head,
                               uds->channels_tail,
                               channel);
  //GNUNET_array_append (uds->channels,
  //                     uds->channels_len,
  //                     channel);

  /* Call connect handlers from test */
  for (uint32_t i = 0; i < uds->connect_cbs_len; i++)
  {
    // TODO check if we really want to pass everything as-is
    struct UnderlayDummy_ConnectCb *connect_cb_struct =
      &uds->connect_cbs[i];
    connect_cb_struct->callback (connect_cb_struct->cls,
                                 peer_id,
                                 mq);
  }

  ////if ((uds->num_channels_target == uds->channels_len) &&
  //if ((1 == uds->channels_len) &&
  //    (GNUNET_NO == uds->finished))
  //{
  //  LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
  //  GNUNET_TESTING_async_finish (&uds->ac);
  //  uds->finished = GNUNET_YES;
  //}
  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //    "(post connect_cb - %u of 1)\n",
  //    uds->channels_len);
  return channel;
}


static void
notify_disconnect_cb (
  void *cls,
  void *handler_cls)
{
  //struct UnderlayDummyState *uds = cls;
  //struct Channel *channel = handler_cls;
  //uint32_t i_target = 0;
  //
  //LOG (GNUNET_ERROR_TYPE_DEBUG, "from notify_disconnect_cb()\n");
  //if (NULL == channel)
  //{
  //  LOG (GNUNET_ERROR_TYPE_WARNING,
  //       "notify_disconnect_cb() was called on a unknown channel\n");
  //  GNUNET_assert (0);
  //  return;
  //}
  ///**
  // * Remove the closed channel:
  // *  1. find the (index of the) closed channel
  // *  2. copy all following channel one to the front
  // */
  //for (uint32_t i = 0; i < uds->channels_len; i++)
  //{
  //  if (channel == uds->channels[i])
  //  {
  //    //uds->channels[i] = NULL; // XXX
  //    i_target = i;
  //    break;
  //  }
  //}
  ////for (uint32_t i = i_target; i < (uds->channels_len - 1); i++)
  ////{
  ////  GNUNET_memcpy ();
  ////}
  //GNUNET_memcpy (&uds->channels[i_target],
  //               &uds->channels[i_target+1],
  //               (uds->channels_len - i_target - 1) * sizeof (struct Channel *));
  //GNUNET_array_grow (uds->channels, uds->channels_len, uds->channels_len-1);
  //GNUNET_free (channel);
}


static void
address_change_cb (void *cls,
                   uint32_t num_addresses,
                   const char *addresses[static num_addresses])
{
  //struct UnderlayDummyState *uds = cls;
  (void) cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Our set of addresses changed\n");
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyState *uds = cls;
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_UNDERLAY_DUMMY_Message, NULL),
    GNUNET_MQ_handler_end ()
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%s) Going to connect to underlay dummy\n",
      uds->node_id);

  uds->h = GNUNET_CORE_UNDERLAY_DUMMY_connect (NULL, // cfg
                                               handlers,
                                               uds, // cls
                                               notify_connect_cb,
                                               notify_disconnect_cb,
                                               address_change_cb);
  GNUNET_TESTING_async_finish (&uds->ac);
}


static void
exec_connect_cleanup (void *cls)
{
  struct UnderlayDummyState *uds = cls;

  GNUNET_assert (NULL != uds->h);
  GNUNET_CORE_UNDERLAY_DUMMY_disconnect (uds->h);
}


// FIXME rename _CORE_ to _UNDERLAY_DUMMY_
//       (in other places, too)
const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_connect (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  const char* node_id)
{
  struct UnderlayDummyState *uds;

  uds = GNUNET_new (struct UnderlayDummyState);
  uds->node_id = GNUNET_strdup (node_id);
  uds->recv_handlers_len = 0;
  uds->recv_handlers = GNUNET_new_array (uds->recv_handlers_len, handle_msg);
  uds->connect_cbs_len = 0;
  uds->connect_cbs =
    GNUNET_new_array (uds->connect_cbs_len,
                      struct UnderlayDummy_ConnectCb);
  //uds->channels = GNUNET_new_array (0, struct Channel *);
  uds->finished = GNUNET_NO;
  return GNUNET_TESTING_command_new_ac (
      uds, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits,
      &uds->ac);
}


static void
handle_msg_test (void *cls,
                 struct Channel *channel,
                 const struct GNUNET_UNDERLAY_DUMMY_Message *msg)
{
  //struct ChannelCount *channel_count = cls;
  struct UnderlayDummyRecvState *udrs = cls;
  struct ChannelCount *channel_count;
  uint32_t channel_i;
  uint64_t num_messages_received;
  uint64_t num_messages_target;
  enum GNUNET_GenericReturnValue ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received test message %" PRIu64 " (%" PRIu64 ")\n",
       GNUNET_ntohll (msg->id),
       GNUNET_ntohll (msg->batch));

  /* First, find the channel count struct with the channel over which we
   * received this message */
  channel_i = udrs->num_channels; /* For error checking -
                                     should be overwritten in the following loop. */
  for (uint32_t i = 0; i<udrs->num_channels; i++)
  {
    channel_count = &udrs->channel_count[i];
    if (NULL == channel_count->channel)
    {
      channel_count->channel = channel;
      channel_count->udrs = udrs;
      channel_i = i;
      break;
    }
    else if (channel == channel_count->channel)
    {
      channel_i = i;
      break;
    }
    // else: continue until suitable channel count structure is found
  }
  GNUNET_break_op (channel_i != udrs->num_channels);
  channel_count->num_messages_received++;

  num_messages_received = channel_count->num_messages_received;
  num_messages_target = channel_count->udrs->num_messages_target;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received %" PRIu64 " messages (of %" PRIu64 " on channel %u)\n",
      num_messages_received,
      num_messages_target,
      channel_i);
  if (num_messages_target > num_messages_received) return;
  if (num_messages_target < num_messages_received)
    GNUNET_assert (0);
  //if (num_messages_target == num_messages_received)
  //  GNUNET_TESTING_async_finish (&udrs->ac);
  ret = GNUNET_YES;
  for (uint32_t i = 0; i < udrs->num_channels; i++)
  {
    channel_count = &udrs->channel_count[i];
    if (channel_count->num_messages_received != udrs->num_messages_target)
      ret = GNUNET_NO;
  }
  if (GNUNET_YES == ret) GNUNET_TESTING_async_finish (&udrs->ac);
}


static void
exec_recv_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummyRecvState *udrs = cls;
  struct UnderlayDummyState *uds;

  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
        // TODO make the "connect" an input to the command
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        (const void**) &uds)) {
    GNUNET_assert (0);
  };
  // FIXME: set cls per hanlder
  GNUNET_array_append (uds->recv_handlers,
                       uds->recv_handlers_len,
                       &handle_msg_test);
  uds->recv_handlers_cls = udrs;
}


static void
exec_recv_cleanup (void *cls)
{
  struct UnderlayDummyRecvState *udrs = cls;

  GNUNET_free (udrs->channel_count);
  GNUNET_free (udrs);
}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_recv (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  uint64_t num_messages)
{
  struct UnderlayDummyRecvState *udrs;

  udrs = GNUNET_new (struct UnderlayDummyRecvState);
  udrs->num_channels = 1; // previously came from an argument to _cmd_recv()
  udrs->channel_count = GNUNET_new_array (udrs->num_channels, struct ChannelCount);
  udrs->num_messages_target = num_messages;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_recv)\n");
  return GNUNET_TESTING_command_new_ac (
      udrs, // state
      label,
      &exec_recv_run,
      &exec_recv_cleanup,
      NULL,
      &udrs->ac);
}


static void
exec_send_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct UnderlayDummySendState *udss = cls;
  struct UnderlayDummyState *uds;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_UNDERLAY_DUMMY_Message *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "exec_send_run()\n");

  // TODO make the "connect" label an input to the command
  if (GNUNET_OK != GNUNET_CORE_get_trait_connect (
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        (const void**) &uds)) {
    GNUNET_assert (0);
  };

  //GNUNET_assert (NULL != uds->channels);
  //LOG (GNUNET_ERROR_TYPE_DEBUG, "uds->channels_len: %u\n", uds->channels_len);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to send %" PRIu64 " messages\n",
      udss->num_messages);
  /* For now send on all available channels as we don't know at this stage
   * which is an usable channel - this should be fine as the unusable channel
   * will (probably) be discoverd and cleand up in the process. */
  for (struct Channel *c_iter = uds->channels_head;
       NULL != c_iter;
       c_iter = c_iter->next)
  {
    for (uint64_t i = 0; i < udss->num_messages; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send message %" PRIu64 " (channel %" PRIu64 ")\n", i, i);
      env = GNUNET_MQ_msg (msg, MTYPE); // usually we wanted to keep the
                                        // envelopes to potentially cancel the
                                        // message
      msg->id = GNUNET_htonll (i);
      msg->batch = GNUNET_htonll (i);
      GNUNET_MQ_send (c_iter->mq, env);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent message %" PRIu64 " (channel %" PRIu64 ")\n", i, i);
    }
  }
  //for (uint32_t i = 0; i < uds->channels_len; i++)
  //{
  //  for (uint64_t ii = 0; ii < udss->num_messages; ii++)
  //  {
  //    LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to send message %" PRIu64 " (channel %" PRIu32 ")\n", ii, i);
  //    env = GNUNET_MQ_msg (msg, MTYPE); // usually we wanted to keep the
  //                                      // envelopes to potentially cancel the
  //                                      // message
  //    msg->id = GNUNET_htonll (ii);
  //    msg->batch = GNUNET_htonll (i);
  //    GNUNET_MQ_send (uds->channels[i]->mq, env);
  //    LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent message %" PRIu64 " (channel %" PRIu32 ")\n", ii, i);
  //  }
  //}
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent messages\n");
}


static void
exec_send_cleanup (void *cls)
{
  //struct UnderlayDummyState *uds = cls;
  (void) cls;

}


const struct GNUNET_TESTING_Command
GNUNET_CORE_cmd_send (
  const char *label,
  enum GNUNET_OS_ProcessStatusType expected_type,
  unsigned long int expected_exit_code,
  uint64_t num_messages)
{
  struct UnderlayDummySendState *udss;

  udss = GNUNET_new (struct UnderlayDummySendState);
  udss->num_messages = num_messages;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_send)\n");
  return GNUNET_TESTING_command_new (
      udss, // state
      label,
      &exec_send_run,
      &exec_send_cleanup,
      NULL);
}


GNUNET_TESTING_MAKE_PLUGIN (
  core,
  underlay_dummy,
  /* connect to underlay dummy 'service' (start it)
   * and set up basic callbacks */
   GNUNET_CORE_cmd_connect ("connect",
                            GNUNET_OS_PROCESS_EXITED,
                            0,
                            my_node_id),
   /* Set up receiving of messages -
    * register a callback with the connect cmd that
    * finishes this command after the specified
    * number of messages were received */
   GNUNET_TESTING_cmd_make_unblocking (
     GNUNET_CORE_cmd_recv ("recv",
                           GNUNET_OS_PROCESS_EXITED,
                           0,
                           NUM_MESSAGES)),
   /* Send specified number of messages */
   GNUNET_TESTING_cmd_make_unblocking (
     GNUNET_CORE_cmd_send ("send",
                           GNUNET_OS_PROCESS_EXITED,
                           0,
                           NUM_MESSAGES)),
   /* Wait until recv is finished */
   GNUNET_TESTING_cmd_finish ("recv-finished",
                              "recv",
                              GNUNET_TIME_relative_multiply (
                                GNUNET_TIME_UNIT_SECONDS, 60)),
   GNUNET_TESTING_cmd_end ()
)


// testing_core_cmd_connecting_peers.c takes as inspiration
// FIXME: likely not ideally placed here, move to its own file
GNUNET_CORE_SIMPLE_DUMMY_UNDERLAY_TRAITS (
    GNUNET_TESTING_MAKE_IMPL_SIMPLE_TRAIT, GNUNET_CORE)


/* end of src/service/core/test_core_plugin_underlay_dummy.c */
