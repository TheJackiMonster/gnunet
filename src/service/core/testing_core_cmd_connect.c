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
 * @file src/service/core/testing_core_connect.c
 * @brief a function to connect to the core service for testing
 * @author ch3
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_arm_lib.h"
#include "gnunet_testing_core_lib.h"
#include "gnunet_core_service.h"


//#define NUM_MESSAGES 10
//#define NUM_CHANNELS 2
//
#define MTYPE 12345

/**
 * @brief Generic logging shortcut
 */
#define LOG(kind, ...) \
  GNUNET_log_from (kind, "testing-core-connect", __VA_ARGS__)


static void
handle_test (void *cls, const struct GNUNET_TESTING_CORE_Message *msg)
{
  struct GNUNET_TESTING_CORE_Channel *channel = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received message (%" PRIu64 ", %" PRIu64 ", %s) - going to call handlers\n",
      GNUNET_ntohll (msg->id),
      GNUNET_ntohll (msg->batch),
      msg->node_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  (We: %s)\n", channel->connect_state->node_id);

  if (0 == strncmp (msg->node_id, channel->connect_state->node_id, NODE_ID_LEN))
    LOG (GNUNET_ERROR_TYPE_ERROR,
        "We received a message from ourself!\n");

  for (uint32_t i = 0; i < channel->connect_state->recv_handlers_len; i++)
  {
    if (NULL == channel->connect_state->recv_handlers[i]) continue;
    // FIXME: set cls per handler
    channel->connect_state->recv_handlers[i] (
        channel->connect_state->recv_handlers_cls,
        channel,
        msg);
  }

  // FIXME do we need to call something like the below?
  //GNUNET_CORE_UNDERLAY_DUMMY_receive_continue (channel->connect_state->h,
  //                                             channel->mq);
}


/**
 * This function prepares an array with traits.
 */
static enum GNUNET_GenericReturnValue
connect_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  struct GNUNET_TESTING_Trait traits[] = {
    GNUNET_CORE_TESTING_make_trait_connect (connect_state),
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


static void
init_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *my_identity)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Connected to core, own pid: %s\n",
      GNUNET_i2s (my_identity));
  GNUNET_memcpy (&connect_state->peer_id, my_identity, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_TESTING_async_finish (&connect_state->ac);
  // TODO we could finish connect at the first incoming connection
}


static void *
connect_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  struct GNUNET_MQ_Handle *mq,
  enum GNUNET_CORE_PeerClass class)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  struct GNUNET_TESTING_CORE_Channel *channel;
  (void) class; // unused

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "A new connection was established with peer %s\n",
      GNUNET_i2s (peer_id));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "  (us: %s)\n",
      GNUNET_i2s (&connect_state->peer_id));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "size of connect_state: %lu of channel: %lu\n",
      sizeof (struct GNUNET_TESTING_CORE_ConnectState),
      sizeof (struct GNUNET_TESTING_CORE_Channel));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "memcmp: %u\n",
      GNUNET_memcmp (&connect_state->peer_id, peer_id));
  if (0 == GNUNET_memcmp (&connect_state->peer_id, peer_id))
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "  (That's us - connection was established to ourself)\n");

  channel = GNUNET_new (struct GNUNET_TESTING_CORE_Channel);
  channel->connect_state = connect_state;
  channel->mq = mq;
  GNUNET_memcpy (&channel->peer_id, peer_id, sizeof (struct GNUNET_PeerIdentity));
  if (0 != GNUNET_memcmp (&connect_state->peer_id, peer_id))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Inserting channel into list\n");
    if ((NULL != connect_state->channels_head) &&
        (NULL != connect_state->channels_tail))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Peer at list head: %s\n",
          GNUNET_i2s (&connect_state->channels_head->peer_id));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Peer at list tail: %s\n",
          GNUNET_i2s (&connect_state->channels_tail->peer_id));
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "empty list\n");
    }
    GNUNET_CONTAINER_DLL_insert (connect_state->channels_head,
                                 connect_state->channels_tail,
                                 channel);
  }

  /* Call connect handlers from test */
  if (0 != GNUNET_memcmp (&connect_state->peer_id, peer_id))
    for (uint32_t i = 0; i < connect_state->connect_cbs_len; i++)
    {
      // TODO check if we really want to pass everything as-is
      struct GNUNET_TESTING_CORE_ConnectCb *connect_cb_struct =
        &connect_state->connect_cbs[i];
      // FIXME this might return something, but the implemented function also
      // returns nothing
      connect_cb_struct->callback (connect_cb_struct->cls,
                                   peer_id,
                                   mq);
    }

  //if ((connect_state->num_channels_target == connect_state->channels_len) &&
  //    (GNUNET_NO == connect_state->finished))
  //{
  //  LOG (GNUNET_ERROR_TYPE_DEBUG, "(post connect_cb _async_finish)\n");
  //  GNUNET_TESTING_async_finish (&connect_state->ac);
  //  connect_state->finished = GNUNET_YES;
  //}
  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //    "(post connect_cb - %u of %u)\n",
  //    connect_state->channels_len,
  //    connect_state->num_channels_target);

  return channel;
}


static void
disconnect_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer,
  void *peer_cls)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  struct GNUNET_TESTING_CORE_Channel *channel = peer_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "from notify_disconnect_cb()\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Channel from peer %s (peer_cls) disconnects\n",
      GNUNET_i2s (&channel->peer_id));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "  %s (arg)\n",
      GNUNET_i2s (peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "  (we are %s)\n",
      GNUNET_i2s (&connect_state->peer_id));
  /**
   * Remove the closed channel:
   *  1. find the (index of the) closed channel
   *  2. copy all following channel one to the front
   */
  //if (NULL != channel->next)
  if (0 != GNUNET_memcmp (&connect_state->peer_id, peer))
  {
    /* this channel might not be in the list */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "removing channel from list\n");
    GNUNET_CONTAINER_DLL_remove (connect_state->channels_head,
                                 connect_state->channels_tail,
                                 channel);
  }
  GNUNET_free (channel);
}


static void
exec_connect_run (void *cls,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;
  const struct GNUNET_TESTING_Command *arm_cmd;
  struct GNUNET_MQ_MessageHandler handlers[] =
  {
    GNUNET_MQ_hd_fixed_size (test, MTYPE, struct GNUNET_TESTING_CORE_Message, NULL),
    GNUNET_MQ_handler_end ()
  };
  const struct GNUNET_CORE_ServiceInfo service_info =
  {
    .service = GNUNET_CORE_SERVICE_TEST,
    .version = { 1, 0 },
    .version_max = { 1, 0 },
    .version_min = { 1, 0 },
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "(%s) Going to connect to core\n",
      connect_state->node_id);

  arm_cmd = GNUNET_TESTING_interpreter_lookup_command (
        is,
        connect_state->arm_service_label);
  if (NULL == arm_cmd)
    GNUNET_TESTING_FAIL (is);
  if (GNUNET_OK !=
      GNUNET_TESTING_ARM_get_trait_config (
        arm_cmd,
        &connect_state->cfg))
    GNUNET_TESTING_FAIL (is);

  connect_state->h = GNUNET_CORE_connect (connect_state->cfg,
                                          connect_state, // cls
                                          init_cb,
                                          connect_cb,
                                          disconnect_cb,
                                          handlers,
                                          &service_info);

}


static void
exec_connect_cleanup (void *cls)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;

  GNUNET_assert (NULL != connect_state->h);
  GNUNET_CORE_disconnect (connect_state->h);
  // TODO cleanup!
}



const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_connect (
  const char *label,
  const char* node_id,
  char *arm_service_label)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state;

  // TODO get handler from caller to call on new connections

  connect_state = GNUNET_new (struct GNUNET_TESTING_CORE_ConnectState);
  connect_state->node_id = GNUNET_strdup (node_id);
  connect_state->arm_service_label = GNUNET_strdup (arm_service_label);
  connect_state->recv_handlers_len = 0;
  connect_state->recv_handlers =
    GNUNET_new_array (connect_state->recv_handlers_len,
                      GNUNET_TESTING_CORE_handle_msg);
  connect_state->connect_cbs_len = 0;
  connect_state->connect_cbs =
    GNUNET_new_array (connect_state->connect_cbs_len,
                      struct GNUNET_TESTING_CORE_ConnectCb);
  connect_state->finished = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_connect)\n");
  return GNUNET_TESTING_command_new_ac ( // TODO make this sync?
      connect_state, // state
      label,
      &exec_connect_run,
      &exec_connect_cleanup,
      &connect_traits,
      &connect_state->ac); // TODO make this sync?
}


/* end of src/service/core/testing_core_connect.c */
