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
 * @file src/service/core/testing_core_send.c
 * @brief a function to send messages to another peer
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
  GNUNET_log_from (kind, "testing-core-send", __VA_ARGS__)


static void *
connect_cb (void *cls,
            const struct GNUNET_PeerIdentity *peer_id,
            struct GNUNET_MQ_Handle *mq);


struct SendState
{
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state;
  uint64_t num_messages;
  enum GNUNET_GenericReturnValue await_new_connection;
};


static void
cleanup_callbacks (struct SendState *send_state)
{
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state =
    send_state->connect_state;
  struct GNUNET_TESTING_CORE_ConnectCb *connect_cb_iter;

  for (uint64_t i = 0; i < connect_state->connect_cbs_len; i++)
  {
    connect_cb_iter = &connect_state->connect_cbs[i];
    if (connect_cb == connect_cb_iter->callback)
    {
      /* remove the callback */
      GNUNET_memcpy (connect_cb_iter,
                     connect_cb_iter + 1,
                     (connect_state->connect_cbs_len - i - 1) *
                       sizeof (struct GNUNET_TESTING_CORE_ConnectCb));
      GNUNET_array_grow (connect_state->connect_cbs,
                         connect_state->connect_cbs_len,
                         connect_state->connect_cbs_len - 1);
      //FIXME the following seems to be a double free, but I currently don't
      //know where the other free should be
      //GNUNET_free (connect_cb_iter);
    }
  }
}


static void
send_messages (struct SendState *send_state)
{
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state =
    send_state->connect_state;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTING_CORE_Message *msg;
  struct GNUNET_TESTING_CORE_Channel *channel_iter;
  uint64_t channel_index = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Going to send %" PRIu64 " messages\n",
      send_state->num_messages);
  GNUNET_assert (NULL != connect_state->channels_head);
  /* For now send on all available channels as we don't know at this stage
   * which is an usable channel - this should be fine as the unusable channel
   * will (probably) be discovered and cleaned up in the process. */
  for (channel_iter = connect_state->channels_head;
       NULL != channel_iter;
       channel_iter = channel_iter->next)
  {
    for (uint64_t i = 0; i < send_state->num_messages; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Going to send message (type %u) %" PRIu64 ", %s (channel %" PRIu64 ") to %s\n",
           MTYPE,
           i,
           connect_state->node_id,
           channel_index,
           GNUNET_i2s (&channel_iter->peer_id));
      env = GNUNET_MQ_msg (msg, MTYPE); // usually we wanted to keep the
                                        // envelopes to potentially cancel the
                                        // message
      msg->id = GNUNET_htonll (i);
      msg->batch = GNUNET_htonll (channel_index);
      GNUNET_memcpy (msg->node_id, connect_state->node_id, NODE_ID_LEN);
      GNUNET_MQ_send (channel_iter->mq, env);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Sent message %" PRIu64 " (channel %" PRIu64 ")\n",
           i,
           channel_index);
    }
    channel_index++;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sent messages\n");

  cleanup_callbacks (send_state);
  GNUNET_free (send_state);
}


static void *
connect_cb (
  void *cls,
  const struct GNUNET_PeerIdentity *peer_id,
  struct GNUNET_MQ_Handle *mq)
{
  struct SendState *send_state = cls;

  send_messages (send_state);
  // FIXME this returns something but the calling function discards the
  // returned value anyways
  return NULL;
}


static void
exec_send_run (void *cls,
               struct GNUNET_TESTING_Interpreter *is)
{
  struct SendState *send_state = cls;
  const struct GNUNET_TESTING_CORE_ConnectState *connect_state;

  // TODO make the "connect" label an input to the command
  if (GNUNET_OK != GNUNET_CORE_TESTING_get_trait_connect (
        GNUNET_TESTING_interpreter_lookup_command (is, "connect"),
        &connect_state)) {
    GNUNET_assert (0);
  };
  send_state->connect_state = connect_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Going to (register to) send messages\n");

  if ((NULL != connect_state->channels_head) &&
      (GNUNET_NO == send_state->await_new_connection))
  {
    /* We are connected to a peer - send messages */
    send_messages (send_state);
  }
  else
  {
    /* We are not connected yet - subscribe via callback */
    // FIXME is the following ok?
    struct GNUNET_TESTING_CORE_ConnectCb *connect_cb_struct =
      GNUNET_new (struct GNUNET_TESTING_CORE_ConnectCb);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Registering our connect callback with the connect callbacks\n");
    connect_cb_struct->callback = connect_cb;
    connect_cb_struct->cls = send_state;
    GNUNET_array_append (connect_state->connect_cbs,
                         connect_state->connect_cbs_len,
                         *connect_cb_struct);
  }
}


static void
exec_send_cleanup (void *cls)
{
  struct GNUNET_TESTING_CORE_ConnectState *connect_state = cls;

}


// TODO add a AWAIT_NEW_CONNECTION flag
const struct GNUNET_TESTING_Command
GNUNET_TESTING_CORE_cmd_send (
  const char *label,
  uint64_t num_messages,
  enum GNUNET_GenericReturnValue await_new_connection)
{
  struct SendState *send_state;

  // TODO make struct static global?
  send_state = GNUNET_new (struct SendState);
  send_state->num_messages = num_messages;
  send_state->await_new_connection = await_new_connection;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "(Setting up _cmd_send)\n");
  return GNUNET_TESTING_command_new (
      send_state, // state
      label,
      &exec_send_run,
      &exec_send_cleanup,
      NULL);
}


/* end of src/service/core/testing_core_recv.c */
