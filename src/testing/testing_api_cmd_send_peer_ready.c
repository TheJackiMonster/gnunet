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
 * @file testing_api_cmd_send_peer_ready.c
 * @brief cmd to send a helper message if peer is ready.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "testing_cmds.h"


/**
 * Struct to hold information for callbacks.
 *
 */
struct SendPeerReadyState
{
  /**
   * Callback to write messages to the master loop.
   *
   */
  TESTING_CMD_HELPER_write_cb write_message;

  /**
   * The message send back to the master loop.
   *
   */
  struct GNUNET_CMDS_PEER_STARTED *reply;
};


/**
 * Trait function of this cmd does nothing.
 *
 */
static enum GNUNET_GenericReturnValue
send_peer_ready_traits (void *cls,
                        const void **ret,
                        const char *trait,
                        unsigned int index)
{
  return GNUNET_NO;
}


/**
 * The cleanup function of this cmd frees resources the cmd allocated.
 *
 */
static void
send_peer_ready_cleanup (void *cls)
{
  struct SendPeerReadyState *sprs = cls;

  GNUNET_free (sprs);
}


/**
 * This function sends a GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED message to the master loop.
 *
 */
static void
send_peer_ready_run (void *cls,
                     struct GNUNET_TESTING_Interpreter *is)
{
  struct SendPeerReadyState *sprs = cls;
  struct GNUNET_CMDS_PEER_STARTED *reply;
  size_t msg_length;

  msg_length = sizeof(struct GNUNET_CMDS_PEER_STARTED);
  reply = GNUNET_new (struct GNUNET_CMDS_PEER_STARTED);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED);
  reply->header.size = htons ((uint16_t) msg_length);
  sprs->reply = reply;
  sprs->write_message ((struct GNUNET_MessageHeader *) reply, msg_length);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param write_message Callback to write messages to the master loop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_peer_ready (const char *label,
                                    TESTING_CMD_HELPER_write_cb write_message)
{
  struct SendPeerReadyState *sprs;

  sprs = GNUNET_new (struct SendPeerReadyState);
  sprs->write_message = write_message;
  {
    struct GNUNET_TESTING_Command cmd = {
      .cls = sprs,
      .label = label,
      .run = &send_peer_ready_run,
      .cleanup = &send_peer_ready_cleanup,
      .traits = &send_peer_ready_traits
    };

    return cmd;
  }
}
