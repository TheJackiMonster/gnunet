/*
   This file is part of GNUnet.
   Copyright (C) 2020--2021 GNUnet e.V.

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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_message_send.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_send.h"

#include "gnunet-service-messenger_member.h"
#include "gnunet-service-messenger_member_session.h"
#include "gnunet-service-messenger_operation.h"

void
send_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  check_room_peer_status(room, NULL);
}

void
send_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  if (!room->peer_message)
    room->peer_message = GNUNET_new(struct GNUNET_HashCode);

  GNUNET_memcpy(room->peer_message, hash, sizeof(struct GNUNET_HashCode));
}

void
send_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                 struct GNUNET_MESSENGER_SrvHandle *handle,
                 const struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_HashCode *hash)
{
  change_handle_member_id (handle, get_room_key(room), &(message->body.id.id));
}

void
send_message_request (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_OperationStore *operation_store = get_room_operation_store(room);

  use_store_operation(
      operation_store,
      &(message->body.request.hash),
      GNUNET_MESSENGER_OP_REQUEST,
      GNUNET_MESSENGER_REQUEST_DELAY
  );
}
