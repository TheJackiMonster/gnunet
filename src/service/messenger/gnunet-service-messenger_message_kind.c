/*
   This file is part of GNUnet.
   Copyright (C) 2020--2024 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_message_kind.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_kind.h"

#include "gnunet-service-messenger_room.h"

#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Message*
create_message_info (struct GNUNET_MESSENGER_Service *service)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! service)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_INFO);

  if (! message)
    return NULL;

  message->body.info.messenger_version = GNUNET_MESSENGER_VERSION;

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_peer (struct GNUNET_MESSENGER_Service *service)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! service)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_PEER);

  if (! message)
    return NULL;

  if (GNUNET_OK == get_service_peer_identity (service,
                                              &(message->body.peer.peer)))
    return message;
  else
  {
    destroy_message (message);
    return NULL;
  }
}


struct GNUNET_MESSENGER_Message*
create_message_miss (const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! peer)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_MISS);

  if (! message)
  {
    return NULL;
  }

  GNUNET_memcpy (&(message->body.miss.peer), peer, sizeof(struct
                                                          GNUNET_PeerIdentity));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_merge (const struct GNUNET_HashCode *previous)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! previous)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_MERGE);

  if (! message)
    return NULL;

  memset (message->body.merge.epochs, 0,
          sizeof (struct GNUNET_HashCode) * 2);

  GNUNET_memcpy (&(message->body.merge.previous), previous,
                 sizeof (struct GNUNET_HashCode));

  return message;
}


struct GNUNET_MESSENGER_Message*
create_message_connection (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! room)
    return NULL;

  message = create_message (GNUNET_MESSENGER_KIND_CONNECTION);

  if (! message)
    return NULL;

  message->body.connection.amount = get_srv_room_amount_of_tunnels (room);
  message->body.connection.flags = get_srv_room_connection_flags (room);

  return message;
}
