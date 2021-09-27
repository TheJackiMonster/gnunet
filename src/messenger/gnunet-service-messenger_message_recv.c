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
 * @file src/messenger/gnunet-service-messenger_message_recv.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_recv.h"

#include "gnunet-service-messenger_operation.h"

static void
forward_about_members (struct GNUNET_MESSENGER_SrvRoom *room,
                       struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                       struct GNUNET_MESSENGER_MemberSession *session,
                       struct GNUNET_CONTAINER_MultiHashMap *map)
{
  if (session->prev)
    forward_about_members (room, tunnel, session->prev, map);

  struct GNUNET_MESSENGER_MessageStore *message_store = get_room_message_store(room);
  struct GNUNET_MESSENGER_ListMessage *element;

  for (element = session->messages.head; element; element = element->next)
  {
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(map, &(element->hash)))
      continue;

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put(map, &(element->hash), NULL,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Forwarding of session message could be duplicated!\n");

    const struct GNUNET_MESSENGER_Message *message = get_store_message(message_store, &(element->hash));

    if (message)
      forward_tunnel_message(tunnel, message, &(element->hash));
  }
}

static int
iterate_forward_members (void *cls,
                         const struct GNUNET_IDENTITY_PublicKey *public_key,
                         struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (GNUNET_YES == is_member_session_completed(session))
    return GNUNET_YES;

  struct GNUNET_CONTAINER_MultiHashMap *map = GNUNET_CONTAINER_multihashmap_create(4, GNUNET_NO);

  forward_about_members (tunnel->room, tunnel, session, map);

  GNUNET_CONTAINER_multihashmap_destroy(map);
  return GNUNET_YES;
}

int
recv_message_info (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  const uint32_t version = get_tunnel_messenger_version(tunnel);

  if (GNUNET_OK != update_tunnel_messenger_version(tunnel, message->body.info.messenger_version))
  {
    disconnect_tunnel(tunnel);
    return GNUNET_NO;
  }

  if (version == get_tunnel_messenger_version(tunnel))
    return GNUNET_NO;

  if (room->host)
  {
    const struct GNUNET_MESSENGER_Ego *ego = get_handle_ego(room->host);

    send_tunnel_message (tunnel, room->host, create_message_info(ego));
  }

  struct GNUNET_PeerIdentity peer;
  get_tunnel_peer_identity(tunnel, &peer);

  if (GNUNET_YES != contains_list_tunnels(&(room->basement), &peer))
  {
    struct GNUNET_MESSENGER_MemberStore *member_store = get_room_member_store(room);

    iterate_store_members(member_store, iterate_forward_members, tunnel);
  }

  check_room_peer_status(room, tunnel);

  return GNUNET_NO;
}

int
recv_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  struct GNUNET_PeerIdentity peer;
  GNUNET_PEER_resolve (tunnel->peer, &peer);

  if (0 == GNUNET_memcmp(&peer, &(message->body.peer.peer)))
  {
    if (!tunnel->peer_message)
      tunnel->peer_message = GNUNET_new(struct GNUNET_HashCode);

    GNUNET_memcpy(tunnel->peer_message, &hash, sizeof(hash));
  }

  return GNUNET_YES;
}

static void
callback_found_message (void *cls,
                        struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = tunnel;

  if (!message)
  {
    struct GNUNET_MESSENGER_OperationStore *operation_store = get_room_operation_store(room);

    use_store_operation(
        operation_store,
        hash,
        GNUNET_MESSENGER_OP_REQUEST,
        GNUNET_MESSENGER_REQUEST_DELAY
    );
  }
  else
    forward_tunnel_message (tunnel, message, hash);
}

/*
 * Function returns GNUNET_NO to drop forwarding the request.
 * It will only be forwarded if it can't be answered!
 */
int
recv_message_request (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberStore *member_store = get_room_member_store(room);
  struct GNUNET_MESSENGER_Member *member = get_store_member_of(member_store, message);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Request for message (%s)\n", GNUNET_h2s (hash));

  if (!member)
    return GNUNET_NO;

  struct GNUNET_MESSENGER_MemberSession *session = get_member_session_of(member, message, hash);

  if ((!session) || (GNUNET_YES != check_member_session_history(session, hash, GNUNET_NO)))
    return GNUNET_NO;

  if (GNUNET_NO == request_room_message(room, &(message->body.request.hash), session, callback_found_message, tunnel))
    return GNUNET_YES;

  return GNUNET_NO;
}
