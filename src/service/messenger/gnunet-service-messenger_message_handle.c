/*
   This file is part of GNUnet.
   Copyright (C) 2020--2025 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_message_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_handle.h"

#include "gnunet-service-messenger_room.h"

static void
handle_member_session_switch (struct GNUNET_MESSENGER_MemberSession *session,
                              const struct GNUNET_MESSENGER_Message *message,
                              const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberSession *next;

  GNUNET_assert ((session) && (message) && (hash));

  next = switch_member_session (session, message, hash);

  if (next != session)
    add_member_session (next->member, next);
}


void
handle_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_SenderSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Member (%s) joins room (%s).\n",
              GNUNET_sh2s (&(message->header.sender_id)), GNUNET_h2s (
                get_srv_room_key (room)));

  if (GNUNET_OK != reset_member_session (session->member, hash))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Resetting member session failed!\n");

  solve_srv_room_member_collisions (
    room,
    &(message->body.join.key),
    &(message->header.sender_id),
    GNUNET_TIME_absolute_ntoh (message->header.timestamp));
}


void
handle_message_leave (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SenderSession *session,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Member (%s) leaves room (%s).\n",
              GNUNET_sh2s (&(message->header.sender_id)), GNUNET_h2s (
                get_srv_room_key (room)));

  close_member_session (session->member);
}


void
handle_message_key (struct GNUNET_MESSENGER_SrvRoom *room,
                    struct GNUNET_MESSENGER_SenderSession *session,
                    const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  handle_member_session_switch (session->member, message, hash);
}


void
handle_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_SenderSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_PeerStore *store;

  store = get_srv_room_peer_store (room);

  if (0 == GNUNET_memcmp (session->peer, &(message->body.peer.peer)))
    update_store_peer (store, &(message->body.peer.peer), GNUNET_YES);

  if (GNUNET_NO == contains_list_tunnels (&(room->basement),
                                          &(message->body.peer.peer)))
    add_to_list_tunnels (&(room->basement), &(message->body.peer.peer), hash);

  if (room->peer_message)
    rebuild_srv_room_basement_structure (room);
}


void
handle_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SenderSession *session,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  handle_member_session_switch (session->member, message, hash);

  solve_srv_room_member_collisions (
    room,
    get_member_session_public_key (session->member),
    &(message->body.id.id),
    GNUNET_TIME_absolute_ntoh (message->header.timestamp));
}


void
handle_message_miss (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_SenderSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_PeerStore *store;
  struct GNUNET_MESSENGER_ListTunnel *element;

  store = get_srv_room_peer_store (room);

  if (0 == GNUNET_memcmp (session->peer, &(message->body.miss.peer)))
    update_store_peer (store, &(message->body.miss.peer), GNUNET_NO);

  element = find_list_tunnels (&(room->basement),
                               &(message->body.miss.peer), NULL);

  if (! element)
    return;

  remove_from_list_tunnels (&(room->basement), element);

  if (room->peer_message)
    rebuild_srv_room_basement_structure (room);
}


void
handle_message_delete (struct GNUNET_MESSENGER_SrvRoom *room,
                       struct GNUNET_MESSENGER_SenderSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_TIME_Relative delay;

  delay = get_message_timeout (message);

  delete_srv_room_message (room, session->member,
                           &(message->body.deletion.hash), delay);
}


void
handle_message_connection (struct GNUNET_MESSENGER_SrvRoom *room,
                           struct GNUNET_MESSENGER_SenderSession *session,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListTunnel *element;

  element = find_list_tunnels (&(room->basement), session->peer, NULL);

  if (! element)
    return;

  memcpy (&(element->connection), &(message->body.connection),
          sizeof (struct GNUNET_MESSENGER_MessageConnection));
}


void
handle_message_subscribe (struct GNUNET_MESSENGER_SrvRoom *room,
                          struct GNUNET_MESSENGER_SenderSession *session,
                          const struct GNUNET_MESSENGER_Message *message,
                          const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Member *member;
  const struct GNUNET_ShortHashCode *discourse;
  struct GNUNET_MESSENGER_Subscription *subscription;

  member = session->member->member;

  discourse = &(message->body.subscribtion.discourse);
  subscription = get_member_subscription (member, discourse);

  {
    struct GNUNET_TIME_Absolute timestamp;
    struct GNUNET_TIME_Relative duration;

    timestamp = GNUNET_TIME_absolute_ntoh (message->header.timestamp);
    duration = GNUNET_TIME_relative_ntoh (message->body.subscribtion.time);

    if (subscription)
      update_subscription (subscription,
                           timestamp,
                           duration);
    else
    {
      subscription =
        create_subscription (room, member, discourse,
                             timestamp,
                             duration);

      if (! subscription)
        return;

      add_member_subscription (member, subscription);
    }
  }

  update_subscription_timing (subscription);
  cleanup_srv_room_discourse_messages (room, discourse);
}
