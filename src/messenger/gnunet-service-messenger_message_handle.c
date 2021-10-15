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
 * @file src/messenger/gnunet-service-messenger_message_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_handle.h"

static void
handle_session_switch (struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberSession *next = switch_member_session(session, message, hash);

  if (next != session)
    add_member_session(next->member, next);
}

void
handle_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Member (%s) joins room (%s).\n",
             GNUNET_sh2s (&(message->header.sender_id)), GNUNET_h2s(get_room_key(room)));

  if (GNUNET_OK != reset_member_session(session, hash))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Resetting member session failed!\n");

  solve_room_member_collisions (
      room,
      &(message->body.join.key),
      &(message->header.sender_id),
      GNUNET_TIME_absolute_ntoh(message->header.timestamp)
  );
}

void
handle_message_leave (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_MemberSession *session,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Member (%s) leaves room (%s).\n",
             GNUNET_sh2s (&(message->header.sender_id)), GNUNET_h2s(get_room_key(room)));

  close_member_session(session);
}

void
handle_message_name (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact = get_member_session_contact(session);

  if (!contact)
    return;

  set_contact_name (contact, message->body.name.name);
}

void
handle_message_key (struct GNUNET_MESSENGER_SrvRoom *room,
                    struct GNUNET_MESSENGER_MemberSession *session,
                    const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  handle_session_switch (session, message, hash);
}

void
handle_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if (GNUNET_NO == contains_list_tunnels (&(room->basement), &(message->body.peer.peer)))
    add_to_list_tunnels (&(room->basement), &(message->body.peer.peer));

  if (room->peer_message)
    rebuild_room_basement_structure (room);
}

void
handle_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_MemberSession *session,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  handle_session_switch (session, message, hash);

  solve_room_member_collisions (
      room,
      get_member_session_public_key(session),
      &(message->body.id.id),
      GNUNET_TIME_absolute_ntoh(message->header.timestamp)
  );
}

void
handle_message_miss (struct GNUNET_MESSENGER_SrvRoom *room,
                     struct GNUNET_MESSENGER_MemberSession *session,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListTunnel *element = find_list_tunnels (&(room->basement), &(message->body.peer.peer), NULL);

  if (!element)
    return;

  remove_from_list_tunnels (&(room->basement), element);

  if (room->peer_message)
    rebuild_room_basement_structure (room);
}

void
handle_message_delete (struct GNUNET_MESSENGER_SrvRoom *room,
                       struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_TIME_Relative delay = GNUNET_TIME_relative_ntoh (message->body.deletion.delay);
  struct GNUNET_TIME_Absolute action = GNUNET_TIME_absolute_ntoh (message->header.timestamp);

  action = GNUNET_TIME_absolute_add (action, delay);
  delay = GNUNET_TIME_absolute_get_difference (GNUNET_TIME_absolute_get (), action);

  delete_room_message (room, session, &(message->body.deletion.hash), delay);
}
