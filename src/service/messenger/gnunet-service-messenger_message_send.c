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
 * @file src/messenger/gnunet-service-messenger_message_send.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_send.h"

#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_member.h"
#include "gnunet-service-messenger_member_session.h"
#include "gnunet-service-messenger_message_kind.h"
#include "gnunet-service-messenger_operation.h"
#include "gnunet-service-messenger_room.h"
#include "gnunet_common.h"

struct GNUNET_MESSENGER_MemberNotify
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_MemberSession *session;
};

static void
notify_about_members (struct GNUNET_MESSENGER_MemberNotify *notify,
                      struct GNUNET_MESSENGER_MemberSession *session,
                      struct GNUNET_CONTAINER_MultiHashMap *map,
                      enum GNUNET_GenericReturnValue check_permission)
{
  if (session->prev)
    notify_about_members (notify, session->prev, map, GNUNET_YES);

  struct GNUNET_MESSENGER_MessageStore *message_store =
    get_srv_room_message_store (notify->room);
  struct GNUNET_MESSENGER_ListMessage *element;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notify through all of member session: %s\n",
              GNUNET_sh2s (get_member_session_id (session)));

  for (element = session->messages.head; element; element = element->next)
  {
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map,
                                                              &(element->hash)))
      continue;

    if ((GNUNET_YES == check_permission) &&
        (GNUNET_YES != check_member_session_history (notify->session,
                                                     &(element->hash),
                                                     GNUNET_NO)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Permission for notification of session message denied!\n");
      continue;
    }

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (map, &(element->hash),
                                                        NULL,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Notification of session message could be duplicated!\n");

    const struct GNUNET_MESSENGER_Message *message = get_store_message (
      message_store, &(element->hash));

    if ((! message) || (GNUNET_YES == is_peer_message (message)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Session message for notification is invalid!\n");
      continue;
    }

    struct GNUNET_MESSENGER_SenderSession sender;
    sender.member = session;

    notify_srv_handle_message (notify->handle, notify->room, &sender, message,
                               &(element->hash), GNUNET_NO);
  }
}


static enum GNUNET_GenericReturnValue
iterate_notify_about_members (void *cls,
                              const struct
                              GNUNET_CRYPTO_PublicKey *public_key,
                              struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberNotify *notify = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Notify about member session: %s\n",
              GNUNET_sh2s (get_member_session_id (session)));

  if ((notify->session == session) || (GNUNET_YES ==
                                       is_member_session_completed (session)))
    return GNUNET_YES;

  struct GNUNET_CONTAINER_MultiHashMap *map =
    GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);

  notify_about_members (notify, session, map, GNUNET_NO);

  GNUNET_CONTAINER_multihashmap_destroy (map);
  return GNUNET_YES;
}


void
send_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  set_srv_handle_key (handle, &(message->body.join.key));

  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_Member *member = add_store_member (member_store,
                                                             &(message->header.
                                                               sender_id));

  struct GNUNET_MESSENGER_MemberSession *session = get_member_session_of (
    member, message, hash);

  if (! session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "A valid session is required to join a room!\n");
    goto skip_member_notification;
  }

  struct GNUNET_MESSENGER_MemberNotify notify;

  notify.room = room;
  notify.handle = handle;
  notify.session = session;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notify about all member sessions except: %s\n",
              GNUNET_sh2s (get_member_session_id (session)));

  iterate_store_members (get_srv_room_member_store (room),
                         iterate_notify_about_members, &notify);

skip_member_notification:
  check_srv_room_peer_status (room, NULL);
}


void
send_message_key (struct GNUNET_MESSENGER_SrvRoom *room,
                  struct GNUNET_MESSENGER_SrvHandle *handle,
                  const struct GNUNET_MESSENGER_Message *message,
                  const struct GNUNET_HashCode *hash)
{
  set_srv_handle_key (handle, &(message->body.key.key));
}


void
send_message_peer (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  if (! room->peer_message)
    room->peer_message = GNUNET_new (struct GNUNET_HashCode);

  GNUNET_memcpy (room->peer_message, hash, sizeof(struct GNUNET_HashCode));

  send_srv_room_message (room, room->host, create_message_connection (room));
}


void
send_message_id (struct GNUNET_MESSENGER_SrvRoom *room,
                 struct GNUNET_MESSENGER_SrvHandle *handle,
                 const struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_HashCode *hash)
{
  change_srv_handle_member_id (handle, get_srv_room_key (room),
                               &(message->body.id.id));
}


void
send_message_request (struct GNUNET_MESSENGER_SrvRoom *room,
                      struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_OperationStore *operation_store =
    get_srv_room_operation_store (room);

  use_store_operation (
    operation_store,
    &(message->body.request.hash),
    GNUNET_MESSENGER_OP_REQUEST,
    GNUNET_MESSENGER_REQUEST_DELAY
    );
}
