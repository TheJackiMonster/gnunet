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
  struct GNUNET_CONTAINER_MultiHashMap *map;
  uint32_t epoch_counter;
};

static void
notify_about_members (struct GNUNET_MESSENGER_MemberNotify *notify,
                      struct GNUNET_MESSENGER_MemberSession *session,
                      enum GNUNET_GenericReturnValue check_permission)
{
  struct GNUNET_MESSENGER_MessageStore *message_store;
  struct GNUNET_MESSENGER_ListMessage *element;

  GNUNET_assert ((notify) && (session));

  if (session->prev)
    notify_about_members (notify, session->prev, GNUNET_YES);

  message_store = get_srv_room_message_store (notify->room);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notify through all of member session: %s\n",
              GNUNET_sh2s (get_member_session_id (session)));

  for (element = session->messages.head; element; element = element->next)
  {
    const struct GNUNET_MESSENGER_Message *message;

    if ((notify->map) &&
        (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (notify->map,
                                                               &(element->hash))
        ))
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

    if ((notify->map) &&
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (notify->map, &(element
                                                                        ->hash),
                                                         NULL,
                                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))



      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Notification of session message could be duplicated!\n");

    message = get_store_message (message_store, &(element->hash));

    if ((! message) || (GNUNET_YES == is_peer_message (message)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Session message for notification is invalid!\n");
      continue;
    }

    {
      struct GNUNET_MESSENGER_SenderSession sender;
      const struct GNUNET_HashCode *epoch;

      sender.member = session;
      epoch = get_store_message_epoch (message_store, &(element->hash));

      notify_srv_handle_message (notify->handle, notify->room, &sender, message,
                                 &(element->hash), epoch, GNUNET_NO);
    }
  }
}


static enum GNUNET_GenericReturnValue
iterate_notify_about_members (void *cls,
                              const struct
                              GNUNET_CRYPTO_PublicKey *public_key,
                              struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberNotify *notify;

  GNUNET_assert ((cls) && (session));

  notify = cls;

  if ((notify->session == session) ||
      (GNUNET_YES == is_member_session_completed (session)))
    return GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Notify about member session: %s\n",
              GNUNET_sh2s (get_member_session_id (session)));

  notify_about_members (notify, session, GNUNET_NO);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_epoch_session_members (void *cls,
                               const struct
                               GNUNET_CRYPTO_PublicKey *public_key,
                               struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberNotify *notify;
  struct GNUNET_MESSENGER_MessageStore *message_store;
  struct GNUNET_MESSENGER_ListMessage *element;

  GNUNET_assert ((cls) && (session));

  notify = cls;

  if ((notify->session == session) ||
      (GNUNET_YES == is_member_session_completed (session)))
    return GNUNET_YES;

  message_store = get_srv_room_message_store (notify->room);

  for (element = session->messages.head; element; element = element->next)
  {
    const struct GNUNET_MESSENGER_Message *message;

    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (notify->map,
                                                              &(element->hash)))
      continue;

    message = get_store_message (message_store, &(element->hash));

    if ((! message) ||
        ((GNUNET_MESSENGER_KIND_JOIN != message->header.kind) &&
         (GNUNET_MESSENGER_KIND_LEAVE != message->header.kind)))
      continue;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Mark member session being labeled as important: %s\n",
                GNUNET_sh2s (get_member_session_id (session)));

    GNUNET_CONTAINER_multihashmap_put (notify->map, &(element->hash), session,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
traverse_epoch_message (struct GNUNET_MESSENGER_MemberNotify *notify,
                        const struct GNUNET_HashCode *hash);


static enum GNUNET_GenericReturnValue
traverse_epoch_session_message (struct GNUNET_MESSENGER_MemberNotify *notify,
                                const struct GNUNET_HashCode *hash,
                                const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_MESSENGER_MemberSession *session;
  enum GNUNET_GenericReturnValue notification;
  struct GNUNET_PeerIdentity *peer_identity;

  GNUNET_assert ((notify) && (message) && (hash));

  session = GNUNET_CONTAINER_multihashmap_get (notify->map, hash);

  if (session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unmark member session from labeled as important: %s\n",
                GNUNET_sh2s (get_member_session_id (session)));

    GNUNET_CONTAINER_multihashmap_put (notify->map, hash, NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
    notify->epoch_counter++;

    notification = GNUNET_YES;
  }
  else if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (notify->map,
                                                                 hash))
    return GNUNET_YES;
  else
    notification = GNUNET_NO;

  peer_identity = NULL;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    if (GNUNET_YES == traverse_epoch_message (notify, &(message->body.join.epoch
                                                        )))
      notification = GNUNET_YES;
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    if (GNUNET_YES == traverse_epoch_message (notify, &(message->body.leave.
                                                        epoch)))
      notification = GNUNET_YES;
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    {
      struct GNUNET_MESSENGER_PeerStore *peer_store;

      peer_store = get_srv_room_peer_store (notify->room);

      if (peer_store)
        peer_identity = get_store_peer_of (peer_store, message, hash);

      if (GNUNET_YES == traverse_epoch_message (notify, &(message->body.merge.
                                                          epochs[0])))
        notification = GNUNET_YES;
      if (GNUNET_YES == traverse_epoch_message (notify, &(message->body.merge.
                                                          epochs[1])))
        notification = GNUNET_YES;
      break;
    }
  default:
    break;
  }

  if (GNUNET_YES != notification)
    return notification;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Notify about past epoch: %s\n",
              GNUNET_h2s (hash));

  if (! session)
  {
    struct GNUNET_MESSENGER_MemberStore *member_store;
    struct GNUNET_MESSENGER_Member *member;

    if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
      goto skip_session;

    member_store = get_srv_room_member_store (notify->room);

    if (member_store)
      member = get_store_member_of (member_store, message);

    if (member)
      session = get_member_session_of (member, message, hash);

skip_session:
    GNUNET_CONTAINER_multihashmap_put (notify->map, hash, NULL,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  {
    struct GNUNET_MESSENGER_SenderSession sender;

    if (session)
      sender.member = session;
    else if (peer_identity)
      sender.peer = peer_identity;
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "No valid sender session for message: %s\n",
                  GNUNET_h2s (hash));
      return notification;
    }

    notify_srv_handle_message (notify->handle, notify->room, &sender, message,
                               hash, hash, GNUNET_NO);
  }

  return notification;
}


static enum GNUNET_GenericReturnValue
traverse_epoch_message (struct GNUNET_MESSENGER_MemberNotify *notify,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MessageStore *message_store;
  const struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((notify) && (hash));

  if (GNUNET_is_zero (hash))
    return GNUNET_NO;

  if (notify->epoch_counter >= GNUNET_CONTAINER_multihashmap_size (notify->map))
    return GNUNET_NO;

  message_store = get_srv_room_message_store (notify->room);

  if (! message_store)
    return GNUNET_NO;

  message = get_store_message (message_store, hash);

  if (! message)
    return GNUNET_NO;

  return traverse_epoch_session_message (notify, hash, message);
}


void
send_message_join (struct GNUNET_MESSENGER_SrvRoom *room,
                   struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberStore *member_store;
  struct GNUNET_MESSENGER_Member *member;
  struct GNUNET_MESSENGER_MemberSession *session;

  set_srv_handle_key (handle, &(message->body.join.key));

  member_store = get_srv_room_member_store (room);
  member = add_store_member (member_store,
                             &(message->header.sender_id));

  if (! member)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "A member could not join with ID: %s\n",
                GNUNET_sh2s (&(message->header.sender_id)));
    goto skip_member_notification;
  }

  session = get_member_session_of (member, message, hash);

  if (! session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "A valid session is required to join a room!\n");
    goto skip_member_notification;
  }

  {
    struct GNUNET_MESSENGER_MemberNotify notify;

    notify.room = room;
    notify.handle = handle;
    notify.session = session;
    notify.map = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
    notify.epoch_counter = 0;

    if (notify.map)
    {
      uint32_t epoch_count;

      iterate_store_members (member_store, iterate_epoch_session_members, &
                             notify);

      epoch_count = GNUNET_CONTAINER_multihashmap_size (notify.map);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Notify about all (%u) related epochs for current membership verification!\n",
                  epoch_count);

      traverse_epoch_message (&notify, &(message->body.join.epoch));

      if (epoch_count > notify.epoch_counter)
      {
        uint32_t missing;

        missing = epoch_count - notify.epoch_counter;

        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Missing at least %u epoch%s for current membership verification!\n",
                    missing, missing > 1? "s" : "");
      }
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Notify about all member sessions except: %s\n",
                GNUNET_sh2s (get_member_session_id (session)));

    iterate_store_members (member_store, iterate_notify_about_members, &notify);

    if (notify.map)
      GNUNET_CONTAINER_multihashmap_destroy (notify.map);
  }

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
  struct GNUNET_MESSENGER_Message *msg;

  if (! room->peer_message)
    room->peer_message = GNUNET_new (struct GNUNET_HashCode);

  GNUNET_memcpy (room->peer_message, hash, sizeof(struct GNUNET_HashCode));

  msg = create_message_connection (room);

  if (! msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Sending connection message failed: %s\n",
                GNUNET_h2s (&(room->key)));
  else
    send_srv_room_message (room, room->host, msg);
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
  struct GNUNET_MESSENGER_OperationStore *operation_store;

  operation_store = get_srv_room_operation_store (room);

  use_store_operation (
    operation_store,
    &(message->body.request.hash),
    GNUNET_MESSENGER_OP_REQUEST,
    GNUNET_MESSENGER_REQUEST_DELAY);
}
