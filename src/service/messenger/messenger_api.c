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
 * @file src/messenger/messenger_api.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"

#include "gnunet-service-messenger.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "messenger_api.h"
#include "messenger_api_contact.h"
#include "messenger_api_contact_store.h"
#include "messenger_api_epoch.h"
#include "messenger_api_epoch_announcement.h"
#include "messenger_api_handle.h"
#include "messenger_api_message.h"
#include "messenger_api_message_control.h"
#include "messenger_api_message_kind.h"
#include "messenger_api_room.h"
#include "messenger_api_util.h"

const char*
GNUNET_MESSENGER_name_of_kind (enum GNUNET_MESSENGER_MessageKind kind)
{
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    return "INFO";
  case GNUNET_MESSENGER_KIND_JOIN:
    return "JOIN";
  case GNUNET_MESSENGER_KIND_LEAVE:
    return "LEAVE";
  case GNUNET_MESSENGER_KIND_NAME:
    return "NAME";
  case GNUNET_MESSENGER_KIND_KEY:
    return "KEY";
  case GNUNET_MESSENGER_KIND_PEER:
    return "PEER";
  case GNUNET_MESSENGER_KIND_ID:
    return "ID";
  case GNUNET_MESSENGER_KIND_MISS:
    return "MISS";
  case GNUNET_MESSENGER_KIND_MERGE:
    return "MERGE";
  case GNUNET_MESSENGER_KIND_REQUEST:
    return "REQUEST";
  case GNUNET_MESSENGER_KIND_INVITE:
    return "INVITE";
  case GNUNET_MESSENGER_KIND_TEXT:
    return "TEXT";
  case GNUNET_MESSENGER_KIND_FILE:
    return "FILE";
  case GNUNET_MESSENGER_KIND_PRIVATE:
    return "PRIVATE";
  case GNUNET_MESSENGER_KIND_DELETION:
    return "DELETION";
  case GNUNET_MESSENGER_KIND_CONNECTION:
    return "CONNECTION";
  case GNUNET_MESSENGER_KIND_TICKET:
    return "TICKET";
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    return "TRANSCRIPT";
  case GNUNET_MESSENGER_KIND_TAG:
    return "TAG";
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    return "SUBSCRIBTION";
  case GNUNET_MESSENGER_KIND_TALK:
    return "TALK";
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    return "ANNOUNCEMENT";
  case GNUNET_MESSENGER_KIND_SECRET:
    return "SECRET";
  case GNUNET_MESSENGER_KIND_APPEAL:
    return "APPEAL";
  case GNUNET_MESSENGER_KIND_ACCESS:
    return "ACCESS";
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    return "REVOLUTION";
  case GNUNET_MESSENGER_KIND_GROUP:
    return "GROUP";
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    return "AUTHORIZATION";
  default:
    return "UNKNOWN";
  }
}


void
GNUNET_MESSENGER_create_room_key (union GNUNET_MESSENGER_RoomKey *key,
                                  const char *input,
                                  enum GNUNET_GenericReturnValue is_public,
                                  enum GNUNET_GenericReturnValue is_group,
                                  enum GNUNET_GenericReturnValue is_feed)
{
  GNUNET_assert (key);

  if (input)
    GNUNET_CRYPTO_hash (
      input, strlen (input), &(key->hash));
  else
    GNUNET_CRYPTO_random_block (
      GNUNET_CRYPTO_QUALITY_STRONG,
      &(key->hash), sizeof (key->hash));

  key->code.public_bit = GNUNET_YES == is_public? 1 : 0;
  key->code.group_bit = GNUNET_YES == is_group? 1 : 0;
  key->code.feed_bit = GNUNET_YES == is_feed? 1 : 0;
  key->code.unused_bits = 0;
}


static void
dequeue_messages_from_room (struct GNUNET_MESSENGER_Room *room);

static void
handle_room_open (void *cls,
                  const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *prev;
  const struct GNUNET_HashCode *epoch;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  prev = &(msg->previous);
  epoch = &(msg->epoch);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Opened room: %s\n", GNUNET_h2s (key));

  open_handle_room (handle, key);

  room = get_handle_room (handle, key);
  if (! room)
    return;

  update_room_last_message (room, prev, epoch);
  dequeue_messages_from_room (room);
}


static void
handle_room_entry (void *cls,
                   const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_PeerIdentity *door;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *prev;
  const struct GNUNET_HashCode *epoch;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  door = &(msg->door);
  key = &(msg->key);
  prev = &(msg->previous);
  epoch = &(msg->epoch);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Entered room: %s\n", GNUNET_h2s (key));

  entry_handle_room_at (handle, door, key);

  room = get_handle_room (handle, key);
  if (! room)
    return;

  update_room_last_message (room, prev, epoch);
  dequeue_messages_from_room (room);
}


static void
handle_room_close (void *cls,
                   const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *prev;
  const struct GNUNET_HashCode *epoch;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  prev = &(msg->previous);
  epoch = &(msg->epoch);

  room = get_handle_room (handle, key);
  if (room)
    update_room_last_message (room, prev, epoch);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Closed room: %s\n", GNUNET_h2s (key));

  close_handle_room (handle, key);
}


static void
handle_room_sync (void *cls,
                  const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *prev;
  const struct GNUNET_HashCode *epoch;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  prev = &(msg->previous);
  epoch = &(msg->epoch);

  room = get_handle_room (handle, key);
  if (! room)
    return;

  update_room_last_message (room, prev, epoch);

  room->wait_for_sync = GNUNET_NO;
  dequeue_messages_from_room (room);
}


static void
handle_member_id (void *cls,
                  const struct GNUNET_MESSENGER_MemberMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_ShortHashCode *id;
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Message *message;
  uint32_t reset;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  id = &(msg->id);
  reset = msg->reset;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Changed member id in room: %s\n",
              GNUNET_h2s (key));

  room = get_handle_room (handle, key);
  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Room is unknown to handle: %s\n",
                GNUNET_h2s (key));
    return;
  }

  if ((! get_room_sender_id (room)) || (GNUNET_YES == reset))
  {
    set_room_sender_id (room, id);
    message = create_message_join (get_handle_key (handle));
  }
  else
    message = create_message_id (id);

  if (! message)
    return;

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
}


static enum GNUNET_GenericReturnValue
check_recv_message (void *cls,
                    const struct GNUNET_MESSENGER_RecvMessage *msg)
{
  struct GNUNET_MESSENGER_Message message;
  uint16_t full_length, length;
  const char *buffer;

  GNUNET_assert (msg);

  full_length = ntohs (msg->header.size);

  if (full_length < sizeof(*msg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Receiving failed: Message invalid!\n");
    return GNUNET_NO;
  }

  length = full_length - sizeof(*msg);
  buffer = ((const char*) msg) + sizeof(*msg);

  if (length < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                      GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Receiving failed: Message too short!\n");
    return GNUNET_NO;
  }

  if (GNUNET_YES != decode_message (&message, length, buffer, GNUNET_YES, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Receiving failed: Message decoding failed!\n");
    return GNUNET_NO;
  }

  cleanup_message (&message);
  return GNUNET_OK;
}


static void
handle_recv_message (void *cls,
                     const struct GNUNET_MESSENGER_RecvMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *sender;
  const struct GNUNET_HashCode *context;
  const struct GNUNET_HashCode *hash;
  const struct GNUNET_HashCode *epoch;
  enum GNUNET_MESSENGER_MessageFlags flags;
  struct GNUNET_MESSENGER_Message message;
  struct GNUNET_MESSENGER_Room *room;
  uint16_t length;
  const char *buffer;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  sender = &(msg->sender);
  context = &(msg->context);
  hash = &(msg->hash);
  epoch = &(msg->epoch);

  flags = (enum GNUNET_MESSENGER_MessageFlags) (msg->flags);

  length = ntohs (msg->header.size) - sizeof(*msg);
  buffer = ((const char*) msg) + sizeof(*msg);

  decode_message (&message, length, buffer, GNUNET_YES, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message: %s during epoch '%s'\n",
              GNUNET_MESSENGER_name_of_kind (message.header.kind),
              GNUNET_h2s (epoch));

  room = get_handle_room (handle, key);
  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Unknown room for this client: %s\n",
                GNUNET_h2s (key));

    goto skip_message;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Raw contact from sender and context: (%s : %s)\n",
              GNUNET_h2s (sender), GNUNET_h2s_full (context));

  process_message_control (room->control,
                           sender,
                           context,
                           hash,
                           epoch,
                           &message,
                           flags);

skip_message:
  cleanup_message (&message);
}


static void
handle_miss_message (void *cls,
                     const struct GNUNET_MESSENGER_GetMessage *msg)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_HashCode *key;
  const struct GNUNET_HashCode *hash;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (msg));

  handle = cls;

  key = &(msg->key);
  hash = &(msg->hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Missing message in room: %s\n",
              GNUNET_h2s (hash));

  room = get_handle_room (handle, key);
  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Miss in unknown room for this client: %s\n", GNUNET_h2s (key));
    return;
  }

  if (! get_room_sender_id (room))
    return;

  {
    struct GNUNET_MESSENGER_Message *message;

    message = create_message_request (hash);
    if (! message)
      return;

    enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
  }
}


static void
reconnect (struct GNUNET_MESSENGER_Handle *handle);

static void
send_open_room (struct GNUNET_MESSENGER_Handle *handle,
                struct GNUNET_MESSENGER_Room *room)
{
  const struct GNUNET_CRYPTO_PublicKey *key;
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  char *msg_buffer;
  ssize_t len;

  GNUNET_assert ((handle) && (handle->mq) && (room));

  key = get_handle_pubkey (handle);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Open room (%s) by member using key: %s\n",
              GNUNET_h2s (get_room_key (room)),
              GNUNET_CRYPTO_public_key_to_string (key));

  len = GNUNET_CRYPTO_public_key_get_length (key);

  env = GNUNET_MQ_msg_extra (msg, len > 0 ? len : 0,
                             GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN);
  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));
  copy_room_last_message (room, &(msg->previous));

  msg_buffer = ((char*) msg) + sizeof(*msg);

  if (len > 0)
    GNUNET_CRYPTO_write_public_key_to_buffer (key, msg_buffer, len);

  GNUNET_MQ_send (handle->mq, env);
}


static void
send_enter_room (struct GNUNET_MESSENGER_Handle *handle,
                 struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_PeerIdentity *door)
{
  const struct GNUNET_CRYPTO_PublicKey *key;
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  char *msg_buffer;
  ssize_t len;

  GNUNET_assert ((handle) && (handle->mq) && (room) && (door));

  key = get_handle_pubkey (handle);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Enter room (%s) via door: %s (%s)\n",
              GNUNET_h2s (get_room_key (room)),
              GNUNET_i2s (door),
              GNUNET_CRYPTO_public_key_to_string (key));

  len = GNUNET_CRYPTO_public_key_get_length (key);

  env = GNUNET_MQ_msg_extra (msg, len > 0 ? len : 0,
                             GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY);
  GNUNET_memcpy (&(msg->door), door, sizeof(*door));
  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));
  copy_room_last_message (room, &(msg->previous));

  msg_buffer = ((char*) msg) + sizeof(*msg);

  if (len > 0)
    GNUNET_CRYPTO_write_public_key_to_buffer (key, msg_buffer, len);

  GNUNET_MQ_send (handle->mq, env);
}


static void
send_close_room (struct GNUNET_MESSENGER_Handle *handle,
                 struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert ((handle) && (handle->mq) && (room));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Close room (%s)!\n",
              GNUNET_h2s (get_room_key (room)));

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE);

  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));
  copy_room_last_message (room, &(msg->previous));

  GNUNET_MQ_send (handle->mq, env);
}


static void
send_sync_room (struct GNUNET_MESSENGER_Handle *handle,
                struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_RoomMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert ((handle) && (handle->mq) && (room));

  if (GNUNET_YES == room->wait_for_sync)
    return;

  room->wait_for_sync = GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sync room (%s)!\n",
              GNUNET_h2s (get_room_key (room)));

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SYNC);

  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));
  copy_room_last_message (room, &(msg->previous));

  GNUNET_MQ_send (handle->mq, env);
}


static enum GNUNET_GenericReturnValue
iterate_reset_room (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_ListTunnel *entry;

  GNUNET_assert ((cls) && (value));

  handle = cls;
  room = value;

  if (GNUNET_YES == room->opened)
    send_open_room (handle, room);

  entry = room->entries.head;
  while (entry)
  {
    struct GNUNET_PeerIdentity door;

    GNUNET_PEER_resolve (entry->peer, &door);
    send_enter_room (handle, room, &door);

    entry = entry->next;
  }

  return GNUNET_YES;
}


static void
callback_reconnect (void *cls)
{
  struct GNUNET_MESSENGER_Handle *handle;

  GNUNET_assert (cls);

  handle = cls;

  handle->reconnect_task = NULL;
  handle->reconnect_time = GNUNET_TIME_STD_BACKOFF (handle->reconnect_time);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Reconnect messenger!\n");

  reconnect (handle);

  GNUNET_CONTAINER_multihashmap_iterate (handle->rooms, iterate_reset_room,
                                         handle);
}


static enum GNUNET_GenericReturnValue
iterate_close_room (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (value));

  handle = cls;
  room = value;

  send_close_room (handle, room);

  return GNUNET_YES;
}


static void
callback_mq_error (void *cls,
                   enum GNUNET_MQ_Error error)
{
  struct GNUNET_MESSENGER_Handle *handle;

  GNUNET_assert (cls);

  handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "MQ_Error: %u\n", error);

  GNUNET_CONTAINER_multihashmap_iterate (handle->rooms, iterate_close_room,
                                         handle);

  if (handle->mq)
  {
    GNUNET_MQ_destroy (handle->mq);
    handle->mq = NULL;
  }

  handle->reconnect_task = GNUNET_SCHEDULER_add_delayed (handle->reconnect_time,
                                                         &callback_reconnect,
                                                         handle);
}


static void
reconnect (struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  {
    const struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_fixed_size (
        member_id,
        GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID,
        struct GNUNET_MESSENGER_MemberMessage, handle
        ),
      GNUNET_MQ_hd_fixed_size (
        room_open,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN,
        struct GNUNET_MESSENGER_RoomMessage, handle
        ),
      GNUNET_MQ_hd_fixed_size (
        room_entry,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY,
        struct GNUNET_MESSENGER_RoomMessage, handle
        ),
      GNUNET_MQ_hd_fixed_size (
        room_close,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE,
        struct GNUNET_MESSENGER_RoomMessage, handle
        ),
      GNUNET_MQ_hd_var_size (
        recv_message,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE,
        struct GNUNET_MESSENGER_RecvMessage, handle
        ),
      GNUNET_MQ_hd_fixed_size (
        miss_message,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE,
        struct GNUNET_MESSENGER_GetMessage, handle
        ),
      GNUNET_MQ_hd_fixed_size (
        room_sync,
        GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SYNC,
        struct GNUNET_MESSENGER_RoomMessage, handle
        ),
      GNUNET_MQ_handler_end ()
    };

    handle->mq = GNUNET_CLIENT_connect (handle->config,
                                        GNUNET_MESSENGER_SERVICE_NAME,
                                        handlers, &callback_mq_error,
                                        handle);
  }
}


struct GNUNET_MESSENGER_Handle*
GNUNET_MESSENGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const char *name,
                          const struct GNUNET_CRYPTO_PrivateKey *key,
                          GNUNET_MESSENGER_MessageCallback msg_callback,
                          void *msg_cls)
{
  struct GNUNET_MESSENGER_Handle *handle;

  GNUNET_assert (cfg);

  handle = create_handle (cfg, msg_callback, msg_cls);

  reconnect (handle);

  if (handle->mq)
  {
    struct GNUNET_MESSENGER_CreateMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    set_handle_name (handle, name);

    if ((! key) || (0 < GNUNET_CRYPTO_private_key_get_length (key)))
      set_handle_key (handle, key);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connect handle!\n");

    env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_CREATE);
    GNUNET_MQ_send (handle->mq, env);
    return handle;
  }
  else
  {
    destroy_handle (handle);
    return NULL;
  }
}


void
GNUNET_MESSENGER_disconnect (struct GNUNET_MESSENGER_Handle *handle)
{
  struct GNUNET_MESSENGER_DestroyMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  if (! handle)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnect handle!\n");

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_DESTROY);
  GNUNET_MQ_send (handle->mq, env);

  destroy_handle (handle);
}


static void
callback_leave_message_sent (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (cls);

  room = cls;

  room->opened = GNUNET_NO;
  clear_list_tunnels (&(room->entries));

  send_close_room (room->handle, room);
}


static void
keep_subscription_alive (void *cls)
{
  struct GNUNET_MESSENGER_RoomSubscription *subscription;
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_ShortHashCode *discourse;

  GNUNET_assert (cls);

  subscription = cls;
  subscription->task = NULL;

  room = subscription->room;
  message = subscription->message;

  subscription->message = NULL;

  discourse = &(message->body.subscription.discourse);

  if (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (room->subscriptions,
                                                           discourse,
                                                           subscription))
  {
    destroy_message (message);
    return;
  }

  GNUNET_free (subscription);

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
}


static void
handle_discourse_subscription (struct GNUNET_MESSENGER_Room *room,
                               struct GNUNET_MESSENGER_Message *message)
{
  const struct GNUNET_ShortHashCode *discourse;
  struct GNUNET_MESSENGER_RoomSubscription *subscription;
  struct GNUNET_TIME_Relative time;
  uint32_t flags;

  GNUNET_assert ((room) && (message));

  flags = message->body.subscription.flags;

  discourse = &(message->body.subscription.discourse);

  subscription = GNUNET_CONTAINER_multishortmap_get (room->subscriptions,
                                                     discourse);

  if (0 == (flags & GNUNET_MESSENGER_FLAG_SUBSCRIPTION_UNSUBSCRIBE))
    goto active_subscription;

  if (! subscription)
    return;

  if (subscription->task)
    GNUNET_SCHEDULER_cancel (subscription->task);

  if (subscription->message)
    destroy_message (subscription->message);

  if (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (room->subscriptions,
                                                           discourse,
                                                           subscription))
  {
    subscription->task = NULL;
    subscription->message = NULL;
    return;
  }

  GNUNET_free (subscription);
  return;

active_subscription:
  if (0 == (flags & GNUNET_MESSENGER_FLAG_SUBSCRIPTION_KEEP_ALIVE))
    return;

  time = GNUNET_TIME_relative_ntoh (message->body.subscription.time);

  if (! subscription)
  {
    subscription = GNUNET_new (struct GNUNET_MESSENGER_RoomSubscription);

    if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (
          room->subscriptions, discourse, subscription,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      GNUNET_free (subscription);
      return;
    }

    subscription->room = room;
  }
  else
  {
    if (subscription->task)
      GNUNET_SCHEDULER_cancel (subscription->task);

    if (subscription->message)
      destroy_message (subscription->message);
  }

  subscription->message = create_message_subscription (discourse, time,
                                                       flags);

  if (! subscription->message)
  {
    subscription->task = NULL;
    return;
  }

  {
    struct GNUNET_TIME_Relative delay;
    delay = GNUNET_TIME_relative_multiply_double (time, 0.9);

    subscription->task = GNUNET_SCHEDULER_add_delayed_with_priority (
      delay, GNUNET_SCHEDULER_PRIORITY_HIGH,
      keep_subscription_alive, subscription);
  }
}


static void
send_message_to_room (struct GNUNET_MESSENGER_Room *room,
                      struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_CRYPTO_PrivateKey *key,
                      const struct GNUNET_HashCode *epoch,
                      struct GNUNET_HashCode *hash)
{
  const struct GNUNET_ShortHashCode *sender_id;
  struct GNUNET_MESSENGER_SendMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  uint16_t msg_length;
  char *msg_buffer;

  GNUNET_assert ((room) && (message) && (key) && (hash));

  sender_id = get_room_sender_id (room);

  if (GNUNET_NO == is_service_message (message))
  {
    struct GNUNET_MESSENGER_Epoch *last_epoch;
    struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
    const struct GNUNET_CRYPTO_SymmetricSessionKey *epoch_key;

    last_epoch = get_room_epoch (room, epoch, GNUNET_YES);

    if (! last_epoch)
      goto send_message;

    announcement = get_epoch_announcement (last_epoch, NULL, GNUNET_YES);

    if ((! announcement) && (GNUNET_YES != is_room_public (room)))
      generate_room_epoch_announcement (room, last_epoch, &announcement);

    if (announcement)
      epoch_key = get_epoch_announcement_key (announcement);
    else
      epoch_key = NULL;

    if (! epoch_key)
      goto send_message;

    if (GNUNET_YES != encrypt_secret_message (message, &(announcement->
                                                         identifier), epoch_key)
        )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Encrypting message (%s) failed!\n",
                  GNUNET_h2s (hash));
      return;
    }
  }

send_message:
  if (GNUNET_YES == is_epoch_message (message))
    message->header.timestamp = GNUNET_TIME_absolute_hton (
      GNUNET_TIME_absolute_get_zero_ ());
  else
    message->header.timestamp = GNUNET_TIME_absolute_hton (
      GNUNET_TIME_absolute_get ());

  GNUNET_memcpy (&(message->header.sender_id), sender_id,
                 sizeof(message->header.sender_id));

  if (0 == GNUNET_CRYPTO_hash_cmp (epoch, &(room->last_epoch)))
    copy_room_last_message (room, &(message->header.previous));
  else
    GNUNET_memcpy (&(message->header.previous), epoch,
                   sizeof(message->header.previous));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      GNUNET_memcpy (&(message->body.join.epoch), epoch,
                     sizeof(message->body.join.epoch));
      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      GNUNET_memcpy (&(message->body.leave.epoch), epoch,
                     sizeof(message->body.leave.epoch));
      break;
    }
  default:
    break;
  }

  message->header.signature.type = key->type;

  msg_length = get_message_size (message, GNUNET_YES);

  env = GNUNET_MQ_msg_extra (
    msg, msg_length,
    GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SEND_MESSAGE);

  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));

  msg_buffer = ((char*) msg) + sizeof(*msg);
  encode_message (message, msg_length, msg_buffer, GNUNET_YES);

  hash_message (message, msg_length, msg_buffer, hash);
  sign_message (message, msg_length, msg_buffer, hash, key);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send message (%s)!\n",
              GNUNET_h2s (hash));

  if (! get_message_discourse (message))
  {
    const struct GNUNET_HashCode *epoch;

    switch (message->header.kind)
    {
    case GNUNET_MESSENGER_KIND_JOIN:
    case GNUNET_MESSENGER_KIND_LEAVE:
      epoch = hash;
      break;
    default:
      epoch = &(room->last_epoch);
      break;
    }

    update_room_last_message (room, hash, epoch);
  }

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_LEAVE:
    GNUNET_MQ_notify_sent (env, callback_leave_message_sent, room);
    break;
  case GNUNET_MESSENGER_KIND_SUBSCRIBTION:
    handle_discourse_subscription (room, message);
    break;
  default:
    break;
  }

  GNUNET_MQ_send (room->handle->mq, env);
}


void
enqueue_message_to_room (struct GNUNET_MESSENGER_Room *room,
                         const struct GNUNET_HashCode *epoch,
                         struct GNUNET_MESSENGER_Message *message,
                         struct GNUNET_MESSENGER_Message *transcript,
                         enum GNUNET_GenericReturnValue sync)
{
  const struct GNUNET_CRYPTO_PrivateKey *key;

  GNUNET_assert ((room) && (message));

  key = get_handle_key (room->handle);

  if (! epoch)
    epoch = &(room->last_epoch);

  enqueue_to_messages (&(room->queue),
                       key,
                       epoch,
                       message,
                       transcript);

  if (GNUNET_YES != is_room_available (room))
    return;

  if ((GNUNET_YES == sync) ||
      (GNUNET_YES == is_message_session_bound (message)))
    send_sync_room (room->handle, room);
  else if (GNUNET_YES != room->wait_for_sync)
    dequeue_messages_from_room (room);
}


static void
dequeue_message_from_room (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_MESSENGER_Message *transcript;
  struct GNUNET_CRYPTO_PrivateKey key;
  struct GNUNET_HashCode epoch;
  struct GNUNET_HashCode hash;
  struct GNUNET_CRYPTO_PublicKey pubkey;

  GNUNET_assert (cls);

  room = cls;

  GNUNET_assert (room->handle);

  room->queue_task = NULL;

  if ((GNUNET_YES != is_room_available (room)) || (! (room->handle->mq)))
    goto next_message;

  message = NULL;
  transcript = NULL;
  memset (&key, 0, sizeof(key));

  message = dequeue_from_messages (&(room->queue),
                                   &key,
                                   &epoch,
                                   &transcript);

  if (! message)
  {
    if (transcript)
      destroy_message (transcript);

    return;
  }

  send_message_to_room (room, message, &key, &epoch, &hash);
  destroy_message (message);

  if (! transcript)
  {
    GNUNET_CRYPTO_private_key_clear (&key);
    goto next_message;
  }

  GNUNET_memcpy (&(transcript->body.transcript.hash), &hash, sizeof(hash));

  memset (&pubkey, 0, sizeof(pubkey));
  GNUNET_CRYPTO_key_get_public (&key, &pubkey);

  if (GNUNET_YES == encrypt_message (transcript, &pubkey))
  {
    struct GNUNET_HashCode other;
    send_message_to_room (room, transcript, &key, &epoch, &other);

    GNUNET_CRYPTO_private_key_clear (&key);

    link_room_message (room, &hash, &other);
    link_room_message (room, &other, &hash);
  }
  else
  {
    GNUNET_CRYPTO_private_key_clear (&key);

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Sending transcript aborted: Encryption failed!\n");
  }

  destroy_message (transcript);

next_message:
  if (! room->queue.head)
    return;

  room->queue_task = GNUNET_SCHEDULER_add_with_priority (
    GNUNET_SCHEDULER_PRIORITY_HIGH, dequeue_message_from_room, room);
}


static void
dequeue_messages_from_room (struct GNUNET_MESSENGER_Room *room)
{
  if ((GNUNET_YES != is_room_available (room)) || (! (room->handle)))
    return;

  if (room->handle->mq)
    dequeue_message_from_room (room);
  else if (! (room->queue_task))
    room->queue_task = GNUNET_SCHEDULER_add_with_priority (
      GNUNET_SCHEDULER_PRIORITY_HIGH, dequeue_message_from_room, room);
}


const char*
GNUNET_MESSENGER_get_name (const struct GNUNET_MESSENGER_Handle *handle)
{
  if (! handle)
    return NULL;

  return get_handle_name (handle);
}


static enum GNUNET_GenericReturnValue
iterate_send_name_to_room (void *cls,
                           struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_Message *message;
  const char *name;

  GNUNET_assert ((cls) && (room));

  handle = cls;

  if (GNUNET_YES != room->use_handle_name)
    return GNUNET_YES;

  name = get_handle_name (handle);
  if (! name)
    return GNUNET_YES;

  message = create_message_name (name);
  if (! message)
    return GNUNET_NO;

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_MESSENGER_set_name (struct GNUNET_MESSENGER_Handle *handle,
                           const char *name)
{
  if (! handle)
    return GNUNET_SYSERR;

  set_handle_name (handle, strlen (name) > 0 ? name : NULL);
  GNUNET_MESSENGER_find_rooms (handle, NULL, iterate_send_name_to_room, handle);
  return GNUNET_YES;
}


static const struct GNUNET_CRYPTO_PublicKey*
get_non_anonymous_key (const struct GNUNET_CRYPTO_PublicKey *public_key)
{
  if (0 == GNUNET_memcmp (public_key, get_anonymous_public_key ()))
    return NULL;

  return public_key;
}


const struct GNUNET_CRYPTO_PublicKey*
GNUNET_MESSENGER_get_key (const struct GNUNET_MESSENGER_Handle *handle)
{
  if (! handle)
    return NULL;

  return get_non_anonymous_key (get_handle_pubkey (handle));
}


static enum GNUNET_GenericReturnValue
iterate_send_key_to_room (void *cls,
                          struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_CRYPTO_PrivateKey *key;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((cls) && (room));

  key = cls;

  message = create_message_key (key);
  if (! message)
    return GNUNET_NO;

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
GNUNET_MESSENGER_set_key (struct GNUNET_MESSENGER_Handle *handle,
                          const struct GNUNET_CRYPTO_PrivateKey *key)
{
  if (! handle)
    return GNUNET_SYSERR;

  if (! key)
  {
    GNUNET_MESSENGER_find_rooms (handle, NULL, iterate_send_key_to_room, NULL);
    set_handle_key (handle, NULL);
    return GNUNET_YES;
  }

  if (0 >= GNUNET_CRYPTO_private_key_get_length (key))
    return GNUNET_SYSERR;

  {
    struct GNUNET_CRYPTO_PrivateKey priv;
    GNUNET_memcpy (&priv, key, sizeof (priv));

    GNUNET_MESSENGER_find_rooms (handle, NULL, iterate_send_key_to_room, &priv);
    GNUNET_CRYPTO_private_key_clear (&priv);
  }

  set_handle_key (handle, key);
  return GNUNET_YES;
}


struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_open_room (struct GNUNET_MESSENGER_Handle *handle,
                            const union GNUNET_MESSENGER_RoomKey *key)
{
  struct GNUNET_MESSENGER_Room *room;

  if ((! handle) || (! key))
    return NULL;

  if ((key->code.feed_bit) && (! key->code.group_bit))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Personal rooms containing private feeds should not be opened!")
    ;
    return NULL;
  }

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, &(key->hash));
  if (! room)
  {
    room = create_room (handle, key);

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
          handle->rooms, &(key->hash), room,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_room (room);
      return NULL;
    }
  }

  send_open_room (handle, room);
  return room;
}


struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_enter_room (struct GNUNET_MESSENGER_Handle *handle,
                             const struct GNUNET_PeerIdentity *door,
                             const union GNUNET_MESSENGER_RoomKey *key)
{
  struct GNUNET_MESSENGER_Room *room;

  if ((! handle) || (! door) || (! key))
    return NULL;

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, &(key->hash));
  if (! room)
  {
    room = create_room (handle, key);

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
          handle->rooms, &(key->hash), room,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      destroy_room (room);
      return NULL;
    }
  }

  send_enter_room (handle, room, door);
  return room;
}


void
GNUNET_MESSENGER_close_room (struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_Message *message;

  if (! room)
    return;

  message = create_message_leave ();

  if (! message)
    return;

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_YES);
}


struct GNUNET_MESSENGER_RoomFind
{
  const struct GNUNET_MESSENGER_Contact *contact;
  GNUNET_MESSENGER_MemberCallback callback;
  size_t counter;
  void *cls;
};

static enum GNUNET_GenericReturnValue
iterate_find_room (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct GNUNET_MESSENGER_RoomFind *find;
  struct GNUNET_MESSENGER_Room *room;
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((cls) && (value));

  find = cls;
  room = value;
  result = GNUNET_YES;

  if ((! find->contact) ||
      (GNUNET_YES == find_room_member (room, find->contact)))
    find->counter--;

  if (find->callback)
    result = find->callback (find->cls, room, find->contact);

  if (find->counter <= 0)
    result = GNUNET_NO;

  return result;
}


int
GNUNET_MESSENGER_find_rooms (const struct GNUNET_MESSENGER_Handle *handle,
                             const struct GNUNET_MESSENGER_Contact *contact,
                             GNUNET_MESSENGER_MemberCallback callback,
                             void *cls)
{
  struct GNUNET_MESSENGER_RoomFind find;

  if (! handle)
    return GNUNET_SYSERR;

  find.contact = contact;
  find.callback = callback;
  find.counter = (contact? contact->rc : SIZE_MAX);
  find.cls = cls;

  if (find.counter <= 0)
    return 0;

  return GNUNET_CONTAINER_multihashmap_iterate (handle->rooms,
                                                iterate_find_room, &find);
}


const struct GNUNET_HashCode*
GNUNET_MESSENGER_room_get_key (const struct GNUNET_MESSENGER_Room *room)
{
  if (! room)
    return NULL;

  return get_room_key (room);
}


const struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_sender (const struct GNUNET_MESSENGER_Room *room,
                             const struct GNUNET_HashCode *hash)
{
  if ((! room) || (! hash))
    return NULL;

  return get_room_sender (room, hash);
}


const struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_recipient (const struct GNUNET_MESSENGER_Room *room,
                                const struct GNUNET_HashCode *hash)
{
  if ((! room) || (! hash))
    return NULL;

  return get_room_recipient (room, hash);
}


const char*
GNUNET_MESSENGER_contact_get_name (const struct
                                   GNUNET_MESSENGER_Contact *contact)
{
  if (! contact)
    return NULL;

  return get_contact_name (contact);
}


const struct GNUNET_CRYPTO_PublicKey*
GNUNET_MESSENGER_contact_get_key (const struct
                                  GNUNET_MESSENGER_Contact *contact)
{
  if (! contact)
    return NULL;

  return get_non_anonymous_key (get_contact_key (contact));
}


size_t
GNUNET_MESSENGER_contact_get_id (const struct
                                 GNUNET_MESSENGER_Contact *contact)
{
  if (! contact)
    return 0;

  return get_contact_id (contact);
}


static void
send_message_to_room_with_key (struct GNUNET_MESSENGER_Room *room,
                               struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_CRYPTO_PublicKey *public_key)
{
  struct GNUNET_MESSENGER_Message *transcript;
  const struct GNUNET_CRYPTO_PublicKey *pubkey;
  const char *handle_name;
  char *original_name;

  transcript = NULL;

  if (GNUNET_MESSENGER_KIND_NAME != message->header.kind)
    goto skip_naming;

  original_name = message->body.name.name;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Apply rule for using handle name in room: %s\n", GNUNET_h2s (
                get_room_key (room)));

  handle_name = get_handle_name (room->handle);

  if ((handle_name) && (GNUNET_YES == room->use_handle_name) &&
      ((! original_name) || (0 == strlen (original_name))))
  {
    if (original_name)
      GNUNET_free (original_name);

    message->body.name.name = GNUNET_strdup (handle_name);
  }

skip_naming:
  if (! public_key)
    goto skip_encryption;

  pubkey = get_handle_pubkey (room->handle);

  if (0 != GNUNET_memcmp (pubkey, public_key))
    transcript = transcribe_message (message, public_key);

  if (GNUNET_YES != encrypt_message (message, public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Sending message aborted: Encryption failed!\n");

    if (transcript)
      destroy_message (transcript);

    destroy_message (message);
    return;
  }

skip_encryption:
  enqueue_message_to_room (room, NULL, message, transcript, GNUNET_NO);
}


void
GNUNET_MESSENGER_send_message (struct GNUNET_MESSENGER_Room *room,
                               const struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_MESSENGER_Contact *contact)
{
  const struct GNUNET_CRYPTO_PublicKey *public_key;

  if ((! room) || (! message))
    return;

  switch (filter_message_sending (message))
  {
  case GNUNET_SYSERR:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Sending message aborted: This kind of message is reserved for the service!\n");
    return;
  case GNUNET_NO:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Sending message aborted: This kind of message could cause issues!\n");
    return;
  default:
    break;
  }

  if (contact)
  {
    public_key = get_non_anonymous_key (
      get_contact_key (contact));

    if (! public_key)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Sending message aborted: Invalid key!\n");
      return;
    }
  }
  else
    public_key = NULL;

  send_message_to_room_with_key (room, copy_message (message), public_key);
}


void
GNUNET_MESSENGER_delete_message (struct GNUNET_MESSENGER_Room *room,
                                 const struct GNUNET_HashCode *hash,
                                 const struct GNUNET_TIME_Relative delay)
{
  const struct GNUNET_MESSENGER_Message *message;

  if ((! room) || (! hash))
    return;

  message = get_room_message (room, hash);

  if ((message) && (GNUNET_YES == is_epoch_message (message)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Deletion of message is not allowed!\n");
    return;
  }

  delete_room_message (room, hash, delay);
}


void
request_message_from_room (const struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_GetMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert ((room) && (hash));

  if (GNUNET_is_zero (hash))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Request message (%s)!\n",
              GNUNET_h2s (hash));

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE);
  GNUNET_memcpy (&(msg->key), get_room_key (room), sizeof(msg->key));
  GNUNET_memcpy (&(msg->hash), hash, sizeof(*hash));
  GNUNET_MQ_send (room->handle->mq, env);
}


const struct GNUNET_MESSENGER_Message*
GNUNET_MESSENGER_get_message (struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *message;

  if ((! room) || (! hash) || (GNUNET_is_zero (hash)))
    return NULL;

  message = get_room_message (room, hash);

  if (! message)
  {
    if ((GNUNET_YES == room->joined) && (get_room_sender_id (room)))
      request_message_from_room (room, hash);
    else
      require_message_from_room (room, hash);
  }

  return message;
}


int
GNUNET_MESSENGER_iterate_members (struct GNUNET_MESSENGER_Room *room,
                                  GNUNET_MESSENGER_MemberCallback callback,
                                  void *cls)
{
  if (! room)
    return GNUNET_SYSERR;

  return iterate_room_members (room, callback, cls);
}
