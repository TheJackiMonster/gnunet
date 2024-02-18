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
 * @file src/messenger/gnunet-service-messenger.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger.h"

#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_room.h"
#include "gnunet-service-messenger_service.h"
#include "gnunet_common.h"
#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Client
{
  struct GNUNET_SERVICE_Client *client;
  struct GNUNET_MESSENGER_SrvHandle *handle;
};

struct GNUNET_MESSENGER_Service *messenger;

static void
handle_create (void *cls,
               const struct GNUNET_MESSENGER_CreateMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Handle created\n");

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static void
handle_destroy (void *cls,
                const struct GNUNET_MESSENGER_DestroyMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Handle destroyed\n");

  GNUNET_SERVICE_client_drop (msg_client->client);
}


static enum GNUNET_GenericReturnValue
check_room_initial_key (const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  const uint16_t full_length = ntohs (msg->header.size);

  if (full_length < sizeof(*msg))
    return GNUNET_NO;

  const uint16_t msg_length = full_length - sizeof(*msg);
  const char *msg_buffer = ((const char*) msg) + sizeof(*msg);

  if (0 == msg_length)
    return GNUNET_OK;

  struct GNUNET_CRYPTO_PublicKey key;
  size_t key_len;

  if (GNUNET_OK != GNUNET_CRYPTO_read_public_key_from_buffer (msg_buffer,
                                                              msg_length,
                                                              &key, &key_len))
    return GNUNET_NO;

  return key_len == msg_length ? GNUNET_OK : GNUNET_NO;
}


static void
initialize_handle_via_key (struct GNUNET_MESSENGER_SrvHandle *handle,
                           const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  GNUNET_assert (handle);

  const uint16_t full_length = ntohs (msg->header.size);
  const uint16_t msg_length = full_length - sizeof(*msg);
  const char *msg_buffer = ((const char*) msg) + sizeof(*msg);

  if (msg_length > 0)
  {
    struct GNUNET_CRYPTO_PublicKey key;
    size_t key_len;

    if (GNUNET_OK == GNUNET_CRYPTO_read_public_key_from_buffer (msg_buffer,
                                                                msg_length,
                                                                &key,
                                                                &key_len))
      set_srv_handle_key (handle, &key);
    else
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Initialization failed while reading invalid key!\n");
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Initialization is missing key!\n");
}


static enum GNUNET_GenericReturnValue
check_room_open (void *cls,
                 const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  return check_room_initial_key (msg);
}


static void
handle_room_open (void *cls,
                  const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  initialize_handle_via_key (msg_client->handle, msg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Opening room: %s\n", GNUNET_h2s (
                &(msg->key)));

  if (GNUNET_YES == open_srv_handle_room (msg_client->handle, &(msg->key)))
  {
    struct GNUNET_HashCode prev;
    sync_srv_handle_messages (msg_client->handle, &(msg->key), &(msg->previous),
                              &prev);

    const struct GNUNET_ShortHashCode *member_id = get_srv_handle_member_id (
      msg_client->handle, &(msg->key));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Opening room with member id: %s\n",
                GNUNET_sh2s (member_id));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN);
    GNUNET_memcpy (&(response->key), &(msg->key), sizeof(response->key));
    GNUNET_memcpy (&(response->previous), &prev, sizeof(response->previous));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Opening room failed: %s\n",
                GNUNET_h2s (&(msg->key)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static enum GNUNET_GenericReturnValue
check_room_entry (void *cls,
                  const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  return check_room_initial_key (msg);
}


static void
handle_room_entry (void *cls,
                   const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  initialize_handle_via_key (msg_client->handle, msg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Entering room: %s, %s\n", GNUNET_h2s (
                &(msg->key)), GNUNET_i2s (&(msg->door)));

  if (GNUNET_YES == entry_srv_handle_room (msg_client->handle, &(msg->door),
                                           &(msg->key)))
  {
    struct GNUNET_HashCode prev;
    sync_srv_handle_messages (msg_client->handle, &(msg->key), &(msg->previous),
                              &prev);

    const struct GNUNET_ShortHashCode *member_id = get_srv_handle_member_id (
      msg_client->handle, &(msg->key));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Entering room with member id: %s\n",
                GNUNET_sh2s (member_id));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY);
    GNUNET_memcpy (&(response->door), &(msg->door), sizeof(response->door));
    GNUNET_memcpy (&(response->key), &(msg->key), sizeof(response->key));
    GNUNET_memcpy (&(response->previous), &prev, sizeof(response->previous));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Entrance into room failed: %s, %s\n",
                GNUNET_h2s (&(msg->key)),
                GNUNET_i2s (&(msg->door)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static void
handle_room_close (void *cls,
                   const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Closing room: %s\n", GNUNET_h2s (
                &(msg->key)));

  if (GNUNET_YES == close_srv_handle_room (msg_client->handle, &(msg->key)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Closing room succeeded: %s\n",
                GNUNET_h2s (&(msg->key)));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE);
    GNUNET_memcpy (&(response->key), &(msg->key), sizeof(response->key));
    GNUNET_memcpy (&(response->previous), &(msg->previous),
                   sizeof(response->previous));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Closing room failed: %s\n",
                GNUNET_h2s (&(msg->key)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static void
handle_room_sync (void *cls,
                  const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Syncing room: %s\n", GNUNET_h2s (
                &(msg->key)));

  struct GNUNET_HashCode prev;
  sync_srv_handle_messages (msg_client->handle, &(msg->key), &(msg->previous),
                            &prev);

  struct GNUNET_MESSENGER_RoomMessage *response;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SYNC);
  GNUNET_memcpy (&(response->key), &(msg->key), sizeof(response->key));
  GNUNET_memcpy (&(response->previous), &prev, sizeof(response->previous));
  GNUNET_MQ_send (msg_client->handle->mq, env);

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static enum GNUNET_GenericReturnValue
check_send_message (void *cls,
                    const struct GNUNET_MESSENGER_SendMessage *msg)
{
  const uint16_t full_length = ntohs (msg->header.size);

  if (full_length < sizeof(*msg))
    return GNUNET_NO;

  const uint16_t msg_length = full_length - sizeof(*msg);
  const char *msg_buffer = ((const char*) msg) + sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;

  if (msg_length < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                          GNUNET_YES))
    return GNUNET_NO;

  if (GNUNET_YES != decode_message (&message, msg_length, msg_buffer,
                                    GNUNET_YES,
                                    NULL))
    return GNUNET_NO;

  enum GNUNET_GenericReturnValue allowed;
  allowed = filter_message_sending (&message);

  cleanup_message (&message);
  return GNUNET_SYSERR != allowed? GNUNET_OK : GNUNET_NO;
}


static void
handle_send_message (void *cls,
                     const struct GNUNET_MESSENGER_SendMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  const struct GNUNET_HashCode *key = &(msg->key);
  const char *msg_buffer = ((const char*) msg) + sizeof(*msg);
  const uint16_t msg_length = ntohs (msg->header.size) - sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;
  decode_message (&message, msg_length, msg_buffer, GNUNET_YES, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending message: %s to %s (by %s)\n",
              GNUNET_MESSENGER_name_of_kind (message.header.kind),
              GNUNET_h2s (key),
              GNUNET_sh2s (&(message.header.sender_id)));

  if (GNUNET_YES != send_srv_handle_message (msg_client->handle, key, &message))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Sending message failed: %s to %s\n",
                GNUNET_MESSENGER_name_of_kind (message.header.kind),
                GNUNET_h2s (key));

  cleanup_message (&message);

  GNUNET_SERVICE_client_continue (msg_client->client);
}


static void
callback_found_message (void *cls,
                        struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  if (! message)
  {
    struct GNUNET_MESSENGER_GetMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (response,
                         GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE);
    GNUNET_memcpy (&(response->key), &(room->key), sizeof(room->key));
    GNUNET_memcpy (&(response->hash), hash, sizeof(*hash));
    GNUNET_MQ_send (msg_client->handle->mq, env);
    return;
  }

  struct GNUNET_MESSENGER_SenderSession session;

  if (GNUNET_YES == is_peer_message (message))
  {
    struct GNUNET_MESSENGER_PeerStore *store = get_srv_room_peer_store (room);

    session.peer = get_store_peer_of (store, message, hash);

    if (! session.peer)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Peer session from sender of message (%s) unknown!\n",
                  GNUNET_h2s (hash));
      return;
    }
  }
  else
  {
    struct GNUNET_MESSENGER_MemberStore *store = get_srv_room_member_store (
      room);
    struct GNUNET_MESSENGER_Member *member = get_store_member_of (store,
                                                                  message);

    if (! member)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Sender of message (%s) unknown!\n",
                  GNUNET_h2s (hash));
      return;
    }

    session.member = get_member_session_of (member, message, hash);

    if (! session.member)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Member session from sender of message (%s) unknown!\n",
                  GNUNET_h2s (hash));
      return;
    }
  }

  notify_srv_handle_message (msg_client->handle, room, &session, message,
                             hash, GNUNET_NO);
}


static void
handle_get_message (void *cls,
                    const struct GNUNET_MESSENGER_GetMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requesting message from room: %s\n",
              GNUNET_h2s (&(msg->key)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Requested message: %s\n",
              GNUNET_h2s (&(msg->hash)));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (messenger,
                                                            &(msg->key));

  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Room not found: %s\n", GNUNET_h2s (
                  &(msg->key)));
    goto end_handling;
  }

  struct GNUNET_MESSENGER_MemberStore *member_store =
    get_srv_room_member_store (room);

  const struct GNUNET_ShortHashCode *member_id;
  member_id = get_srv_handle_member_id (msg_client->handle,
                                        &(msg->key));

  struct GNUNET_MESSENGER_Member *member = get_store_member (member_store,
                                                             member_id);

  if (! member)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Member not valid to request a message! (%s)\n",
                GNUNET_sh2s (member_id));
    goto end_handling;
  }

  const struct GNUNET_CRYPTO_PublicKey *pubkey = get_srv_handle_key (
    msg_client->handle);

  if (! pubkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Handle needs to have a public key to request a message! (%s)\n",
                GNUNET_sh2s (member_id));
    goto end_handling;
  }

  struct GNUNET_MESSENGER_MemberSession *session = get_member_session (member,
                                                                       pubkey);

  if (! session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Session not valid to request a message! (%s)\n",
                GNUNET_sh2s (member_id));
    goto end_handling;
  }

  request_srv_room_message (room, &(msg->hash), session, callback_found_message,
                            msg_client);

end_handling:
  GNUNET_SERVICE_client_continue (msg_client->client);
}


static void*
callback_client_connect (void *cls,
                         struct GNUNET_SERVICE_Client *client,
                         struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MESSENGER_Client *msg_client = GNUNET_new (struct
                                                           GNUNET_MESSENGER_Client);

  msg_client->client = client;
  msg_client->handle = add_service_handle (messenger, mq);

  return msg_client;
}


static void
callback_client_disconnect (void *cls,
                            struct GNUNET_SERVICE_Client *client,
                            void *internal_cls)
{
  struct GNUNET_MESSENGER_Client *msg_client = internal_cls;

  remove_service_handle (messenger, msg_client->handle);

  GNUNET_free (msg_client);
}


/**
 * Setup MESSENGER internals.
 *
 * @param[in/out] cls closure
 * @param[in] config configuration to use
 * @param[in/out] service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *config,
     struct GNUNET_SERVICE_Handle *service)
{
  messenger = create_service (config, service);

  if (! messenger)
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  GNUNET_MESSENGER_SERVICE_NAME,
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &callback_client_connect,
  &callback_client_disconnect,
  NULL,
  GNUNET_MQ_hd_fixed_size (create,
                           GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_CREATE,
                           struct
                           GNUNET_MESSENGER_CreateMessage, NULL),
  GNUNET_MQ_hd_fixed_size (destroy,
                           GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_DESTROY,
                           struct
                           GNUNET_MESSENGER_DestroyMessage, NULL),
  GNUNET_MQ_hd_var_size (room_open, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN,
                         struct GNUNET_MESSENGER_RoomMessage, NULL),
  GNUNET_MQ_hd_var_size (room_entry, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY,
                         struct GNUNET_MESSENGER_RoomMessage, NULL),
  GNUNET_MQ_hd_fixed_size (room_close, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE,
                           struct GNUNET_MESSENGER_RoomMessage, NULL),
  GNUNET_MQ_hd_var_size (send_message,
                         GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SEND_MESSAGE, struct
                         GNUNET_MESSENGER_SendMessage, NULL),
  GNUNET_MQ_hd_fixed_size (get_message,
                           GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE,
                           struct
                           GNUNET_MESSENGER_GetMessage, NULL),
  GNUNET_MQ_hd_fixed_size (room_sync, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SYNC,
                           struct GNUNET_MESSENGER_RoomMessage, NULL),
  GNUNET_MQ_handler_end ());
