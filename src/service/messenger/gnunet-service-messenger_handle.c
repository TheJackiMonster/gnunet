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
 * @file src/messenger/gnunet-service-messenger_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet_messenger_service.h"

#include "gnunet-service-messenger.h"
#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_room.h"

#include "messenger_api_util.h"

struct GNUNET_MESSENGER_NextMemberId
{
  struct GNUNET_ShortHashCode id;
  enum GNUNET_GenericReturnValue reset;
};

struct GNUNET_MESSENGER_SrvHandle*
create_srv_handle (struct GNUNET_MESSENGER_Service *service,
                   struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert ((service) && (mq));

  struct GNUNET_MESSENGER_SrvHandle *handle = GNUNET_new (struct
                                                          GNUNET_MESSENGER_SrvHandle);

  handle->service = service;
  handle->mq = mq;

  handle->member_ids = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  handle->next_ids = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
  handle->routing = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);

  handle->notify = NULL;

  return handle;
}


static enum GNUNET_GenericReturnValue
iterate_close_rooms (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;
  close_service_room (handle->service, handle, key, GNUNET_NO);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_free_values (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


void
destroy_srv_handle (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert (handle);

  GNUNET_CONTAINER_multihashmap_iterate (handle->routing,
                                         iterate_close_rooms, handle);

  if (handle->notify)
    GNUNET_SCHEDULER_cancel (handle->notify);

  GNUNET_CONTAINER_multihashmap_iterate (handle->next_ids,
                                         iterate_free_values, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids,
                                         iterate_free_values, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (handle->next_ids);
  GNUNET_CONTAINER_multihashmap_destroy (handle->member_ids);
  GNUNET_CONTAINER_multihashmap_destroy (handle->routing);

  GNUNET_free (handle);
}


void
set_srv_handle_key (struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_CRYPTO_PublicKey *key)
{
  GNUNET_assert (handle);

  if ((handle->key) && (! key))
  {
    GNUNET_free (handle->key);
    handle->key = NULL;
  }
  else if (! handle->key)
    handle->key = GNUNET_new (struct GNUNET_CRYPTO_PublicKey);

  if (key)
    memcpy (handle->key, key, sizeof(struct GNUNET_CRYPTO_PublicKey));
}


const struct GNUNET_CRYPTO_PublicKey*
get_srv_handle_key (const struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert (handle);

  return handle->key;
}


void
get_srv_handle_data_subdir (const struct GNUNET_MESSENGER_SrvHandle *handle,
                            const char *name,
                            char **dir)
{
  GNUNET_assert ((handle) && (dir));

  if (name)
    GNUNET_asprintf (dir, "%s%s%c%s%c", handle->service->dir, "identities",
                     DIR_SEPARATOR, name, DIR_SEPARATOR);
  else
    GNUNET_asprintf (dir, "%s%s%c", handle->service->dir, "anonymous",
                     DIR_SEPARATOR);
}


static enum GNUNET_GenericReturnValue
create_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  struct GNUNET_ShortHashCode *random_id = GNUNET_new (struct
                                                       GNUNET_ShortHashCode);

  if (! random_id)
    return GNUNET_NO;

  generate_free_member_id (random_id, NULL);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key,
                                                      random_id,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free (random_id);
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Created a new member id (%s) for room: %s\n", GNUNET_sh2s (
                random_id),
              GNUNET_h2s (key));

  return GNUNET_YES;
}


const struct GNUNET_ShortHashCode*
get_srv_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle,
                          const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  return GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);
}


enum GNUNET_GenericReturnValue
change_srv_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle,
                             const struct GNUNET_HashCode *key,
                             const struct GNUNET_ShortHashCode *unique_id)
{
  GNUNET_assert ((handle) && (key) && (unique_id));

  struct GNUNET_ShortHashCode *member_id = GNUNET_CONTAINER_multihashmap_get (
    handle->member_ids, key);

  if (! member_id)
  {
    member_id = GNUNET_new (struct GNUNET_ShortHashCode);
    GNUNET_memcpy (member_id, unique_id, sizeof(*member_id));

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key,
                                                        member_id,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      GNUNET_free (member_id);
      return GNUNET_SYSERR;
    }
  }

  if (0 == GNUNET_memcmp (unique_id, member_id))
    return GNUNET_OK;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Change a member id (%s) for room (%s).\n", GNUNET_sh2s (
                member_id),
              GNUNET_h2s (key));

  GNUNET_memcpy (member_id, unique_id, sizeof(*unique_id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Member id changed to (%s).\n",
              GNUNET_sh2s (unique_id));
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
open_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->routing,
                                                      key,
                                                      NULL,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE))
    return GNUNET_NO;

  if ((! get_srv_handle_member_id (handle, key)) &&
      (GNUNET_YES != create_handle_member_id (handle,
                                              key)))
    return GNUNET_NO;

  return open_service_room (handle->service, handle, key);
}


enum GNUNET_GenericReturnValue
entry_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_PeerIdentity *door,
                       const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (door) && (key));

  if ((! get_srv_handle_member_id (handle, key)) && (GNUNET_YES !=
                                                     create_handle_member_id (
                                                       handle, key)))
    return GNUNET_NO;

  return entry_service_room (handle->service, handle, door, key);
}


enum GNUNET_GenericReturnValue
close_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  GNUNET_CONTAINER_multihashmap_get_multiple (handle->next_ids, key,
                                              iterate_free_values, NULL);
  GNUNET_CONTAINER_multihashmap_remove_all (handle->next_ids, key);

  if ((handle->notify) && (0 == GNUNET_CONTAINER_multihashmap_size (
                             handle->next_ids)))
  {
    GNUNET_SCHEDULER_cancel (handle->notify);
    handle->notify = NULL;
  }

  if (! get_srv_handle_member_id (handle, key))
    return GNUNET_NO;

  enum GNUNET_GenericReturnValue result;
  result = close_service_room (handle->service, handle, key, GNUNET_YES);

  if (GNUNET_YES != result)
    return result;

  GNUNET_CONTAINER_multihashmap_remove_all (handle->routing, key);
  return result;
}


enum GNUNET_GenericReturnValue
is_srv_handle_routing (const struct GNUNET_MESSENGER_SrvHandle *handle,
                       const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  return GNUNET_CONTAINER_multihashmap_contains (handle->routing, key);
}


void
sync_srv_handle_messages (struct GNUNET_MESSENGER_SrvHandle *handle,
                          const struct GNUNET_HashCode *key,
                          const struct GNUNET_HashCode *prev,
                          struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((handle) && (key) && (prev) && (hash));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (handle->service,
                                                            key);

  if ((! room) || (! get_srv_handle_member_id (handle, key)))
  {
    GNUNET_memcpy (hash, prev, sizeof(*hash));
    return;
  }

  merge_srv_room_last_messages (room, handle);
  get_message_state_chain_hash (&(room->state), hash);
}


enum GNUNET_GenericReturnValue
send_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key,
                         const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert ((handle) && (key) && (message));

  const struct GNUNET_ShortHashCode *id = get_srv_handle_member_id (handle,
                                                                    key);

  if (! id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "It is required to be a member of a room to send messages!\n");
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending message with member id: %s\n",
              GNUNET_sh2s (id));

  if (0 != GNUNET_memcmp (id, &(message->header.sender_id)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Member id does not match with handle!\n");
    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (handle->service,
                                                            key);

  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "The room (%s) is unknown!\n",
                GNUNET_h2s (key));
    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_Message *msg = copy_message (message);
  return send_srv_room_message (room, handle, msg);
}


static const struct GNUNET_HashCode*
get_next_member_session_context (const struct
                                 GNUNET_MESSENGER_MemberSession *session)
{
  if (session->next)
    return get_next_member_session_context (session->next);
  else
    return get_member_session_context (session);
}


static const struct GNUNET_MESSENGER_MemberSession*
get_handle_member_session (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (room) && (key) && (handle->service));

  const struct GNUNET_ShortHashCode *id = get_srv_handle_member_id (handle,
                                                                    key);

  if (! id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Handle is missing a member id for its member session! (%s)\n",
                GNUNET_h2s (key));
    return NULL;
  }

  struct GNUNET_MESSENGER_MemberStore *store = get_srv_room_member_store (room);
  struct GNUNET_MESSENGER_Member *member = get_store_member (store, id);

  const struct GNUNET_CRYPTO_PublicKey *pubkey = get_srv_handle_key (handle);

  if (! pubkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Handle is missing a public key for its member session! (%s)\n",
                GNUNET_h2s (key));
    return NULL;
  }

  return get_member_session (member, pubkey);
}


void
notify_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_MESSENGER_SenderSession *session,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash,
                           enum GNUNET_GenericReturnValue recent)
{
  GNUNET_assert ((handle) && (room) && (session) && (message) && (hash));

  const struct GNUNET_HashCode *key = get_srv_room_key (room);

  if ((! handle->mq) || (! get_srv_handle_member_id (handle, key)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Notifying client about message requires membership!\n");
    return;
  }

  struct GNUNET_HashCode sender;
  const struct GNUNET_HashCode *context = NULL;

  if (GNUNET_YES == is_peer_message (message))
  {
    const struct GNUNET_PeerIdentity *identity = session->peer;
    GNUNET_CRYPTO_hash (identity, sizeof(*identity), &sender);

    context = &sender;
  }
  else
  {
    const struct GNUNET_CRYPTO_PublicKey *pubkey = get_contact_key (
      session->member->contact);
    GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &sender);

    context = get_next_member_session_context (session->member);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Notifying client about message: %s (%s)\n",
              GNUNET_h2s (hash), GNUNET_MESSENGER_name_of_kind (
                message->header.kind));

  struct GNUNET_MESSENGER_RecvMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  uint16_t length = get_message_size (message, GNUNET_YES);

  env = GNUNET_MQ_msg_extra (msg, length,
                             GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE);

  GNUNET_memcpy (&(msg->key), key, sizeof(msg->key));
  GNUNET_memcpy (&(msg->sender), &sender, sizeof(msg->sender));
  GNUNET_memcpy (&(msg->context), context, sizeof(msg->context));
  GNUNET_memcpy (&(msg->hash), hash, sizeof(msg->hash));

  msg->flags = (uint32_t) GNUNET_MESSENGER_FLAG_NONE;

  if (GNUNET_YES == is_peer_message (message))
    msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_PEER;
  else if (get_handle_member_session (handle, room, key) == session->member)
    msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_SENT;

  if (GNUNET_YES == recent)
    msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_RECENT;

  char *buffer = ((char*) msg) + sizeof(*msg);
  encode_message (message, length, buffer, GNUNET_YES);

  GNUNET_MQ_send (handle->mq, env);
}


static enum GNUNET_GenericReturnValue
iterate_next_member_ids (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;
  struct GNUNET_MESSENGER_NextMemberId *next = value;

  struct GNUNET_MESSENGER_MemberMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID);

  GNUNET_memcpy (&(msg->key), key, sizeof(*key));
  GNUNET_memcpy (&(msg->id), &(next->id), sizeof(next->id));
  msg->reset = (uint32_t) next->reset;

  GNUNET_MQ_send (handle->mq, env);

  GNUNET_free (next);
  return GNUNET_YES;
}


static void
task_notify_srv_handle_member_id (void *cls)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;
  handle->notify = NULL;

  GNUNET_CONTAINER_multihashmap_iterate (handle->next_ids,
                                         iterate_next_member_ids, handle);
  GNUNET_CONTAINER_multihashmap_clear (handle->next_ids);
}


void
notify_srv_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle,
                             struct GNUNET_MESSENGER_SrvRoom *room,
                             const struct GNUNET_ShortHashCode *member_id,
                             enum GNUNET_GenericReturnValue reset)
{
  GNUNET_assert ((handle) && (room) && (member_id));

  struct GNUNET_MESSENGER_NextMemberId *next = GNUNET_new (struct
                                                           GNUNET_MESSENGER_NextMemberId);
  if (! next)
  {
    return;
  }

  GNUNET_memcpy (&(next->id), member_id, sizeof(next->id));
  next->reset = reset;

  const struct GNUNET_HashCode *key = get_srv_room_key (room);

  struct GNUNET_MESSENGER_NextMemberId *prev =
    GNUNET_CONTAINER_multihashmap_get (handle->next_ids, key);
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_put (handle->next_ids, key,
                                                       next,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE))
  {
    return;
  }

  if (prev)
    GNUNET_free (prev);

  if (! handle->notify)
    handle->notify = GNUNET_SCHEDULER_add_now (task_notify_srv_handle_member_id,
                                               handle);
}
