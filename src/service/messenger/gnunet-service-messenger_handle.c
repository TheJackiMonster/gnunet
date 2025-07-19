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
  struct GNUNET_MESSENGER_SrvHandle *handle;

  GNUNET_assert ((service) && (mq));

  handle = GNUNET_new (struct GNUNET_MESSENGER_SrvHandle);

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
  struct GNUNET_MESSENGER_SrvHandle *handle;

  GNUNET_assert ((cls) && (key));

  handle = cls;

  close_service_room (handle->service, handle, key, GNUNET_NO);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_free_values (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  GNUNET_assert (value);

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
  struct GNUNET_ShortHashCode *random_id;

  GNUNET_assert ((handle) && (key));

  random_id = GNUNET_new (struct GNUNET_ShortHashCode);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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
  struct GNUNET_ShortHashCode *member_id;

  GNUNET_assert ((handle) && (key) && (unique_id));

  member_id = GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Change a member id (%s) for room (%s).\n", GNUNET_sh2s (
                member_id),
              GNUNET_h2s (key));

  GNUNET_memcpy (member_id, unique_id, sizeof(*unique_id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Member id changed to (%s).\n",
              GNUNET_sh2s (unique_id));
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
open_srv_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        handle->routing, key, NULL,
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

  {
    enum GNUNET_GenericReturnValue result;
    result = close_service_room (handle->service, handle, key, GNUNET_YES);

    if (GNUNET_YES != result)
      return result;

    GNUNET_CONTAINER_multihashmap_remove_all (handle->routing, key);
    return result;
  }
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
                          struct GNUNET_HashCode *hash,
                          struct GNUNET_HashCode *epoch)
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_MessageStore *store;

  GNUNET_assert ((handle) && (key) && (prev) && (hash) && (epoch));

  room = get_service_room (handle->service, key);

  if ((! room) || (! get_srv_handle_member_id (handle, key)))
  {
    GNUNET_memcpy (hash, prev, sizeof(*hash));
    goto sync_epoch;
  }

  merge_srv_room_last_messages (room, handle);
  get_message_state_chain_hash (&(room->state), hash);

sync_epoch:
  if (! room)
  {
    GNUNET_memcpy (epoch, hash, sizeof(*epoch));
    return;
  }

  store = get_srv_room_message_store (room);

  if (! store)
    return;

  GNUNET_memcpy (epoch, get_store_message_epoch (store, hash),
                 sizeof(*epoch));
}


enum GNUNET_GenericReturnValue
send_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key,
                         const struct GNUNET_MESSENGER_Message *message)
{
  const struct GNUNET_ShortHashCode *id;
  struct GNUNET_MESSENGER_SrvRoom *room;

  GNUNET_assert ((handle) && (key) && (message));

  id = get_srv_handle_member_id (handle, key);

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

  room = get_service_room (handle->service, key);

  if (! room)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "The room (%s) is unknown!\n",
                GNUNET_h2s (key));
    return GNUNET_NO;
  }

  {
    struct GNUNET_MESSENGER_Message *msg;
    msg = copy_message (message);

    if (! msg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Copying message failed!\n");
      return GNUNET_NO;
    }

    return send_srv_room_message (room, handle, msg);
  }
}


static const struct GNUNET_HashCode*
get_next_member_session_context (const struct
                                 GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

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
  const struct GNUNET_ShortHashCode *id;
  const struct GNUNET_CRYPTO_PublicKey *pubkey;

  GNUNET_assert ((handle) && (room) && (key) && (handle->service));

  id = get_srv_handle_member_id (handle, key);

  if (! id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Handle is missing a member id for its member session! (%s)\n",
                GNUNET_h2s (key));
    return NULL;
  }

  pubkey = get_srv_handle_key (handle);

  if (! pubkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Handle is missing a public key for its member session! (%s)\n",
                GNUNET_h2s (key));
    return NULL;
  }

  {
    struct GNUNET_MESSENGER_MemberStore *store;
    struct GNUNET_MESSENGER_Member *member;

    store = get_srv_room_member_store (room);
    member = get_store_member (store, id);

    return get_member_session (member, pubkey);
  }
}


void
notify_srv_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_MESSENGER_SenderSession *session,
                           const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash,
                           const struct GNUNET_HashCode *epoch,
                           enum GNUNET_GenericReturnValue recent)
{
  const struct GNUNET_HashCode *key;
  const struct GNUNET_ShortHashCode *id;
  const struct GNUNET_HashCode *context;
  struct GNUNET_TIME_Absolute timestamp;
  const struct GNUNET_ShortHashCode *discourse;
  struct GNUNET_MESSENGER_Subscription *subscription;
  struct GNUNET_HashCode sender;

  GNUNET_assert ((handle) && (room) && (session) && (message) && (hash) && (
                   epoch));

  key = get_srv_room_key (room);
  id = get_srv_handle_member_id (handle, key);

  if (! handle->mq)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Notifying client is missing a message queue!\n");
    return;
  }
  else if (! id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Notifying client about message requires membership!\n");
    return;
  }

  context = NULL;

  if (GNUNET_MESSENGER_KIND_TALK != message->header.kind)
    goto skip_message_filter;

  timestamp = GNUNET_TIME_absolute_ntoh (message->header.timestamp);
  discourse = &(message->body.talk.discourse);

  {
    struct GNUNET_MESSENGER_MemberStore *member_store;
    struct GNUNET_MESSENGER_Member *member;

    member_store = get_srv_room_member_store (room);

    if (! member_store)
      return;

    member = get_store_member (member_store, id);

    if (! member)
      return;

    subscription = get_member_subscription (member, discourse);
  }

  if ((! subscription) ||
      (GNUNET_YES != has_subscription_of_timestamp (subscription, timestamp)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropping message for client outside of subscription: %s\n",
                GNUNET_h2s (hash));
    return;
  }

skip_message_filter:
  if (GNUNET_YES == is_peer_message (message))
  {
    const struct GNUNET_PeerIdentity *identity = session->peer;
    GNUNET_CRYPTO_hash (identity, sizeof(*identity), &sender);

    context = &sender;
  }
  else
  {
    const struct GNUNET_CRYPTO_PublicKey *pubkey;
    pubkey = get_member_session_public_key (session->member);
    GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &sender);

    context = get_next_member_session_context (session->member);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying client about message: %s (%s)\n",
              GNUNET_h2s (hash), GNUNET_MESSENGER_name_of_kind (
                message->header.kind));

  {
    struct GNUNET_MESSENGER_RecvMessage *msg;
    struct GNUNET_MQ_Envelope *env;
    uint16_t length;
    char *buffer;

    length = get_message_size (message, GNUNET_YES);

    env = GNUNET_MQ_msg_extra (msg, length,
                               GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE);

    GNUNET_memcpy (&(msg->key), key, sizeof(msg->key));
    GNUNET_memcpy (&(msg->sender), &sender, sizeof(msg->sender));
    GNUNET_memcpy (&(msg->context), context, sizeof(msg->context));
    GNUNET_memcpy (&(msg->hash), hash, sizeof(msg->hash));
    GNUNET_memcpy (&(msg->epoch), epoch, sizeof(msg->epoch));

    msg->flags = (uint32_t) GNUNET_MESSENGER_FLAG_NONE;

    if (GNUNET_YES == is_peer_message (message))
      msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_PEER;
    else if (get_handle_member_session (handle, room, key) == session->member)
      msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_SENT;

    if (GNUNET_YES == recent)
      msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_RECENT;

    buffer = ((char*) msg) + sizeof(*msg);
    encode_message (message, length, buffer, GNUNET_YES);

    GNUNET_MQ_send (handle->mq, env);
  }
}


static enum GNUNET_GenericReturnValue
iterate_next_member_ids (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_NextMemberId *next;

  GNUNET_assert ((cls) && (value));

  handle = cls;
  next = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying client about next member id: %s (%s)\n",
              GNUNET_sh2s (&(next->id)), GNUNET_h2s (key));

  {
    struct GNUNET_MESSENGER_MemberMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg (
      msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID);

    GNUNET_memcpy (&(msg->key), key, sizeof(*key));
    GNUNET_memcpy (&(msg->id), &(next->id), sizeof(next->id));
    msg->reset = (uint32_t) next->reset;

    GNUNET_MQ_send (handle->mq, env);
  }

  GNUNET_free (next);
  return GNUNET_YES;
}


static void
task_notify_srv_handle_member_id (void *cls)
{
  struct GNUNET_MESSENGER_SrvHandle *handle;

  GNUNET_assert (cls);

  handle = cls;
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
  struct GNUNET_MESSENGER_NextMemberId *next;
  struct GNUNET_MESSENGER_NextMemberId *prev;
  const struct GNUNET_HashCode *key;

  GNUNET_assert ((handle) && (room) && (member_id));

  next = GNUNET_new (struct GNUNET_MESSENGER_NextMemberId);
  key = get_srv_room_key (room);

  if (! next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Allocation of next member id failed: %s (%s)\n",
                GNUNET_sh2s (member_id), GNUNET_h2s (key));
    return;
  }

  GNUNET_memcpy (&(next->id), member_id, sizeof(next->id));
  next->reset = reset;

  prev = GNUNET_CONTAINER_multihashmap_get (handle->next_ids, key);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_put (handle->next_ids, key,
                                                       next,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Update of next member id failed: %s (%s)\n",
                GNUNET_sh2s (member_id), GNUNET_h2s (key));
    return;
  }

  if (prev)
    GNUNET_free (prev);

  if (! handle->notify)
    handle->notify = GNUNET_SCHEDULER_add_now (task_notify_srv_handle_member_id,
                                               handle);
}
