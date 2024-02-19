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
 * @file src/messenger/messenger_api_room.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_room.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "messenger_api_contact_store.h"
#include "messenger_api_handle.h"
#include "messenger_api_message.h"
#include <string.h>

struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle,
             const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_new (struct
                                                   GNUNET_MESSENGER_Room);

  room->handle = handle;
  GNUNET_memcpy (&(room->key), key, sizeof(*key));

  memset (&(room->last_message), 0, sizeof(room->last_message));

  room->opened = GNUNET_NO;
  room->use_handle_name = GNUNET_YES;
  room->wait_for_sync = GNUNET_NO;

  room->sender_id = NULL;

  init_list_tunnels (&(room->entries));

  room->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  room->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
  room->links = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_queue_messages (&(room->queue));

  return room;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_message (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry = value;

  destroy_message (entry->message);
  GNUNET_free (entry);

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_link (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_HashCode *hash = value;
  GNUNET_free (hash);
  return GNUNET_YES;
}


void
destroy_room (struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  clear_queue_messages (&(room->queue));
  clear_list_tunnels (&(room->entries));

  if (room->messages)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->messages,
                                           iterate_destroy_message, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->messages);
  }

  if (room->members)
    GNUNET_CONTAINER_multishortmap_destroy (room->members);

  if (room->links)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->links,
                                           iterate_destroy_link, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->links);
  }

  if (room->sender_id)
    GNUNET_free (room->sender_id);

  GNUNET_free (room);
}


enum GNUNET_GenericReturnValue
is_room_available (const struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  if (! get_room_sender_id (room))
    return GNUNET_NO;

  if ((GNUNET_YES == room->opened) || (room->entries.head))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


const struct GNUNET_ShortHashCode*
get_room_sender_id (const struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  return room->sender_id;
}


void
set_room_sender_id (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_ShortHashCode *id)
{
  GNUNET_assert (room);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Set member id for room: %s\n",
              GNUNET_h2s (&(room->key)));

  if (! id)
  {
    if (room->sender_id)
      GNUNET_free (room->sender_id);

    room->sender_id = NULL;
    return;
  }

  if (! room->sender_id)
    room->sender_id = GNUNET_new (struct GNUNET_ShortHashCode);

  GNUNET_memcpy (room->sender_id, id, sizeof(struct GNUNET_ShortHashCode));
}


const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry =
    GNUNET_CONTAINER_multihashmap_get (
      room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->message;
}


struct GNUNET_MESSENGER_Contact*
get_room_sender (const struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry =
    GNUNET_CONTAINER_multihashmap_get (
      room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->sender;
}


struct GNUNET_MESSENGER_Contact*
get_room_recipient (const struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry =
    GNUNET_CONTAINER_multihashmap_get (
      room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->recipient;
}


void
callback_room_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  struct GNUNET_MESSENGER_Handle *handle = room->handle;

  if (! handle)
    return;

  struct GNUNET_MESSENGER_RoomMessageEntry *entry;
  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (! entry)
    return;

  if (handle->msg_callback)
    handle->msg_callback (handle->msg_cls, room,
                          entry->sender,
                          entry->recipient,
                          entry->message,
                          hash,
                          entry->flags);

  if (entry->flags & GNUNET_MESSENGER_FLAG_UPDATE)
    entry->flags ^= GNUNET_MESSENGER_FLAG_UPDATE;
}


static void
handle_message (struct GNUNET_MESSENGER_Room *room,
                const struct GNUNET_HashCode *hash,
                struct GNUNET_MESSENGER_RoomMessageEntry *entry);


void
handle_join_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (! entry->sender)
  {
    struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store (
      room->handle);
    struct GNUNET_HashCode context;

    get_context_from_member (&(room->key), &(entry->message->header.sender_id),
                             &context);

    entry->sender = get_store_contact (store, &context,
                                       &(entry->message->body.join.key));
  }

  if ((GNUNET_YES != GNUNET_CONTAINER_multishortmap_contains_value (
         room->members, &(entry->message->header.sender_id), entry->sender)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multishortmap_put (room->members,
                                                        &(entry->message->header
                                                          .sender_id),
                                                        entry->sender,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    increase_contact_rc (entry->sender);
}


static void
handle_leave_message (struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *hash,
                      struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if ((! entry->sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (room->members,
                                                            &(entry->message->
                                                              header.sender_id),
                                                            entry->sender)))
    return;

  if (GNUNET_YES == decrease_contact_rc (entry->sender))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "A contact does not share any room with you anymore!\n");
}


static void
handle_name_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Set rule for using handle name in room: %s\n",
                GNUNET_h2s (&(room->key)));

    const char *handle_name = get_handle_name (room->handle);

    if ((handle_name) && (0 == strcmp (handle_name,
                                       entry->message->body.name.name)))
      room->use_handle_name = GNUNET_YES;
  }

  if (! entry->sender)
    return;

  set_contact_name (entry->sender, entry->message->body.name.name);
}


static void
handle_key_message (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash,
                    struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (! entry->sender)
    return;

  struct GNUNET_HashCode context;
  get_context_from_member (&(room->key), &(entry->message->header.sender_id),
                           &context);

  struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store (
    room->handle);

  update_store_contact (store, entry->sender, &context, &context,
                        &(entry->message->body.key.key));
}


static void
handle_id_message (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    set_room_sender_id (room, &(entry->message->body.id.id));

  if ((! entry->sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (room->members,
                                                            &(entry->message->
                                                              header.sender_id),
                                                            entry->sender)) ||
      (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (room->members,
                                                        &(entry->message->body.
                                                          id.id),
                                                        entry->sender,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    return;

  struct GNUNET_HashCode context, next_context;
  get_context_from_member (&(room->key), &(entry->message->header.sender_id),
                           &context);
  get_context_from_member (&(room->key), &(entry->message->body.id.id),
                           &next_context);

  struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store (
    room->handle);

  update_store_contact (store, entry->sender, &context, &next_context,
                        get_contact_key (entry->sender));
}


static void
handle_miss_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (0 == (GNUNET_MESSENGER_FLAG_SENT & entry->flags))
    return;

  struct GNUNET_MESSENGER_ListTunnel *match = find_list_tunnels (
    &(room->entries), &(entry->message->body.miss.peer), NULL);

  if (match)
    remove_from_list_tunnels (&(room->entries), match);
}


static void
handle_private_message (struct GNUNET_MESSENGER_Room *room,
                        const struct GNUNET_HashCode *hash,
                        struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  struct GNUNET_MESSENGER_Message *private_message = copy_message (
    entry->message);

  if (! private_message)
    return;

  if (GNUNET_YES != decrypt_message (private_message,
                                     get_handle_key (room->handle)))
  {
    destroy_message (private_message);
    private_message = NULL;
  }

  if (! private_message)
    return;

  destroy_message (entry->message);

  entry->recipient = get_handle_contact (room->handle, &(room->key));

  entry->message = private_message;
  entry->flags |= GNUNET_MESSENGER_FLAG_PRIVATE;

  if ((entry->sender) && (entry->recipient))
    handle_message (room, hash, entry);
}


extern void
delete_message_in_room (struct GNUNET_MESSENGER_Room *room,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_TIME_Relative delay);


static void
handle_delete_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  const struct GNUNET_HashCode *target_hash =
    &(entry->message->body.deletion.hash);

  if (get_handle_contact (room->handle, &(room->key)) == entry->sender)
  {
    struct GNUNET_TIME_Relative delay;
    struct GNUNET_TIME_Absolute action;

    delay = GNUNET_TIME_relative_ntoh (entry->message->body.deletion.delay);

    action = GNUNET_TIME_absolute_ntoh (entry->message->header.timestamp);
    action = GNUNET_TIME_absolute_add (action, delay);

    delay = GNUNET_TIME_absolute_get_difference (GNUNET_TIME_absolute_get (),
                                                 action);

    link_room_deletion (room, target_hash, delay, delete_message_in_room);
  }

  struct GNUNET_MESSENGER_RoomMessageEntry *target =
    GNUNET_CONTAINER_multihashmap_get (room->messages, target_hash);

  if (! target)
    return;

  if (((target->sender != entry->sender) &&
       (get_handle_contact (room->handle, &(room->key)) != entry->sender)))
    return;

  target->flags |= GNUNET_MESSENGER_FLAG_DELETE;
  callback_room_message (room, target_hash);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (room->messages,
                                                          target_hash,
                                                          target))
  {
    destroy_message (target->message);
    GNUNET_free (target);
  }
}


static void
handle_transcript_message (struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_HashCode *hash,
                           struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (get_handle_contact (room->handle, &(room->key)) != entry->sender)
    return;

  const struct GNUNET_HashCode *original_hash =
    &(entry->message->body.transcript.hash);
  struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store (
    room->handle);

  struct GNUNET_MESSENGER_RoomMessageEntry *original =
    GNUNET_CONTAINER_multihashmap_get (room->messages, original_hash);
  struct GNUNET_MESSENGER_Message *original_message;

  if (original)
    goto read_transcript;

  original = GNUNET_new (struct GNUNET_MESSENGER_RoomMessageEntry);

  if (! original)
    return;

  original->sender = NULL;
  original->recipient = NULL;

  original->message = NULL;
  original->flags = GNUNET_MESSENGER_FLAG_NONE;
  original->completed = GNUNET_NO;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->messages,
                                                      original_hash,
                                                      original,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free (original);
    return;
  }

read_transcript:
  original_message = copy_message (entry->message);

  if (! original_message)
    return;

  if (GNUNET_YES != read_transcript_message (original_message))
  {
    destroy_message (original_message);
    return;
  }

  original->recipient = get_store_contact (store,
                                           NULL,
                                           &(entry->message->body.transcript.key));

  if (original->message)
  {
    if (GNUNET_MESSENGER_KIND_PRIVATE == original->message->header.kind)
      original->flags |= GNUNET_MESSENGER_FLAG_PRIVATE;

    copy_message_header (original_message, &(original->message->header));
    destroy_message (original->message);
  }

  original->message = original_message;

  link_room_message (room, hash, original_hash);
  link_room_message (room, original_hash, hash);

  if ((original->sender) && (original->recipient))
  {
    original->flags |= GNUNET_MESSENGER_FLAG_UPDATE;
    handle_message (room, original_hash, original);
  }
}


static void
handle_message (struct GNUNET_MESSENGER_Room *room,
                const struct GNUNET_HashCode *hash,
                struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  switch (entry->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    handle_join_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    handle_leave_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    handle_name_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    handle_key_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    handle_id_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    handle_miss_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    handle_private_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    handle_delete_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    handle_transcript_message (room, hash, entry);
    break;
  default:
    break;
  }

  if (entry->flags & GNUNET_MESSENGER_FLAG_UPDATE)
    callback_room_message (room, hash);
}


void
handle_room_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash,
                     enum GNUNET_MESSENGER_MessageFlags flags)
{
  GNUNET_assert ((room) && (message) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry;
  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (entry)
    goto update_entry;

  entry = GNUNET_new (struct GNUNET_MESSENGER_RoomMessageEntry);

  if (! entry)
    return;

  entry->sender = NULL;
  entry->recipient = NULL;

  entry->message = NULL;
  entry->flags = GNUNET_MESSENGER_FLAG_NONE;
  entry->completed = GNUNET_NO;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->messages, hash,
                                                      entry,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free (entry);
    return;
  }

update_entry:
  entry->sender = sender;
  entry->flags = flags;

  if (entry->message)
  {
    if (GNUNET_MESSENGER_KIND_PRIVATE == message->header.kind)
      entry->flags |= GNUNET_MESSENGER_FLAG_PRIVATE;

    copy_message_header (entry->message, &(message->header));
  }
  else
    entry->message = copy_message (message);

  entry->completed = GNUNET_YES;

  handle_message (room, hash, entry);
}


void
update_room_last_message (struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  GNUNET_memcpy (&(room->last_message), hash, sizeof(room->last_message));
}


struct GNUNET_MESSENGER_MemberCall
{
  struct GNUNET_MESSENGER_Room *room;
  GNUNET_MESSENGER_MemberCallback callback;
  void *cls;
};

static enum GNUNET_GenericReturnValue
iterate_local_members (void *cls,
                       const struct GNUNET_ShortHashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_MemberCall *call = cls;
  struct GNUNET_MESSENGER_Contact *contact = value;

  return call->callback (call->cls, call->room, contact);
}


int
iterate_room_members (struct GNUNET_MESSENGER_Room *room,
                      GNUNET_MESSENGER_MemberCallback callback,
                      void *cls)
{
  GNUNET_assert (room);

  if (! callback)
    return GNUNET_CONTAINER_multishortmap_iterate (room->members, NULL, NULL);

  struct GNUNET_MESSENGER_MemberCall call;

  call.room = room;
  call.callback = callback;
  call.cls = cls;

  GNUNET_assert (callback);

  return GNUNET_CONTAINER_multishortmap_iterate (room->members,
                                                 iterate_local_members,
                                                 &call);
}


struct GNUNET_MESSENGER_MemberFind
{
  const struct GNUNET_MESSENGER_Contact *contact;
  enum GNUNET_GenericReturnValue result;
};

static enum GNUNET_GenericReturnValue
iterate_find_member (void *cls,
                     const struct GNUNET_ShortHashCode *key,
                     void *value)
{
  struct GNUNET_MESSENGER_MemberFind *find = cls;
  struct GNUNET_MESSENGER_Contact *contact = value;

  if (contact == find->contact)
  {
    find->result = GNUNET_YES;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
find_room_member (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert (room);

  struct GNUNET_MESSENGER_MemberFind find;

  find.contact = contact;
  find.result = GNUNET_NO;

  GNUNET_CONTAINER_multishortmap_iterate (room->members, iterate_find_member,
                                          &find);

  return find.result;
}


static enum GNUNET_GenericReturnValue
find_linked_hash (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
{
  const struct GNUNET_HashCode **result = cls;
  struct GNUNET_HashCode *hash = value;

  if (0 == GNUNET_CRYPTO_hash_cmp (hash, *result))
  {
    *result = NULL;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


void
link_room_message (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   const struct GNUNET_HashCode *other)
{
  GNUNET_assert ((room) && (hash) && (other));

  const struct GNUNET_HashCode **result = &other;
  GNUNET_CONTAINER_multihashmap_get_multiple (room->links, hash,
                                              find_linked_hash, result);

  if (! *result)
    return;

  struct GNUNET_HashCode *value = GNUNET_memdup (other, sizeof(struct
                                                               GNUNET_HashCode));
  if (! value)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->links, hash, value,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
    GNUNET_free (value);
}


struct GNUNET_MESSENGER_RoomLinkDeletionInfo
{
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_TIME_Relative delay;
  GNUNET_MESSENGER_RoomLinkDeletion deletion;
};


static enum GNUNET_GenericReturnValue
clear_linked_hash (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct GNUNET_HashCode **linked = cls;
  struct GNUNET_HashCode *hash = value;

  if (0 != GNUNET_CRYPTO_hash_cmp (*linked, hash))
    return GNUNET_YES;

  *linked = hash;
  return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
delete_linked_hash (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_RoomLinkDeletionInfo *info = cls;
  struct GNUNET_HashCode *hash = value;

  struct GNUNET_HashCode key_value;
  GNUNET_memcpy (&key_value, key, sizeof (key_value));

  struct GNUNET_HashCode *linked = &key_value;

  GNUNET_CONTAINER_multihashmap_get_multiple (info->room->links, hash,
                                              clear_linked_hash, &linked);

  if ((linked != &key_value) &&
      (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (info->room->links,
                                                           hash, linked)))
    GNUNET_free (linked);

  if (info->deletion)
    info->deletion (info->room, hash, info->delay);

  GNUNET_free (hash);
  return GNUNET_YES;
}


void
link_room_deletion (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash,
                    const struct GNUNET_TIME_Relative delay,
                    GNUNET_MESSENGER_RoomLinkDeletion deletion)
{
  GNUNET_assert ((room) && (hash));

  struct GNUNET_MESSENGER_RoomLinkDeletionInfo info;
  info.room = room;
  info.delay = delay;
  info.deletion = deletion;

  GNUNET_CONTAINER_multihashmap_get_multiple (room->links, hash,
                                              delete_linked_hash, &info);
  GNUNET_CONTAINER_multihashmap_remove_all (room->links, hash);
}
