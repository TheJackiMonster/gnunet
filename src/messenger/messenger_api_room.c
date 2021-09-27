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
 * @file src/messenger/messenger_api_room.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_room.h"

#include "messenger_api_handle.h"

struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle,
             const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_new(struct GNUNET_MESSENGER_Room);

  room->handle = handle;
  GNUNET_memcpy(&(room->key), key, sizeof(*key));

  room->opened = GNUNET_NO;
  room->contact_id = NULL;

  init_list_tunnels (&(room->entries));

  room->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  room->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);

  return room;
}

static int
iterate_destroy_message (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry = value;

  destroy_message (entry->message);
  GNUNET_free(entry);

  return GNUNET_YES;
}

void
destroy_room (struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert(room);

  clear_list_tunnels (&(room->entries));

  if (room->messages)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->messages, iterate_destroy_message, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->messages);
  }

  if (room->members)
    GNUNET_CONTAINER_multishortmap_destroy (room->members);

  if (room->contact_id)
    GNUNET_free(room->contact_id);

  GNUNET_free(room);
}

const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((room) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry = GNUNET_CONTAINER_multihashmap_get (
      room->messages, hash
  );

  return (entry? entry->message : NULL);
}

struct GNUNET_MESSENGER_Contact*
get_room_sender (const struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((room) && (hash));

  struct GNUNET_MESSENGER_RoomMessageEntry *entry = GNUNET_CONTAINER_multihashmap_get (
      room->messages, hash
  );

  return (entry? entry->sender : NULL);
}

static struct GNUNET_MESSENGER_Contact*
handle_join_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if (!sender)
  {
    struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store(room->handle);
    struct GNUNET_HashCode context;

    get_context_from_member(&(room->key), &(message->header.sender_id), &context);

    sender = get_store_contact(store, &context, &(message->body.join.key));
  }

  if ((GNUNET_YES != GNUNET_CONTAINER_multishortmap_contains_value(room->members, &(message->header.sender_id), sender)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multishortmap_put(room->members, &(message->header.sender_id), sender,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    increase_contact_rc(sender);

  return sender;
}

static void
handle_leave_message (struct GNUNET_MESSENGER_Room *room,
                      struct GNUNET_MESSENGER_Contact *sender,
                      const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  if ((!sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove(room->members, &(message->header.sender_id), sender)))
    return;

  struct GNUNET_HashCode context;
  get_context_from_member(&(room->key), &(message->header.sender_id), &context);

  if (GNUNET_YES == decrease_contact_rc(sender))
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "A contact does not share any room with you anymore!\n");
}

static void
handle_name_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if (!sender)
    return;

  set_contact_name (sender, message->body.name.name);
}

static void
handle_key_message (struct GNUNET_MESSENGER_Room *room,
                    struct GNUNET_MESSENGER_Contact *sender,
                    const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  if (!sender)
    return;

  struct GNUNET_HashCode context;
  get_context_from_member(&(room->key), &(message->header.sender_id), &context);

  struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store(room->handle);

  update_store_contact(store, sender, &context, &context, &(message->body.key.key));
}

static void
handle_id_message (struct GNUNET_MESSENGER_Room *room,
                   struct GNUNET_MESSENGER_Contact *sender,
                   const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  if ((!sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove(room->members, &(message->header.sender_id), sender)) ||
      (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put(room->members, &(message->body.id.id), sender,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    return;

  struct GNUNET_HashCode context, next_context;
  get_context_from_member(&(room->key), &(message->header.sender_id), &context);
  get_context_from_member(&(room->key), &(message->body.id.id), &next_context);

  struct GNUNET_MESSENGER_ContactStore *store = get_handle_contact_store(room->handle);

  update_store_contact(store, sender, &context, &next_context, get_contact_key(sender));
}

static void
handle_miss_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if ((room->contact_id) && (0 == GNUNET_memcmp(&(message->header.sender_id), room->contact_id)))
  {
    struct GNUNET_MESSENGER_ListTunnel *match = find_list_tunnels (&(room->entries), &(message->body.miss.peer), NULL);

    if (match)
      remove_from_list_tunnels (&(room->entries), match);
  }
}

static void
handle_delete_message (struct GNUNET_MESSENGER_Room *room,
                       struct GNUNET_MESSENGER_Contact *sender,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry = GNUNET_CONTAINER_multihashmap_get (
      room->messages, &(message->body.deletion.hash)
  );

  if ((entry) && ((entry->sender == sender) || (get_handle_contact (room->handle, &(room->key)) == sender)) &&
      (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (room->messages, &(message->body.deletion.hash), entry)))
  {
    destroy_message (entry->message);
    GNUNET_free(entry);
  }
}

struct GNUNET_MESSENGER_Contact*
handle_room_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains (room->messages, hash))
    return sender;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    sender = handle_join_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    handle_leave_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    handle_name_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    handle_key_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    handle_id_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    handle_miss_message (room, sender, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_DELETE:
    handle_delete_message (room, sender, message, hash);
    break;
  default:
    break;
  }

  struct GNUNET_MESSENGER_RoomMessageEntry *entry = GNUNET_new(struct GNUNET_MESSENGER_RoomMessageEntry);

  if (!entry)
    return sender;

  entry->sender = sender;
  entry->message = copy_message (message);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->messages, hash, entry,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_message (entry->message);
    GNUNET_free(entry);
  }

  return sender;
}

struct GNUNET_MESSENGER_MemberCall
{
  struct GNUNET_MESSENGER_Room *room;
  GNUNET_MESSENGER_MemberCallback callback;
  void *cls;
};

static int
iterate_local_members (void* cls,
                       const struct GNUNET_ShortHashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_MemberCall *call = cls;
  struct GNUNET_MESSENGER_Contact *contact = value;

  return call->callback(call->cls, call->room, contact);
}

int
iterate_room_members (struct GNUNET_MESSENGER_Room *room,
                      GNUNET_MESSENGER_MemberCallback callback,
                      void* cls)
{
  GNUNET_assert(room);

  if (!callback)
    return GNUNET_CONTAINER_multishortmap_iterate(room->members, NULL, NULL);

  struct GNUNET_MESSENGER_MemberCall call;

  call.room = room;
  call.callback = callback;
  call.cls = cls;

  GNUNET_assert(callback);

  return GNUNET_CONTAINER_multishortmap_iterate(room->members, iterate_local_members, &call);
}

struct GNUNET_MESSENGER_MemberFind
{
  const struct GNUNET_MESSENGER_Contact *contact;
  int result;
};

static int
iterate_find_member (void* cls,
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

int
find_room_member (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_MESSENGER_Contact *contact)
{
  GNUNET_assert(room);

  struct GNUNET_MESSENGER_MemberFind find;

  find.contact = contact;
  find.result = GNUNET_NO;

  GNUNET_CONTAINER_multishortmap_iterate(room->members, iterate_find_member, &find);

  return find.result;
}
