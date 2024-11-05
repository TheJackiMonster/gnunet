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
 * @file src/messenger/messenger_api_room.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_room.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"

#include "messenger_api.h"
#include "messenger_api_contact_store.h"
#include "messenger_api_epoch.h"
#include "messenger_api_epoch_announcement.h"
#include "messenger_api_epoch_group.h"
#include "messenger_api_handle.h"
#include "messenger_api_message.h"
#include "messenger_api_message_control.h"
#include "messenger_api_message_kind.h"

#include <stdint.h>
#include <string.h>

struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle,
             const union GNUNET_MESSENGER_RoomKey *key)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((handle) && (key));

  room = GNUNET_new (struct GNUNET_MESSENGER_Room);
  room->handle = handle;

  GNUNET_memcpy (&(room->key), key, sizeof(*key));

  memset (&(room->last_message), 0, sizeof(room->last_message));
  memset (&(room->last_epoch), 0, sizeof(room->last_epoch));

  room->joined = GNUNET_NO;
  room->opened = GNUNET_NO;
  room->use_handle_name = GNUNET_YES;
  room->wait_for_sync = GNUNET_NO;

  room->sender_id = NULL;

  init_list_tunnels (&(room->entries));

  room->actions = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  room->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  room->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
  room->links = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  room->subscriptions = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
  room->epochs = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  room->requests = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_queue_messages (&(room->queue));
  room->queue_task = NULL;

  room->request_task = NULL;

  room->control = create_message_control (room);

  return room;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_action (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_MESSENGER_RoomAction *action;

  GNUNET_assert (value);

  action = value;

  if (action->task)
    GNUNET_SCHEDULER_cancel (action->task);

  GNUNET_free (action);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_message (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert (value);

  entry = value;

  destroy_message (entry->message);
  GNUNET_free (entry);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_link (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_HashCode *hash;

  GNUNET_assert (value);

  hash = value;

  GNUNET_free (hash);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_subscription (void *cls,
                              const struct GNUNET_ShortHashCode *key,
                              void *value)
{
  struct GNUNET_MESSENGER_RoomSubscription *subscription;

  GNUNET_assert (value);

  subscription = value;

  if (subscription->task)
    GNUNET_SCHEDULER_cancel (subscription->task);

  if (subscription->message)
    destroy_message (subscription->message);

  GNUNET_free (subscription);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_epoch (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert (value);

  epoch = value;

  destroy_epoch (epoch);
  return GNUNET_YES;
}


void
destroy_room (struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  destroy_message_control (room->control);

  if (room->actions)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->actions,
                                           iterate_destroy_action, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->actions);
  }

  if (room->request_task)
    GNUNET_SCHEDULER_cancel (room->request_task);

  if (room->queue_task)
    GNUNET_SCHEDULER_cancel (room->queue_task);

  clear_queue_messages (&(room->queue));
  clear_list_tunnels (&(room->entries));

  if (room->requests)
    GNUNET_CONTAINER_multihashmap_destroy (room->requests);

  if (room->epochs)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->epochs,
                                           iterate_destroy_epoch,
                                           NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->epochs);
  }

  if (room->subscriptions)
  {
    GNUNET_CONTAINER_multishortmap_iterate (room->subscriptions,
                                            iterate_destroy_subscription,
                                            NULL);

    GNUNET_CONTAINER_multishortmap_destroy (room->subscriptions);
  }

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


const struct GNUNET_HashCode*
get_room_key (const struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  return &(room->key.hash);
}


enum GNUNET_GenericReturnValue
is_room_public (const struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  return room->key.code.public_bit? GNUNET_YES : GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
is_message_entry_recent (const struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert (entry);

  if (GNUNET_MESSENGER_FLAG_RECENT & entry->flags)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static struct GNUNET_MESSENGER_Epoch*
get_room_availble_epoch_entry (struct GNUNET_MESSENGER_Room *room,
                               const struct GNUNET_HashCode *hash,
                               const struct GNUNET_MESSENGER_RoomMessageEntry *
                               entry,
                               const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_MESSENGER_Epoch *room_epoch;

  GNUNET_assert ((room) && (hash) && (entry));

  room_epoch = get_room_epoch (
    room, &(entry->epoch),
    is_message_entry_recent (entry));

  if (! room_epoch)
    return NULL;

  if (GNUNET_YES == delay_epoch_message_for_its_members (room_epoch, hash))
    return NULL;

  if (GNUNET_NO == is_epoch_member (
        room_epoch,
        get_handle_contact (room->handle, get_room_key (room))))
    return NULL;

  if (GNUNET_NO == is_epoch_member (
        room_epoch, contact? contact : entry->sender))
    return NULL;

  return room_epoch;
}


static void
handle_room_delayed_deletion (struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_HashCode *hash,
                              const struct GNUNET_MESSENGER_RoomMessageEntry *
                              entry)
{
  const struct GNUNET_HashCode *target_hash;
  struct GNUNET_MESSENGER_RoomMessageEntry *target;

  target_hash = &(entry->message->body.deletion.hash);

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
  {
    struct GNUNET_TIME_Relative delay;

    delay = get_message_timeout (entry->message);

    link_room_deletion (room, target_hash, delay, delete_room_message);
  }

  target = GNUNET_CONTAINER_multihashmap_get (room->messages, target_hash);
  if (! target)
    return;

  if ((target->sender != entry->sender) &&
      (! (GNUNET_MESSENGER_FLAG_SENT & entry->flags)))
    return;

  target->flags |= GNUNET_MESSENGER_FLAG_DELETE;
  callback_room_message (room, target_hash);

  switch (target->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    {
      struct GNUNET_MESSENGER_Epoch *epoch;
      struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

      epoch = get_room_message_epoch (room, target_hash);

      if (! epoch)
        break;

      announcement = get_epoch_announcement (
        epoch,
        &(target->message->body.announcement.identifier),
        GNUNET_NO);

      if (! announcement)
        break;

      revoke_epoch_announcement_member (
        announcement,
        target_hash,
        target->message,
        target->sender);
      break;
    }
  default:
    break;
  }

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (
        room->messages, target_hash, target))
  {
    destroy_message (target->message);
    GNUNET_free (target);
  }
}


static void
handle_room_delayed_announcement (struct GNUNET_MESSENGER_Room *room,
                                  const struct GNUNET_HashCode *hash,
                                  const struct
                                  GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  enum GNUNET_GenericReturnValue sent;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, NULL);

  if (! epoch)
    return;

  identifier = &(entry->message->body.announcement.identifier);

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    sent = GNUNET_YES;
  else
    sent = GNUNET_NO;

  if (identifier->code.group_bit)
  {
    struct GNUNET_MESSENGER_EpochGroup *group;

    group = get_epoch_group (epoch, identifier, GNUNET_NO);

    if (! group)
      return;

    handle_epoch_group_announcement_delay (
      group,
      entry->message,
      hash,
      entry->sender,
      sent);
  }
  else
  {
    struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

    announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

    if (! announcement)
      return;

    handle_epoch_announcement_delay (
      announcement,
      entry->message,
      hash,
      entry->sender,
      sent);
  }
}


static void
handle_room_delayed_appeal (struct GNUNET_MESSENGER_Room *room,
                            const struct GNUNET_HashCode *hash,
                            const struct GNUNET_MESSENGER_RoomMessageEntry *
                            entry)
{
  const struct GNUNET_MESSENGER_RoomMessageEntry *event_entry;
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;

  GNUNET_assert ((room) && (hash) && (entry));

  event_entry = GNUNET_CONTAINER_multihashmap_get (
    room->messages, &(entry->message->body.appeal.event));

  if (! event_entry)
    return;

  if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != event_entry->message->header.kind)
    return;

  epoch = get_room_availble_epoch_entry (
    room, hash, event_entry, entry->sender);

  if (! epoch)
    return;

  identifier = &(event_entry->message->body.announcement.identifier);

  if (identifier->code.group_bit)
    return;

  announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

  if (! announcement)
    return;

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    return;

  if (GNUNET_YES != is_epoch_member (epoch, entry->sender))
    return;

  if (GNUNET_YES == is_epoch_announcement_member (announcement, entry->sender))
    return;

  key = get_epoch_announcement_key (announcement);

  if (! key)
    return;

  send_epoch_announcement_access (announcement, hash);
}


static void
handle_room_delayed_action (struct GNUNET_MESSENGER_Room *room,
                            const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (! entry->message))
    return;

  if ((entry->flags & GNUNET_MESSENGER_FLAG_UPDATE) ||
      (entry->flags & GNUNET_MESSENGER_FLAG_DELETE))
    goto skip_delayed_handling;

  switch (entry->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_DELETION:
    handle_room_delayed_deletion (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    handle_room_delayed_announcement (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    handle_room_delayed_appeal (room, hash, entry);
    break;
  default:
    break;
  }

skip_delayed_handling:
  if (entry->flags & GNUNET_MESSENGER_FLAG_UPDATE)
    callback_room_message (room, hash);
}


static void
handle_room_action_task (void *cls)
{
  struct GNUNET_MESSENGER_RoomAction *action;
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (cls);

  action = cls;
  action->task = NULL;

  room = action->room;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (
        room->actions, &(action->hash), action))
    handle_room_delayed_action (room, &(action->hash));

  GNUNET_free (action);
}


void
delay_room_action (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   const struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_MESSENGER_RoomAction *action;

  GNUNET_assert ((room) && (hash));

  action = GNUNET_new (struct GNUNET_MESSENGER_RoomAction);

  if (! action)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        room->actions, hash, action,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE))
  {
    GNUNET_free (action);
    return;
  }

  GNUNET_memcpy (&(action->hash), hash, sizeof(action->hash));

  action->room = room;
  action->task = GNUNET_SCHEDULER_add_delayed_with_priority (
    delay,
    GNUNET_SCHEDULER_PRIORITY_HIGH,
    handle_room_action_task,
    action);
}


void
cancel_room_action (struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (room->actions, hash)
      )
    return;

  GNUNET_CONTAINER_multihashmap_get_multiple (room->actions, hash,
                                              iterate_destroy_action, NULL);
  GNUNET_CONTAINER_multihashmap_remove_all (room->actions, hash);
}


struct GNUNET_MESSENGER_RoomCancelAction
{
  enum GNUNET_MESSENGER_MessageKind kind;
  const struct GNUNET_HashCode *epoch_hash;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  const struct GNUNET_MESSENGER_Contact *contact;

  struct GNUNET_CONTAINER_MultiHashMap *map;
};

static enum GNUNET_GenericReturnValue
iterate_cancel_action_by (void *cls,
                          const struct GNUNET_HashCode *hash,
                          void *value)
{
  struct GNUNET_MESSENGER_RoomCancelAction *cancel;
  struct GNUNET_MESSENGER_RoomAction *action;
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((cls) && (hash) && (value));

  cancel = cls;
  action = value;
  room = action->room;

  message = get_room_message (room, hash);

  if ((! message) || (message->header.kind != cancel->kind))
    return GNUNET_YES;

  if (cancel->epoch_hash)
  {
    const struct GNUNET_MESSENGER_Epoch *epoch;

    epoch = get_room_message_epoch (room, hash);

    if ((! epoch) || (0 != GNUNET_CRYPTO_hash_cmp (&(epoch->hash), cancel->
                                                   epoch_hash)))
      return GNUNET_YES;
  }

  if (cancel->identifier)
  {
    const union GNUNET_MESSENGER_EpochIdentifier *identifier;

    identifier = get_room_message_epoch_identifier (room, hash);

    if ((! identifier) || (0 != GNUNET_memcmp (identifier, cancel->identifier)))
      return GNUNET_YES;
  }

  if ((cancel->contact) && (cancel->contact != get_room_sender (room, hash)))
    return GNUNET_YES;

  GNUNET_CONTAINER_multihashmap_put (cancel->map, hash, NULL,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_cancel_action (void *cls,
                       const struct GNUNET_HashCode *hash,
                       void *value)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (hash));

  room = cls;

  cancel_room_action (room, hash);
  return GNUNET_YES;
}


void
cancel_room_actions_by (struct GNUNET_MESSENGER_Room *room,
                        enum GNUNET_MESSENGER_MessageKind kind,
                        const struct GNUNET_HashCode *epoch_hash,
                        const union GNUNET_MESSENGER_EpochIdentifier *identifier
                        ,
                        const struct GNUNET_MESSENGER_Contact *contact)
{
  struct GNUNET_MESSENGER_RoomCancelAction cancel;

  GNUNET_assert (room);

  cancel.kind = kind;
  cancel.epoch_hash = epoch_hash;
  cancel.identifier = identifier;
  cancel.contact = contact;

  cancel.map = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  if (! cancel.map)
    return;

  GNUNET_CONTAINER_multihashmap_iterate (room->actions,
                                         iterate_cancel_action_by,
                                         &cancel);

  GNUNET_CONTAINER_multihashmap_iterate (cancel.map,
                                         iterate_cancel_action,
                                         room);

  GNUNET_CONTAINER_multihashmap_destroy (cancel.map);
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


struct GNUNET_MESSENGER_Handle*
get_room_handle (struct GNUNET_MESSENGER_Room *room)
{
  GNUNET_assert (room);

  return room->handle;
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
              GNUNET_h2s (get_room_key (room)));

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


struct GNUNET_MESSENGER_Epoch*
get_room_epoch (struct GNUNET_MESSENGER_Room *room,
                const struct GNUNET_HashCode *hash,
                enum GNUNET_GenericReturnValue recent)
{
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert ((room) && (hash));

  if (GNUNET_is_zero (hash))
    return NULL;

  epoch = GNUNET_CONTAINER_multihashmap_get (room->epochs, hash);

  if (epoch)
    return epoch;

  if (GNUNET_YES == recent)
    epoch = create_new_epoch (room, hash);
  else
    epoch = create_epoch (room, hash);

  if (! epoch)
    return NULL;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->epochs,
                                                      hash,
                                                      epoch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_epoch (epoch);
    return NULL;
  }

  return epoch;
}


void
generate_room_epoch_announcement (struct GNUNET_MESSENGER_Room *room,
                                  struct GNUNET_MESSENGER_Epoch *epoch,
                                  struct GNUNET_MESSENGER_EpochAnnouncement **
                                  announcement)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *epoch_announcement;

  GNUNET_assert ((room) && (epoch) && (announcement) && (! (*announcement)));

  epoch_announcement = create_epoch_announcement (epoch, NULL, GNUNET_YES);

  if (! epoch_announcement)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (epoch->announcements,
                                                       &(epoch_announcement->
                                                         identifier.hash),
                                                       epoch_announcement,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_epoch_announcement (epoch_announcement);
    return;
  }

  if (! get_epoch_announcement_key (epoch_announcement))
    set_epoch_announcement_key (epoch_announcement, NULL, GNUNET_YES);

  *announcement = epoch_announcement;

  send_epoch_announcement (epoch_announcement);
}


struct GNUNET_MESSENGER_Epoch*
get_room_message_epoch (struct GNUNET_MESSENGER_Room *room,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (! entry)
    return NULL;

  return get_room_epoch (room, &(entry->epoch),
                         is_message_entry_recent (entry));
}


const union GNUNET_MESSENGER_EpochIdentifier*
get_room_message_epoch_identifier (const struct GNUNET_MESSENGER_Room *room,
                                   const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (! entry->message))
    return NULL;

  switch (entry->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    return &(entry->message->body.announcement.identifier);
  case GNUNET_MESSENGER_KIND_SECRET:
    return &(entry->message->body.secret.identifier);
  case GNUNET_MESSENGER_KIND_APPEAL:
    return get_room_message_epoch_identifier (room,
                                              &(entry->message->body.appeal.
                                                event));
  case GNUNET_MESSENGER_KIND_ACCESS:
    return get_room_message_epoch_identifier (room,
                                              &(entry->message->body.access.
                                                event));
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    return &(entry->message->body.revolution.identifier);
  case GNUNET_MESSENGER_KIND_GROUP:
    return &(entry->message->body.group.identifier);
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    return &(entry->message->body.authorization.identifier);
  default:
    return NULL;
  }
}


const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room,
                  const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  if (! (room->messages))
    return NULL;

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->message;
}


enum GNUNET_GenericReturnValue
is_room_message_sent (const struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (! entry)
    return GNUNET_SYSERR;

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


struct GNUNET_MESSENGER_Contact*
get_room_sender (const struct GNUNET_MESSENGER_Room *room,
                 const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->sender;
}


struct GNUNET_MESSENGER_Contact*
get_room_recipient (const struct GNUNET_MESSENGER_Room *room,
                    const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (GNUNET_YES != entry->completed))
    return NULL;

  return entry->recipient;
}


const struct GNUNET_HashCode*
get_room_epoch_hash (const struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (! entry)
    return NULL;

  return &(entry->epoch);
}


void
delete_room_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     const struct GNUNET_TIME_Relative delay)
{
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((room) && (hash));

  message = create_message_deletion (hash, delay);

  if (! message)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Sending deletion aborted: Message creation failed!\n");
    return;
  }

  enqueue_message_to_room (room, NULL, message, NULL, GNUNET_NO);
}


void
callback_room_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  handle = room->handle;
  if (! handle)
    return;

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


static enum GNUNET_GenericReturnValue
is_epoch_identifier_upper (const union GNUNET_MESSENGER_EpochIdentifier *
                           identifier,
                           const union GNUNET_MESSENGER_EpochIdentifier *other)
{
  uint32_t level, other_level;

  GNUNET_assert ((identifier) && (other));

  level = (uint32_t) identifier->code.level_bits;
  other_level = (uint32_t) other->code.level_bits;

  if (level > other_level)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
iterate_room_request (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((cls) && (key));

  room = cls;
  request_message_from_room (room, key);

  return GNUNET_YES;
}


static void
handle_room_request_task (void *cls)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (cls);

  room = cls;
  room->request_task = NULL;

  if ((GNUNET_YES != room->joined) || (! get_room_sender_id (room)))
  {
    struct GNUNET_TIME_Relative delay;
    delay = GNUNET_TIME_relative_get_millisecond_ ();
    delay = GNUNET_TIME_relative_multiply (delay, 100);

    room->request_task = GNUNET_SCHEDULER_add_delayed_with_priority (
      delay,
      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
      handle_room_request_task,
      room);
    return;
  }

  GNUNET_CONTAINER_multihashmap_iterate (
    room->requests,
    iterate_room_request,
    room);

  GNUNET_CONTAINER_multihashmap_clear (room->requests);
}


void
require_message_from_room (struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((room) && (hash));

  if (GNUNET_is_zero (hash))
    return;

  if (get_room_message (room, hash))
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        room->requests,
        hash, NULL,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE))
    return;

  if (room->request_task)
    return;

  room->request_task = GNUNET_SCHEDULER_add_with_priority (
    GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
    handle_room_request_task,
    room);
}


static void
handle_message (struct GNUNET_MESSENGER_Room *room,
                const struct GNUNET_HashCode *hash,
                struct GNUNET_MESSENGER_RoomMessageEntry *entry);


static void
handle_join_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (! entry->sender)
  {
    struct GNUNET_MESSENGER_ContactStore *store;
    struct GNUNET_HashCode context;

    store = get_handle_contact_store (room->handle);

    get_context_from_member (get_room_key (room),
                             &(entry->message->header.sender_id),
                             &context);

    entry->sender = get_store_contact (store, &context,
                                       &(entry->message->body.join.key));
  }

  if ((GNUNET_YES != GNUNET_CONTAINER_multishortmap_contains_value (
         room->members, &(entry->message->header.sender_id), entry->sender)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multishortmap_put (
         room->members,
         &(entry->message->header.sender_id),
         entry->sender,
         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    increase_contact_rc (entry->sender);

  if ((get_room_sender_id (room)) &&
      (0 == GNUNET_memcmp (&(entry->message->header.sender_id),
                           get_room_sender_id (room))) &&
      (0 == GNUNET_memcmp (&(entry->message->body.join.key), get_handle_pubkey (
                             room->handle))))
    room->joined = GNUNET_YES;

  require_message_from_room (room, &(entry->message->body.join.epoch));
}


static enum GNUNET_GenericReturnValue
iterate_room_epoch_member_invalidation (void *cls,
                                        const struct GNUNET_HashCode *key,
                                        void *value)
{
  struct GNUNET_MESSENGER_Contact *contact;
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert ((cls) && (value));

  contact = cls;
  epoch = value;

  invalidate_epoch_keys_by_member (epoch, contact);
  return GNUNET_YES;
}


static void
handle_leave_message (struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *hash,
                      struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if ((! entry->sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (
         room->members,
         &(entry->message->header.sender_id),
         entry->sender)))
    return;

  if (GNUNET_MESSENGER_FLAG_RECENT & entry->flags)
    GNUNET_CONTAINER_multihashmap_iterate (
      room->epochs, iterate_room_epoch_member_invalidation,
      entry->sender);

  if (GNUNET_YES == decrease_contact_rc (entry->sender))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "A contact does not share any room with you anymore!\n");

  require_message_from_room (room, &(entry->message->body.leave.epoch));
}


static void
handle_name_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
  {
    const char *handle_name;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Set rule for using handle name in room: %s\n",
                GNUNET_h2s (get_room_key (room)));

    handle_name = get_handle_name (room->handle);

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
  struct GNUNET_HashCode context;
  struct GNUNET_MESSENGER_ContactStore *store;

  GNUNET_assert ((room) && (hash) && (entry));

  if (! entry->sender)
    return;

  get_context_from_member (
    get_room_key (room),
    &(entry->message->header.sender_id),
    &context);

  store = get_handle_contact_store (room->handle);

  update_store_contact (store, entry->sender, &context, &context,
                        &(entry->message->body.key.key));
}


static void
handle_id_message (struct GNUNET_MESSENGER_Room *room,
                   const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_HashCode context, next_context;
  struct GNUNET_MESSENGER_ContactStore *store;

  GNUNET_assert ((room) && (hash) && (entry));

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    set_room_sender_id (room, &(entry->message->body.id.id));

  if ((! entry->sender) ||
      (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (
         room->members, &(entry->message->header.sender_id),
         entry->sender)) ||
      (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (
         room->members, &(entry->message->body.id.id),
         entry->sender,
         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)))
    return;

  get_context_from_member (get_room_key (room), &(entry->message->header.
                                                  sender_id),
                           &context);
  get_context_from_member (get_room_key (room), &(entry->message->body.id.id),
                           &next_context);

  store = get_handle_contact_store (room->handle);

  update_store_contact (store, entry->sender, &context, &next_context,
                        get_contact_key (entry->sender));
}


static void
handle_miss_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash,
                     struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_ListTunnel *match;

  GNUNET_assert ((room) && (hash) && (entry));

  if (0 == (GNUNET_MESSENGER_FLAG_SENT & entry->flags))
    return;

  match = find_list_tunnels (
    &(room->entries),
    &(entry->message->body.miss.peer),
    NULL);

  if (match)
    remove_from_list_tunnels (&(room->entries), match);
}


static void
handle_merge_message (struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *hash,
                      struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  GNUNET_assert ((room) && (hash) && (entry));

  require_message_from_room (room, &(entry->message->body.merge.epochs[0]));
  require_message_from_room (room, &(entry->message->body.merge.epochs[1]));
}


static void
handle_private_message (struct GNUNET_MESSENGER_Room *room,
                        const struct GNUNET_HashCode *hash,
                        struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Message *private_message;

  GNUNET_assert ((room) && (hash) && (entry));

  private_message = copy_message (entry->message);

  if (! private_message)
    return;

  if (GNUNET_YES != decrypt_message (
        private_message, get_handle_key (room->handle)))
  {
    destroy_message (private_message);
    private_message = NULL;
  }

  if (! private_message)
    return;

  destroy_message (entry->message);

  entry->recipient = get_handle_contact (room->handle, get_room_key (room));

  entry->message = private_message;
  entry->flags |= GNUNET_MESSENGER_FLAG_PRIVATE;

  if ((entry->sender) && (entry->recipient))
    handle_message (room, hash, entry);
}


static void
handle_delete_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_TIME_Relative delay;

  GNUNET_assert ((room) && (hash) && (entry));

  delay = get_message_timeout (entry->message);

  delay_room_action (room, hash, delay);
}


static void
handle_transcript_message (struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_HashCode *hash,
                           struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  const struct GNUNET_HashCode *original_hash;
  struct GNUNET_MESSENGER_RoomMessageEntry *original;
  struct GNUNET_MESSENGER_Message *original_message;

  GNUNET_assert ((room) && (hash) && (entry));

  if (! (GNUNET_MESSENGER_FLAG_SENT & entry->flags))
    return;

  original_hash = &(entry->message->body.transcript.hash);

  original = GNUNET_CONTAINER_multihashmap_get (room->messages, original_hash);

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

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        room->messages, original_hash, original,
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

  {
    struct GNUNET_MESSENGER_ContactStore *store;

    store = get_handle_contact_store (room->handle);
    original->recipient = get_store_contact (
      store, NULL,
      &(entry->message->body.transcript.key));
  }

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
handle_announcement_message (struct GNUNET_MESSENGER_Room *room,
                             const struct GNUNET_HashCode *hash,
                             struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochNonce *nonce;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  enum GNUNET_GenericReturnValue sent;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, NULL);

  if (! epoch)
    return;

  nonce = &(entry->message->body.announcement.nonce);

  if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (
        epoch->nonces, &(nonce->hash)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unsafe announcement: Nonce (%s) has already been used in this epoch! [%s]\n",
                GNUNET_sh2s (&(nonce->hash)), GNUNET_h2s (&(epoch->hash)));
    return;
  }

  GNUNET_CONTAINER_multishortmap_put (epoch->nonces, &(nonce->hash), NULL,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  identifier = &(entry->message->body.announcement.identifier);

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    sent = GNUNET_YES;
  else
    sent = GNUNET_NO;

  if (identifier->code.group_bit)
  {
    struct GNUNET_MESSENGER_EpochGroup *group;

    group = get_epoch_group (epoch, identifier, GNUNET_NO);

    if (! group)
      return;

    handle_epoch_group_announcement (
      group,
      entry->message,
      hash,
      entry->sender,
      sent);
  }
  else
  {
    struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

    announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

    if (! announcement)
      return;

    handle_epoch_announcement (
      announcement,
      entry->message,
      hash,
      entry->sender,
      sent);
  }
}


static void
handle_secret_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, NULL);

  if (! epoch)
    return;

  identifier = &(entry->message->body.secret.identifier);

  if (identifier->code.group_bit)
    return;

  announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

  if (! announcement)
    return;

  handle_epoch_announcement_message (
    announcement, entry->message, hash);
}


static void
handle_appeal_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  const struct GNUNET_MESSENGER_RoomMessageEntry *event_entry;
  struct GNUNET_MESSENGER_Epoch *epoch;
  const struct GNUNET_MESSENGER_Contact *contact;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
  struct GNUNET_TIME_Relative timeout;

  GNUNET_assert ((room) && (hash) && (entry));

  event_entry = GNUNET_CONTAINER_multihashmap_get (
    room->messages, &(entry->message->body.appeal.event));

  if (! event_entry)
    return;

  if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != event_entry->message->header.kind)
    return;

  epoch = get_room_availble_epoch_entry (
    room, hash, event_entry, entry->sender);

  if (! epoch)
    return;

  contact = get_handle_contact (room->handle, get_room_key (room));

  if (! contact)
    return;

  if (GNUNET_YES != is_epoch_member (epoch, contact))
    return;

  identifier = &(event_entry->message->body.announcement.identifier);

  if (identifier->code.group_bit)
    return;

  announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

  if (! announcement)
    return;

  if (GNUNET_YES == is_epoch_announcement_member (announcement, entry->sender))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Appealing contact is already member of epoch announcement! [%s]\n",
                GNUNET_sh2s (&(identifier->hash)));
    return;
  }

  if (contact == event_entry->sender)
    timeout = GNUNET_TIME_relative_get_zero_ ();
  else
  {
    timeout = get_message_timeout (entry->message);

    if (GNUNET_TIME_relative_is_zero (timeout))
      return;

    timeout = GNUNET_TIME_relative_multiply_double (
      timeout, get_epoch_position_factor (epoch, contact, NULL));
  }

  if (GNUNET_MESSENGER_FLAG_SENT & entry->flags)
    set_epoch_announcement_appeal (announcement,
                                   get_message_timeout (entry->message));

  delay_room_action (room, hash, timeout);
}


static void
handle_access_message (struct GNUNET_MESSENGER_Room *room,
                       const struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  const struct GNUNET_MESSENGER_RoomMessageEntry *event_entry;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert ((room) && (hash) && (entry));

  if (! (GNUNET_MESSENGER_FLAG_RECENT & entry->flags))
    return;

  event_entry = GNUNET_CONTAINER_multihashmap_get (
    room->messages, &(entry->message->body.access.event));

  if (! event_entry)
    return;

  switch (event_entry->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_APPEAL:
    {
      struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
      enum GNUNET_GenericReturnValue appealed;

      if (GNUNET_MESSENGER_FLAG_SENT & event_entry->flags)
        appealed = GNUNET_YES;
      else
        appealed = GNUNET_NO;

      event_entry = GNUNET_CONTAINER_multihashmap_get (room->messages,
                                                       &(event_entry->message->
                                                         body.appeal.event));

      if (! event_entry)
        return;

      if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != event_entry->message->header.
          kind)
        return;

      identifier = &(event_entry->message->body.announcement.identifier);
      epoch = get_room_availble_epoch_entry (room, hash, event_entry, entry->
                                             sender);

      if (! epoch)
        return;

      announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

      if (! announcement)
        return;

      if (GNUNET_YES != appealed)
      {
        const struct GNUNET_CRYPTO_SymmetricSessionKey *shared_key;

        shared_key = get_epoch_announcement_key (announcement);

        if ((shared_key) && (GNUNET_OK == verify_message_by_key (entry->message,
                                                                 shared_key)))
          cancel_room_action (room, &(entry->message->body.access.event));

        return;
      }

      handle_epoch_announcement_access (announcement, entry->message, hash);
      break;
    }
  case GNUNET_MESSENGER_KIND_GROUP:
    {
      struct GNUNET_MESSENGER_EpochGroup *group;
      const struct GNUNET_HashCode *partner_hash;
      const struct GNUNET_MESSENGER_RoomMessageEntry *init_entry;

      identifier = &(event_entry->message->body.group.identifier);
      epoch = get_room_availble_epoch_entry (room, hash, event_entry, entry->
                                             sender);

      if (! epoch)
        return;

      if ((epoch->main_announcement) &&
          (GNUNET_YES != is_epoch_identifier_upper (identifier, &(epoch->
                                                                  main_announcement
                                                                  ->identifier))
          ))
        return;

      if ((epoch->main_group) &&
          (GNUNET_YES != is_epoch_identifier_upper (identifier, &(epoch->
                                                                  main_group->
                                                                  identifier))))
        return;

      partner_hash = &(event_entry->message->body.group.partner);
      init_entry = GNUNET_CONTAINER_multihashmap_get (room->messages,
                                                      &(event_entry->message->
                                                        body.group.initiator));

      if ((! init_entry) || (event_entry->sender != init_entry->sender))
        return;

      if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != init_entry->message->header.kind
          )
        return;

      event_entry = GNUNET_CONTAINER_multihashmap_get (room->messages,
                                                       partner_hash);

      if (! event_entry)
        return;

      if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != event_entry->message->header.
          kind)
        return;

      if (! (GNUNET_MESSENGER_FLAG_SENT & event_entry->flags))
        return;

      {
        struct GNUNET_HashCode main_hash;
        enum GNUNET_GenericReturnValue has_hash;

        if (epoch->main_group)
          has_hash = get_epoch_group_member_hash (epoch->main_group, &main_hash,
                                                  GNUNET_NO);
        else if (epoch->main_announcement)
          has_hash = get_epoch_announcement_member_hash (epoch->
                                                         main_announcement, &
                                                         main_hash, GNUNET_NO);
        else
          return;

        if ((GNUNET_OK != has_hash) ||
            (0 != GNUNET_CRYPTO_hash_cmp (&main_hash, partner_hash)))
          return;
      }

      group = get_epoch_group (epoch, identifier, GNUNET_NO);

      if (! group)
        return;

      handle_epoch_group_access (group, entry->message, hash);
      break;
    }
  default:
    return;
  }
}


static void
handle_revolution_message (struct GNUNET_MESSENGER_Room *room,
                           const struct GNUNET_HashCode *hash,
                           struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochNonce *nonce;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, entry->sender);

  if (! epoch)
    return;

  nonce = &(entry->message->body.announcement.nonce);

  if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_contains (epoch->nonces, &(
                                                               nonce->hash)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unsafe revolution: Nonce (%s) has already been used in this epoch! [%s]\n",
                GNUNET_sh2s (&(nonce->hash)), GNUNET_h2s (&(epoch->hash)));
    return;
  }

  GNUNET_CONTAINER_multishortmap_put (epoch->nonces, &(nonce->hash), NULL,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  identifier = &(entry->message->body.revolution.identifier);

  if (identifier->code.group_bit)
  {
    struct GNUNET_MESSENGER_EpochGroup *group;
    const struct GNUNET_CRYPTO_SymmetricSessionKey *key;

    group = get_epoch_group (epoch, identifier, GNUNET_YES);

    if (! group)
      return;

    key = get_epoch_group_key (group);

    if (! key)
      return;

    if (GNUNET_OK != verify_message_by_key (entry->message, key))
      return;

    invalidate_epoch_group (group, NULL);
  }
  else
  {
    struct GNUNET_MESSENGER_EpochAnnouncement *announcement;
    const struct GNUNET_CRYPTO_SymmetricSessionKey *key;

    announcement = get_epoch_announcement (epoch, identifier, GNUNET_YES);

    if (! announcement)
      return;

    key = get_epoch_announcement_key (announcement);

    if (! key)
      return;

    if (GNUNET_OK != verify_message_by_key (entry->message, key))
      return;

    invalidate_epoch_announcement (announcement, NULL);
  }
}


static void
handle_group_message (struct GNUNET_MESSENGER_Room *room,
                      const struct GNUNET_HashCode *hash,
                      struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, entry->sender);

  if (! epoch)
    return;

  identifier = &(entry->message->body.group.identifier);
  group = get_epoch_group (epoch, identifier, GNUNET_NO);

  if (! (GNUNET_MESSENGER_FLAG_SENT & entry->flags))
    return;

  set_epoch_proposal_group (epoch, hash);

  set_epoch_group_key (group, NULL, GNUNET_YES);
  send_epoch_group_access (group, hash);
}


static void
handle_authorization_message (struct GNUNET_MESSENGER_Room *room,
                              const struct GNUNET_HashCode *hash,
                              struct GNUNET_MESSENGER_RoomMessageEntry *entry)
{
  struct GNUNET_MESSENGER_Epoch *epoch;
  const union GNUNET_MESSENGER_EpochIdentifier *identifier;
  struct GNUNET_MESSENGER_EpochGroup *auth_group;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *group_key;
  const struct GNUNET_MESSENGER_RoomMessageEntry *event_entry;
  struct GNUNET_CRYPTO_SymmetricSessionKey shared_key;

  GNUNET_assert ((room) && (hash) && (entry));

  epoch = get_room_availble_epoch_entry (room, hash, entry, entry->sender);

  if (! epoch)
    return;

  identifier = &(entry->message->body.authorization.identifier);
  auth_group = get_epoch_group (epoch, identifier, GNUNET_NO);

  if (! auth_group)
    return;

  group_key = get_epoch_group_key (auth_group);

  if (! group_key)
    return;

  event_entry = GNUNET_CONTAINER_multihashmap_get (
    room->messages, &(entry->message->body.authorization.event));

  if (! event_entry)
    return;

  switch (event_entry->message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    {
      identifier = &(event_entry->message->body.announcement.identifier);

      if (0 == GNUNET_memcmp (identifier, &(auth_group->identifier)))
        return;

      if (identifier->code.group_bit)
      {
        struct GNUNET_MESSENGER_EpochGroup *group;
        uint32_t next_level;

        if (GNUNET_YES != is_epoch_identifier_upper (
              identifier, &(auth_group->identifier)))
          return;

        group = get_epoch_group (epoch, identifier, GNUNET_NO);

        if (! group)
          return;

        next_level = get_epoch_group_level (auth_group) + 1;

        if (next_level != get_epoch_group_level (group))
          return;

        if (GNUNET_NO == extract_authorization_message_key (
              entry->message, group_key, &shared_key))
          return;

        if (get_epoch_group_key (group))
          return;

        set_epoch_group_key (group, &shared_key, GNUNET_YES);
        send_epoch_group_announcement (group);
      }
      else
      {
        struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

        announcement = get_epoch_announcement (epoch, identifier, GNUNET_NO);

        if (! announcement)
          return;

        if (GNUNET_NO == extract_authorization_message_key (
              entry->message, group_key, &shared_key))
          return;

        if (GNUNET_OK != verify_message_by_key (
              event_entry->message, &shared_key))
          return;

        if (get_epoch_announcement_key (announcement))
          return;

        set_epoch_announcement_key (announcement, &shared_key, GNUNET_YES);
        send_epoch_announcement (announcement);
      }

      break;
    }
  case GNUNET_MESSENGER_KIND_GROUP:
    {
      struct GNUNET_MESSENGER_EpochGroup *group;
      const struct GNUNET_HashCode *announcement_hash;
      uint32_t next_level;

      identifier = &(event_entry->message->body.group.identifier);

      if ((0 == GNUNET_memcmp (identifier, &(auth_group->identifier))) ||
          (GNUNET_YES != is_epoch_identifier_upper (identifier, &(auth_group->
                                                                  identifier))))
        return;

      if (! (identifier->code.group_bit))
        return;

      group = get_epoch_group (epoch, identifier, GNUNET_NO);

      if (! group)
        return;

      next_level = get_epoch_group_level (auth_group) + 1;

      if (next_level != get_epoch_group_level (group))
        return;

      if (event_entry->sender == entry->sender)
        announcement_hash = &(event_entry->message->body.group.initiator);
      else
        announcement_hash = &(event_entry->message->body.group.partner);

      event_entry = GNUNET_CONTAINER_multihashmap_get (room->messages,
                                                       announcement_hash);

      if (! event_entry)
        return;

      if (GNUNET_MESSENGER_KIND_ANNOUNCEMENT != event_entry->message->header.
          kind)
        return;

      identifier = &(event_entry->message->body.announcement.identifier);

      if (0 != GNUNET_memcmp (identifier, &(auth_group->identifier)))
        return;

      if (GNUNET_NO == extract_authorization_message_key (
            entry->message, group_key, &shared_key))
        return;

      if (get_epoch_group_key (group))
        return;

      set_epoch_group_key (group, &shared_key, GNUNET_YES);
      send_epoch_group_announcement (group);
      break;
    }
  default:
    break;
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
  case GNUNET_MESSENGER_KIND_MERGE:
    handle_merge_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    handle_private_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_DELETION:
    handle_delete_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_TRANSCRIPT:
    handle_transcript_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_ANNOUNCEMENT:
    handle_announcement_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_SECRET:
    handle_secret_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_APPEAL:
    handle_appeal_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_ACCESS:
    handle_access_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_REVOLUTION:
    handle_revolution_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_GROUP:
    handle_group_message (room, hash, entry);
    break;
  case GNUNET_MESSENGER_KIND_AUTHORIZATION:
    handle_authorization_message (room, hash, entry);
    break;
  default:
    break;
  }

  if (GNUNET_YES == is_epoch_message (entry->message))
  {
    struct GNUNET_MESSENGER_Epoch *epoch;

    epoch = get_room_epoch (room, &(entry->epoch), GNUNET_NO);

    if ((! epoch) || (get_epoch_size (epoch)))
      return;

    reset_epoch_size (epoch);
  }

  if (entry->flags & GNUNET_MESSENGER_FLAG_UPDATE)
    delay_room_action (room, hash, GNUNET_TIME_relative_get_zero_ ());
}


void
handle_room_message (struct GNUNET_MESSENGER_Room *room,
                     struct GNUNET_MESSENGER_Contact *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash,
                     const struct GNUNET_HashCode *epoch,
                     enum GNUNET_MESSENGER_MessageFlags flags)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (message) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if (entry)
    goto update_entry;

  entry = GNUNET_new (struct GNUNET_MESSENGER_RoomMessageEntry);

  if (! entry)
    return;

  entry->sender = NULL;
  entry->recipient = NULL;

  entry->message = NULL;

  GNUNET_memcpy (&(entry->epoch), epoch, sizeof (entry->epoch));

  entry->flags = GNUNET_MESSENGER_FLAG_NONE;
  entry->completed = GNUNET_NO;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        room->messages, hash, entry,
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


enum GNUNET_GenericReturnValue
update_room_message (struct GNUNET_MESSENGER_Room *room,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;

  GNUNET_assert ((room) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (! entry->message))
    return GNUNET_SYSERR;

  if (entry->flags & GNUNET_MESSENGER_FLAG_UPDATE)
    return GNUNET_NO;

  entry->flags |= GNUNET_MESSENGER_FLAG_UPDATE;
  handle_message (room, hash, entry);
  return GNUNET_YES;
}


enum GNUNET_GenericReturnValue
update_room_secret_message (struct GNUNET_MESSENGER_Room *room,
                            const struct GNUNET_HashCode *hash,
                            const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                            enum GNUNET_GenericReturnValue update)
{
  struct GNUNET_MESSENGER_RoomMessageEntry *entry;
  struct GNUNET_MESSENGER_Message *secret_message;

  GNUNET_assert ((room) && (hash) && (key));

  entry = GNUNET_CONTAINER_multihashmap_get (room->messages, hash);

  if ((! entry) || (! entry->message) ||
      (GNUNET_MESSENGER_KIND_SECRET != entry->message->header.kind))
    return GNUNET_SYSERR;

  secret_message = copy_message (entry->message);

  if (! secret_message)
    return GNUNET_NO;

  if (GNUNET_YES != decrypt_secret_message (secret_message, key))
  {
    destroy_message (secret_message);
    secret_message = NULL;
  }

  if (! secret_message)
    return GNUNET_NO;

  destroy_message (entry->message);

  entry->message = secret_message;
  entry->flags |= GNUNET_MESSENGER_FLAG_SECRET;

  if (GNUNET_YES == update)
    entry->flags |= GNUNET_MESSENGER_FLAG_UPDATE;

  if (entry->sender)
    handle_message (room, hash, entry);

  return GNUNET_YES;
}


void
update_room_last_message (struct GNUNET_MESSENGER_Room *room,
                          const struct GNUNET_HashCode *hash,
                          const struct GNUNET_HashCode *epoch)
{
  GNUNET_assert ((room) && (hash) && (epoch));

  GNUNET_memcpy (&(room->last_message), hash, sizeof(room->last_message));

  if (epoch)
    GNUNET_memcpy (&(room->last_epoch), epoch, sizeof(room->last_epoch));
}


void
copy_room_last_message (const struct GNUNET_MESSENGER_Room *room,
                        struct GNUNET_HashCode *hash)
{
  GNUNET_assert (room);

  GNUNET_memcpy (hash, &(room->last_message), sizeof(room->last_message));
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
  struct GNUNET_MESSENGER_MemberCall *call;
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((cls) && (value));

  call = cls;
  contact = value;

  return call->callback (call->cls, call->room, contact);
}


int
iterate_room_members (struct GNUNET_MESSENGER_Room *room,
                      GNUNET_MESSENGER_MemberCallback callback,
                      void *cls)
{
  struct GNUNET_MESSENGER_MemberCall call;

  GNUNET_assert (room);

  if (! callback)
    return GNUNET_CONTAINER_multishortmap_iterate (room->members, NULL, NULL);

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
  struct GNUNET_MESSENGER_MemberFind *find;
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((cls) && (value));

  find = cls;
  contact = value;

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
  struct GNUNET_MESSENGER_MemberFind find;

  GNUNET_assert (room);

  find.contact = contact;
  find.result = GNUNET_NO;

  GNUNET_CONTAINER_multishortmap_iterate (
    room->members, iterate_find_member, &find);

  return find.result;
}


static enum GNUNET_GenericReturnValue
find_linked_hash (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
{
  const struct GNUNET_HashCode **result;
  struct GNUNET_HashCode *hash;

  GNUNET_assert ((cls) && (value));

  result = cls;
  hash = value;

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
  const struct GNUNET_HashCode **result;
  struct GNUNET_HashCode *value;

  GNUNET_assert ((room) && (hash) && (other));

  result = &other;
  GNUNET_CONTAINER_multihashmap_get_multiple (room->links, hash,
                                              find_linked_hash, result);

  if (! *result)
    return;

  value = GNUNET_memdup (other, sizeof(struct GNUNET_HashCode));
  if (! value)
    return;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        room->links, hash, value,
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
  struct GNUNET_HashCode **linked;
  struct GNUNET_HashCode *hash;

  GNUNET_assert ((cls) && (value));

  linked = cls;
  hash = value;

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
  struct GNUNET_MESSENGER_RoomLinkDeletionInfo *info;
  struct GNUNET_HashCode *hash;
  struct GNUNET_HashCode key_value;
  struct GNUNET_HashCode *linked;

  GNUNET_assert ((cls) && (key) && (value));

  info = cls;
  hash = value;

  GNUNET_memcpy (&key_value, key, sizeof (key_value));

  linked = &key_value;
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
  struct GNUNET_MESSENGER_RoomLinkDeletionInfo info;

  GNUNET_assert ((room) && (hash));

  info.room = room;
  info.delay = delay;
  info.deletion = deletion;

  GNUNET_CONTAINER_multihashmap_get_multiple (room->links, hash,
                                              delete_linked_hash, &info);
  GNUNET_CONTAINER_multihashmap_remove_all (room->links, hash);
}
