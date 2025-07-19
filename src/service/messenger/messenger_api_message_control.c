/*
   This file is part of GNUnet.
   Copyright (C) 2024 GNUnet e.V.

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
 * @file src/messenger/messenger_api_message_control.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message_control.h"

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_scheduler_lib.h"
#include "messenger_api_contact.h"
#include "messenger_api_contact_store.h"
#include "messenger_api_handle.h"
#include "messenger_api_message.h"
#include "messenger_api_room.h"

struct GNUNET_MESSENGER_MessageControl*
create_message_control (struct GNUNET_MESSENGER_Room *room)
{
  struct GNUNET_MESSENGER_MessageControl *control;

  GNUNET_assert (room);

  control = GNUNET_new (struct GNUNET_MESSENGER_MessageControl);
  control->room = room;

  control->peer_messages = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
  control->member_messages = GNUNET_CONTAINER_multishortmap_create (8,
                                                                    GNUNET_NO);

  control->head = NULL;
  control->tail = NULL;

  return control;
}


void
destroy_message_control (struct GNUNET_MESSENGER_MessageControl *control)
{
  GNUNET_assert (control);

  while (control->head)
  {
    struct GNUNET_MESSENGER_MessageControlQueue *queue;
    queue = control->head;

    if (queue->task)
      GNUNET_SCHEDULER_cancel (queue->task);

    destroy_message (queue->message);

    GNUNET_CONTAINER_DLL_remove (control->head, control->tail, queue);
    GNUNET_free (queue);
  }

  GNUNET_CONTAINER_multishortmap_destroy (control->peer_messages);
  GNUNET_CONTAINER_multishortmap_destroy (control->member_messages);

  GNUNET_free (control);
}


static void
enqueue_message_control (struct GNUNET_MESSENGER_MessageControl *control,
                         const struct GNUNET_HashCode *sender,
                         const struct GNUNET_HashCode *context,
                         const struct GNUNET_HashCode *hash,
                         const struct GNUNET_HashCode *epoch,
                         const struct GNUNET_MESSENGER_Message *message,
                         enum GNUNET_MESSENGER_MessageFlags flags)
{
  struct GNUNET_CONTAINER_MultiShortmap *map;
  struct GNUNET_MESSENGER_MessageControlQueue *queue;

  GNUNET_assert ((control) && (sender) && (context) && (hash) && (message));

  if (GNUNET_YES == is_peer_message (message))
    map = control->peer_messages;
  else
    map = control->member_messages;

  queue = GNUNET_new (struct GNUNET_MESSENGER_MessageControlQueue);
  queue->control = control;

  GNUNET_memcpy (&(queue->sender), sender, sizeof (queue->sender));
  GNUNET_memcpy (&(queue->context), context, sizeof (queue->context));
  GNUNET_memcpy (&(queue->hash), hash, sizeof (queue->hash));
  GNUNET_memcpy (&(queue->epoch), epoch, sizeof (queue->epoch));

  queue->message = copy_message (message);
  queue->flags = flags;
  queue->task = NULL;

  GNUNET_CONTAINER_DLL_insert (control->head, control->tail, queue);

  GNUNET_CONTAINER_multishortmap_put (map,
                                      &(message->header.sender_id),
                                      queue,
                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


static void
handle_message_control (struct GNUNET_MESSENGER_MessageControl *control,
                        struct GNUNET_MESSENGER_Contact *contact,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_HashCode *epoch,
                        const struct GNUNET_MESSENGER_Message *message,
                        enum GNUNET_MESSENGER_MessageFlags flags)
{
  GNUNET_assert ((control) && (hash) && (message));

  handle_room_message (control->room, contact, message, hash, epoch, flags);

  if ((flags & GNUNET_MESSENGER_FLAG_RECENT) &&
      (! get_message_discourse (message)))
    update_room_last_message (control->room, hash, epoch);

  callback_room_message (control->room, hash);
}


static void
task_message_control (void *cls)
{
  struct GNUNET_MESSENGER_MessageControlQueue *queue;
  struct GNUNET_MESSENGER_MessageControl *control;
  struct GNUNET_MESSENGER_Contact *contact;
  struct GNUNET_CONTAINER_MultiShortmap *map;

  GNUNET_assert (cls);

  queue = cls;
  control = queue->control;

  queue->task = NULL;

  {
    struct GNUNET_MESSENGER_Handle *handle;
    struct GNUNET_MESSENGER_ContactStore *store;

    handle = get_room_handle (control->room);
    store = get_handle_contact_store (handle);

    contact = get_store_contact_raw (
      store, &(queue->context), &(queue->sender));
  }

  if (GNUNET_YES == is_peer_message (queue->message))
    map = control->peer_messages;
  else
    map = control->member_messages;

  GNUNET_CONTAINER_multishortmap_remove (map,
                                         &(queue->message->header.sender_id),
                                         queue);

  GNUNET_CONTAINER_DLL_remove (control->head, control->tail, queue);

  handle_message_control (control,
                          contact,
                          &(queue->hash),
                          &(queue->epoch),
                          queue->message,
                          queue->flags);

  destroy_message (queue->message);

  GNUNET_free (queue);
}


static enum GNUNET_GenericReturnValue
iterate_message_control (void *cls,
                         const struct GNUNET_ShortHashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_MessageControlQueue *queue;

  GNUNET_assert ((key) && (value));

  queue = value;

  if (queue->task)
    return GNUNET_YES;

  queue->task = GNUNET_SCHEDULER_add_with_priority (
    GNUNET_SCHEDULER_PRIORITY_DEFAULT,
    task_message_control,
    queue);

  return GNUNET_YES;
}


void
process_message_control (struct GNUNET_MESSENGER_MessageControl *control,
                         const struct GNUNET_HashCode *sender,
                         const struct GNUNET_HashCode *context,
                         const struct GNUNET_HashCode *hash,
                         const struct GNUNET_HashCode *epoch,
                         const struct GNUNET_MESSENGER_Message *message,
                         enum GNUNET_MESSENGER_MessageFlags flags)
{
  struct GNUNET_MESSENGER_Contact *contact;
  struct GNUNET_CONTAINER_MultiShortmap *map;
  const struct GNUNET_ShortHashCode *id;

  GNUNET_assert ((control) && (sender) && (context) && (hash) && (message));

  {
    struct GNUNET_MESSENGER_Handle *handle;
    struct GNUNET_MESSENGER_ContactStore *store;

    handle = get_room_handle (control->room);
    store = get_handle_contact_store (handle);

    contact = get_store_contact_raw (store, context, sender);
  }

  if ((! contact) &&
      (GNUNET_MESSENGER_KIND_JOIN != message->header.kind) &&
      (GNUNET_MESSENGER_KIND_PEER != message->header.kind))
    enqueue_message_control (control, sender, context, hash, epoch, message,
                             flags);
  else
  {
    if ((! contact) && (GNUNET_MESSENGER_KIND_JOIN == message->header.kind))
      flags |= GNUNET_MESSENGER_FLAG_MEMBER;

    handle_message_control (control, contact, hash, epoch, message, flags);
  }

  map = NULL;
  id = &(message->header.sender_id);

  if (GNUNET_YES == is_peer_message (message))
    map = control->peer_messages;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    map = control->member_messages;
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    map = control->peer_messages;
    break;
  case GNUNET_MESSENGER_KIND_ID:
    map = control->member_messages;
    id = &(message->body.id.id);
    break;
  default:
    break;
  }

  if (! map)
    return;

  GNUNET_CONTAINER_multishortmap_get_multiple (map,
                                               id,
                                               iterate_message_control,
                                               NULL);
}
