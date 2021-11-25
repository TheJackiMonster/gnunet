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
 * @file src/messenger/messenger_api_handle.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_handle.h"

#include "messenger_api_util.h"

struct GNUNET_MESSENGER_Handle*
create_handle (const struct GNUNET_CONFIGURATION_Handle *cfg,
               GNUNET_MESSENGER_IdentityCallback identity_callback,
               void *identity_cls,
               GNUNET_MESSENGER_MessageCallback msg_callback,
               void *msg_cls)
{
  GNUNET_assert(cfg);

  struct GNUNET_MESSENGER_Handle *handle = GNUNET_new(struct GNUNET_MESSENGER_Handle);

  handle->cfg = cfg;
  handle->mq = NULL;

  handle->identity_callback = identity_callback;
  handle->identity_cls = identity_cls;

  handle->msg_callback = msg_callback;
  handle->msg_cls = msg_cls;

  handle->name = NULL;
  handle->pubkey = NULL;

  handle->reconnect_time = GNUNET_TIME_relative_get_zero_ ();
  handle->reconnect_task = NULL;

  handle->rooms = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_contact_store(get_handle_contact_store(handle));

  return handle;
}

static int
iterate_destroy_room (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_Room *room = value;

  destroy_room (room);

  return GNUNET_YES;
}

void
destroy_handle (struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert(handle);

  if (handle->reconnect_task)
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);

  if (handle->mq)
    GNUNET_MQ_destroy (handle->mq);

  if (handle->name)
    GNUNET_free(handle->name);

  if (handle->pubkey)
    GNUNET_free(handle->pubkey);

  if (handle->rooms)
  {
    GNUNET_CONTAINER_multihashmap_iterate (handle->rooms, iterate_destroy_room, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (handle->rooms);
  }

  clear_contact_store(get_handle_contact_store(handle));

  GNUNET_free(handle);
}

void
set_handle_name (struct GNUNET_MESSENGER_Handle *handle,
                 const char *name)
{
  GNUNET_assert(handle);

  if (handle->name)
    GNUNET_free(handle->name);

  handle->name = name ? GNUNET_strdup(name) : NULL;
}

const char*
get_handle_name (const struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert(handle);

  return handle->name;
}

void
set_handle_key (struct GNUNET_MESSENGER_Handle *handle,
                const struct GNUNET_IDENTITY_PublicKey *pubkey)
{
  GNUNET_assert(handle);

  if (!handle->pubkey)
    handle->pubkey = GNUNET_new(struct GNUNET_IDENTITY_PublicKey);

  GNUNET_memcpy(handle->pubkey, pubkey, sizeof(*pubkey));
}

const struct GNUNET_IDENTITY_PublicKey*
get_handle_key (const struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert(handle);

  if (handle->pubkey)
    return handle->pubkey;

  return get_anonymous_public_key ();
}

struct GNUNET_MESSENGER_ContactStore*
get_handle_contact_store (struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert(handle);

  return &(handle->contact_store);
}

struct GNUNET_MESSENGER_Contact*
get_handle_contact (struct GNUNET_MESSENGER_Handle *handle,
                    const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if ((!room) || (!(room->contact_id)))
    return NULL;

  struct GNUNET_HashCode context;
  get_context_from_member (key, room->contact_id, &context);

  return get_store_contact(get_handle_contact_store(handle), &context, get_handle_key(handle));
}

void
open_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                  const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
    room->opened = GNUNET_YES;
}

void
entry_handle_room_at (struct GNUNET_MESSENGER_Handle *handle,
                      const struct GNUNET_PeerIdentity *door,
                      const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (door) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
    add_to_list_tunnels (&(room->entries), door);
}

void
close_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                   const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_MESSENGER_Room *room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if ((room) && (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (handle->rooms, key, room)))
    destroy_room (room);
}
