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
 * @file src/messenger/messenger_api_handle.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_handle.h"

#include "messenger_api_epoch.h"
#include "messenger_api_epoch_announcement.h"
#include "messenger_api_epoch_group.h"
#include "messenger_api_room.h"
#include "messenger_api_util.h"

struct GNUNET_MESSENGER_Handle*
create_handle (const struct GNUNET_CONFIGURATION_Handle *config,
               GNUNET_MESSENGER_MessageCallback msg_callback,
               void *msg_cls)
{
  struct GNUNET_MESSENGER_Handle *handle;

  GNUNET_assert (config);

  handle = GNUNET_new (struct GNUNET_MESSENGER_Handle);

  handle->config = config;
  handle->mq = NULL;

  handle->group_keys = GNUNET_CONFIGURATION_get_value_yesno (
    handle->config,
    GNUNET_MESSENGER_SERVICE_NAME,
    "MESSENGER_GROUP_KEYS");

  if (handle->config)
    handle->namestore = GNUNET_NAMESTORE_connect (handle->config);

  handle->msg_callback = msg_callback;
  handle->msg_cls = msg_cls;

  handle->name = NULL;
  handle->key = NULL;
  handle->pubkey = NULL;

  handle->reconnect_time = GNUNET_TIME_relative_get_zero_ ();
  handle->reconnect_task = NULL;

  handle->key_monitor = NULL;

  handle->rooms = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_contact_store (get_handle_contact_store (handle));

  return handle;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_room (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (value);

  room = value;

  destroy_room (room);
  return GNUNET_YES;
}


void
destroy_handle (struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  clear_contact_store (get_handle_contact_store (handle));

  if (handle->rooms)
  {
    GNUNET_CONTAINER_multihashmap_iterate (
      handle->rooms, iterate_destroy_room, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (handle->rooms);
  }

  if (handle->key_monitor)
    GNUNET_NAMESTORE_zone_monitor_stop (handle->key_monitor);

  if (handle->reconnect_task)
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);

  if (handle->mq)
    GNUNET_MQ_destroy (handle->mq);

  if (handle->namestore)
    GNUNET_NAMESTORE_disconnect (handle->namestore);

  if (handle->name)
    GNUNET_free (handle->name);

  if (handle->key)
    GNUNET_free (handle->key);

  if (handle->pubkey)
    GNUNET_free (handle->pubkey);

  GNUNET_free (handle);
}


void
set_handle_name (struct GNUNET_MESSENGER_Handle *handle,
                 const char *name)
{
  GNUNET_assert (handle);

  if (handle->name)
    GNUNET_free (handle->name);

  handle->name = name ? GNUNET_strdup (name) : NULL;
}


const char*
get_handle_name (const struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  return handle->name;
}


static void
cb_key_error (void *cls)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const char *name;

  GNUNET_assert (cls);

  handle = cls;
  name = get_handle_name (handle);

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error on monitoring records: %s\n",
              name);
}


static void
cb_key_monitor (void *cls,
                const struct GNUNET_CRYPTO_PrivateKey *zone,
                const char *label,
                unsigned int rd_count,
                const struct GNUNET_GNSRECORD_Data *rd,
                struct GNUNET_TIME_Absolute expiry)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const struct GNUNET_MESSENGER_RoomEpochKeyRecord *record;
  struct GNUNET_MESSENGER_Room *room;
  struct GNUNET_MESSENGER_Epoch *epoch;
  union GNUNET_MESSENGER_EpochIdentifier identifier;
  enum GNUNET_GenericReturnValue valid;
  struct GNUNET_CRYPTO_SymmetricSessionKey shared_key;

  GNUNET_assert (
    (cls) && (zone) && (label) && (rd_count) && (rd));

  handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Monitor record with label: %s\n",
              label);

  if ((GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_EPOCH_KEY != rd->record_type) ||
      (sizeof (*record) != rd->data_size) || (! rd->data))
    goto monitor_next;

  record = rd->data;
  room = get_handle_room (handle, &(record->key));

  if (! room)
    goto monitor_next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Monitor epoch key record of room: %s\n",
              GNUNET_h2s (get_room_key (room)));

  epoch = get_room_epoch (room, &(record->hash), GNUNET_NO);

  if (! epoch)
    goto monitor_next;

  GNUNET_memcpy (
    &identifier,
    &(record->identifier),
    sizeof (record->identifier));
  valid = (GNUNET_MESSENGER_FLAG_EPOCH_VALID & record->flags? GNUNET_YES :
           GNUNET_NO);

  {
    struct GNUNET_CRYPTO_SymmetricSessionKey skey;
    struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

    if (GNUNET_YES != GNUNET_CRYPTO_kdf (&skey, sizeof (skey),
                                         get_room_key (room),
                                         sizeof (room->key),
                                         zone,
                                         sizeof (*zone),
                                         &(epoch->hash),
                                         sizeof (epoch->hash),
                                         &(identifier.hash),
                                         sizeof (identifier.hash),
                                         NULL))
      goto monitor_next;

    GNUNET_CRYPTO_symmetric_derive_iv (
      &iv,
      &skey,
      get_room_key (room), sizeof (room->key),
      &(epoch->hash), sizeof (epoch->hash),
      &(identifier.hash), sizeof (identifier.hash),
      NULL);

    if (-1 == GNUNET_CRYPTO_symmetric_decrypt (&(record->shared_key),
                                               sizeof (record->shared_key),
                                               &skey,
                                               &iv,
                                               &shared_key))
      goto monitor_next;

    GNUNET_CRYPTO_zero_keys (&skey, sizeof (skey));
  }

  if (identifier.code.group_bit)
  {
    struct GNUNET_MESSENGER_EpochGroup *group;

    group = get_epoch_group (epoch, &identifier, valid);

    if (! group)
      goto monitor_next;

    set_epoch_group_key (group, &shared_key, GNUNET_NO);
  }
  else
  {
    struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

    announcement = get_epoch_announcement (epoch, &identifier, valid);

    if (! announcement)
      goto monitor_next;

    set_epoch_announcement_key (announcement, &shared_key, GNUNET_NO);
  }

monitor_next:
  GNUNET_NAMESTORE_zone_monitor_next (handle->key_monitor, 1);
}


static enum GNUNET_GenericReturnValue
it_announcement_store_key (GNUNET_UNUSED void *cls,
                           GNUNET_UNUSED const struct GNUNET_ShortHashCode *key,
                           void *value)
{
  struct GNUNET_MESSENGER_EpochAnnouncement *announcement;

  GNUNET_assert (value);

  announcement = value;

  if ((cls) && (GNUNET_YES != announcement->stored))
    write_epoch_announcement_record (announcement, GNUNET_NO);
  else if (! cls)
    announcement->stored = GNUNET_NO;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
it_group_store_key (GNUNET_UNUSED void *cls,
                    GNUNET_UNUSED const struct GNUNET_ShortHashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_EpochGroup *group;

  GNUNET_assert (value);

  group = value;

  if ((cls) && (GNUNET_YES != group->stored))
    write_epoch_group_record (group, GNUNET_NO);
  else if (! cls)
    group->stored = GNUNET_NO;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
it_epoch_store_keys (void *cls,
                     GNUNET_UNUSED const struct GNUNET_HashCode *key,
                     void *value)
{
  const struct GNUNET_MESSENGER_Epoch *epoch;

  GNUNET_assert (value);

  epoch = value;

  GNUNET_CONTAINER_multishortmap_iterate (epoch->announcements,
                                          it_announcement_store_key, cls);
  GNUNET_CONTAINER_multishortmap_iterate (epoch->groups, it_group_store_key,
                                          cls);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
it_room_store_keys (void *cls,
                    GNUNET_UNUSED const struct GNUNET_HashCode *key,
                    void *value)
{
  const struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert (value);

  room = value;

  GNUNET_CONTAINER_multihashmap_iterate (
    room->epochs,
    it_epoch_store_keys,
    cls);
  return GNUNET_YES;
}


static void
cb_key_sync (void *cls)
{
  struct GNUNET_MESSENGER_Handle *handle;
  const char *name;

  GNUNET_assert (cls);

  handle = cls;
  name = get_handle_name (handle);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Syncing epoch and group keys completed: %s\n",
              name);

  GNUNET_CONTAINER_multihashmap_iterate (
    handle->rooms, it_room_store_keys, handle);
}


void
set_handle_key (struct GNUNET_MESSENGER_Handle *handle,
                const struct GNUNET_CRYPTO_PrivateKey *key)
{
  GNUNET_assert (handle);

  if (handle->key_monitor)
  {
    GNUNET_NAMESTORE_zone_monitor_stop (handle->key_monitor);
    handle->key_monitor = NULL;
  }

  if (! key)
  {
    if (handle->key)
      GNUNET_free (handle->key);

    if (handle->pubkey)
      GNUNET_free (handle->pubkey);

    handle->key = NULL;
    handle->pubkey = NULL;
    return;
  }

  if (! handle->key)
    handle->key = GNUNET_new (struct GNUNET_CRYPTO_PrivateKey);

  if (! handle->pubkey)
    handle->pubkey = GNUNET_new (struct GNUNET_CRYPTO_PublicKey);

  GNUNET_memcpy (handle->key, key, sizeof(*key));
  GNUNET_CRYPTO_key_get_public (key, handle->pubkey);

  // Resets epoch and group keys as not stored yet
  GNUNET_CONTAINER_multihashmap_iterate (
    handle->rooms, it_room_store_keys, NULL);

  handle->key_monitor = GNUNET_NAMESTORE_zone_monitor_start2 (
    handle->config,
    handle->key,
    GNUNET_YES,
    cb_key_error,
    handle,
    cb_key_monitor,
    handle,
    cb_key_sync,
    handle,
    GNUNET_GNSRECORD_FILTER_NONE);
}


const struct GNUNET_CRYPTO_PrivateKey*
get_handle_key (const struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  if (handle->key)
    return handle->key;

  return get_anonymous_private_key ();
}


const struct GNUNET_CRYPTO_PublicKey*
get_handle_pubkey (const struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  if (handle->pubkey)
    return handle->pubkey;

  return get_anonymous_public_key ();
}


struct GNUNET_MESSENGER_ContactStore*
get_handle_contact_store (struct GNUNET_MESSENGER_Handle *handle)
{
  GNUNET_assert (handle);

  return &(handle->contact_store);
}


struct GNUNET_MESSENGER_Contact*
get_handle_contact (struct GNUNET_MESSENGER_Handle *handle,
                    const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room;
  const struct GNUNET_ShortHashCode *contact_id;

  GNUNET_assert ((handle) && (key));

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (! room)
    return NULL;

  contact_id = get_room_sender_id (room);

  if (! contact_id)
    return NULL;

  {
    struct GNUNET_HashCode context;
    get_context_from_member (key, contact_id, &context);

    return get_store_contact (get_handle_contact_store (handle),
                              &context,
                              get_handle_pubkey (handle));
  }
}


void
open_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                  const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((handle) && (key));

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
    room->opened = GNUNET_YES;
}


void
entry_handle_room_at (struct GNUNET_MESSENGER_Handle *handle,
                      const struct GNUNET_PeerIdentity *door,
                      const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((handle) && (door) && (key));

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if (room)
    add_to_list_tunnels (&(room->entries), door, NULL);
}


void
close_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                   const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room;

  GNUNET_assert ((handle) && (key));

  room = GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);

  if ((room) && (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (
                   handle->rooms, key, room)))
    destroy_room (room);
}


struct GNUNET_MESSENGER_Room*
get_handle_room (struct GNUNET_MESSENGER_Handle *handle,
                 const struct GNUNET_HashCode *key)
{
  GNUNET_assert ((handle) && (key));

  return GNUNET_CONTAINER_multihashmap_get (handle->rooms, key);
}


enum GNUNET_GenericReturnValue
store_handle_epoch_key (const struct GNUNET_MESSENGER_Handle *handle,
                        const struct GNUNET_HashCode *key,
                        const struct GNUNET_HashCode *hash,
                        const struct GNUNET_ShortHashCode *identifier,
                        const struct GNUNET_CRYPTO_SymmetricSessionKey *
                        shared_key,
                        uint32_t flags,
                        GNUNET_NAMESTORE_ContinuationWithStatus cont,
                        void *cont_cls,
                        struct GNUNET_NAMESTORE_QueueEntry **query)
{
  const struct GNUNET_CRYPTO_PrivateKey *zone;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_GNSRECORD_Data data;
  struct GNUNET_MESSENGER_RoomEpochKeyRecord record;
  char *label;

  GNUNET_assert ((handle) && (key) && (hash) && (identifier) && (query));

  if (! handle->namestore)
    return GNUNET_SYSERR;

  zone = get_handle_key (handle);

  if (! zone)
    return GNUNET_SYSERR;

  expiration = GNUNET_TIME_absolute_get_forever_ ();

  memset (&data, 0, sizeof (data));
  memset (&record, 0, sizeof (record));

  if (shared_key)
  {
    struct GNUNET_CRYPTO_SymmetricSessionKey skey;
    struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

    if (GNUNET_YES != GNUNET_CRYPTO_kdf (&skey, sizeof (skey),
                                         key, sizeof (*key),
                                         zone, sizeof (*zone),
                                         hash, sizeof (*hash),
                                         identifier, sizeof (*identifier),
                                         NULL))
      return GNUNET_SYSERR;

    GNUNET_memcpy (&(record.key), key, sizeof (record.key));
    GNUNET_memcpy (&(record.hash), hash, sizeof (record.hash));
    GNUNET_memcpy (
      &(record.identifier),
      identifier,
      sizeof (record.identifier));

    GNUNET_CRYPTO_symmetric_derive_iv (
      &iv,
      &skey,
      key, sizeof (*key),
      hash, sizeof (*hash),
      identifier, sizeof (*identifier),
      NULL);

    if (-1 == GNUNET_CRYPTO_symmetric_encrypt (shared_key,
                                               sizeof (*shared_key),
                                               &skey,
                                               &iv,
                                               &(record.shared_key)))
      return GNUNET_SYSERR;

    record.flags = flags;

    data.record_type = GNUNET_GNSRECORD_TYPE_MESSENGER_ROOM_EPOCH_KEY;
    data.data = &record;
    data.data_size = sizeof (record);
    data.expiration_time = expiration.abs_value_us;
    data.flags = GNUNET_GNSRECORD_RF_PRIVATE;

    GNUNET_CRYPTO_zero_keys (&skey, sizeof (skey));
  }

  {
    char lower_key [9];
    char lower_hash [9];
    char lower_id [7];
    const char *s;

    memset (lower_key, 0, sizeof (lower_key));
    memset (lower_hash, 0, sizeof (lower_hash));
    memset (lower_id, 0, sizeof (lower_id));

    s = GNUNET_h2s (key);
    if (GNUNET_OK != GNUNET_STRINGS_utf8_tolower (s, lower_key))
      GNUNET_memcpy (lower_key, s, sizeof (lower_key));

    s = GNUNET_h2s (hash);
    if (GNUNET_OK != GNUNET_STRINGS_utf8_tolower (s, lower_hash))
      GNUNET_memcpy (lower_hash, s, sizeof (lower_hash));

    s = GNUNET_sh2s (identifier);
    if (GNUNET_OK != GNUNET_STRINGS_utf8_tolower (s, lower_id))
      GNUNET_memcpy (lower_id, s, sizeof (lower_id));

    GNUNET_asprintf (
      &label,
      "epoch_key_%s%s%s",
      lower_key,
      lower_hash,
      lower_id);
  }

  if (! label)
    return GNUNET_SYSERR;

  if (*query)
    GNUNET_NAMESTORE_cancel (*query);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Store epoch key record with label: %s [%d]\n",
              label,
              shared_key? 1 : 0);

  *query = GNUNET_NAMESTORE_record_set_store (
    handle->namestore,
    zone,
    label,
    shared_key? 1 : 0,
    &data,
    cont,
    cont_cls);

  GNUNET_free (label);
  return GNUNET_OK;
}
