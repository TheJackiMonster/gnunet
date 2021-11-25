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
 * @file src/messenger/gnunet-service-messenger_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_handle.h"

#include "gnunet-service-messenger.h"
#include "gnunet-service-messenger_message_kind.h"

#include "messenger_api_util.h"

struct GNUNET_MESSENGER_SrvHandle*
create_handle (struct GNUNET_MESSENGER_Service *service,
               struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert((service) && (mq));

  struct GNUNET_MESSENGER_SrvHandle *handle = GNUNET_new(struct GNUNET_MESSENGER_SrvHandle);

  handle->service = service;
  handle->mq = mq;

  handle->name = NULL;
  handle->ego = NULL;

  handle->member_ids = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  return handle;
}

int
iterate_free_member_ids (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  GNUNET_free(value);

  return GNUNET_YES;
}

void
destroy_handle (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  if (handle->service->dir)
    save_handle_configuration (handle);

  if (handle->name)
    GNUNET_free(handle->name);

  GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_free_member_ids, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (handle->member_ids);

  GNUNET_free(handle);
}

void
get_handle_data_subdir (const struct GNUNET_MESSENGER_SrvHandle *handle,
                        const char *name,
                        char **dir)
{
  GNUNET_assert((handle) && (dir));

  if (name)
    GNUNET_asprintf (dir, "%s%s%c%s%c", handle->service->dir, "identities",
                     DIR_SEPARATOR, name, DIR_SEPARATOR);
  else
    GNUNET_asprintf (dir, "%s%s%c", handle->service->dir, "anonymous",
                     DIR_SEPARATOR);
}

static int
create_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_ShortHashCode *random_id = GNUNET_new(struct GNUNET_ShortHashCode);

  if (!random_id)
    return GNUNET_NO;

  generate_free_member_id (random_id, NULL);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key, random_id,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free(random_id);
    return GNUNET_NO;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Created a new member id (%s) for room: %s\n", GNUNET_sh2s (random_id),
             GNUNET_h2s (key));

  return GNUNET_YES;
}

const struct GNUNET_ShortHashCode*
get_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle,
                      const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  return GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);
}

int
change_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle,
                         const struct GNUNET_HashCode *key,
                         const struct GNUNET_ShortHashCode *unique_id)
{
  GNUNET_assert((handle) && (key) && (unique_id));

  struct GNUNET_ShortHashCode *member_id = GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);

  if (!member_id)
  {
    member_id = GNUNET_new(struct GNUNET_ShortHashCode);
    GNUNET_memcpy(member_id, unique_id, sizeof(*member_id));

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key, member_id,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      GNUNET_free(member_id);
      return GNUNET_SYSERR;
    }
  }

  if (0 == GNUNET_memcmp(unique_id, member_id))
    goto send_message_to_client;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Change a member id (%s) for room (%s).\n", GNUNET_sh2s (member_id),
             GNUNET_h2s (key));

  GNUNET_memcpy(member_id, unique_id, sizeof(*unique_id));

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Member id changed to (%s).\n", GNUNET_sh2s (unique_id));

  struct GNUNET_MESSENGER_MemberMessage *msg;
  struct GNUNET_MQ_Envelope *env;

send_message_to_client:

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID);

  GNUNET_memcpy(&(msg->key), key, sizeof(*key));
  GNUNET_memcpy(&(msg->id), member_id, sizeof(*member_id));

  GNUNET_MQ_send (handle->mq, env);
  return GNUNET_OK;
}

static void
change_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle,
                    const char *name)
{
  GNUNET_assert(handle);

  if (handle->name)
    GNUNET_free(handle->name);

  handle->name = name ? GNUNET_strdup(name) : NULL;

  const uint16_t name_len = handle->name ? strlen (handle->name) : 0;

  struct GNUNET_MESSENGER_NameMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra(msg, name_len + 1, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_NAME);

  char *extra = ((char*) msg) + sizeof(*msg);

  if (name_len)
    GNUNET_memcpy(extra, handle->name, name_len);

  extra[name_len] = '\0';

  GNUNET_MQ_send (handle->mq, env);
}

static void
change_handle_ego (struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_MESSENGER_Ego *ego)
{
  GNUNET_assert(handle);

  handle->ego = ego;

  ego = get_handle_ego (handle);

  const uint16_t length = GNUNET_IDENTITY_key_get_length(&(ego->pub));

  struct GNUNET_MESSENGER_KeyMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra(msg, length, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_KEY);

  char *extra = ((char*) msg) + sizeof(*msg);

  if (GNUNET_IDENTITY_write_key_to_buffer(&(ego->pub), extra, length) < 0)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Could not write key to buffer.\n");

  GNUNET_MQ_send (handle->mq, env);
}

struct GNUNET_MESSENGER_MessageHandle
{
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_Message *message;
};

static int
iterate_send_message (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_MessageHandle *msg_handle = cls;

  send_handle_message (msg_handle->handle, key, msg_handle->message);

  return GNUNET_YES;
}

void
set_handle_ego (struct GNUNET_MESSENGER_SrvHandle *handle,
                const struct GNUNET_MESSENGER_Ego *ego)
{
  GNUNET_assert((handle) && (ego));

  struct GNUNET_MESSENGER_MessageHandle msg_handle;

  msg_handle.handle = handle;
  msg_handle.message = create_message_key (&(ego->priv));

  GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_send_message, &msg_handle);

  destroy_message (msg_handle.message);

  change_handle_ego (handle, ego);
}

const struct GNUNET_MESSENGER_Ego*
get_handle_ego (const struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  static struct GNUNET_MESSENGER_Ego anonymous;
  static int read_keys = 0;

  if (handle->ego)
    return handle->ego;

  if (!read_keys)
  {
    struct GNUNET_IDENTITY_Ego *ego = GNUNET_IDENTITY_ego_get_anonymous ();
    GNUNET_memcpy(&(anonymous.priv), GNUNET_IDENTITY_ego_get_private_key (ego), sizeof(anonymous.priv));
    GNUNET_IDENTITY_ego_get_public_key (ego, &(anonymous.pub));
    read_keys = 1;
  }

  return &anonymous;
}

static void
callback_setup_handle_name (void *cls,
                            const char *name,
                            const struct GNUNET_MESSENGER_Ego *ego)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Setting up handle...\n");

  change_handle_name (handle, name);
  change_handle_ego (handle, ego);

  if (handle->service->dir)
    load_handle_configuration (handle);
}

void
setup_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle,
                   const char *name)
{
  GNUNET_assert(handle);

  struct GNUNET_MESSENGER_EgoStore *store = get_service_ego_store(handle->service);

  lookup_store_ego (store, name, callback_setup_handle_name, handle);
}

static void
callback_update_handle (void *cls,
                        const char *name,
                        const struct GNUNET_MESSENGER_Ego *ego)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Updating handle...\n");

  struct GNUNET_MESSENGER_EgoStore *store = get_service_ego_store(handle->service);

  if (!ego)
    create_store_ego(store, handle->name, handle);
  else
    change_handle_ego (handle, ego);
}

void
update_handle (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  if (!handle->name)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Updating handle failed: Name is required!\n");
    return;
  }

  struct GNUNET_MESSENGER_EgoStore *store = get_service_ego_store(handle->service);

  lookup_store_ego (store, handle->name, callback_update_handle, handle);
}

static void
callback_set_handle_name (void *cls,
                          const char *name,
                          const struct GNUNET_MESSENGER_Ego *ego)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Renaming handle...\n");

  if (ego)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Renaming handle failed: Name is occupied! (%s)\n", name);
    return;
  }

  struct GNUNET_MESSENGER_EgoStore *store = get_service_ego_store(handle->service);

  int rename_ego_in_store = handle->ego? GNUNET_YES : GNUNET_NO;

  char *old_dir;
  get_handle_data_subdir (handle, handle->name, &old_dir);

  char *new_dir;
  get_handle_data_subdir (handle, name, &new_dir);

  int result = 0;

  if (GNUNET_YES == GNUNET_DISK_directory_test (old_dir, GNUNET_YES))
  {
    GNUNET_DISK_directory_create_for_file (new_dir);

    result = rename (old_dir, new_dir);
  }
  else if (GNUNET_YES == GNUNET_DISK_directory_test (new_dir, GNUNET_NO))
    result = -1;

  if (0 == result)
  {
    struct GNUNET_MESSENGER_MessageHandle msg_handle;

    msg_handle.handle = handle;
    msg_handle.message = create_message_name (name);

    GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_send_message, &msg_handle);

    destroy_message (msg_handle.message);

    change_handle_name (handle, name);
  }
  else
    rename_ego_in_store = GNUNET_NO;

  GNUNET_free(old_dir);
  GNUNET_free(new_dir);

  if (GNUNET_YES == rename_ego_in_store)
    rename_store_ego(store, handle->name, name);
}

void
set_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle,
                 const char *name)
{
  GNUNET_assert(handle);

  if (!name)
  {
    if (handle->ego)
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Renaming handle failed: Name is required!\n");
    else
      change_handle_name (handle, name);

    return;
  }

  struct GNUNET_MESSENGER_EgoStore *store = get_service_ego_store(handle->service);

  lookup_store_ego (store, name, callback_set_handle_name, handle);
}

int
open_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                  const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  if ((!get_handle_member_id (handle, key)) && (GNUNET_YES != create_handle_member_id (handle, key)))
    return GNUNET_NO;

  return open_service_room (handle->service, handle, key);
}

int
entry_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_PeerIdentity *door,
                   const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (door) && (key));

  if ((!get_handle_member_id (handle, key)) && (GNUNET_YES != create_handle_member_id (handle, key)))
    return GNUNET_NO;

  return entry_service_room (handle->service, handle, door, key);
}

int
close_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  if (!get_handle_member_id (handle, key))
    return GNUNET_NO;

  return close_service_room (handle->service, handle, key);
}

int
send_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                     const struct GNUNET_HashCode *key,
                     const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert((handle) && (key) && (message));

  const struct GNUNET_ShortHashCode *id = get_handle_member_id (handle, key);

  if (!id)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "It is required to be a member of a room to send messages!\n");
    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (handle->service, key);

  if (!room)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "The room (%s) is unknown!\n", GNUNET_h2s (key));
    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_Message *msg = copy_message(message);

  GNUNET_memcpy(&(msg->header.sender_id), id, sizeof(*id));

  return send_room_message (room, handle, msg);
}

static const struct GNUNET_HashCode*
get_next_member_session_contect(const struct GNUNET_MESSENGER_MemberSession *session)
{
  if (session->next)
    return get_next_member_session_contect (session->next);
  else
    return get_member_session_context(session);
}

static const struct GNUNET_MESSENGER_MemberSession*
get_handle_member_session (struct GNUNET_MESSENGER_SrvHandle *handle,
                           struct GNUNET_MESSENGER_SrvRoom *room,
                           const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (room) && (key) && (handle->service));

  const struct GNUNET_ShortHashCode *id = get_handle_member_id(handle, key);

  if (!id)
    return NULL;

  struct GNUNET_MESSENGER_MemberStore *store = get_room_member_store(room);
  struct GNUNET_MESSENGER_Member *member = get_store_member(store, id);

  const struct GNUNET_MESSENGER_Ego *ego = get_handle_ego(handle);

  if (!ego)
    return NULL;

  return get_member_session(member, &(ego->pub));
}

void
notify_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle,
                       struct GNUNET_MESSENGER_SrvRoom *room,
                       const struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((handle) && (room) && (session) && (message) && (hash));

  const struct GNUNET_HashCode *key = get_room_key(room);

  if ((!handle->mq) || (!get_handle_member_id (handle, key)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Notifying client about message requires membership!\n");
    return;
  }

  const struct GNUNET_IDENTITY_PublicKey *pubkey = get_contact_key(session->contact);

  struct GNUNET_HashCode sender;
  GNUNET_CRYPTO_hash(pubkey, sizeof(*pubkey), &sender);

  const struct GNUNET_HashCode *context = get_next_member_session_contect (session);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Notifying client about message: %s\n", GNUNET_h2s (hash));

  struct GNUNET_MESSENGER_Message *private_message = NULL;

  if (GNUNET_MESSENGER_KIND_PRIVATE == message->header.kind)
  {
    private_message = copy_message(message);

    if (GNUNET_YES != decrypt_message(private_message, &(get_handle_ego(handle)->priv)))
    {
      destroy_message(private_message);
      private_message = NULL;
    }
    else
      message = private_message;
  }

  struct GNUNET_MESSENGER_RecvMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  uint16_t length = get_message_size (message, GNUNET_YES);

  env = GNUNET_MQ_msg_extra(msg, length, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE);

  GNUNET_memcpy(&(msg->key), key, sizeof(msg->key));
  GNUNET_memcpy(&(msg->sender), &sender, sizeof(msg->sender));
  GNUNET_memcpy(&(msg->context), context, sizeof(msg->context));
  GNUNET_memcpy(&(msg->hash), hash, sizeof(msg->hash));

  msg->flags = (uint32_t) GNUNET_MESSENGER_FLAG_NONE;

  if (get_handle_member_session(handle, room, key) == session)
    msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_SENT;

  if (private_message)
    msg->flags |= (uint32_t) GNUNET_MESSENGER_FLAG_PRIVATE;

  char *buffer = ((char*) msg) + sizeof(*msg);
  encode_message (message, length, buffer, GNUNET_YES);

  if (private_message)
    destroy_message(private_message);

  GNUNET_MQ_send (handle->mq, env);
}

static int
callback_scan_for_rooms (void *cls,
                         const char *filename)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

  if ((GNUNET_YES == GNUNET_DISK_file_test (filename)) && (GNUNET_OK == GNUNET_CONFIGURATION_parse (cfg, filename)))
  {
    struct GNUNET_HashCode key;
    struct GNUNET_ShortHashCode member_id;

    if ((GNUNET_OK == GNUNET_CONFIGURATION_get_data (cfg, "room", "key", &key, sizeof(key))) &&
        (GNUNET_OK == GNUNET_CONFIGURATION_get_data (cfg, "room", "member_id", &member_id, sizeof(member_id))))
      change_handle_member_id (handle, &key, &member_id);
  }

  GNUNET_CONFIGURATION_destroy (cfg);
  return GNUNET_OK;
}

void
load_handle_configuration (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  char *id_dir;
  get_handle_data_subdir (handle, handle->name, &id_dir);

  if (GNUNET_YES == GNUNET_DISK_directory_test (id_dir, GNUNET_YES))
  {
    char *scan_dir;
    GNUNET_asprintf (&scan_dir, "%s%s%c", id_dir, "rooms", DIR_SEPARATOR);

    if (GNUNET_OK == GNUNET_DISK_directory_test (scan_dir, GNUNET_YES))
      GNUNET_DISK_directory_scan (scan_dir, callback_scan_for_rooms, handle);

    GNUNET_free(scan_dir);
  }

  GNUNET_free(id_dir);
}

static int
iterate_save_rooms (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;
  struct GNUNET_ShortHashCode *member_id = value;

  char *id_dir;
  get_handle_data_subdir (handle, handle->name, &id_dir);

  char *filename;
  GNUNET_asprintf (&filename, "%s%s%c%s.cfg", id_dir, "rooms", DIR_SEPARATOR, GNUNET_h2s (key));

  GNUNET_free(id_dir);

  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

  char *key_data = GNUNET_STRINGS_data_to_string_alloc (key, sizeof(*key));

  if (key_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "room", "key", key_data);

    GNUNET_free(key_data);
  }

  char *member_id_data = GNUNET_STRINGS_data_to_string_alloc (member_id, sizeof(*member_id));

  if (member_id_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "room", "member_id", member_id_data);

    GNUNET_free(member_id_data);
  }

  GNUNET_CONFIGURATION_write (cfg, filename);
  GNUNET_CONFIGURATION_destroy (cfg);

  GNUNET_free(filename);

  return GNUNET_YES;
}

void
save_handle_configuration (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  char *id_dir;
  get_handle_data_subdir (handle, handle->name, &id_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (id_dir, GNUNET_NO)) || (GNUNET_OK
      == GNUNET_DISK_directory_create (id_dir)))
  {
    char *save_dir;
    GNUNET_asprintf (&save_dir, "%s%s%c", id_dir, "rooms", DIR_SEPARATOR);

    if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
        (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
      GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_save_rooms, handle);

    GNUNET_free(save_dir);
  }

  GNUNET_free(id_dir);
}
