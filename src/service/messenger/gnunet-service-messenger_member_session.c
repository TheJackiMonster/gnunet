/*
   This file is part of GNUnet.
   Copyright (C) 2021--2024 GNUnet e.V.

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
 * @file src/messenger/gnunet-service-messenger_member_session.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_member_session.h"

#include "gnunet-service-messenger_room.h"
#include "gnunet-service-messenger_message_store.h"

#include "messenger_api_contact_store.h"

struct GNUNET_MESSENGER_MemberSession*
create_member_session (struct GNUNET_MESSENGER_Member *member,
                       const struct GNUNET_CRYPTO_PublicKey *pubkey)
{
  struct GNUNET_MESSENGER_MemberSession *session;

  if ((! member) || (! pubkey) || (! (member->store)))
    return NULL;

  session = GNUNET_new (struct GNUNET_MESSENGER_MemberSession);
  session->member = member;

  GNUNET_memcpy (&(session->public_key), pubkey, sizeof(session->public_key));

  get_context_from_member (
    get_member_session_key (session),
    get_member_session_id (session),
    &(session->context)
    );

  {
    struct GNUNET_MESSENGER_ContactStore *store;

    store = get_member_contact_store (member->store);

    session->contact = get_store_contact (
      store,
      get_member_session_context (session),
      get_member_session_public_key (session)
      );
  }

  if (! (session->contact))
  {
    GNUNET_free (session);
    return NULL;
  }

  increase_contact_rc (session->contact);

  session->history = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_list_messages (&(session->messages));

  session->prev = NULL;
  session->next = NULL;

  session->start = GNUNET_TIME_absolute_get ();

  session->closed = GNUNET_NO;
  session->completed = GNUNET_NO;

  return session;
}


static struct GNUNET_MESSENGER_MemberStore*
get_session_member_store (const struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert (session);

  member = session->member;

  GNUNET_assert (member);

  return member->store;
}


static struct GNUNET_MESSENGER_SrvRoom*
get_session_room (const struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberStore *store;

  GNUNET_assert (session);

  store = get_session_member_store (session);

  GNUNET_assert (store);

  return store->room;
}


static void
check_member_session_completion (struct GNUNET_MESSENGER_MemberSession *session)
{
  const struct GNUNET_HashCode *start;
  const struct GNUNET_HashCode *end;
  struct GNUNET_MESSENGER_MessageStore *msg_store;
  struct GNUNET_MESSENGER_ListMessages level;
  struct GNUNET_MESSENGER_ListMessages list;

  GNUNET_assert (session);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Check session history (%s) for completion.\n",
              GNUNET_sh2s (get_member_session_id (session)));

  if (! session->messages.tail)
  {
    session->completed = GNUNET_YES;
    goto completion;
  }

  start = &(session->messages.head->hash);
  end = &(session->messages.tail->hash);

  msg_store = get_srv_room_message_store (get_session_room (session));

  init_list_messages (&level);
  add_to_list_messages (&level, end);

  init_list_messages (&list);

  while (level.head)
  {
    struct GNUNET_MESSENGER_ListMessage *element;

    for (element = level.head; element; element = element->next)
    {
      const struct GNUNET_MESSENGER_MessageLink *link;

      link = get_store_message_link (
        msg_store, &(element->hash), GNUNET_NO
        );

      if (! link)
        continue;

      add_to_list_messages (&list, &(link->first));

      if (GNUNET_YES == link->multiple)
        add_to_list_messages (&list, &(link->second));
    }

    clear_list_messages (&level);

    for (element = list.head; element; element = element->next)
      if (GNUNET_YES == check_member_session_history (session, &(element->hash),
                                                      GNUNET_YES))
        break;

    if (element)
      if (0 != GNUNET_CRYPTO_hash_cmp (&(element->hash), start))
        add_to_list_messages (&level, &(element->hash));
      else
        session->completed = GNUNET_YES;
    else
      copy_list_messages (&level, &list);

    clear_list_messages (&list);
  }

completion:
  if (GNUNET_YES == is_member_session_completed (session))
  {
    struct GNUNET_MESSENGER_MemberStore *member_store;
    struct GNUNET_MESSENGER_ContactStore *store;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Completed session history (%s)\n",
                GNUNET_sh2s (get_member_session_id (session)));

    member_store = get_session_member_store (session);
    store = get_member_contact_store (member_store);

    if ((session->contact) && (GNUNET_YES == decrease_contact_rc (
                                 session->contact)))
      remove_store_contact (
        store,
        session->contact,
        get_member_session_context (session)
        );

    session->contact = NULL;
  }
}


static enum GNUNET_GenericReturnValue
iterate_copy_history (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_MemberSession *next;

  GNUNET_assert ((cls) && (key));

  next = cls;

  GNUNET_CONTAINER_multihashmap_put (next->history, key, (value? next : NULL),
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  return GNUNET_YES;
}


struct GNUNET_MESSENGER_MemberSession*
switch_member_session (struct GNUNET_MESSENGER_MemberSession *session,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberStore *store;
  struct GNUNET_MESSENGER_MemberSession *next;

  if ((! session) || (! message) || (! hash))
    return NULL;

  GNUNET_assert ((GNUNET_MESSENGER_KIND_ID == message->header.kind) ||
                 (GNUNET_MESSENGER_KIND_KEY == message->header.kind));

  store = get_session_member_store (session);
  next = GNUNET_new (struct GNUNET_MESSENGER_MemberSession);

  if (GNUNET_MESSENGER_KIND_ID == message->header.kind)
  {
    next->member = add_store_member (store,
                                     &(message->body.id.id));
    if (! next->member)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to switch member session to ID: %s\n",
                  GNUNET_sh2s (&(message->body.id.id)));

      GNUNET_free (next);
      return NULL;
    }
  }
  else
    next->member = session->member;

  if (GNUNET_MESSENGER_KIND_KEY == message->header.kind)
    GNUNET_memcpy (&(next->public_key), &(message->body.key.key),
                   sizeof(next->public_key));
  else
    GNUNET_memcpy (&(next->public_key), get_member_session_public_key (session),
                   sizeof(next->public_key));

  get_context_from_member (
    get_member_session_key (next),
    get_member_session_id (next),
    &(next->context)
    );

  update_store_contact (
    get_member_contact_store (store),
    get_member_session_contact (session),
    get_member_session_context (session),
    get_member_session_context (next),
    get_member_session_public_key (next)
    );

  next->contact = get_member_session_contact (session);

  if (! (next->contact))
  {
    GNUNET_free (next);
    return NULL;
  }

  increase_contact_rc (next->contact);

  next->history = GNUNET_CONTAINER_multihashmap_create (
    GNUNET_CONTAINER_multihashmap_size (session->history), GNUNET_NO
    );

  GNUNET_CONTAINER_multihashmap_iterate (session->history, iterate_copy_history,
                                         next);

  init_list_messages (&(next->messages));
  copy_list_messages (&(next->messages), &(session->messages));

  session->next = next;
  next->prev = session;
  next->next = NULL;

  next->start = GNUNET_TIME_absolute_get ();

  session->closed = GNUNET_YES;
  next->closed = GNUNET_NO;
  next->completed = GNUNET_NO;

  check_member_session_completion (session);

  return next;
}


void
destroy_member_session (struct GNUNET_MESSENGER_MemberSession *session)
{
  struct GNUNET_MESSENGER_MemberStore *store;
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert (session);

  GNUNET_CONTAINER_multihashmap_destroy (session->history);

  clear_list_messages (&(session->messages));

  store = get_session_member_store (session);
  contact = get_member_session_contact (session);

  if ((contact) && (GNUNET_YES == decrease_contact_rc (contact)))
    remove_store_contact (
      get_member_contact_store (store),
      contact,
      get_member_session_context (session)
      );

  GNUNET_free (session);
}


enum GNUNET_GenericReturnValue
reset_member_session (struct GNUNET_MESSENGER_MemberSession *session,
                      const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact;

  GNUNET_assert ((session) && (hash));

  {
    struct GNUNET_MESSENGER_MemberStore *member_store;
    struct GNUNET_MESSENGER_ContactStore *store;

    member_store = get_session_member_store (session);
    store = get_member_contact_store (member_store);
    contact = get_store_contact (
      store,
      get_member_session_context (session),
      get_member_session_public_key (session)
      );
  }

  if (! contact)
    return GNUNET_SYSERR;

  if (contact == session->contact)
    goto clear_messages;

  session->contact = contact;
  increase_contact_rc (session->contact);

clear_messages:
  clear_list_messages (&(session->messages));
  add_to_list_messages (&(session->messages), hash);

  session->next = NULL;
  session->closed = GNUNET_NO;
  session->completed = GNUNET_NO;

  return GNUNET_OK;
}


void
close_member_session (struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  session->closed = GNUNET_YES;
  check_member_session_completion (session);
}


enum GNUNET_GenericReturnValue
is_member_session_closed (const struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return session->closed;
}


enum GNUNET_GenericReturnValue
is_member_session_completed (const struct
                             GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return session->completed;
}


struct GNUNET_TIME_Absolute
get_member_session_start (const struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  if (session->prev)
    return get_member_session_start (session->prev);

  return session->start;
}


const struct GNUNET_HashCode*
get_member_session_key (const struct GNUNET_MESSENGER_MemberSession *session)
{
  const struct GNUNET_MESSENGER_MemberStore *store;

  GNUNET_assert ((session) && (session->member));

  store = get_session_member_store (session);

  return get_member_store_key (store);
}


const struct GNUNET_ShortHashCode*
get_member_session_id (const struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return get_member_id (session->member);
}


const struct GNUNET_CRYPTO_PublicKey*
get_member_session_public_key (const struct
                               GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return &(session->public_key);
}


const struct GNUNET_HashCode*
get_member_session_context (const struct
                            GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return &(session->context);
}


struct GNUNET_MESSENGER_Contact*
get_member_session_contact (struct GNUNET_MESSENGER_MemberSession *session)
{
  GNUNET_assert (session);

  return session->contact;
}


enum GNUNET_GenericReturnValue
verify_member_session_as_sender (const struct
                                 GNUNET_MESSENGER_MemberSession *session,
                                 const struct GNUNET_MESSENGER_Message *message,
                                 const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((session) && (message) && (hash));

  if (GNUNET_YES == is_member_session_completed (session))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Check message (%s) using history!\n",
                GNUNET_h2s (hash));

    if (GNUNET_YES == check_member_session_history (session, hash, GNUNET_YES))
      return GNUNET_OK;
    else
      return GNUNET_SYSERR;
  }

  if (0 != GNUNET_memcmp (get_member_session_id (session),
                          &(message->header.sender_id)))
    return GNUNET_SYSERR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Check message (%s) using key: %s\n",
              GNUNET_h2s (hash),
              GNUNET_CRYPTO_public_key_to_string (
                get_member_session_public_key (session)));

  return verify_message (message, hash, get_member_session_public_key (
                           session));
}


enum GNUNET_GenericReturnValue
check_member_session_history (const struct
                              GNUNET_MESSENGER_MemberSession *session,
                              const struct GNUNET_HashCode *hash,
                              enum GNUNET_GenericReturnValue ownership)
{
  GNUNET_assert ((session) && (hash));

  if (GNUNET_YES == ownership)
    return (NULL != GNUNET_CONTAINER_multihashmap_get (session->history, hash)?
            GNUNET_YES : GNUNET_NO);
  else
    return GNUNET_CONTAINER_multihashmap_contains (session->history, hash);
}


static void
update_member_chain_history (struct GNUNET_MESSENGER_MemberSession *session,
                             const struct GNUNET_HashCode *hash,
                             enum GNUNET_GenericReturnValue ownership)
{
  GNUNET_assert ((session) && (hash));

  if ((GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (session->history, hash,
                                                       (GNUNET_YES == ownership?
                                                        session : NULL),
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      && (session->next))
    update_member_chain_history (session->next, hash, ownership);
}


void
update_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                               const struct GNUNET_MESSENGER_Message *message,
                               const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((session) && (message) && (hash));

  if (GNUNET_YES == is_member_session_completed (session))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updating sessions history (%s) += (%s)\n",
              GNUNET_sh2s (get_member_session_id (session)), GNUNET_h2s (hash));

  if (GNUNET_OK == verify_member_session_as_sender (session, message, hash))
  {
    if (GNUNET_YES == is_message_session_bound (message))
      add_to_list_messages (&(session->messages), hash);

    update_member_chain_history (session, hash, GNUNET_YES);
  }
  else
    update_member_chain_history (session, hash, GNUNET_NO);

  if (GNUNET_YES == session->closed)
    check_member_session_completion (session);
}


static void
clear_member_chain_history (struct GNUNET_MESSENGER_MemberSession *session,
                            const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((session) && (hash));

  if ((0 < GNUNET_CONTAINER_multihashmap_remove_all (session->history, hash)) &&
      (session->next))
    clear_member_session_history (session->next, hash);
}


void
clear_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                              const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((session) && (hash));

  clear_member_chain_history (session, hash);
}


struct GNUNET_MESSENGER_MemberSessionHistoryEntry
{
  struct GNUNET_HashCode hash;
  unsigned char ownership;
};

static void
load_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                             const char *path)
{
  struct GNUNET_DISK_FileHandle *handle;
  enum GNUNET_GenericReturnValue status;

  GNUNET_assert ((session) && (path));

  if (GNUNET_YES != GNUNET_DISK_file_test (path))
    return;

  {
    enum GNUNET_DISK_AccessPermissions permission;

    permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    handle = GNUNET_DISK_file_open (path, GNUNET_DISK_OPEN_READ, permission);
  }

  if (! handle)
    return;

  GNUNET_DISK_file_seek (handle, 0, GNUNET_DISK_SEEK_SET);

  do {
    struct GNUNET_MESSENGER_MemberSessionHistoryEntry entry;
    ssize_t len;

    len = GNUNET_DISK_file_read (handle, &(entry.hash), sizeof(entry.hash));

    if (len != sizeof(entry.hash))
      break;

    len = GNUNET_DISK_file_read (handle, &(entry.ownership),
                                 sizeof(entry.ownership));

    if (len != sizeof(entry.ownership))
      break;

    status = GNUNET_CONTAINER_multihashmap_put (session->history, &(entry.hash),
                                                (entry.ownership? session :
                                                 NULL),
                                                GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  } while (status == GNUNET_OK);

  GNUNET_DISK_file_close (handle);
}


void
load_member_session (struct GNUNET_MESSENGER_Member *member,
                     const char *directory)
{
  char *config_file;
  struct GNUNET_MESSENGER_MemberSession *session;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_assert ((member) && (directory));

  GNUNET_asprintf (&config_file, "%s%s", directory, "session.cfg");

  session = NULL;

  if (GNUNET_YES != GNUNET_DISK_file_test (config_file))
    goto free_config;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Load session configuration of member: %s\n", config_file);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    goto free_config;

  if (GNUNET_OK == GNUNET_CONFIGURATION_parse (cfg, config_file))
  {
    struct GNUNET_CRYPTO_PublicKey key;
    enum GNUNET_GenericReturnValue key_result;
    unsigned long long numeric_value;
    char *key_data;

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "session",
                                                            "key", &key_data))
      goto destroy_config;

    key_result = GNUNET_CRYPTO_public_key_from_string (key_data, &key);
    GNUNET_free (key_data);

    if (GNUNET_OK != key_result)
      goto destroy_config;

    session = create_member_session (member, &key);

    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "session",
                                                            "start",
                                                            &numeric_value))
      session->start.abs_value_us = numeric_value;

    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "session",
                                                            "closed",
                                                            &numeric_value))
      session->closed = (GNUNET_YES == numeric_value? GNUNET_YES : GNUNET_NO);

    if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "session",
                                                            "completed",
                                                            &numeric_value))
      session->completed = (GNUNET_YES == numeric_value? GNUNET_YES :
                            GNUNET_NO);
  }

destroy_config:
  GNUNET_CONFIGURATION_destroy (cfg);

free_config:
  GNUNET_free (config_file);

  if (! session)
    return;

  {
    char *history_file;
    GNUNET_asprintf (&history_file, "%s%s", directory, "history.map");

    load_member_session_history (session, history_file);
    GNUNET_free (history_file);
  }

  {
    char *messages_file;
    GNUNET_asprintf (&messages_file, "%s%s", directory, "messages.list");

    load_list_messages (&(session->messages), messages_file);
    GNUNET_free (messages_file);
  }

  add_member_session (member, session);
}


static struct GNUNET_MESSENGER_MemberSession*
get_cycle_safe_next_session (struct GNUNET_MESSENGER_MemberSession *session,
                             struct GNUNET_MESSENGER_MemberSession *next)
{
  struct GNUNET_MESSENGER_MemberSession *check;

  if (! next)
    return NULL;

  check = next;

  do {
    if (check == session)
      return NULL;

    check = check->next;
  } while (check);

  return next;
}


void
load_member_session_next (struct GNUNET_MESSENGER_MemberSession *session,
                          const char *directory)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config_file;


  GNUNET_assert ((session) && (directory));

  GNUNET_asprintf (&config_file, "%s%s", directory, "session.cfg");

  if (GNUNET_YES != GNUNET_DISK_file_test (config_file))
    goto free_config;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Load next session configuration of member: %s\n", config_file);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    goto free_config;

  if (GNUNET_OK == GNUNET_CONFIGURATION_parse (cfg, config_file))
  {
    struct GNUNET_CRYPTO_PublicKey next_key;
    enum GNUNET_GenericReturnValue key_result;
    struct GNUNET_ShortHashCode next_id;
    char *key_data;

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "session",
                                                            "next_key",
                                                            &key_data))
      goto destroy_config;

    key_result = GNUNET_CRYPTO_public_key_from_string (key_data, &next_key);
    GNUNET_free (key_data);

    if (GNUNET_OK != key_result)
      goto destroy_config;

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "session", "next_id",
                                                    &next_id, sizeof(next_id)))
      goto destroy_config;

    {
      struct GNUNET_MESSENGER_MemberStore *store;
      struct GNUNET_MESSENGER_Member *member;

      store = get_session_member_store (session);
      member = get_store_member (store, &next_id);

      session->next = get_cycle_safe_next_session (
        session, member? get_member_session (member, &next_key) : NULL
        );
    }

    if (session->next)
      session->next->prev = session;
  }

destroy_config:
  GNUNET_CONFIGURATION_destroy (cfg);

free_config:
  GNUNET_free (config_file);
}


static enum GNUNET_GenericReturnValue
iterate_save_member_session_history_hentries (void *cls,
                                              const struct GNUNET_HashCode *key,
                                              void *value)
{
  struct GNUNET_DISK_FileHandle *handle;
  unsigned char ownership;

  GNUNET_assert ((cls) && (key));

  handle = cls;
  ownership = value? GNUNET_YES : GNUNET_NO;

  GNUNET_DISK_file_write (handle, key, sizeof(*key));
  GNUNET_DISK_file_write (handle, &ownership, sizeof(ownership));

  return GNUNET_YES;
}


static void
save_member_session_history (struct GNUNET_MESSENGER_MemberSession *session,
                             const char *path)
{
  struct GNUNET_DISK_FileHandle *handle;

  GNUNET_assert ((session) && (path));

  {
    enum GNUNET_DISK_AccessPermissions permission;

    permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

    handle = GNUNET_DISK_file_open (
      path, GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_WRITE, permission
      );
  }

  if (! handle)
    return;

  GNUNET_DISK_file_seek (handle, 0, GNUNET_DISK_SEEK_SET);

  GNUNET_CONTAINER_multihashmap_iterate (
    session->history,
    iterate_save_member_session_history_hentries,
    handle
    );

  GNUNET_DISK_file_sync (handle);
  GNUNET_DISK_file_close (handle);
}


void
save_member_session (struct GNUNET_MESSENGER_MemberSession *session,
                     const char *directory)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config_file;
  char *key_data;

  GNUNET_assert ((session) && (directory));

  GNUNET_asprintf (&config_file, "%s%s", directory, "session.cfg");

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Save session configuration of member: %s\n", config_file);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    goto free_config;

  key_data = GNUNET_CRYPTO_public_key_to_string (
    get_member_session_public_key (session));

  if (key_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "session", "key", key_data);
    GNUNET_free (key_data);
  }

  if (session->next)
  {
    const struct GNUNET_ShortHashCode *next_id = get_member_session_id (
      session->next);

    char *next_id_data = GNUNET_STRINGS_data_to_string_alloc (next_id,
                                                              sizeof(*next_id));

    if (next_id_data)
    {
      GNUNET_CONFIGURATION_set_value_string (cfg, "session", "next_id",
                                             next_id_data);
      GNUNET_free (next_id_data);
    }

    key_data = GNUNET_CRYPTO_public_key_to_string (
      get_member_session_public_key (session->next));

    if (key_data)
    {
      GNUNET_CONFIGURATION_set_value_string (cfg, "session", "next_key",
                                             key_data);
      GNUNET_free (key_data);
    }
  }

  GNUNET_CONFIGURATION_set_value_number (cfg, "session", "start",
                                         session->start.abs_value_us);

  GNUNET_CONFIGURATION_set_value_number (cfg, "session", "closed",
                                         session->closed);
  GNUNET_CONFIGURATION_set_value_number (cfg, "session", "completed",
                                         session->completed);

  GNUNET_CONFIGURATION_write (cfg, config_file);
  GNUNET_CONFIGURATION_destroy (cfg);

free_config:
  GNUNET_free (config_file);

  {
    char *history_file;
    GNUNET_asprintf (&history_file, "%s%s", directory, "history.map");

    save_member_session_history (session, history_file);
    GNUNET_free (history_file);
  }

  {
    char *messages_file;
    GNUNET_asprintf (&messages_file, "%s%s", directory, "messages.list");

    save_list_messages (&(session->messages), messages_file);
    GNUNET_free (messages_file);
  }
}
