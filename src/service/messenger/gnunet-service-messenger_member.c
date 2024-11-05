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
 * @file src/messenger/gnunet-service-messenger_member.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet-service-messenger_member.h"

#include "gnunet-service-messenger_member_session.h"

#include "messenger_api_util.h"

struct GNUNET_MESSENGER_Member*
create_member (struct GNUNET_MESSENGER_MemberStore *store,
               const struct GNUNET_ShortHashCode *id)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert (store);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Create new member: %s\n",
              GNUNET_sh2s (id));

  member = GNUNET_new (struct GNUNET_MESSENGER_Member);
  member->store = store;

  if (id)
    GNUNET_memcpy (&(member->id), id, sizeof(member->id));
  else if (GNUNET_YES != generate_free_member_id (&(member->id),
                                                  store->members))
  {
    GNUNET_free (member);
    return NULL;
  }

  member->sessions = GNUNET_CONTAINER_multihashmap_create (2, GNUNET_NO);
  member->subscriptions = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);

  return member;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_session (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_MemberSession *session;

  GNUNET_assert (value);

  session = value;

  destroy_member_session (session);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_subscription (void *cls,
                              const struct GNUNET_ShortHashCode *key,
                              void *value)
{
  struct GNUNET_MESSENGER_Subscription *subscription;

  GNUNET_assert (value);

  subscription = value;

  destroy_subscription (subscription);
  return GNUNET_YES;
}


void
destroy_member (struct GNUNET_MESSENGER_Member *member)
{
  GNUNET_assert ((member) && (member->sessions));

  GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                         iterate_destroy_session, NULL);
  GNUNET_CONTAINER_multishortmap_iterate (member->subscriptions,
                                          iterate_destroy_subscription, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (member->sessions);
  GNUNET_CONTAINER_multishortmap_destroy (member->subscriptions);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Free member: %s\n",
              GNUNET_sh2s (&(member->id)));

  GNUNET_free (member);
}


const struct GNUNET_ShortHashCode*
get_member_id (const struct GNUNET_MESSENGER_Member *member)
{
  GNUNET_assert (member);

  return &(member->id);
}


static enum GNUNET_GenericReturnValue
callback_scan_for_sessions (void *cls,
                            const char *filename)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert ((cls) && (filename));

  member = cls;

  if (GNUNET_YES == GNUNET_DISK_directory_test (filename, GNUNET_YES))
  {
    char *directory;

    GNUNET_asprintf (&directory, "%s%c", filename, DIR_SEPARATOR);

    load_member_session (member, directory);
    GNUNET_free (directory);
  }

  return GNUNET_OK;
}


void
load_member (struct GNUNET_MESSENGER_MemberStore *store,
             const char *directory)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_MESSENGER_Member *member;
  char *config_file;

  GNUNET_assert ((store) && (directory));

  GNUNET_asprintf (&config_file, "%s%s", directory, "member.cfg");

  member = NULL;

  if (GNUNET_YES != GNUNET_DISK_file_test (config_file))
    goto free_config;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Load member configuration: %s\n",
              config_file);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    goto free_config;

  if (GNUNET_OK == GNUNET_CONFIGURATION_parse (cfg, config_file))
  {
    struct GNUNET_ShortHashCode id;

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_data (cfg, "member", "id", &id,
                                                    sizeof(id)))
      goto destroy_config;

    member = add_store_member (store, &id);
  }

destroy_config:
  GNUNET_CONFIGURATION_destroy (cfg);

free_config:
  GNUNET_free (config_file);

  if (! member)
    return;

  {
    char *scan_dir;
    GNUNET_asprintf (&scan_dir, "%s%s%c", directory, "sessions", DIR_SEPARATOR);

    if (GNUNET_OK == GNUNET_DISK_directory_test (scan_dir, GNUNET_YES))
      GNUNET_DISK_directory_scan (scan_dir, callback_scan_for_sessions, member);

    GNUNET_free (scan_dir);
  }
}


static enum GNUNET_GenericReturnValue
iterate_load_next_session (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  const char *sessions_directory;
  char *load_dir;

  GNUNET_assert ((cls) && (key));

  sessions_directory = cls;

  GNUNET_asprintf (&load_dir, "%s%s%c", sessions_directory, GNUNET_h2s (key),
                   DIR_SEPARATOR);

  {
    struct GNUNET_MESSENGER_MemberSession *session;

    GNUNET_assert (value);

    session = value;

    if (GNUNET_YES == GNUNET_DISK_directory_test (load_dir, GNUNET_YES))
      load_member_session_next (session, load_dir);
  }

  GNUNET_free (load_dir);
  return GNUNET_YES;
}


void
load_member_next_sessions (const struct GNUNET_MESSENGER_Member *member,
                           const char *directory)
{
  char *load_dir;

  GNUNET_assert ((member) && (directory));

  GNUNET_asprintf (&load_dir, "%s%s%c", directory, "sessions", DIR_SEPARATOR);

  GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                         iterate_load_next_session, load_dir);

  GNUNET_free (load_dir);
}


static enum GNUNET_GenericReturnValue
iterate_save_session (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  const char *sessions_directory;
  char *save_dir;

  GNUNET_assert ((cls) && (key));

  sessions_directory = cls;

  GNUNET_asprintf (&save_dir, "%s%s%c", sessions_directory, GNUNET_h2s (key),
                   DIR_SEPARATOR);

  {
    struct GNUNET_MESSENGER_MemberSession *session;

    GNUNET_assert (value);

    session = value;

    if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
        (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
      save_member_session (session, save_dir);
  }

  GNUNET_free (save_dir);
  return GNUNET_YES;
}


void
save_member (struct GNUNET_MESSENGER_Member *member,
             const char *directory)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config_file;
  char *id_data;

  GNUNET_assert ((member) && (directory));

  GNUNET_asprintf (&config_file, "%s%s", directory, "member.cfg");

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Save member configuration: %s\n",
              config_file);

  cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());

  if (! cfg)
    goto free_config;

  id_data = GNUNET_STRINGS_data_to_string_alloc (&(member->id),
                                                 sizeof(member->id));

  if (id_data)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg, "member", "id", id_data);

    GNUNET_free (id_data);
  }

  GNUNET_CONFIGURATION_write (cfg, config_file);
  GNUNET_CONFIGURATION_destroy (cfg);

free_config:
  GNUNET_free (config_file);

  {
    char *save_dir;
    GNUNET_asprintf (&save_dir, "%s%s%c", directory, "sessions", DIR_SEPARATOR);

    if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
        (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
      GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                             iterate_save_session, save_dir);

    GNUNET_free (save_dir);
  }
}


static void
sync_session_contact_from_next (struct GNUNET_MESSENGER_MemberSession *session,
                                struct GNUNET_MESSENGER_MemberSession *next)
{
  GNUNET_assert ((session) && (next));

  if (session == next)
    return;

  if (next->next)
    sync_session_contact_from_next (session, next->next);
  else
    session->contact = next->contact;
}


static enum GNUNET_GenericReturnValue
iterate_sync_session_contact (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct GNUNET_MESSENGER_MemberSession *session;

  GNUNET_assert (value);

  session = value;

  if (session->next)
    sync_session_contact_from_next (session, session->next);

  return GNUNET_YES;
}


void
sync_member_contacts (struct GNUNET_MESSENGER_Member *member)
{
  GNUNET_assert ((member) && (member->sessions));

  GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                         iterate_sync_session_contact, NULL);
}


struct GNUNET_MESSENGER_MemberSession*
get_member_session (const struct GNUNET_MESSENGER_Member *member,
                    const struct GNUNET_CRYPTO_PublicKey *public_key)
{
  struct GNUNET_HashCode hash;

  GNUNET_assert ((member) && (public_key));

  GNUNET_CRYPTO_hash (public_key, sizeof(*public_key), &hash);

  return GNUNET_CONTAINER_multihashmap_get (member->sessions, &hash);
}


struct GNUNET_MESSENGER_ClosureSearchSession
{
  const struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_HashCode *hash;

  struct GNUNET_MESSENGER_MemberSession *match;
};

static enum GNUNET_GenericReturnValue
iterate_search_session (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_MESSENGER_ClosureSearchSession *search;
  struct GNUNET_MESSENGER_MemberSession *session;

  GNUNET_assert ((cls) && (value));

  search = cls;
  session = value;

  if (GNUNET_OK != verify_member_session_as_sender (session, search->message,
                                                    search->hash))
    return GNUNET_YES;

  search->match = session;
  return GNUNET_NO;
}


static struct GNUNET_MESSENGER_MemberSession*
try_member_session (struct GNUNET_MESSENGER_Member *member,
                    const struct GNUNET_CRYPTO_PublicKey *public_key)
{
  struct GNUNET_MESSENGER_MemberSession *session;

  GNUNET_assert ((member) && (public_key));

  session = get_member_session (member, public_key);

  if (session)
    return session;

  session = create_member_session (member, public_key);

  if (session)
    add_member_session (member, session);

  return session;
}


struct GNUNET_MESSENGER_MemberSession*
get_member_session_of (struct GNUNET_MESSENGER_Member *member,
                       const struct GNUNET_MESSENGER_Message *message,
                       const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((member) && (message) && (hash) &&
                 (0 == GNUNET_memcmp (&(member->id),
                                      &(message->header.sender_id))));

  if (GNUNET_MESSENGER_KIND_JOIN == message->header.kind)
    return try_member_session (member, &(message->body.join.key));

  {
    struct GNUNET_MESSENGER_ClosureSearchSession search;

    search.message = message;
    search.hash = hash;

    search.match = NULL;
    GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                           iterate_search_session, &search);

    return search.match;
  }
}


void
add_member_session (struct GNUNET_MESSENGER_Member *member,
                    struct GNUNET_MESSENGER_MemberSession *session)
{
  const struct GNUNET_CRYPTO_PublicKey *public_key;
  struct GNUNET_HashCode hash;

  if (! session)
    return;

  GNUNET_assert ((member) && (session->member == member));

  public_key = get_member_session_public_key (session);
  GNUNET_CRYPTO_hash (public_key, sizeof(*public_key), &hash);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        member->sessions, &hash, session,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Adding a member session failed: %s\n",
                GNUNET_h2s (&hash));
}


void
remove_member_session (struct GNUNET_MESSENGER_Member *member,
                       struct GNUNET_MESSENGER_MemberSession *session)
{
  const struct GNUNET_CRYPTO_PublicKey *public_key;
  struct GNUNET_HashCode hash;

  GNUNET_assert ((member) && (session) && (session->member == member));

  public_key = get_member_session_public_key (session);
  GNUNET_CRYPTO_hash (public_key, sizeof(*public_key), &hash);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (member->sessions,
                                                          &hash, session))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Removing a member session failed: %s\n",
                GNUNET_h2s (&hash));
}


struct GNUNET_MESSENGER_ClosureIterateSessions
{
  GNUNET_MESSENGER_MemberIteratorCallback it;
  void *cls;
};

static enum GNUNET_GenericReturnValue
iterate_member_sessions_it (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct GNUNET_MESSENGER_ClosureIterateSessions *iterate;
  struct GNUNET_MESSENGER_MemberSession *session;

  GNUNET_assert ((cls) && (value));

  iterate = cls;
  session = value;

  return iterate->it (iterate->cls, get_member_session_public_key (session),
                      session);
}


int
iterate_member_sessions (struct GNUNET_MESSENGER_Member *member,
                         GNUNET_MESSENGER_MemberIteratorCallback it,
                         void *cls)
{
  struct GNUNET_MESSENGER_ClosureIterateSessions iterate;

  GNUNET_assert ((member) && (member->sessions) && (it));

  iterate.it = it;
  iterate.cls = cls;

  return GNUNET_CONTAINER_multihashmap_iterate (member->sessions,
                                                iterate_member_sessions_it,
                                                &iterate);
}


void
add_member_subscription (struct GNUNET_MESSENGER_Member *member,
                         struct GNUNET_MESSENGER_Subscription *subscription)
{
  const struct GNUNET_ShortHashCode *discourse;

  GNUNET_assert ((member) && (member->subscriptions) && (subscription));

  discourse = get_subscription_discourse (subscription);

  if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (
        member->subscriptions, discourse, subscription,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Adding a member subscription failed: %s\n",
                GNUNET_sh2s (discourse));
}


void
remove_member_subscription (struct GNUNET_MESSENGER_Member *member,
                            struct GNUNET_MESSENGER_Subscription *subscription)
{
  const struct GNUNET_ShortHashCode *discourse;

  GNUNET_assert ((member) && (member->subscriptions) && (subscription));

  discourse = get_subscription_discourse (subscription);

  if (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (member->subscriptions
                                                           ,
                                                           discourse,
                                                           subscription))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Removing a member subscription failed: %s\n",
                GNUNET_sh2s (discourse));
}


struct GNUNET_MESSENGER_Subscription*
get_member_subscription (struct GNUNET_MESSENGER_Member *member,
                         const struct GNUNET_ShortHashCode *discourse)
{
  GNUNET_assert ((member) && (member->subscriptions) && (discourse));

  return GNUNET_CONTAINER_multishortmap_get (member->subscriptions, discourse);
}


int
iterate_member_subscriptions (struct GNUNET_MESSENGER_Member *member,
                              GNUNET_MESSENGER_SubscriptionIteratorCallback it,
                              void *cls)
{
  GNUNET_assert ((member) && (member->subscriptions) && (it));

  return GNUNET_CONTAINER_multishortmap_iterate (member->subscriptions,
                                                 (
                                                   GNUNET_CONTAINER_ShortmapIterator)
                                                 it,
                                                 cls);
}
