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
 * @file src/messenger/gnunet-service-messenger_member_store.c
 * @brief GNUnet MESSENGER service
 */

#include "platform.h"
#include "gnunet-service-messenger_member_store.h"

#include "gnunet-service-messenger_member.h"
#include "gnunet-service-messenger_service.h"
#include "gnunet-service-messenger_room.h"

#include "messenger_api_message.h"

void
init_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert ((store) && (room));

  store->room = room;
  store->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
}


static enum GNUNET_GenericReturnValue
iterate_destroy_members (void *cls,
                         const struct GNUNET_ShortHashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert (value);

  member = value;

  destroy_member (member);
  return GNUNET_YES;
}


void
clear_member_store (struct GNUNET_MESSENGER_MemberStore *store)
{
  GNUNET_assert ((store) && (store->members));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Clear member store of room: %s\n",
              GNUNET_h2s (get_srv_room_key (store->room)));

  GNUNET_CONTAINER_multishortmap_iterate (store->members,
                                          iterate_destroy_members, NULL);
  GNUNET_CONTAINER_multishortmap_destroy (store->members);
}


struct GNUNET_MESSENGER_ContactStore*
get_member_contact_store (struct GNUNET_MESSENGER_MemberStore *store)
{
  struct GNUNET_MESSENGER_SrvRoom *room;

  GNUNET_assert ((store) && (store->room));

  room = store->room;

  return get_service_contact_store (room->service);
}


const struct GNUNET_HashCode*
get_member_store_key (const struct GNUNET_MESSENGER_MemberStore *store)
{
  GNUNET_assert (store);

  return get_srv_room_key ((const struct
                            GNUNET_MESSENGER_SrvRoom*) store->room);
}


static enum GNUNET_GenericReturnValue
callback_scan_for_members (void *cls,
                           const char *filename)
{
  struct GNUNET_MESSENGER_MemberStore *store;

  GNUNET_assert ((cls) && (filename));

  store = cls;

  if (GNUNET_YES == GNUNET_DISK_directory_test (filename, GNUNET_YES))
  {
    char *directory;

    GNUNET_asprintf (&directory, "%s%c", filename, DIR_SEPARATOR);

    load_member (store, directory);

    GNUNET_free (directory);
  }

  return GNUNET_OK;
}


static enum GNUNET_GenericReturnValue
iterate_load_next_member_sessions (void *cls,
                                   const struct GNUNET_ShortHashCode *id,
                                   void *value)
{
  struct GNUNET_MESSENGER_Member *member;
  const char *sync_dir;
  char *member_dir;

  GNUNET_assert ((value) && (id) && (cls));

  member = value;
  sync_dir = cls;

  if (! member)
    return GNUNET_YES;

  GNUNET_asprintf (&member_dir, "%s%s%c", sync_dir, GNUNET_sh2s (id),
                   DIR_SEPARATOR);

  if (GNUNET_YES == GNUNET_DISK_directory_test (member_dir, GNUNET_YES))
    load_member_next_sessions (member, member_dir);

  GNUNET_free (member_dir);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_sync_member_contacts (void *cls,
                              const struct GNUNET_ShortHashCode *id,
                              void *value)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert (value);

  member = value;

  if (! member)
    return GNUNET_YES;

  sync_member_contacts (member);
  return GNUNET_YES;
}


void
load_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   const char *directory)
{
  char *scan_dir;

  GNUNET_assert ((store) && (directory));

  GNUNET_asprintf (&scan_dir, "%s%s%c", directory, "members", DIR_SEPARATOR);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Load member store from directory: %s\n",
              scan_dir);

  if (GNUNET_OK == GNUNET_DISK_directory_test (scan_dir, GNUNET_YES))
    GNUNET_DISK_directory_scan (scan_dir, callback_scan_for_members, store);

  GNUNET_CONTAINER_multishortmap_iterate (store->members,
                                          iterate_load_next_member_sessions,
                                          scan_dir);
  GNUNET_CONTAINER_multishortmap_iterate (store->members,
                                          iterate_sync_member_contacts, NULL);

  GNUNET_free (scan_dir);
}


static enum GNUNET_GenericReturnValue
iterate_save_members (void *cls,
                      const struct GNUNET_ShortHashCode *id,
                      void *value)
{
  struct GNUNET_MESSENGER_Member *member;
  const char *save_dir;
  char *member_dir;

  GNUNET_assert ((value) && (id) && (cls));

  member = value;
  save_dir = cls;

  if (! member)
    return GNUNET_YES;

  GNUNET_asprintf (&member_dir, "%s%s%c", save_dir, GNUNET_sh2s (id),
                   DIR_SEPARATOR);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (member_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create (member_dir)))
    save_member (member, member_dir);

  GNUNET_free (member_dir);
  return GNUNET_YES;
}


void
save_member_store (struct GNUNET_MESSENGER_MemberStore *store,
                   const char *directory)
{
  char *save_dir;

  GNUNET_assert ((store) && (directory));

  GNUNET_asprintf (&save_dir, "%s%s%c", directory, "members", DIR_SEPARATOR);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Save member store to directory: %s\n",
              save_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (save_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create (save_dir)))
    GNUNET_CONTAINER_multishortmap_iterate (store->members,
                                            iterate_save_members, save_dir);

  GNUNET_free (save_dir);
}


struct GNUNET_MESSENGER_Member*
get_store_member (const struct GNUNET_MESSENGER_MemberStore *store,
                  const struct GNUNET_ShortHashCode *id)
{
  GNUNET_assert ((store) && (store->members) && (id));

  return GNUNET_CONTAINER_multishortmap_get (store->members, id);
}


struct GNUNET_MESSENGER_Member*
get_store_member_of (struct GNUNET_MESSENGER_MemberStore *store,
                     const struct GNUNET_MESSENGER_Message *message)
{
  GNUNET_assert ((store) && (message));

  if (GNUNET_YES == is_peer_message (message))
    return NULL;

  if (GNUNET_MESSENGER_KIND_JOIN == message->header.kind)
    return add_store_member (store, &(message->header.sender_id));
  else
    return get_store_member (store, &(message->header.sender_id));
}


struct GNUNET_MESSENGER_Member*
add_store_member (struct GNUNET_MESSENGER_MemberStore *store,
                  const struct GNUNET_ShortHashCode *id)
{
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert ((store) && (store->members));

  member = id? get_store_member (store, id) : NULL;

  if (member)
    return member;

  member = create_member (store, id);

  if (! member)
    return NULL;

  if (GNUNET_OK != GNUNET_CONTAINER_multishortmap_put (store->members,
                                                       get_member_id (member),
                                                       member,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    destroy_member (member);
    return NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added store member with id: %s\n",
              GNUNET_sh2s (get_member_id (member)));

  return member;
}


struct GNUNET_MESSENGER_ClosureIterateMembers
{
  GNUNET_MESSENGER_MemberIteratorCallback it;
  void *cls;
};

static int
iterate_store_members_it (void *cls,
                          const struct GNUNET_ShortHashCode *key,
                          void *value)
{
  struct GNUNET_MESSENGER_ClosureIterateMembers *iterate;
  struct GNUNET_MESSENGER_Member *member;

  GNUNET_assert ((cls) && (value));

  iterate = cls;
  member = value;

  return iterate_member_sessions (member, iterate->it, iterate->cls);
}


int
iterate_store_members (struct GNUNET_MESSENGER_MemberStore *store,
                       GNUNET_MESSENGER_MemberIteratorCallback it,
                       void *cls)
{
  struct GNUNET_MESSENGER_ClosureIterateMembers iterate;

  GNUNET_assert ((store) && (store->members) && (it));

  iterate.it = it;
  iterate.cls = cls;

  return GNUNET_CONTAINER_multishortmap_iterate (store->members,
                                                 iterate_store_members_it,
                                                 &iterate);
}
