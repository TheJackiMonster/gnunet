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
 * @file src/messenger/gnunet-service-messenger_message_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_store.h"

#include "gnunet-service-messenger_list_messages.h"

#include "messenger_api_message.h"

void
init_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  GNUNET_assert (store);

  store->storage_messages = NULL;

  store->entries = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->links = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->discourses = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  store->rewrite_entries = GNUNET_NO;
  store->write_links = GNUNET_NO;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_entries (void *cls,
                         const struct GNUNET_HashCode *key,
                         void *value)
{
  struct GNUNET_MESSENGER_MessageEntry *entry;

  GNUNET_assert (value);

  entry = value;

  GNUNET_free (entry);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_messages (void *cls,
                          const struct GNUNET_HashCode *key,
                          void *value)
{
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (value);
  
  message = value;

  destroy_message (message);
  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_destroy_links (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_HashCode *previous;

  GNUNET_assert (value);

  previous = value;

  GNUNET_free (previous);
  return GNUNET_YES;
}


void
clear_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  GNUNET_assert (store);

  if (store->storage_messages)
  {
    GNUNET_DISK_file_close (store->storage_messages);

    store->storage_messages = NULL;
  }

  GNUNET_CONTAINER_multihashmap_iterate (store->entries,
                                         iterate_destroy_entries, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->messages,
                                         iterate_destroy_messages, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->links, iterate_destroy_links,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->discourses,
                                         iterate_destroy_messages, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (store->entries);
  GNUNET_CONTAINER_multihashmap_destroy (store->messages);
  GNUNET_CONTAINER_multihashmap_destroy (store->links);
  GNUNET_CONTAINER_multihashmap_destroy (store->discourses);
}


struct GNUNET_MESSENGER_MessageEntryStorage
{
  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_MessageEntry entry;
};

#define load_message_store_attribute_failed(file, attribute) \
        sizeof(attribute) != GNUNET_DISK_file_read (file, &(attribute), \
                                                    sizeof(attribute))

#define save_message_store_attribute_failed(file, attribute) \
        sizeof(attribute) != GNUNET_DISK_file_write (file, &(attribute), \
                                                     sizeof(attribute))

static void
load_message_store_entries (struct GNUNET_MESSENGER_MessageStore *store,
                            const char *filename)
{
  enum GNUNET_DISK_AccessPermissions permission;
  struct GNUNET_DISK_FileHandle *entries;
  struct GNUNET_MESSENGER_MessageEntryStorage storage;
  struct GNUNET_MESSENGER_MessageEntry *entry;
  
  permission = (GNUNET_DISK_PERM_USER_READ);
  entries = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                   permission);

  if (! entries)
    return;

  memset (&storage, 0, sizeof(storage));

  do
  {
    entry = NULL;

    if ((load_message_store_attribute_failed (entries, storage.hash)) ||
        (load_message_store_attribute_failed (entries, storage.entry.offset)) ||
        (load_message_store_attribute_failed (entries, storage.entry.length)))
      break;

    entry = GNUNET_new (struct GNUNET_MESSENGER_MessageEntry);

    GNUNET_memcpy (entry, &(storage.entry), sizeof(*entry));

    if ((GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (store->entries,
                                                               &(storage.hash)))
        ||
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (store->entries,
                                                         &(storage.hash), entry,
                                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    {
      store->rewrite_entries = GNUNET_YES;
      break;
    }
  }
  while (entry);

  if (entry)
    GNUNET_free (entry);

  GNUNET_DISK_file_close (entries);
}


struct GNUNET_MESSENGER_MessageLinkStorage
{
  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_MessageLink link;
};

static void
load_message_store_links (struct GNUNET_MESSENGER_MessageStore *store,
                          const char *filename)
{
  enum GNUNET_DISK_AccessPermissions permission;
  struct GNUNET_DISK_FileHandle *entries;
  struct GNUNET_MESSENGER_MessageLinkStorage storage;
  struct GNUNET_MESSENGER_MessageLink *link;
  
  permission = (GNUNET_DISK_PERM_USER_READ);

  entries = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                   permission);

  if (! entries)
    return;

  memset (&storage, 0, sizeof(storage));

  do
  {
    link = NULL;

    if ((load_message_store_attribute_failed (entries, storage.hash)) ||
        (load_message_store_attribute_failed (entries,
                                              storage.link.multiple)) ||
        (load_message_store_attribute_failed (entries, storage.link.first)) ||
        ((GNUNET_YES == storage.link.multiple) &&
         (load_message_store_attribute_failed (entries, storage.link.second))))
      break;

    link = GNUNET_new (struct GNUNET_MESSENGER_MessageLink);

    GNUNET_memcpy (link, &(storage.link), sizeof(*link));

    if ((GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (store->links,
                                                               &(storage.hash)))
        ||
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (store->links,
                                                         &(storage.hash), link,
                                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))

      break;
  }
  while (link);

  if (link)
    GNUNET_free (link);

  GNUNET_DISK_file_close (entries);
}


void
load_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory)
{
  enum GNUNET_DISK_AccessPermissions permission;
  char *filename;

  GNUNET_assert ((store) && (directory));

  permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  if (store->storage_messages)
    GNUNET_DISK_file_close (store->storage_messages);

  GNUNET_asprintf (&filename, "%s%s", directory, "messages.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    store->storage_messages = GNUNET_DISK_file_open (filename,
                                                     GNUNET_DISK_OPEN_READWRITE,
                                                     permission);
  else
    store->storage_messages = NULL;

  GNUNET_free (filename);

  if (! store->storage_messages)
    return;

  GNUNET_asprintf (&filename, "%s%s", directory, "entries.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    load_message_store_entries (store, filename);

  GNUNET_free (filename);

  GNUNET_asprintf (&filename, "%s%s", directory, "links.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    load_message_store_links (store, filename);

  GNUNET_free (filename);
}


struct GNUNET_MESSENGER_ClosureMessageSave
{
  struct GNUNET_MESSENGER_MessageStore *store;

  struct GNUNET_DISK_FileHandle *storage;
};

static enum GNUNET_GenericReturnValue
iterate_save_links (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct GNUNET_MESSENGER_ClosureMessageSave *save;
  struct GNUNET_MESSENGER_MessageLink *link;

  GNUNET_assert ((cls) && (key) && (value));

  save = cls;
  link = value;

  if ((save_message_store_attribute_failed (save->storage, (*key))) ||
      (save_message_store_attribute_failed (save->storage, link->multiple)) ||
      (save_message_store_attribute_failed (save->storage, link->first)))
    return GNUNET_NO;

  if ((GNUNET_YES == link->multiple) &&
      (save_message_store_attribute_failed (save->storage, link->second)))
    return GNUNET_NO;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_save_entries (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct GNUNET_MESSENGER_ClosureMessageSave *save;
  struct GNUNET_MESSENGER_MessageEntry *entry;

  GNUNET_assert ((cls) && (key) && (value));

  save = cls;
  entry = value;

  if ((save_message_store_attribute_failed (save->storage, (*key))) ||
      (save_message_store_attribute_failed (save->storage, entry->offset)) ||
      (save_message_store_attribute_failed (save->storage, entry->length)))
    return GNUNET_NO;

  return GNUNET_YES;
}


static enum GNUNET_GenericReturnValue
iterate_save_messages (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_MESSENGER_MessageEntryStorage storage;
  struct GNUNET_MESSENGER_ClosureMessageSave *save;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((cls) && (key) && (value));
  
  save = cls;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (save->store->entries,
                                                            key))
    return GNUNET_YES;

  message = value;

  GNUNET_memcpy (&(storage.hash), key, sizeof(storage.hash));

  storage.entry.length = get_message_size (message, GNUNET_YES);
  storage.entry.offset = GNUNET_DISK_file_seek (save->store->storage_messages,
                                                0, GNUNET_DISK_SEEK_END);

  if ((GNUNET_SYSERR == storage.entry.offset) ||
      (save_message_store_attribute_failed (save->storage, storage.hash)) ||
      (save_message_store_attribute_failed (save->storage,
                                            storage.entry.offset)) ||
      (save_message_store_attribute_failed (save->storage,
                                            storage.entry.length)))
    return GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Storing message with hash: %s\n",
              GNUNET_h2s (&(storage.hash)));

  {
    char *buffer;
    buffer = GNUNET_malloc (storage.entry.length);

    encode_message (message, storage.entry.length, buffer, GNUNET_YES);

    GNUNET_DISK_file_write (save->store->storage_messages, buffer,
                            storage.entry.length);

    GNUNET_free (buffer);
  }

  return GNUNET_YES;
}


void
save_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory)
{
  struct GNUNET_MESSENGER_ClosureMessageSave save;
  enum GNUNET_DISK_AccessPermissions permission;
  char *filename;

  GNUNET_assert ((store) && (directory));

  permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  if (GNUNET_YES != store->write_links)
    goto save_entries;

  GNUNET_asprintf (&filename, "%s%s", directory, "links.store");

  save.store = store;
  save.storage = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE
                                        | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free (filename);

  if (! save.storage)
    goto save_entries;

  if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage, 0,
                                              GNUNET_DISK_SEEK_SET))
    goto close_links;

  GNUNET_CONTAINER_multihashmap_iterate (store->links, iterate_save_links,
                                         &save);
  store->write_links = GNUNET_NO;

close_links:
  GNUNET_DISK_file_close (save.storage);

save_entries:
  GNUNET_asprintf (&filename, "%s%s", directory, "entries.store");

  save.store = store;
  save.storage = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE
                                        | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free (filename);

  if (! save.storage)
    return;

  if (GNUNET_YES == store->rewrite_entries)
  {
    if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage, 0,
                                                GNUNET_DISK_SEEK_SET))
      goto close_entries;

    GNUNET_CONTAINER_multihashmap_iterate (store->entries, iterate_save_entries,
                                           &save);
    store->rewrite_entries = GNUNET_NO;
  }
  else if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage, 0,
                                                   GNUNET_DISK_SEEK_END))
    goto close_entries;

  if (store->storage_messages)
    GNUNET_DISK_file_close (store->storage_messages);

  GNUNET_asprintf (&filename, "%s%s", directory, "messages.store");

  store->storage_messages = GNUNET_DISK_file_open (filename,
                                                   GNUNET_DISK_OPEN_READWRITE
                                                   | GNUNET_DISK_OPEN_CREATE,
                                                   permission);

  GNUNET_free (filename);

  if (store->storage_messages)
  {
    GNUNET_CONTAINER_multihashmap_iterate (store->messages,
                                           iterate_save_messages, &save);

    GNUNET_DISK_file_sync (store->storage_messages);
    GNUNET_DISK_file_sync (save.storage);
  }

close_entries:
  GNUNET_DISK_file_close (save.storage);
}


enum GNUNET_GenericReturnValue
contains_store_message (const struct GNUNET_MESSENGER_MessageStore *store,
                        const struct GNUNET_HashCode *hash)
{
  GNUNET_assert ((store) && (hash));

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (store->messages,
                                                            hash))
    return GNUNET_YES;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (store->discourses,
                                                            hash))
    return GNUNET_YES;

  return GNUNET_CONTAINER_multihashmap_contains (store->entries, hash);
}


const struct GNUNET_MESSENGER_Message*
get_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                   const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_MESSENGER_MessageEntry *entry;
  enum GNUNET_GenericReturnValue decoding;
  struct GNUNET_HashCode check;
  char *buffer;

  GNUNET_assert ((store) && (hash));

  message = GNUNET_CONTAINER_multihashmap_get (store->messages, hash);

  if (message)
    return message;

  message = GNUNET_CONTAINER_multihashmap_get (store->discourses, hash);

  if (message)
    return message;

  if (! store->storage_messages)
    return NULL;

  entry = GNUNET_CONTAINER_multihashmap_get (store->entries, hash);

  if (! entry)
    return NULL;

  if (entry->offset != GNUNET_DISK_file_seek (store->storage_messages,
                                              entry->offset,
                                              GNUNET_DISK_SEEK_SET))
    return message;

  buffer = GNUNET_malloc (entry->length);

  if (! buffer)
    return NULL;

  if ((GNUNET_DISK_file_read (store->storage_messages, buffer, entry->length) !=
       entry->length) ||
      (entry->length < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                              GNUNET_YES)))
    goto free_buffer;

  message = create_message (GNUNET_MESSENGER_KIND_UNKNOWN);
  decoding = decode_message (message, entry->length, buffer,
                             GNUNET_YES, NULL);

  hash_message (message, entry->length, buffer, &check);

  if ((GNUNET_YES != decoding) || (GNUNET_CRYPTO_hash_cmp (hash, &check) != 0))
  {
    if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (store->entries,
                                                            hash, entry))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Corrupted entry could not be removed from store: %s\n",
                  GNUNET_h2s (hash));

    store->rewrite_entries = GNUNET_YES;

    goto free_message;
  }

  if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (store->messages, hash,
                                                      message,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))

    goto free_buffer;

  free_message : destroy_message (message);
  message = NULL;

free_buffer:
  GNUNET_free (buffer);

  return message;
}


const struct GNUNET_MESSENGER_MessageLink*
get_store_message_link (struct GNUNET_MESSENGER_MessageStore *store,
                        const struct GNUNET_HashCode *hash,
                        enum GNUNET_GenericReturnValue deleted_only)
{
  const struct GNUNET_MESSENGER_Message *message;

  if (deleted_only)
    goto get_link;

  message = get_store_message (store, hash);

  if (message)
  {
    static struct GNUNET_MESSENGER_MessageLink link;

    GNUNET_memcpy (&(link.first), &(message->header.previous),
                  sizeof(link.first));

    link.multiple = GNUNET_MESSENGER_KIND_MERGE == message->header.kind?
                    GNUNET_YES : GNUNET_NO;

    if (GNUNET_YES == link.multiple)
      GNUNET_memcpy (&(link.second), &(message->body.merge.previous),
                    sizeof(link.second));
    else
      GNUNET_memcpy (&(link.second), &(message->header.previous),
                    sizeof(link.second));

    return &link;
  }

get_link:
  return GNUNET_CONTAINER_multihashmap_get (store->links, hash);
}


static void
add_link (struct GNUNET_MESSENGER_MessageStore *store,
          const struct GNUNET_HashCode *hash,
          const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_MESSENGER_MessageLink *link;

  GNUNET_assert ((store) && (hash) && (message));
  
  link = GNUNET_new (struct GNUNET_MESSENGER_MessageLink);

  GNUNET_memcpy (&(link->first), &(message->header.previous),
                 sizeof(link->first));

  link->multiple = GNUNET_MESSENGER_KIND_MERGE == message->header.kind?
                   GNUNET_YES : GNUNET_NO;

  if (GNUNET_YES == link->multiple)
    GNUNET_memcpy (&(link->second), &(message->body.merge.previous),
                   sizeof(link->second));
  else
    GNUNET_memcpy (&(link->second), &(message->header.previous),
                   sizeof(link->second));

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (store->links, hash, link,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))

    GNUNET_free (link);
  else
    store->write_links = GNUNET_YES;
}


enum GNUNET_GenericReturnValue
put_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                   const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_CONTAINER_MultiHashMap *map;

  GNUNET_assert ((store) && (hash) && (message));

  map = store->messages;

  if (get_message_discourse (message))
    map = store->discourses;

  return GNUNET_CONTAINER_multihashmap_put (map, hash, message,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
}


enum GNUNET_GenericReturnValue
delete_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                      const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_MessageEntry *entry;

  GNUNET_assert ((store) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (store->entries, hash);

  if (! entry)
    goto clear_memory;

  {
    const struct GNUNET_MESSENGER_Message *message;
    message = get_store_message (store, hash);

    if (message)
      add_link (store, hash, message);
  }

  if (! store->storage_messages)
    goto clear_entry;

  if (entry->offset != GNUNET_DISK_file_seek (store->storage_messages,
                                              entry->offset,
                                              GNUNET_DISK_SEEK_SET))
    return GNUNET_SYSERR;

  {
    char *clear_buffer;
    clear_buffer = GNUNET_malloc (entry->length);

    if (! clear_buffer)
      return GNUNET_SYSERR;

    GNUNET_CRYPTO_zero_keys (clear_buffer, entry->length);

    if ((entry->length != GNUNET_DISK_file_write (store->storage_messages,
                                                  clear_buffer, entry->length)) ||
        (GNUNET_OK
        !=
        GNUNET_DISK_file_sync (
          store->storage_messages)))
    {
      GNUNET_free (clear_buffer);
      return GNUNET_SYSERR;
    }

    GNUNET_free (clear_buffer);
  }

clear_entry:
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (store->entries, hash,
                                                          entry))
    store->rewrite_entries = GNUNET_YES;

clear_memory:
  GNUNET_CONTAINER_multihashmap_remove_all (store->messages, hash);
  return GNUNET_OK;
}


struct GNUNET_MESSENGER_CleanupDiscourseMessages
{
  struct GNUNET_MESSENGER_ListMessages *list;
  struct GNUNET_ShortHashCode discourse;
  struct GNUNET_TIME_Absolute timestamp;
};

static enum GNUNET_GenericReturnValue
iterate_flag_for_cleanup_discourse_message (void *cls,
                                            const struct GNUNET_HashCode *key,
                                            void *value)
{
  struct GNUNET_MESSENGER_CleanupDiscourseMessages *cleanup;
  struct GNUNET_MESSENGER_Message *message;
  const struct GNUNET_ShortHashCode *discourse;

  GNUNET_assert ((cls) && (key) && (value));

  cleanup = cls;
  message = value;

  discourse = get_message_discourse (message);

  if ((! discourse) || (0 != GNUNET_memcmp (discourse, &(cleanup->discourse))))
    return GNUNET_YES;

  {
    struct GNUNET_TIME_Absolute timestamp;
    timestamp = GNUNET_TIME_absolute_ntoh (message->header.timestamp);

    if (GNUNET_TIME_absolute_cmp(timestamp, >=, cleanup->timestamp))
      return GNUNET_YES;
  }

  add_to_list_messages (cleanup->list, key);
  destroy_message(message);

  return GNUNET_YES;
}

void
cleanup_store_discourse_messages_before (struct GNUNET_MESSENGER_MessageStore *store,
                                         const struct GNUNET_ShortHashCode *discourse,
                                         const struct GNUNET_TIME_Absolute timestamp)
{
  struct GNUNET_MESSENGER_ListMessages list;
  struct GNUNET_MESSENGER_CleanupDiscourseMessages cleanup;

  GNUNET_assert ((store) && (discourse));
    
  init_list_messages (&list);

  cleanup.list = &list;
  cleanup.timestamp = timestamp;

  GNUNET_memcpy (&(cleanup.discourse), discourse, 
                 sizeof (struct GNUNET_ShortHashCode));

  GNUNET_CONTAINER_multihashmap_iterate (store->discourses, 
                                         iterate_flag_for_cleanup_discourse_message,
                                         &cleanup);
  
  {
    struct GNUNET_MESSENGER_ListMessage *element;
    for (element = list.head; element; element = element->next)
      GNUNET_CONTAINER_multihashmap_remove_all (store->discourses, &(element->hash));
  }

  clear_list_messages (&list);
}
