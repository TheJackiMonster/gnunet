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
 * @file src/messenger/gnunet-service-messenger_message_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_store.h"

#include "gnunet-service-messenger_list_messages.h"

#include "gnunet_common.h"
#include "gnunet_network_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_util_lib.h"
#include "messenger_api_message.h"

#include <stdint.h>
#include <string.h>

void
init_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory)
{
  GNUNET_assert (store);

  store->directory = directory? GNUNET_strdup (directory) : NULL;

  store->storage_messages = NULL;
  store->writing_task = NULL;

  store->entries = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->links = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->discourses = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->epochs = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

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
iterate_destroy_hashs (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_HashCode *hash;

  GNUNET_assert (value);

  hash = value;

  GNUNET_free (hash);
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

  if (store->writing_task)
  {
    GNUNET_SCHEDULER_cancel (store->writing_task);
    store->writing_task = NULL;
  }

  GNUNET_CONTAINER_multihashmap_iterate (store->entries,
                                         iterate_destroy_entries, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->messages,
                                         iterate_destroy_messages, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->links, iterate_destroy_hashs,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->discourses,
                                         iterate_destroy_messages, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->epochs, iterate_destroy_hashs,
                                         NULL);

  GNUNET_CONTAINER_multihashmap_destroy (store->entries);
  GNUNET_CONTAINER_multihashmap_destroy (store->messages);
  GNUNET_CONTAINER_multihashmap_destroy (store->links);
  GNUNET_CONTAINER_multihashmap_destroy (store->discourses);
  GNUNET_CONTAINER_multihashmap_destroy (store->epochs);

  if (store->directory)
  {
    GNUNET_free (store->directory);
    store->directory = NULL;
  }
}


void
move_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory)
{
  GNUNET_assert ((store) && (directory));

  if (store->directory)
  {
    if (0 == strcmp (store->directory, directory))
      return;

    if (GNUNET_YES == GNUNET_DISK_directory_test (directory, GNUNET_NO))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Moving message store failed because directory exists already! (%s)\n",
                  directory);
      return;
    }

    if (0 != rename (store->directory, directory))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Moving message store failed! (%s -> %s)\n",
                  store->directory, directory);
      return;
    }

    GNUNET_free (store->directory);
  }

  store->directory = GNUNET_strdup (directory);
}


struct GNUNET_MESSENGER_MessageEntryStorage
{
  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_MessageEntry entry;
};

static int
load_message_store_attribute (const struct GNUNET_DISK_FileHandle *file,
                              void *attribute,
                              size_t attribute_len,
                              uint64_t *size)
{
  ssize_t result;

  result = GNUNET_DISK_file_read (file, attribute, attribute_len);
  if (GNUNET_SYSERR != result)
    *size -= result;

  return attribute_len != result;
}


#define load_message_store_attribute_failed(file, attribute, size) \
        load_message_store_attribute (file, &(attribute), sizeof(attribute), \
                                      &(size))

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
  uint64_t entry_size, size;

  if (GNUNET_OK != GNUNET_DISK_file_size (
        filename, &size, GNUNET_NO, GNUNET_YES))
    return;

  entry_size = sizeof(storage.hash) + sizeof(storage.entry.offset) + sizeof(
    storage.entry.length);

  if (size < entry_size)
    return;

  permission = (GNUNET_DISK_PERM_USER_READ);
  entries = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                   permission);

  if (! entries)
    return;

  memset (&storage, 0, sizeof(storage));
  entry = NULL;

  while (size >= entry_size)
  {
    if ((load_message_store_attribute_failed (entries, storage.hash, size)) ||
        (load_message_store_attribute_failed (entries, storage.entry.offset,
                                              size)) ||
        (load_message_store_attribute_failed (entries, storage.entry.length,
                                              size)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Loading message entry failed!\n");
      break;
    }

    entry = GNUNET_new (struct GNUNET_MESSENGER_MessageEntry);

    if (! entry)
      break;

    GNUNET_memcpy (entry, &(storage.entry), sizeof(*entry));

    if ((GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
           store->entries, &(storage.hash))) ||
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
           store->entries, &(storage.hash), entry,
           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Loading message entry twice: %s\n",
                  GNUNET_h2s (&(storage.hash)));
      store->rewrite_entries = GNUNET_YES;
      break;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loading message entry with hash: %s\n",
                GNUNET_h2s (&(storage.hash)));

    entry = NULL;
  }

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
  struct GNUNET_DISK_FileHandle *links;
  struct GNUNET_MESSENGER_MessageLinkStorage storage;
  struct GNUNET_MESSENGER_MessageLink *link;
  uint64_t link_size, size;

  if (GNUNET_OK != GNUNET_DISK_file_size (
        filename, &size, GNUNET_NO, GNUNET_YES))
    return;

  link_size = sizeof(storage.hash) + sizeof(storage.link.multiple) + sizeof(
    storage.link.first);

  if (size < link_size)
    return;

  permission = (GNUNET_DISK_PERM_USER_READ);

  links = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                 permission);

  if (! links)
    return;

  memset (&storage, 0, sizeof(storage));
  link = NULL;

  while (size >= link_size)
  {
    if ((load_message_store_attribute_failed (links, storage.hash, size)) ||
        (load_message_store_attribute_failed (links,
                                              storage.link.multiple, size)) ||
        (load_message_store_attribute_failed (links, storage.link.first, size))
        ||
        ((GNUNET_YES == storage.link.multiple) &&
         (load_message_store_attribute_failed (links, storage.link.second, size)
         )))
      break;

    link = GNUNET_new (struct GNUNET_MESSENGER_MessageLink);

    if (! link)
      break;

    GNUNET_memcpy (link, &(storage.link), sizeof(*link));

    if ((GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
           store->links, &(storage.hash))) ||
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
           store->links, &(storage.hash), link,
           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
      break;

    link = NULL;
  }

  if (link)
    GNUNET_free (link);

  GNUNET_DISK_file_close (links);
}


static void
load_message_store_epochs (struct GNUNET_MESSENGER_MessageStore *store,
                           const char *filename)
{
  enum GNUNET_DISK_AccessPermissions permission;
  struct GNUNET_DISK_FileHandle *epochs;
  struct GNUNET_HashCode storage[2];
  struct GNUNET_HashCode *epoch;
  uint64_t epoch_size, size;

  if (GNUNET_OK != GNUNET_DISK_file_size (
        filename, &size, GNUNET_NO, GNUNET_YES))
    return;

  epoch_size = sizeof(storage[0]) + sizeof(storage[1]);

  if (size < epoch_size)
    return;

  permission = (GNUNET_DISK_PERM_USER_READ);

  epochs = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                  permission);

  if (! epochs)
    return;

  epoch = NULL;

  while (size >= epoch_size)
  {
    if ((load_message_store_attribute_failed (epochs, storage[0], size)) ||
        (load_message_store_attribute_failed (epochs, storage[1], size)))
      break;

    epoch = GNUNET_new (struct GNUNET_HashCode);

    if (! epoch)
      break;

    GNUNET_memcpy (epoch, &(storage[1]), sizeof(*epoch));

    if ((GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
           store->epochs, &(storage[0]))) ||
        (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
           store->epochs, &(storage[0]), epoch,
           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
      break;

    epoch = NULL;
  }

  if (epoch)
    GNUNET_free (epoch);

  GNUNET_DISK_file_close (epochs);
}


void
load_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  enum GNUNET_DISK_AccessPermissions permission;
  char *filename;

  GNUNET_assert (store);

  if (! store->directory)
    return;

  permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  if (store->storage_messages)
    GNUNET_DISK_file_close (store->storage_messages);

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "messages.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    store->storage_messages = GNUNET_DISK_file_open (filename,
                                                     GNUNET_DISK_OPEN_READWRITE,
                                                     permission);
  else
    store->storage_messages = NULL;

  GNUNET_free (filename);

  if (! store->storage_messages)
    return;

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "entries.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    load_message_store_entries (store, filename);

  GNUNET_free (filename);

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "links.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    load_message_store_links (store, filename);

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "epochs.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    load_message_store_epochs (store, filename);

  GNUNET_free (filename);
}


struct GNUNET_MESSENGER_ClosureMessageSave
{
  struct GNUNET_MESSENGER_MessageStore *store;

  struct GNUNET_DISK_FileHandle *storage;
};


static enum GNUNET_GenericReturnValue
iterate_save_epochs (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_MESSENGER_ClosureMessageSave *save;
  struct GNUNET_HashCode *epoch;

  GNUNET_assert ((cls) && (key) && (value));

  save = cls;
  epoch = value;

  if ((save_message_store_attribute_failed (save->storage, (*key))) ||
      (save_message_store_attribute_failed (save->storage, (*epoch))))
    return GNUNET_NO;

  return GNUNET_YES;
}


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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Storing message entry with hash: %s\n",
              GNUNET_h2s (key));

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

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
        save->store->entries, key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Skipping storage of message: %s\n", GNUNET_h2s (key));
    return GNUNET_YES;
  }

  message = value;

  GNUNET_memcpy (&(storage.hash), key, sizeof(storage.hash));

  storage.entry.length = get_message_size (message, GNUNET_YES);
  storage.entry.offset = GNUNET_DISK_file_seek (
    save->store->storage_messages, 0, GNUNET_DISK_SEEK_END);

  if ((GNUNET_SYSERR == storage.entry.offset) ||
      (save_message_store_attribute_failed (save->storage, storage.hash)) ||
      (save_message_store_attribute_failed (save->storage,
                                            storage.entry.offset)) ||
      (save_message_store_attribute_failed (save->storage,
                                            storage.entry.length)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Storing entry of message failed: %s\n", GNUNET_h2s (key));
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Storing message with hash: %s\n",
              GNUNET_h2s (&(storage.hash)));

  {
    char *buffer;
    buffer = GNUNET_malloc (storage.entry.length);

    if (! buffer)
      return GNUNET_NO;

    encode_message (message, storage.entry.length, buffer, GNUNET_YES);

    GNUNET_DISK_file_write (save->store->storage_messages, buffer,
                            storage.entry.length);

    GNUNET_free (buffer);
  }

  {
    struct GNUNET_MESSENGER_MessageEntry *entry;
    entry = GNUNET_new (struct GNUNET_MESSENGER_MessageEntry);

    if (! entry)
      return GNUNET_NO;

    GNUNET_memcpy (entry, &(storage.entry), sizeof(*entry));

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
          save->store->entries, &(storage.hash), entry,
          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Message entry might get stored twice: %s\n",
                  GNUNET_h2s (&(storage.hash)));
      GNUNET_free (entry);
      return GNUNET_NO;
    }
  }

  return GNUNET_YES;
}


void
save_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  struct GNUNET_MESSENGER_ClosureMessageSave save;
  enum GNUNET_DISK_AccessPermissions permission;
  char *filename;

  GNUNET_assert (store);

  if (! store->directory)
    return;

  permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "epochs.store");

  save.store = store;
  save.storage = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE
                                        | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free (filename);

  if (! save.storage)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No access to local storage of message epochs!\n");
    goto save_links;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage, 0,
                                              GNUNET_DISK_SEEK_SET))
    goto close_epochs;

  GNUNET_CONTAINER_multihashmap_iterate (store->epochs, iterate_save_epochs,
                                         &save);

close_epochs:
  GNUNET_DISK_file_close (save.storage);

save_links:
  if (GNUNET_YES != store->write_links)
    goto save_entries;

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "links.store");

  save.store = store;
  save.storage = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE
                                        | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free (filename);

  if (! save.storage)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No access to local storage of message links!\n");
    goto save_entries;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage, 0,
                                              GNUNET_DISK_SEEK_SET))
    goto close_links;

  GNUNET_CONTAINER_multihashmap_iterate (store->links, iterate_save_links,
                                         &save);
  store->write_links = GNUNET_NO;

close_links:
  GNUNET_DISK_file_close (save.storage);

save_entries:
  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "entries.store");

  save.store = store;
  save.storage = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE
                                        | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free (filename);

  if (! save.storage)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No access to local storage of message entries!\n");
    return;
  }

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

  GNUNET_asprintf (&filename,
                   "%s%s", store->directory, "messages.store");

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
  save.storage = NULL;
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

  if (GNUNET_is_zero (hash))
    return NULL;

  message = GNUNET_CONTAINER_multihashmap_get (store->messages, hash);

  if (message)
    return message;

  message = GNUNET_CONTAINER_multihashmap_get (store->discourses, hash);

  if (message)
    return message;

  if (! store->storage_messages)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Local storage of messages is unavailable: %s\n",
                GNUNET_h2s (hash));
    return NULL;
  }

  entry = GNUNET_CONTAINER_multihashmap_get (store->entries, hash);

  if (! entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No entry in storage for message found: %s\n",
                GNUNET_h2s (hash));
    return NULL;
  }

  if (entry->offset != GNUNET_DISK_file_seek (store->storage_messages,
                                              entry->offset,
                                              GNUNET_DISK_SEEK_SET))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Offset for message in local storage invalid: %s\n",
                GNUNET_h2s (hash));
    return NULL;
  }

  buffer = GNUNET_malloc (entry->length);

  if (! buffer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Allocation for message data buffer failed: %s\n",
                GNUNET_h2s (hash));
    return NULL;
  }

  if ((GNUNET_DISK_file_read (store->storage_messages, buffer, entry->length) !=
       entry->length) ||
      (entry->length < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN,
                                              GNUNET_YES)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Reading message from local storage failed: %s\n",
                GNUNET_h2s (hash));
    goto free_buffer;
  }

  message = create_message (GNUNET_MESSENGER_KIND_UNKNOWN);
  decoding = decode_message (message, entry->length, buffer,
                             GNUNET_YES, NULL);

  hash_message (message, entry->length, buffer, &check);

  if ((GNUNET_YES != decoding) || (GNUNET_CRYPTO_hash_cmp (hash, &check) != 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Decoding message failed or checksum mismatched: %s\n",
                GNUNET_h2s (hash));

    if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (store->entries,
                                                            hash, entry))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Corrupted entry could not be removed from store: %s\n",
                  GNUNET_h2s (hash));

    store->rewrite_entries = GNUNET_YES;
    goto free_message;
  }

  if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (
        store->messages, hash, message,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    goto free_buffer;

free_message:
  destroy_message (message);
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

  if (GNUNET_is_zero (hash))
    return NULL;

  if (GNUNET_YES == deleted_only)
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


const struct GNUNET_HashCode*
get_store_message_epoch (const struct GNUNET_MESSENGER_MessageStore *store,
                         const struct GNUNET_HashCode *hash)
{
  struct GNUNET_HashCode *epoch;

  GNUNET_assert ((store) && (hash));

  epoch = GNUNET_CONTAINER_multihashmap_get (store->epochs, hash);

  if (! epoch)
    return hash;

  return epoch;
}


static void
add_link (struct GNUNET_MESSENGER_MessageStore *store,
          const struct GNUNET_HashCode *hash,
          const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_MESSENGER_MessageLink *link;

  GNUNET_assert ((store) && (hash) && (message));

  if (GNUNET_is_zero (hash))
    return;

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

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        store->links, hash, link,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    GNUNET_free (link);
  else
    store->write_links = GNUNET_YES;
}


static void
put_store_message_epoch (struct GNUNET_MESSENGER_MessageStore *store,
                         const struct GNUNET_HashCode *hash,
                         const struct GNUNET_HashCode *epoch)
{
  struct GNUNET_HashCode *copy;

  GNUNET_assert ((store) && (hash) && (epoch));

  if (GNUNET_is_zero (hash))
    return;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (
        store->epochs, hash))
    return;

  copy = GNUNET_new (struct GNUNET_HashCode);

  if (! copy)
    return;

  GNUNET_memcpy (copy, epoch, sizeof (struct GNUNET_HashCode));

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        store->epochs, hash, copy,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    GNUNET_free (copy);
}


static void
task_save_messages (void *cls)
{
  struct GNUNET_MESSENGER_MessageStore *store;

  GNUNET_assert (cls);

  store = cls;
  store->writing_task = NULL;

  save_message_store (store);
}


enum GNUNET_GenericReturnValue
put_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                   const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_HashCode *epoch;
  struct GNUNET_CONTAINER_MultiHashMap *map;
  enum GNUNET_GenericReturnValue result;

  GNUNET_assert ((store) && (hash) && (message));

  if (GNUNET_is_zero (hash))
    return GNUNET_SYSERR;

  epoch = GNUNET_CONTAINER_multihashmap_get (store->epochs, hash);

  if (epoch)
    goto reverse_epoch;

  epoch = GNUNET_new (struct GNUNET_HashCode);

  if (! epoch)
    goto skip_epoch;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
  case GNUNET_MESSENGER_KIND_LEAVE:
    GNUNET_memcpy (epoch, hash, sizeof (struct GNUNET_HashCode));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    {
      const struct GNUNET_HashCode *epoch0;
      const struct GNUNET_HashCode *epoch1;

      epoch0 = &(message->body.merge.epochs[0]);
      epoch1 = &(message->body.merge.epochs[1]);

      if (0 == GNUNET_CRYPTO_hash_cmp (epoch0, epoch1))
        GNUNET_memcpy (epoch, epoch0, sizeof (struct GNUNET_HashCode));
      else
        GNUNET_memcpy (epoch, hash, sizeof (struct GNUNET_HashCode));

      break;
    }
  default:
    GNUNET_memcpy (
      epoch,
      get_store_message_epoch (store, &(message->header.previous)),
      sizeof (struct GNUNET_HashCode));
    break;
  }

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (
        store->epochs, hash, epoch,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free (epoch);
    goto skip_epoch;
  }

reverse_epoch:
  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    put_store_message_epoch (
      store,
      &(message->header.previous),
      &(message->body.join.epoch));
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    put_store_message_epoch (
      store,
      &(message->header.previous),
      &(message->body.leave.epoch));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    put_store_message_epoch (
      store,
      &(message->header.previous),
      &(message->body.merge.epochs[0]));
    put_store_message_epoch (
      store,
      &(message->body.merge.previous),
      &(message->body.merge.epochs[1]));
    break;
  default:
    put_store_message_epoch (
      store,
      &(message->header.previous),
      epoch);
    break;
  }

skip_epoch:
  map = store->messages;

  if (get_message_discourse (message))
    map = store->discourses;

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (map, hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Message has already been stored! (%s)\n",
                GNUNET_h2s (hash));
    return GNUNET_SYSERR;
  }

  result = GNUNET_CONTAINER_multihashmap_put (
    map, hash, message,
    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  if ((GNUNET_OK != result) || (map == store->discourses))
    return result;

  if (! store->writing_task)
    store->writing_task = GNUNET_SCHEDULER_add_with_priority (
      GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
      task_save_messages,
      store);

  return result;
}


enum GNUNET_GenericReturnValue
delete_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                      const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_MessageEntry *entry;
  const struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert ((store) && (hash));

  entry = GNUNET_CONTAINER_multihashmap_get (store->entries, hash);

  if (! entry)
    goto clear_memory;

  message = get_store_message (store, hash);

  if (message)
  {
    if (GNUNET_YES == is_epoch_message (message))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Deletion of message is not allowed! (%s)\n",
                  GNUNET_h2s (hash));
      return GNUNET_SYSERR;
    }

    add_link (store, hash, message);
  }

  if (! store->storage_messages)
    goto clear_entry;

  if (entry->offset != GNUNET_DISK_file_seek (store->storage_messages,
                                              entry->offset,
                                              GNUNET_DISK_SEEK_SET))
    return GNUNET_SYSERR;

  {
    enum GNUNET_GenericReturnValue result;
    char *clear_buffer;

    clear_buffer = GNUNET_malloc (entry->length);

    if (! clear_buffer)
      return GNUNET_SYSERR;

    GNUNET_CRYPTO_zero_keys (clear_buffer, entry->length);

    if ((entry->length != GNUNET_DISK_file_write (store->storage_messages,
                                                  clear_buffer, entry->length))
        ||
        (GNUNET_OK != GNUNET_DISK_file_sync (store->storage_messages)))
      result = GNUNET_SYSERR;
    else
      result = GNUNET_OK;

    GNUNET_free (clear_buffer);

    if (GNUNET_OK != result)
      return result;
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

    if (GNUNET_TIME_absolute_cmp (timestamp, >=, cleanup->timestamp))
      return GNUNET_YES;
  }

  add_to_list_messages (cleanup->list, key);
  destroy_message (message);

  return GNUNET_YES;
}


void
cleanup_store_discourse_messages_before (struct GNUNET_MESSENGER_MessageStore *
                                         store,
                                         const struct GNUNET_ShortHashCode *
                                         discourse,
                                         const struct GNUNET_TIME_Absolute
                                         timestamp)
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
      GNUNET_CONTAINER_multihashmap_remove_all (
        store->discourses,
        &(element->hash));
  }

  clear_list_messages (&list);
}
