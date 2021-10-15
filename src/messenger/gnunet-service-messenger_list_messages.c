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
 * @file src/messenger/gnunet-service-messenger_list_messages.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_list_messages.h"

void
init_list_messages (struct GNUNET_MESSENGER_ListMessages *messages)
{
  GNUNET_assert(messages);

  messages->head = NULL;
  messages->tail = NULL;
}

void
clear_list_messages (struct GNUNET_MESSENGER_ListMessages *messages)
{
  GNUNET_assert(messages);

  while (messages->head)
  {
    struct GNUNET_MESSENGER_ListMessage *element = messages->head;

    GNUNET_CONTAINER_DLL_remove(messages->head, messages->tail, element);
    GNUNET_free(element);
  }

  messages->head = NULL;
  messages->tail = NULL;
}

void
add_to_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((messages) && (hash));

  struct GNUNET_MESSENGER_ListMessage *element = GNUNET_new(struct GNUNET_MESSENGER_ListMessage);

  GNUNET_memcpy(&(element->hash), hash, sizeof(struct GNUNET_HashCode));

  GNUNET_CONTAINER_DLL_insert_tail(messages->head, messages->tail, element);
}

void
copy_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                    const struct GNUNET_MESSENGER_ListMessages *origin)
{
  GNUNET_assert((messages) && (origin));

  struct GNUNET_MESSENGER_ListMessage *element;

  for (element = origin->head; element; element = element->next)
    add_to_list_messages (messages, &(element->hash));
}

void
remove_from_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                           const struct GNUNET_HashCode *hash)
{
  GNUNET_assert((messages) && (hash));

  struct GNUNET_MESSENGER_ListMessage *element;

  for (element = messages->head; element; element = element->next)
    if (0 == GNUNET_CRYPTO_hash_cmp (&(element->hash), hash))
    {
      GNUNET_CONTAINER_DLL_remove(messages->head, messages->tail, element);
      GNUNET_free(element);
      break;
    }
}

void
load_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                    const char *path)
{
  GNUNET_assert((messages) && (path));

  if (GNUNET_YES != GNUNET_DISK_file_test (path))
    return;

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open(
      path, GNUNET_DISK_OPEN_READ, permission
  );

  if (!handle)
    return;

  GNUNET_DISK_file_seek(handle, 0, GNUNET_DISK_SEEK_SET);

  struct GNUNET_HashCode hash;
  ssize_t len;

  do {
    len = GNUNET_DISK_file_read(handle, &hash, sizeof(hash));

    if (len != sizeof(hash))
      break;

    add_to_list_messages(messages, &hash);
  } while (len == sizeof(hash));

  GNUNET_DISK_file_close(handle);
}

void
save_list_messages (const struct GNUNET_MESSENGER_ListMessages *messages,
                    const char *path)
{
  GNUNET_assert((messages) && (path));

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  struct GNUNET_DISK_FileHandle *handle = GNUNET_DISK_file_open(
      path, GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_WRITE, permission
  );

  if (!handle)
    return;

  GNUNET_DISK_file_seek(handle, 0, GNUNET_DISK_SEEK_SET);

  struct GNUNET_MESSENGER_ListMessage *element;

  for (element = messages->head; element; element = element->next)
    GNUNET_DISK_file_write(handle, &(element->hash), sizeof(element->hash));

  GNUNET_DISK_file_sync(handle);
  GNUNET_DISK_file_close(handle);
}
