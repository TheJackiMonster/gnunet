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
 * @file src/messenger/gnunet-service-messenger_message_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"

struct GNUNET_MESSENGER_MessageEntry
{
  off_t offset;
  uint16_t length;
};

struct GNUNET_MESSENGER_Message;

struct GNUNET_MESSENGER_MessageLink
{
  uint8_t multiple;

  struct GNUNET_HashCode first;
  struct GNUNET_HashCode second;
};

struct GNUNET_MESSENGER_MessageStore
{
  struct GNUNET_DISK_FileHandle *storage_messages;

  struct GNUNET_CONTAINER_MultiHashMap *entries;
  struct GNUNET_CONTAINER_MultiHashMap *messages;
  struct GNUNET_CONTAINER_MultiHashMap *links;

  int rewrite_entries;
  int write_links;
};

/**
 * Initializes a message <i>store</i> as fully empty.
 *
 * @param[out] store Message store
 */
void
init_message_store (struct GNUNET_MESSENGER_MessageStore *store);

/**
 * Clears a message <i>store</i>, wipes its content and deallocates its memory.
 *
 * @param[in/out] store Message store
 */
void
clear_message_store (struct GNUNET_MESSENGER_MessageStore *store);

/**
 * Loads messages from a <i>directory</i> into a message <i>store</i>.
 *
 * @param[out] store Message store
 * @param[in] directory Path to a directory
 */
void
load_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory);

/**
 * Saves messages from a message <i>store</i> into a <i>directory</i>.
 *
 * @param[in] store Message store
 * @param[in] directory Path to a directory
 */
void
save_message_store (struct GNUNET_MESSENGER_MessageStore *store,
                    const char *directory);

/**
 * Checks if a message matching a given <i>hash</i> is stored in a message <i>store</i>.
 * The function returns #GNUNET_YES if a match is found, #GNUNET_NO otherwise.
 *
 * The message has not to be loaded from disk into memory for this check!
 *
 * @param[in] store Message store
 * @param[in] hash Hash of message
 * @return #GNUNET_YES on match, otherwise #GNUNET_NO
 */
int
contains_store_message (const struct GNUNET_MESSENGER_MessageStore *store,
                        const struct GNUNET_HashCode *hash);

/**
 * Returns the message from a message <i>store</i> matching a given <i>hash</i>. If no matching
 * message is found, NULL gets returned.
 *
 * This function requires the message to be loaded into memory!
 * @see contains_store_message()
 *
 * @param[in/out] store Message store
 * @param[in] hash Hash of message
 * @return Message or NULL
 */
const struct GNUNET_MESSENGER_Message*
get_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                   const struct GNUNET_HashCode *hash);

/**
 * Returns the message link from a message <i>store</i> matching a given <i>hash</i>. If the
 * flag is set to #GNUNET_YES, only links from deleted messages will be returned or NULL.
 *
 * Otherwise message links will also returned for messages found in the store under the given
 * hash. The link which will be returned copies link information from the message for
 * temporary usage.
 *
 * @param[in/out] store Message store
 * @param[in] hash Hash of message
 * @param[in] deleted_only Flag
 * @return Message link or NULL
 */
const struct GNUNET_MESSENGER_MessageLink*
get_store_message_link (struct GNUNET_MESSENGER_MessageStore *store,
                        const struct GNUNET_HashCode *hash,
                        int deleted_only);

/**
 * Stores a message into the message store. The result indicates if the operation was successful.
 *
 * @param[in/out] store Message store
 * @param[in] hash Hash of message
 * @param[in/out] message Message
 * @return #GNUNET_OK on success, otherwise #GNUNET_NO
 */
int
put_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                   const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_Message *message);

/**
 * Deletes a message in the message store. It will be removed from disk space and memory. The result
 * indicates if the operation was successful.
 *
 * @param[in/out] store Message store
 * @param[in] hash Hash of message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
delete_store_message (struct GNUNET_MESSENGER_MessageStore *store,
                      const struct GNUNET_HashCode *hash);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H
