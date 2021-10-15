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
 * @file src/messenger/gnunet-service-messenger_list_messages.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_LIST_MESSAGES_H
#define GNUNET_SERVICE_MESSENGER_LIST_MESSAGES_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"

struct GNUNET_MESSENGER_ListMessage
{
  struct GNUNET_MESSENGER_ListMessage *prev;
  struct GNUNET_MESSENGER_ListMessage *next;

  struct GNUNET_HashCode hash;
};

struct GNUNET_MESSENGER_ListMessages
{
  struct GNUNET_MESSENGER_ListMessage *head;
  struct GNUNET_MESSENGER_ListMessage *tail;
};

/**
 * Initializes list of message hashes as empty list.
 *
 * @param[out] messages List of hashes
 */
void
init_list_messages (struct GNUNET_MESSENGER_ListMessages *messages);

/**
 * Clears the list of message hashes.
 *
 * @param[in/out] messages List of hashes
 */
void
clear_list_messages (struct GNUNET_MESSENGER_ListMessages *messages);

/**
 * Adds a specific <i>hash</i> from a message to the end of the list.
 *
 * @param[in/out] messages List of hashes
 * @param[in] hash Hash of message
 */
void
add_to_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                      const struct GNUNET_HashCode *hash);

/**
 * Copies all message hashes from an <i>origin</i> to another list.
 *
 * @param[in/out] messages Destination list of hashes
 * @param[in] origin Source list of hashes
 */
void
copy_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                    const struct GNUNET_MESSENGER_ListMessages *origin);

/**
 * Removes the first entry with a matching <i>hash</i> from the list.
 *
 * @param[in/out] messages List of hashes
 * @param[in] hash Hash of message
 */
void
remove_from_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                           const struct GNUNET_HashCode *hash);

/**
 * Loads the list of message hashes from a file under a given <i>path</i>.
 *
 * @param[out] messages List of hashes
 * @param[in] path Path of file
 */
void
load_list_messages (struct GNUNET_MESSENGER_ListMessages *messages,
                    const char *path);

/**
 * Saves the list of message hashes to a file under a given <i>path</i>.
 *
 * @param[in] messages List of hashes
 * @param[in] path Path of file
 */
void
save_list_messages (const struct GNUNET_MESSENGER_ListMessages *messages,
                    const char *path);

#endif //GNUNET_SERVICE_MESSENGER_LIST_MESSAGES_H
