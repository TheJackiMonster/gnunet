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
 * @file src/messenger/gnunet-service-messenger_list_handles.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_LIST_HANDLES_H
#define GNUNET_SERVICE_MESSENGER_LIST_HANDLES_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"

struct GNUNET_MESSENGER_SrvHandle;

struct GNUNET_MESSENGER_ListHandle
{
  struct GNUNET_MESSENGER_ListHandle *prev;
  struct GNUNET_MESSENGER_ListHandle *next;

  struct GNUNET_MESSENGER_SrvHandle *handle;
};

struct GNUNET_MESSENGER_ListHandles
{
  struct GNUNET_MESSENGER_ListHandle *head;
  struct GNUNET_MESSENGER_ListHandle *tail;
};

/**
 * Initializes list of <i>handles</i> as empty list.
 *
 * @param[out] handles List of handles
 */
void
init_list_handles (struct GNUNET_MESSENGER_ListHandles *handles);

/**
 * Destroys remaining <i>handles</i> and clears the list.
 *
 * @param[in/out] handles List of handles
 */
void
clear_list_handles (struct GNUNET_MESSENGER_ListHandles *handles);

/**
 * Adds a specific <i>handle</i> to the end of the list.
 *
 * @param[in/out] handles List of handles
 * @param[in/out] handle Handle
 */
void
add_list_handle (struct GNUNET_MESSENGER_ListHandles *handles,
                 struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Removes the first entry matching with a specific <i>handle</i> from the list of
 * <i>handles</i> and returns #GNUNET_YES on success or #GNUNET_NO on failure.
 *
 * @param[in/out] handles List of handles
 * @param[in/out] handle Handle
 * @return #GNUNET_YES on success, otherwise #GNUNET_NO
 */
int
remove_list_handle (struct GNUNET_MESSENGER_ListHandles *handles,
                    struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Searches linearly through the list of <i>handles</i> for members of a specific room
 * which is identified by a given <i>key</i>.
 *
 * If no handle is found which is a current member, NULL gets returned.
 *
 * @param[in] handles List of handles
 * @param[in] key Common key of a room
 * @return First handle which is a current member
 */
struct GNUNET_MESSENGER_SrvHandle*
find_list_handle_by_member (const struct GNUNET_MESSENGER_ListHandles *handles,
                            const struct GNUNET_HashCode *key);

#endif //GNUNET_SERVICE_MESSENGER_LIST_HANDLES_H
