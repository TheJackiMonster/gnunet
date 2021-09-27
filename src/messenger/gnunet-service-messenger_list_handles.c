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
 * @file src/messenger/gnunet-service-messenger_list_handles.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_list_handles.h"

#include "gnunet-service-messenger_handle.h"

void
init_list_handles (struct GNUNET_MESSENGER_ListHandles *handles)
{
  GNUNET_assert(handles);

  handles->head = NULL;
  handles->tail = NULL;
}

void
clear_list_handles (struct GNUNET_MESSENGER_ListHandles *handles)
{
  GNUNET_assert(handles);

  while (handles->head)
  {
    struct GNUNET_MESSENGER_ListHandle *element = handles->head;

    GNUNET_CONTAINER_DLL_remove(handles->head, handles->tail, element);
    destroy_handle (element->handle);
    GNUNET_free(element);
  }

  handles->head = NULL;
  handles->tail = NULL;
}

void
add_list_handle (struct GNUNET_MESSENGER_ListHandles *handles,
                 struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert((handles) && (handle));

  struct GNUNET_MESSENGER_ListHandle *element = GNUNET_new(struct GNUNET_MESSENGER_ListHandle);

  element->handle = handle;

  GNUNET_CONTAINER_DLL_insert_tail(handles->head, handles->tail, element);
}

int
remove_list_handle (struct GNUNET_MESSENGER_ListHandles *handles,
                    struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert((handles) && (handle));

  struct GNUNET_MESSENGER_ListHandle *element;

  for (element = handles->head; element; element = element->next)
    if (element->handle == handle)
      break;

  if (!element)
    return GNUNET_NO;

  GNUNET_CONTAINER_DLL_remove(handles->head, handles->tail, element);
  GNUNET_free(element);

  return GNUNET_YES;
}

struct GNUNET_MESSENGER_SrvHandle*
find_list_handle_by_member (const struct GNUNET_MESSENGER_ListHandles *handles,
                            const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handles) && (key));

  struct GNUNET_MESSENGER_ListHandle *element;

  for (element = handles->head; element; element = element->next)
    if (get_handle_member_id ((struct GNUNET_MESSENGER_SrvHandle*) element->handle, key))
      return element->handle;

  return NULL;
}
