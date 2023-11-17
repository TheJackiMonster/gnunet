/*
   This file is part of GNUnet.
   Copyright (C) 2023 GNUnet e.V.

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
 * @file src/messenger/messenger_api_queue_messages.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_queue_messages.h"

void
init_queue_messages (struct GNUNET_MESSENGER_QueueMessages *messages)
{
  GNUNET_assert (messages);

  messages->head = NULL;
  messages->tail = NULL;
}


void
clear_queue_messages (struct GNUNET_MESSENGER_QueueMessages *messages)
{
  GNUNET_assert (messages);

  while (messages->head)
  {
    struct GNUNET_MESSENGER_QueueMessage *element = messages->head;

    GNUNET_CONTAINER_DLL_remove (messages->head, messages->tail, element);

    if (element->message)
      destroy_message (element->message);

    GNUNET_free (element);
  }

  messages->head = NULL;
  messages->tail = NULL;
}


void
enqueue_to_messages (struct GNUNET_MESSENGER_QueueMessages *messages,
                     const struct GNUNET_CRYPTO_PrivateKey *sender,
                     const struct GNUNET_MESSENGER_Message *message,
                     enum GNUNET_GenericReturnValue priority)
{
  GNUNET_assert ((messages) && (message));

  struct GNUNET_MESSENGER_QueueMessage *element = GNUNET_new (struct
                                                              GNUNET_MESSENGER_QueueMessage);

  if (! element)
    return;

  element->message = copy_message (message);

  if (sender)
    GNUNET_memcpy (&(element->sender), sender, sizeof (element->sender));

  if (! element->message)
  {
    GNUNET_free (element);
    return;
  }

  if (GNUNET_YES == priority)
    GNUNET_CONTAINER_DLL_insert (messages->head, messages->tail, element);
  else
    GNUNET_CONTAINER_DLL_insert_tail (messages->head, messages->tail, element);
}


struct GNUNET_MESSENGER_Message*
dequeue_from_messages (struct GNUNET_MESSENGER_QueueMessages *messages,
                       struct GNUNET_CRYPTO_PrivateKey *sender)
{
  GNUNET_assert (messages);

  struct GNUNET_MESSENGER_QueueMessage *element = messages->head;

  if (! element)
    return NULL;

  struct GNUNET_MESSENGER_Message *message = element->message;

  GNUNET_CONTAINER_DLL_remove (messages->head, messages->tail, element);

  if (sender)
    GNUNET_memcpy (sender, &(element->sender), sizeof (*sender));

  GNUNET_free (element);
  return message;
}
