/*
   This file is part of GNUnet.
   Copyright (C) 2023--2024 GNUnet e.V.

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

#include "gnunet_messenger_service.h"
#include "messenger_api_message.h"

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
    struct GNUNET_MESSENGER_QueueMessage *element;
    element = messages->head;

    GNUNET_CONTAINER_DLL_remove (messages->head, messages->tail, element);

    if (element->message)
      destroy_message (element->message);

    if (element->transcript)
      destroy_message (element->transcript);

    GNUNET_free (element);
  }

  messages->head = NULL;
  messages->tail = NULL;
}


void
enqueue_to_messages (struct GNUNET_MESSENGER_QueueMessages *messages,
                     const struct GNUNET_CRYPTO_PrivateKey *sender,
                     struct GNUNET_MESSENGER_Message *message,
                     struct GNUNET_MESSENGER_Message *transcript)
{
  struct GNUNET_MESSENGER_QueueMessage *element;
  enum GNUNET_MESSENGER_MessageKind kind;

  GNUNET_assert ((messages) && (sender) && (message));

  element = GNUNET_new (struct GNUNET_MESSENGER_QueueMessage);
  if (! element)
    return;

  kind = message->header.kind;

  element->message = message;
  element->transcript = transcript;

  GNUNET_memcpy (&(element->sender), sender, sizeof (element->sender));

  if (! element->message)
  {
    if (element->transcript)
      destroy_message (element->transcript);

    GNUNET_free (element);
    return;
  }

  if (GNUNET_MESSENGER_KIND_JOIN == kind)
    GNUNET_CONTAINER_DLL_insert (messages->head, messages->tail, element);
  else if (GNUNET_MESSENGER_KIND_SUBSCRIBE == kind)
  {
    struct GNUNET_MESSENGER_QueueMessage *other;
    
    other = messages->head;
    while (other)
    {
      if (GNUNET_MESSENGER_KIND_TALK == other->message->header.kind)
        break;

      other = other->next;
    }

    GNUNET_CONTAINER_DLL_insert_before (messages->head, messages->tail, other, element);
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (messages->head, messages->tail, element);
}


struct GNUNET_MESSENGER_Message*
dequeue_from_messages (struct GNUNET_MESSENGER_QueueMessages *messages,
                       struct GNUNET_CRYPTO_PrivateKey *sender,
                       struct GNUNET_MESSENGER_Message **transcript)
{
  struct GNUNET_MESSENGER_QueueMessage *element;
  struct GNUNET_MESSENGER_Message *message;

  GNUNET_assert (messages);

  element = messages->head;
  if (! element)
  {
    if (transcript)
      *transcript = NULL;

    return NULL;
  }

  message = element->message;

  if (transcript)
    *transcript = element->transcript;
  else if (element->transcript)
    destroy_message (element->transcript);

  GNUNET_CONTAINER_DLL_remove (messages->head, messages->tail, element);

  if (sender)
    GNUNET_memcpy (sender, &(element->sender), sizeof (*sender));

  GNUNET_free (element);
  return message;
}
