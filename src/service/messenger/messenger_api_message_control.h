/*
   This file is part of GNUnet.
   Copyright (C) 2024 GNUnet e.V.

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
 * @file src/messenger/messenger_api_message_control.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_MESSAGE_CONTROL_H
#define GNUNET_MESSENGER_API_MESSAGE_CONTROL_H

#include "gnunet_common.h"
#include "gnunet_messenger_service.h"
#include "gnunet_util_lib.h"

struct GNUNET_MESSENGER_Message;
struct GNUNET_MESSENGER_MessageControl;

struct GNUNET_MESSENGER_MessageControlQueue
{
  struct GNUNET_MESSENGER_MessageControl *control;

  struct GNUNET_HashCode sender;
  struct GNUNET_HashCode context;
  struct GNUNET_HashCode hash;

  struct GNUNET_MESSENGER_Message *message;
  enum GNUNET_MESSENGER_MessageFlags flags;
  struct GNUNET_SCHEDULER_Task *task;

  struct GNUNET_MESSENGER_MessageControlQueue *prev;
  struct GNUNET_MESSENGER_MessageControlQueue *next;
};

struct GNUNET_MESSENGER_Room;

struct GNUNET_MESSENGER_MessageControl
{
  struct GNUNET_MESSENGER_Room *room;

  struct GNUNET_CONTAINER_MultiShortmap *peer_messages;
  struct GNUNET_CONTAINER_MultiShortmap *member_messages;

  struct GNUNET_MESSENGER_MessageControlQueue *head;
  struct GNUNET_MESSENGER_MessageControlQueue *tail;
};

/**
 * Creates and allocates a new message control for a <i>room</i> of the client API.
 *
 * @param[in,out] room Room
 * @return New message control
 */
struct GNUNET_MESSENGER_MessageControl*
create_message_control (struct GNUNET_MESSENGER_Room *room);

/**
 * Destroys a message control and frees its memory fully from the client API.
 *
 * @param[in,out] control Message control
 */
void
destroy_message_control (struct GNUNET_MESSENGER_MessageControl *control);

/**
 * Processes a new <i>message</i> with its <i>hash</i> and regarding information about
 * <i>sender</i>, <i>context</i> and message <i>flags</i> using a selected message
 * <i>control</i>.
 *
 * The message control will ensure order of messages so that senders of messages
 * can be identified via previously processed messages.
 *
 * @param[in,out] control Message control
 * @param[in] sender Sender hash
 * @param[in] context Context hash
 * @param[in] hash Message hash
 * @param[in] message Message
 * @param[in] flags Message flags
 */
void
process_message_control (struct GNUNET_MESSENGER_MessageControl *control,
                         const struct GNUNET_HashCode *sender,
                         const struct GNUNET_HashCode *context,
                         const struct GNUNET_HashCode *hash,
                         const struct GNUNET_MESSENGER_Message *message,
                         enum GNUNET_MESSENGER_MessageFlags flags);

#endif //GNUNET_MESSENGER_API_MESSAGE_CONTROL_H